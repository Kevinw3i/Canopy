use async_trait::async_trait;
use dashmap::DashMap;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use shared::dto::database::{ExplainSummary, ExplainTableSummary, QueryDatabaseResponse};
use shared::dto::entitlements::DatabaseScope;
use sqlparser::ast::{
    visit_expressions, Expr, Query, Select, SetExpr, Statement, TableFactor, TableWithJoins,
    Value as SqlValue,
};
use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::Parser;
use std::collections::{BTreeSet, HashMap};
use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::DatabaseConnectionConfig;

#[derive(Debug, Clone)]
pub struct DatabaseSecret {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct ValidatedQuery {
    pub normalized_sql: String,
    pub tables: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct QueryRows {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<JsonValue>>,
    /// True when the executor truncated the row stream because it would
    /// have exceeded the response byte budget. The TUI / Claude client can
    /// surface this as "results truncated; narrow the query".
    #[allow(dead_code)] // Surfaced via `QueryDatabaseResponse::truncated`.
    pub truncated_by_byte_budget: bool,
}

/// Hard cap on the total approximate response payload size that the
/// executor will materialize in memory. Even with `LIMIT`, a single
/// authorized SELECT can pull large TEXT / BLOB columns or use allow-listed
/// functions to construct large values; without this cap the control-plane
/// can be pushed into OOM by a legitimate-looking query. Tied to the
/// advertised `McpGuardrails::max_response_bytes` default of 1 MiB.
pub const MAX_QUERY_RESPONSE_BYTES: usize = 1024 * 1024;

/// Cache TTL for the *negative-only* `information_schema.tables` lookup
/// cache. Only `View` / `Other` decisions are stored — positive `BaseTable`
/// answers are NEVER cached, so a DDL race that swaps a BASE TABLE for a
/// VIEW cannot be served from stale state. The negative cache is bounded
/// so a VIEW that an operator later legitimately drops + recreates as a
/// real table is not blocked for hours.
const TABLE_TYPE_NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(300);

/// Distinguishes the on-disk MySQL object behind a name referenced from a
/// validated SELECT. The control-plane treats anything that is NOT
/// `BaseTable` as untrusted when `DatabaseScope::allow_views = false`: a
/// VIEW can re-expand into base tables outside the scope, run under a
/// privileged DEFINER, or hide a query plan that bypasses the EXPLAIN
/// budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableType {
    /// `information_schema.tables.table_type = 'BASE TABLE'` — a regular
    /// on-disk table. This is the only type Canopy MCP allows by default.
    BaseTable,
    /// `information_schema.tables.table_type = 'VIEW'` (or `SYSTEM VIEW`,
    /// which we lump in here because both expand via the view definition
    /// and run under the view's DEFINER). Only allowed when the operator
    /// has set `DatabaseScope::allow_views = true`.
    View,
    /// Anything else MySQL might surface (e.g. `SEQUENCE` on MariaDB,
    /// future engine-specific types). Treated like `View` — denied unless
    /// `allow_views` is on AND the operator has accepted the risk.
    Other,
}

/// One (schema, table) pair to resolve via `information_schema.tables`.
/// Names are case-insensitive on the wire for parity with MySQL's
/// case-insensitive default `lower_case_table_names = 1`; the executor
/// lowercases both before lookup, which matches the validator's lowercase
/// invariant enforced at scope load time.
#[derive(Debug, Clone)]
pub struct TableTypeQuery {
    pub schema: String,
    pub table: String,
}

/// Hard cap on how many `(schema, table)` pairs the view-guard executor
/// will resolve in one request. a previous implementation allowed an
/// unbounded list lets a Claude session pile up information_schema work
/// per request. Real MCP queries touch a small handful of tables; 32 is
/// well above the legitimate ceiling and well below any DOS threshold.
const MAX_VIEW_TARGETS_PER_QUERY: usize = 32;

/// Outcome of `DatabaseExecutor::query_with_view_check`. The variant
/// separation lets the route audit each terminal state with the right
/// structured reason while reusing a single MDL-protected connection
/// across the entire view-check + EXPLAIN + SELECT pipeline.
#[derive(Debug)]
pub enum ViewCheckedQueryOutcome {
    /// View check + EXPLAIN evaluation both passed under MDL on the same
    /// connection that ran the SELECT. The `explain` summary is the one
    /// that was actually used to gate the SELECT, not a stale snapshot
    /// from an earlier connection.
    Ok {
        types: HashMap<(String, String), TableType>,
        explain: ExplainSummary,
        rows: QueryRows,
    },
    /// Between the route's Layer-A `fetch_table_types` reject and the
    /// Layer-B re-check inside this method, the type of at least one
    /// referenced object flipped (DDL race). The SELECT was NOT
    /// executed and the transaction was rolled back.
    ViewSwapDetected {
        types: HashMap<(String, String), TableType>,
        offender: (String, String, TableType),
    },
    /// EXPLAIN ran inside the same MDL-protected transaction as the
    /// view check and `evaluate_explain` rejected
    /// the plan against scope policy. The transaction was rolled back
    /// and the SELECT was NOT executed.
    ExplainRejected {
        types: HashMap<(String, String), TableType>,
        explain: ExplainSummary,
        error: DatabaseError,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Denied(String),
    #[error("{message}")]
    QueryPlanRejected {
        message: String,
        table: Option<String>,
        access_type: Option<String>,
        estimated_rows: Option<u64>,
        reason: &'static str,
    },
    #[error("{message}")]
    Internal {
        message: String,
        reason: &'static str,
    },
    /// The control-plane refused to queue the request — typically the
    /// per-connection semaphore had no slot within `connect_timeout_ms`
    ///. Mapped to HTTP 503 by `database_error_response`
    /// so clients see an overload signal rather than a generic 500.
    #[error("{message}")]
    Overloaded {
        message: String,
        reason: &'static str,
    },
}

/// Marker error type the connection-permit helper wraps in `anyhow::Error`
/// so the route can downcast and distinguish "local semaphore queue
/// full" overload from genuine connection-attempt failures. Surfaces as
/// `anyhow::Result::Err(...)` to the trait method's caller; the route
/// uses `err.chain().any(|e| e.is::<ConnectionQueueFull>())` to recognise
/// the overload case and emit the typed `DatabaseError::Overloaded`.
#[derive(Debug)]
pub struct ConnectionQueueFull;

impl std::fmt::Display for ConnectionQueueFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "database connection limiter queue is full; refusing this request \
             instead of queueing indefinitely",
        )
    }
}

impl std::error::Error for ConnectionQueueFull {}

/// Marker error type for "we got a local semaphore slot, but acquiring
/// the actual MySQL connection failed in a way that smells like
/// upstream-side saturation rather than a server bug". Two scenarios
/// `query_with_view_check` wraps in this marker:
///
/// 1. `tokio::time::timeout(connect_timeout, Conn::new(...))` fired —
///    the upstream TCP / TLS handshake or proxy is too slow.
/// 2. `mysql_async` surfaced a server error whose code matches "Too
///    many connections" (`1040`) — RDS Proxy / MySQL is at its
///    capacity, not Canopy.
///
/// without this marker, a saturated RDS Proxy or
/// a `max_connections`-bound MySQL surfaced as a generic 500
/// `database_execution_failed`, breaking client retry/backoff
/// semantics. The route translates this marker to
/// `DatabaseError::Overloaded { reason: "database_connection_unavailable" }`
/// and HTTP 503, matching the existing `connection_queue_full` shape.
#[derive(Debug)]
pub struct DatabaseConnectionUnavailable;

impl std::fmt::Display for DatabaseConnectionUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "database connection acquisition failed in a way consistent with \
             upstream saturation (timeout or server-too-busy); refusing this \
             request so the client can back off and retry",
        )
    }
}

impl std::error::Error for DatabaseConnectionUnavailable {}

/// Inspect a `mysql_async` error chain for the well-known server-side
/// saturation signal (error code `1040`, "Too many connections" /
/// `1203`, "Too many user connections"). Used by the connection-acquire
/// helper to translate raw mysql_async errors into the typed
/// `DatabaseConnectionUnavailable` marker so the route can return a
/// 503 overload instead of a 500.
fn is_mysql_capacity_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        if let Some(mysql_async::Error::Server(server_err)) =
            cause.downcast_ref::<mysql_async::Error>()
        {
            // the capacity bucket covers
            // memory/resource exhaustion in addition to plain
            // connection-count saturation:
            //   1037 ER_OUT_OF_MEMORY        — server allocation failed.
            //   1040 ER_CON_COUNT_ERROR      — max_connections exhausted.
            //   1041 ER_OUT_OF_RESOURCES     — generic resource exhaustion.
            //   1203 ER_TOO_MANY_USER_CONNECTIONS — RDS Proxy borrow
            //                                      exhaustion / per-user
            //                                      quota.
            // Deliberately excluded:
            //   1129 ER_HOST_IS_BLOCKED      — security/abuse signal, not
            //                                  capacity. Treating it as
            //                                  503 would mask the alert.
            //   1205 ER_LOCK_WAIT_TIMEOUT    — transient lock contention,
            //                                  not connection capacity.
            matches!(server_err.code, 1037 | 1040 | 1041 | 1203)
        } else {
            false
        }
    })
}

/// Acquire a MySQL `Conn` from any future of shape
/// `Future<Output = Result<Conn, mysql_async::Error>>` while uniformly
/// classifying both client-side timeout AND server-side capacity errors
/// (the codes covered by `is_mysql_capacity_error`) as
/// `DatabaseConnectionUnavailable`. Used by every executor method so the
/// route's `classify_executor_overload` sees the same shaped marker
/// regardless of which executor entry point first failed.
async fn acquire_conn_or_classify_overload<F>(
    connect_timeout: Duration,
    fut: F,
) -> anyhow::Result<mysql_async::Conn>
where
    F: std::future::Future<Output = Result<mysql_async::Conn, mysql_async::Error>>,
{
    match tokio::time::timeout(connect_timeout, fut).await {
        Ok(Ok(conn)) => Ok(conn),
        Ok(Err(err)) => {
            let wrapped: anyhow::Error = err.into();
            if is_mysql_capacity_error(&wrapped) {
                // Codex round 40 + 41 (HIGH): tag the route-level
                // 503 marker. `is_ambiguous_acquire_failure`
                // re-inspects the chain via downcast_ref to
                // `mysql_async::Error::Server` and skips the
                // cool-down / permit hold for capacity codes —
                // no orphan session, just upstream refusal.
                Err(anyhow::Error::new(DatabaseConnectionUnavailable).context(wrapped))
            } else {
                Err(wrapped)
            }
        }
        Err(_) => Err(anyhow::Error::new(DatabaseConnectionUnavailable)
            .context("database connection acquisition timed out under connect_timeout_ms")),
    }
}

/// Hard upper bound on how long a background cleanup task can hold the
/// connection permit waiting for `pool.disconnect()` or
/// `conn.disconnect()` to complete. The permit will eventually release
/// even if MySQL is permanently wedged; this prevents a stalled
/// upstream from leaking every connection slot forever.
///
/// Codex round 23 (HIGH): for this cap to actually bound concurrent
/// server-side sessions, the server itself must be set to drop the
/// session at a horizon **shorter** than the cap. We do that in
/// `mysql_opts_for_conn` by injecting `SET SESSION net_read_timeout =
/// 10` / `net_write_timeout = 10` / `wait_timeout = 25` as init SQL.
/// Together those guarantee that, regardless of whether the client-
/// side `disconnect` future completes within the cap, the server will
/// have already torn down the TCP session and freed the upstream
/// `max_connections` slot before the limiter releases its accounting
/// permit. Without those init values the helpers below would only
/// bound client-side resource usage, not the upstream session count
/// they claim to bound.
///
/// Picked at 30 s because it greatly exceeds the largest configurable
/// `connect_timeout_ms` (10 s) plus typical TCP RST/QUIT, while still
/// being short enough that operators see slot depletion recover
/// within a minute of the upstream coming back. See
/// `ACQUIRE_FAILURE_PERMIT_HOLD` below for the **longer** hold used
/// when init SQL never ran.
const POOL_CLEANUP_HARD_CAP: Duration = Duration::from_secs(30);

/// Hold time used by `permit_hold_after_acquire_failure`. Strictly
/// longer than `POOL_CLEANUP_HARD_CAP` because the acquire-failure
/// path is the one case where our init SQL may NOT have run yet (the
/// future was cancelled during TCP / handshake / auth / init), so the
/// only horizon that bounds the orphan upstream session is the
/// role-level `wait_timeout` set by the operator — not the 25 s init
/// value we would otherwise install.
///
/// Codex round 25 (HIGH): an acquire-failure-induced orphan session
/// will live as long as the role's `wait_timeout`. The repo operator
/// docs (`docs/zh-TW/OPERATOR-SETUP.md`) MUST mandate that role-level
/// `wait_timeout` be ≤ this constant; otherwise the helper releases
/// the limiter slot before MySQL has reaped the orphan, and a retry
/// can put us back over `max_connections`. The control plane is not
/// in a position to probe and validate that at runtime today (we hold
/// the read-only Secrets Manager credential, not an admin one), so
/// the contract is enforced by operator setup + doc + a comfortable
/// margin here: 60 s comfortably covers the operator guidance
/// (`wait_timeout` ≤ 30 s) plus a typical TCP keep-alive window for
/// pre-init RST.
const ACQUIRE_FAILURE_PERMIT_HOLD: Duration = Duration::from_secs(60);

/// Maximum allowed `@@session.wait_timeout` on a pre-init connection,
/// in seconds. See `preflight_session_safety` and round-26 review.
const PREFLIGHT_WAIT_TIMEOUT_CEILING_SECS: u64 = 30;

/// Open a *pre-init* connection (no `OptsBuilder::init` SQL) and verify
/// that the server-side `@@session.wait_timeout` is at or below
/// `PREFLIGHT_WAIT_TIMEOUT_CEILING_SECS`.
///
/// Codex round 26 (HIGH): the operator doc `docs/zh-TW/OPERATOR-SETUP.md`
/// declares the invariant
///   role-level `wait_timeout` ≤ 30 s
/// but documentation cannot enforce a runtime guarantee — an operator
/// who follows the `SET PERSIST_ONLY init_connect = ...` recipe and
/// forgets to restart MySQL is still serving partial sessions with
/// the default 28 800 s timeout. This preflight closes that gap by
/// actually connecting as the read-only user, asking the server what
/// `@@session.wait_timeout` it would hand a session that hasn't run
/// init SQL, and failing startup readiness if the answer is too
/// large.
///
/// The connection is built deliberately without our own
/// `OptsBuilder::init` so the value reported is the one a partial
/// (auth done, init not run) session would see — which is the exact
/// state `permit_hold_after_acquire_failure` is sized for. Calling
/// this from `AppState::run_preflight` keeps the health endpoint at
/// 503 (and the ALB target unhealthy) until the upstream invariant
/// is met.
pub async fn preflight_session_safety(
    connection: &DatabaseConnectionConfig,
    secret: &DatabaseSecret,
) -> anyhow::Result<()> {
    use mysql_async::prelude::Queryable;

    let mut opts = mysql_async::OptsBuilder::default()
        .ip_or_hostname(connection.host.clone())
        .tcp_port(connection.port)
        .db_name(Some(connection.database.clone()))
        .user(Some(secret.username.clone()))
        .pass(Some(secret.password.clone()));
    if connection.require_tls {
        let mut ssl_opts = mysql_async::SslOpts::default();
        if connection.accept_invalid_tls_certs {
            ssl_opts = ssl_opts.with_danger_accept_invalid_certs(true);
        }
        if connection.skip_tls_hostname_verification {
            ssl_opts = ssl_opts.with_danger_skip_domain_validation(true);
        }
        opts = opts.ssl_opts(Some(ssl_opts));
    }

    // Codex round 40 (HIGH): hard-cap the preflight connect/disconnect
    // budget so an operator who set `connect_timeout_ms` very large
    // cannot wedge startup readiness or block the reprobe loop for
    // arbitrarily long. 5 s comfortably covers a healthy
    // RDS/Aurora handshake while staying well inside any
    // operationally-sensible deadline.
    const MAX_PREFLIGHT_CONNECT_BUDGET: Duration = Duration::from_secs(5);
    let connect_timeout = std::cmp::min(
        Duration::from_millis(connection.connect_timeout_ms),
        MAX_PREFLIGHT_CONNECT_BUDGET,
    );
    let mut conn = match tokio::time::timeout(connect_timeout, mysql_async::Conn::new(opts)).await {
        Ok(Ok(c)) => c,
        Ok(Err(err)) => {
            // Codex round 36 + 37 + 41 (HIGH): three-way classify.
            //   - Pre-session (auth denied, ECONNREFUSED, ...): no
            //     marker, no cool-down.
            //   - Capacity (1037/1040/1041/1203): mark BOTH
            //     `DatabaseConnectionUnavailable` (route 503) AND
            //     `DatabaseOverloadRetryable` so
            //     `is_ambiguous_acquire_failure` skips the
            //     5-minute reprobe cool-down — there is no orphan
            //     session, just upstream capacity refusal.
            //   - Everything else (driver/TLS/unknown IO): stays
            //     ambiguous → cool-down.
            if is_pre_session_mysql_error(&err) {
                return Err(
                    anyhow::Error::new(err).context("preflight connect failed (pre-session)")
                );
            }
            let wrapped: anyhow::Error = err.into();
            if is_mysql_capacity_error(&wrapped) {
                // `is_ambiguous_acquire_failure` detects capacity
                // by downcasting `mysql_async::Error::Server` in
                // the chain, so the marker stack here matches the
                // request-path acquire helper.
                return Err(anyhow::Error::new(DatabaseConnectionUnavailable)
                    .context(wrapped)
                    .context("preflight connect refused (upstream capacity)"));
            }
            return Err(anyhow::Error::new(DatabaseConnectionUnavailable)
                .context(wrapped)
                .context("preflight connect failed (ambiguous)"));
        }
        Err(_) => {
            // Codex round 35 + 36 (HIGH): we cancelled
            // `Conn::new` mid-flight. The server may have
            // allocated an authenticated session it cannot
            // know is orphaned — exactly the case where the
            // cool-down matters. Tag ambiguous.
            return Err(anyhow::Error::new(DatabaseConnectionUnavailable)
                .context("preflight connect timed out (connect_timeout_ms)"));
        }
    };

    // Codex round 27 (HIGH): we MUST validate both @@session and
    // @@global. See round 38 comment below for the cleanup
    // structure that makes this safe under flapping upstreams.
    //
    // Codex round 38 + 39 (HIGH): the cleanup invariants are
    //   - probe is bounded internally (no outer cancellation can
    //     interrupt cleanup); see PROBE_QUERY_BUDGET.
    //   - disconnect always runs and its outcome is captured.
    //   - if disconnect didn't return Ok(Ok(())), we cannot prove
    //     the server-side session is gone — tag ambiguous, even
    //     if probe succeeded with healthy wait_timeout values,
    //     so the caller applies the orphan cool-down.
    const PROBE_QUERY_BUDGET: Duration = Duration::from_secs(10);
    let probe_result: anyhow::Result<(u64, u64)> =
        match tokio::time::timeout(PROBE_QUERY_BUDGET, async {
            let session_wait: Option<u64> =
                conn.query_first("SELECT @@session.wait_timeout").await?;
            let global_wait: Option<u64> = conn.query_first("SELECT @@global.wait_timeout").await?;
            let session_wait = session_wait
                .ok_or_else(|| anyhow::anyhow!("SELECT @@session.wait_timeout returned no rows"))?;
            let global_wait = global_wait
                .ok_or_else(|| anyhow::anyhow!("SELECT @@global.wait_timeout returned no rows"))?;
            anyhow::Ok((session_wait, global_wait))
        })
        .await
        {
            Ok(r) => r,
            Err(_) => Err(anyhow::anyhow!(
                "preflight probe exceeded PROBE_QUERY_BUDGET"
            )),
        };
    // Capture disconnect outcome so we can tell whether the
    // server-side session is provably gone.
    let disconnect_outcome = tokio::time::timeout(connect_timeout, conn.disconnect()).await;
    let disconnect_clean = matches!(disconnect_outcome, Ok(Ok(())));

    let (session_wait, global_wait) = match probe_result {
        Ok(t) => t,
        Err(e) => {
            // Probe failed mid-flight; ambiguous regardless of
            // disconnect outcome.
            return Err(anyhow::Error::new(DatabaseConnectionUnavailable)
                .context(e.context("preflight probe failed after connect (ambiguous)")));
        }
    };

    if session_wait > PREFLIGHT_WAIT_TIMEOUT_CEILING_SECS
        || global_wait > PREFLIGHT_WAIT_TIMEOUT_CEILING_SECS
    {
        let invariant_err = anyhow::anyhow!(
            "wait_timeout invariant violated on database connection (host={}, db={}): \
             @@session={session_wait}s, @@global={global_wait}s, both must be ≤ {ceiling}s. \
             A connection that fails before our `OptsBuilder::init` runs inherits @@global, \
             so a low @@session.wait_timeout via init_connect is NOT enough on its own. \
             Fix the upstream via parameter group (RDS/Aurora) or `SET GLOBAL/SET PERSIST \
             wait_timeout = 25`; see docs/zh-TW/OPERATOR-SETUP.md.",
            connection.host,
            connection.database,
            ceiling = PREFLIGHT_WAIT_TIMEOUT_CEILING_SECS,
        );
        // Codex round 39 (HIGH): invariant violation + clean
        // disconnect = no orphan to protect. Invariant violation
        // + failed/timed-out disconnect = orphan with the very
        // wait_timeout we just rejected (e.g. 28 800 s), so we
        // tag ambiguous to apply the orphan cool-down.
        return if disconnect_clean {
            Err(invariant_err)
        } else {
            Err(anyhow::Error::new(DatabaseConnectionUnavailable).context(invariant_err))
        };
    }

    // Healthy invariant. If disconnect didn't return Ok(Ok(())),
    // the upstream session may linger ≤ 25 s (the value we just
    // verified). That is shorter than DB_REPROBE_COOLDOWN, so we
    // do NOT need to tag ambiguous — the next reprobe tick
    // (60 s) will already be safe.
    let _ = disconnect_clean; // kept for documentation
    Ok(())
}

/// Drive `pool.disconnect()` to completion while holding `permit`, with
/// the caller waiting at most `cleanup_budget` for it to finish.
///
/// Codex round 21 (HIGH): the obvious shape
///
///   let _permit = acquire();
///   let _ = tokio::time::timeout(cleanup_budget, pool.disconnect()).await;
///
/// has a subtle accounting bug. On timeout the disconnect future is
/// cancelled mid-flight but `_permit` releases the slot immediately as
/// the surrounding scope exits, even though the server-side session
/// (reset / QUIT / TLS shutdown) may still be alive. Under retry storms
/// against a wedged upstream, Canopy could admit more concurrent
/// requests than `max_connections` lets in, defeating the load shedding
/// contract this limiter exists to enforce.
///
/// This helper instead spawns a detached task that owns *both* the
/// permit and the pool. The task runs `pool.disconnect()` under
/// `POOL_CLEANUP_HARD_CAP` so a dead upstream cannot leak slots
/// forever, and releases the permit only when disconnect actually
/// returns (or the hard cap fires). The current task waits up to
/// `cleanup_budget` to see if the disconnect lands quickly; if not,
/// dropping the JoinHandle simply detaches it — tokio tasks are not
/// cancelled on handle drop — so the slot remains accounted for in the
/// background while the caller returns.
///
/// `context` is a short literal label used in the warn log on timeout
/// so it can be attributed back to the call site.
async fn release_pool_bounded_cleanup(
    permit: OwnedSemaphorePermit,
    pool: mysql_async::Pool,
    cleanup_budget: Duration,
    context: &'static str,
) {
    let mut handle = tokio::spawn(async move {
        // `_held` is the permit lifetime: by holding it inside the
        // task we guarantee the limiter only counts the slot as free
        // once `pool.disconnect()` actually returns.
        let _held = permit;
        let _ = tokio::time::timeout(POOL_CLEANUP_HARD_CAP, pool.disconnect()).await;
    });
    if tokio::time::timeout(cleanup_budget, &mut handle)
        .await
        .is_err()
    {
        tracing::warn!(
            operation = context,
            cleanup_budget_ms = cleanup_budget.as_millis() as u64,
            hard_cap_ms = POOL_CLEANUP_HARD_CAP.as_millis() as u64,
            "pool.disconnect() exceeded cleanup_budget; connection permit will be held by a \
             background cleanup task (bounded by POOL_CLEANUP_HARD_CAP) so max_connections \
             continues to bound concurrent server-side sessions"
        );
        // Drop the JoinHandle — the task is detached and continues to
        // run until it finishes or hits the hard cap, at which point
        // the permit is released.
    }
}

/// Same accounting invariant as `release_pool_bounded_cleanup` but for
/// the standalone `Conn::new(...)` lifecycle used by the MDL-protected
/// `query_with_view_check` path (which deliberately bypasses the pool).
///
/// Codex round 22 (HIGH): the pool variant fixed `explain` / `query` /
/// `fetch_table_types`, but `query_with_view_check` — the load-bearing
/// path the route actually drives `/api/mcp/database/query` through —
/// still wrapped `conn.disconnect()` in a stack-bound timeout. On
/// expiry the future drops, `Drop for Conn` spawns its own background
/// cleanup, and the `OwnedSemaphorePermit` releases as the caller's
/// stack unwinds — even though the upstream session may still be
/// alive. Under retries against a wedged upstream, this is the path
/// that admits more concurrent server-side sessions than
/// `max_connections` is supposed to allow.
///
/// This helper moves both the `Conn` and the permit into a detached
/// task. The task runs `conn.disconnect()` under
/// `POOL_CLEANUP_HARD_CAP` so a dead upstream cannot leak slots
/// forever, and releases the permit only when disconnect returns or
/// the hard cap fires. The current task waits up to `cleanup_budget`
/// for the disconnect to land; if not, dropping the JoinHandle simply
/// detaches it (tokio tasks are not cancelled on handle drop).
async fn release_conn_bounded_cleanup(
    permit: OwnedSemaphorePermit,
    conn: mysql_async::Conn,
    cleanup_budget: Duration,
    context: &'static str,
) {
    let mut handle = tokio::spawn(async move {
        let _held = permit;
        let _ = tokio::time::timeout(POOL_CLEANUP_HARD_CAP, conn.disconnect()).await;
    });
    if tokio::time::timeout(cleanup_budget, &mut handle)
        .await
        .is_err()
    {
        tracing::warn!(
            operation = context,
            cleanup_budget_ms = cleanup_budget.as_millis() as u64,
            hard_cap_ms = POOL_CLEANUP_HARD_CAP.as_millis() as u64,
            "conn.disconnect() exceeded cleanup_budget; connection permit will be held by a \
             background cleanup task (bounded by POOL_CLEANUP_HARD_CAP) so max_connections \
             continues to bound concurrent server-side sessions"
        );
    }
}

/// Hold `permit` for `ACQUIRE_FAILURE_PERMIT_HOLD` after a connection
/// acquire fails (timeout or error), without owning a `Conn` we could
/// disconnect.
///
/// Codex round 24 + 25 (HIGH): `Conn::new(...)` and `pool.get_conn()`
/// both open the TCP socket, run the MySQL handshake, authenticate,
/// AND execute any `OptsBuilder::init` SQL before returning. If our
/// `acquire_conn_or_classify_overload` timeout fires anywhere in that
/// window, the future is cancelled and the partially-built `Conn`
/// drops — but the server may already have an authenticated session
/// it doesn't know is orphaned. Releasing the limiter permit
/// immediately on this path lets a fresh request open a new session
/// while the old one still consumes a slot in MySQL's
/// `max_connections`, putting us right back where the bounded
/// cleanup is supposed to prevent over-admission.
///
/// The orphan's lifetime depends on whether init SQL ran before
/// cancellation:
///
/// - If init SQL ran, server-side `wait_timeout` is 25 s
///   (`mysql_opts_for_conn`).
/// - If init SQL did NOT run, the orphan lives as long as the
///   **role-level** `wait_timeout` — which `docs/zh-TW/OPERATOR-SETUP.md`
///   now mandates be ≤ 30 s.
///
/// We can't actively `KILL CONNECTION` here because we don't have the
/// `thread_id` and don't want to demand DBA privileges for the
/// Secrets-Manager-issued read-only role. So we hold the permit for
/// `ACQUIRE_FAILURE_PERMIT_HOLD` (60 s) — comfortably longer than the
/// 30 s role-level `wait_timeout` ceiling, with margin to spare for
/// operator misconfiguration. After that the slot returns; the warn
/// log below tells operators to investigate the upstream.
/// Decide whether a `Conn::new` / `pool.get_conn` failure could have
/// left a half-built server-side session.
///
/// Codex round 30 (MED): only timeout / capacity / TLS handshake
/// errors are "ambiguous" (the TCP socket may have completed and the
/// server may have allocated an authenticated session before
/// cancellation). Deterministic config errors — wrong password,
/// unknown database, TLS validation rejected by the server — never
/// produce an upstream session. Holding the permit for
/// `ACQUIRE_FAILURE_PERMIT_HOLD` (60 s) on those is just queue
/// exhaustion: every retry burns a slot for a minute even though the
/// limiter invariant is not at risk.
pub fn is_ambiguous_acquire_failure(err: &anyhow::Error) -> bool {
    // Codex round 40 + 41 (HIGH): a failure is ambiguous (orphan-
    // risk → cool-down) iff:
    //   - it carries the `DatabaseConnectionUnavailable` marker
    //     (the route-level 503 signal), AND
    //   - it is NOT a known upstream capacity refusal.
    // Capacity errors (MySQL server codes 1037 / 1040 / 1041 /
    // 1203) are deterministic — the server explicitly refused to
    // allocate a session, so there is no orphan to protect.
    //
    // `DatabaseOverloadRetryable` exists for documentation /
    // tracing but `anyhow::Error::context(typed_marker)` wraps
    // it inside `ContextError<T,_>`, so `e.is::<T>()` checking the
    // chain does NOT see it. We instead inspect every chain layer
    // and ask: is any of them a `mysql_async::Error::Server` with
    // a known capacity code? That works because anyhow preserves
    // the original typed error at the chain root via
    // `Error::new(err)` / `err.into()`.
    let has_unavailable = err.chain().any(|e| e.is::<DatabaseConnectionUnavailable>());
    if !has_unavailable {
        return false;
    }
    let is_capacity = err.chain().any(|e| {
        e.downcast_ref::<mysql_async::Error>()
            .map(|me| {
                matches!(
                    me,
                    mysql_async::Error::Server(s)
                        if matches!(s.code, 1037 | 1040 | 1041 | 1203)
                )
            })
            .unwrap_or(false)
    });
    !is_capacity
}

/// Decide whether a `mysql_async::Error` is *definitely* pre-session
/// (i.e. the server never allocated an authenticated session for the
/// connection attempt). Used by `preflight_session_safety` to decide
/// whether to tag the resulting error as ambiguous.
///
/// Codex round 37 (HIGH): allowlist, not denylist. We treat the
/// outcome as ambiguous (might-have-orphan, set cool-down) by
/// default, and only short-circuit to "deterministic, no cool-down"
/// for error variants/codes we can prove never allocated a session.
/// `Conn::new` does handshake + auth + setup before returning, so
/// driver/protocol failures and unclassified I/O variants can have
/// touched the server post-handshake — they must stay ambiguous to
/// avoid orphan accumulation under a flapping upstream.
pub fn is_pre_session_mysql_error(err: &mysql_async::Error) -> bool {
    use mysql_async::Error;
    use mysql_async::IoError;
    use std::io::ErrorKind;
    match err {
        Error::Server(server_err) => matches!(
            server_err.code,
            // ER_ACCESS_DENIED_ERROR — auth phase, server closes.
            1045
            // ER_DBACCESS_DENIED_ERROR — auth phase.
            | 1044
            // ER_BAD_DB_ERROR — auth phase, server closes.
            | 1049
            // ER_HOST_IS_BLOCKED — pre-handshake reject (max
            // connect errors hit).
            | 1129
            // ER_HOST_NOT_PRIVILEGED — pre-handshake reject.
            | 1130
            // ER_PASSWORD_NO_MATCH — auth phase.
            | 1133
        ),
        Error::Io(IoError::Io(io_err)) => matches!(
            io_err.kind(),
            // ConnectionRefused / no listener / unrouteable address
            // — TCP layer never completed handshake.
            ErrorKind::ConnectionRefused
                | ErrorKind::NotFound
                | ErrorKind::AddrNotAvailable
                | ErrorKind::InvalidInput
        ),
        // URL parsing / config errors never touch the wire.
        Error::Url(_) => true,
        // TLS handshake, driver protocol, and unclassified Other
        // failures may have reached the server post-auth before
        // surfacing the error. Treat as ambiguous.
        _ => false,
    }
}

fn permit_hold_after_acquire_failure(permit: OwnedSemaphorePermit, context: &'static str) {
    tracing::warn!(
        operation = context,
        hold_ms = ACQUIRE_FAILURE_PERMIT_HOLD.as_millis() as u64,
        "connection acquire failed; holding limiter permit for ACQUIRE_FAILURE_PERMIT_HOLD \
         so a half-built upstream session does not put us over max_connections before the \
         server's role-level `wait_timeout` reaps it (operators: confirm role `wait_timeout` \
         is ≤ 30 s — see docs/zh-TW/OPERATOR-SETUP.md)"
    );
    tokio::spawn(async move {
        let _held = permit;
        tokio::time::sleep(ACQUIRE_FAILURE_PERMIT_HOLD).await;
    });
}

#[async_trait]
pub trait DatabaseSecretProvider: Send + Sync {
    async fn load_secret(&self, secret_arn: &str) -> anyhow::Result<DatabaseSecret>;
}

#[async_trait]
pub trait DatabaseExecutor: Send + Sync {
    async fn explain(
        &self,
        connection: &DatabaseConnectionConfig,
        secret: &DatabaseSecret,
        sql: &str,
        timeout_ms: u64,
    ) -> anyhow::Result<ExplainSummary>;

    async fn query(
        &self,
        connection: &DatabaseConnectionConfig,
        secret: &DatabaseSecret,
        sql: &str,
        timeout_ms: u64,
    ) -> anyhow::Result<QueryRows>;

    /// Resolve a batch of `(schema, table)` references to their MySQL table
    /// type by reading `information_schema.tables`. The caller is the view
    /// guard in `query_database`: it batches every referenced table the
    /// SELECT touches and rejects the query if any resolves to a `VIEW`
    /// while the scope has `allow_views = false`. Implementations should
    /// cache denials across calls (the production MySQL executor stores a
    /// 5-minute negative-only cache via `TABLE_TYPE_NEGATIVE_CACHE_TTL`) so
    /// a Claude session repeatedly asking about a known VIEW does not
    /// generate `information_schema` round-trips, while positive
    /// `BaseTable` answers are always re-queried (see the
    /// no-positive-cache rationale).
    ///
    /// Keys in the returned map are lowercase `(schema, table)`. Missing
    /// entries mean MySQL had no row for that pair — the caller must treat
    /// the absence as denied, since a non-existent reference would either
    /// blow up in the upcoming EXPLAIN anyway or (in the case of an
    /// information_schema permission gap) leave the type unverified.
    ///
    /// This is the "Layer A" cheap pre-check called from the route. The
    /// authoritative check happens inside `query_with_view_check` on the
    /// same connection that runs the SELECT.
    async fn fetch_table_types(
        &self,
        connection: &DatabaseConnectionConfig,
        secret: &DatabaseSecret,
        tables: &[TableTypeQuery],
        timeout_ms: u64,
    ) -> anyhow::Result<HashMap<(String, String), TableType>>;

    /// Run view check + EXPLAIN evaluation + the user SELECT on a single
    /// MDL-protected transaction. This closes both:
    ///
    ///   * the cross-connection TOCTOU between Layer A
    ///     (`fetch_table_types`) and the SELECT.
    ///   * the cross-connection TOCTOU between EXPLAIN
    ///     and the SELECT (EXPLAIN's plan could otherwise be stale by the
    ///     time the SELECT runs).
    ///
    /// Implementation requirements:
    ///   1. Reject `view_targets.len() > MAX_VIEW_TARGETS_PER_QUERY` and
    ///      `view_targets.is_empty()` (call `query` instead).
    ///   2. Open ONE connection.
    ///   3. `SET SESSION group_concat_max_len`. `max_execution_time` is
    ///      changed between phases — see steps 8 and 10.
    ///   4. `START TRANSACTION READ ONLY` so metadata locks persist
    ///      across statements.
    ///   5. For each entry in `view_targets`, issue
    ///      `SELECT 1 FROM `schema`.`table` LIMIT 0` to acquire
    ///      `MDL_SHARED_READ` on the object NAME. This is what blocks
    ///      concurrent DDL from swapping the type until COMMIT/ROLLBACK.
    ///   6. Run a fresh `information_schema.tables` lookup on the same
    ///      connection.
    ///   7. If any target is non-`BASE TABLE` or missing → `ROLLBACK`
    ///      + return `ViewSwapDetected`.
    ///   8. `SET SESSION max_execution_time = explain_timeout_ms` and run
    ///      `EXPLAIN FORMAT=JSON <sql>` on the same connection, also
    ///      wrapped in a client-side `tokio::time::timeout` of the same
    ///      budget. without this split, a slow
    ///      EXPLAIN holds MDL for the full statement timeout and blocks
    ///      DDL longer than configured.
    ///   9. Run `evaluate_explain(scope, &explain, &connection.database)`.
    ///      If it returns `Err` → `ROLLBACK` + return `ExplainRejected`.
    ///  10. `SET SESSION max_execution_time = statement_timeout_ms` and
    ///      run the user SELECT.
    ///  11. `COMMIT`.
    ///
    /// On ANY error after step 4, the implementation MUST attempt
    /// `ROLLBACK` before returning the error so server-side transaction
    /// state is not left dangling.
    #[allow(clippy::too_many_arguments)]
    async fn query_with_view_check(
        &self,
        connection: &DatabaseConnectionConfig,
        secret: &DatabaseSecret,
        scope: &DatabaseScope,
        view_targets: &[TableTypeQuery],
        sql: &str,
        explain_timeout_ms: u64,
        statement_timeout_ms: u64,
    ) -> anyhow::Result<ViewCheckedQueryOutcome>;
}

pub struct AwsSecretsDatabaseSecretProvider {
    client: aws_sdk_secretsmanager::Client,
}

impl AwsSecretsDatabaseSecretProvider {
    pub fn new(client: aws_sdk_secretsmanager::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl DatabaseSecretProvider for AwsSecretsDatabaseSecretProvider {
    async fn load_secret(&self, secret_arn: &str) -> anyhow::Result<DatabaseSecret> {
        let resp = self
            .client
            .get_secret_value()
            .secret_id(secret_arn)
            .send()
            .await?;
        let raw = resp
            .secret_string()
            .ok_or_else(|| anyhow::anyhow!("database secret has no SecretString"))?;
        #[derive(Deserialize)]
        struct SecretJson {
            username: String,
            password: String,
        }
        let parsed: SecretJson = serde_json::from_str(raw)?;
        Ok(DatabaseSecret {
            username: parsed.username,
            password: parsed.password,
        })
    }
}

#[derive(Default)]
pub struct MySqlDatabaseExecutor {
    connection_limits: DashMap<String, Arc<Semaphore>>,
    /// **Negative-only** cache for `information_schema.tables`. Key is
    /// `(connection_key, schema, table)` using the EXACT lowercase form the
    /// validator already enforced; value is the resolved type plus the
    /// `Instant` it was fetched. Only `View` / `Other` decisions are ever
    /// stored — a previous implementation allowed caching a positive
    /// `BaseTable` answer turns a `DROP TABLE` + `CREATE VIEW` migration
    /// into a time-bounded `allow_views = false` bypass: the route would
    /// keep approving queries against the new VIEW for up to the TTL using
    /// a stale BASE TABLE entry. A stale negative entry, by contrast, can
    /// only over-block (availability cost, not a security risk) and the
    /// TTL still bounds that cost.
    table_type_negative_cache: DashMap<(String, String, String), (TableType, Instant)>,
}

impl MySqlDatabaseExecutor {
    pub fn new() -> Self {
        Self::default()
    }

    async fn acquire_connection_permit(
        &self,
        connection: &DatabaseConnectionConfig,
    ) -> anyhow::Result<OwnedSemaphorePermit> {
        let key = connection_limit_key(connection);
        let max_connections = connection.max_connections.max(1) as usize;
        let semaphore = self
            .connection_limits
            .entry(key)
            .or_insert_with(|| Arc::new(Semaphore::new(max_connections)))
            .clone();
        // bound the wait on the per-connection
        // semaphore so the documented caller wall clock holds even under
        // connection saturation. Without this, a retry storm against a
        // pool whose `max_connections` is already in use can queue HTTP
        // tasks indefinitely AFTER the route has already committed the
        // durable `attempt` audit — breaking every downstream
        // wall-clock guarantee. We reuse `connect_timeout_ms` as the
        // queue budget on the principle that "waiting for a slot" and
        // "waiting for a socket" have similar operational meaning to
        // the operator. On expiry we return a structured error; the
        // route surfaces it as a 503 to the caller.
        let queue_budget = Duration::from_millis(connection.connect_timeout_ms);
        match tokio::time::timeout(queue_budget, semaphore.acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) => Err(anyhow::anyhow!("database connection limiter closed")),
            // wrap with the `ConnectionQueueFull`
            // marker so the route can downcast and emit a typed 503
            // overload response + audit instead of collapsing the
            // saturation case into a generic 500.
            Err(_) => Err(anyhow::Error::new(ConnectionQueueFull)),
        }
    }
}

#[async_trait]
impl DatabaseExecutor for MySqlDatabaseExecutor {
    async fn explain(
        &self,
        connection: &DatabaseConnectionConfig,
        secret: &DatabaseSecret,
        sql: &str,
        timeout_ms: u64,
    ) -> anyhow::Result<ExplainSummary> {
        use mysql_async::prelude::Queryable;

        let permit = self.acquire_connection_permit(connection).await?;
        let pool = mysql_pool(connection, secret)?;
        let connect_timeout = Duration::from_millis(connection.connect_timeout_ms);
        let cleanup_budget = connect_timeout;

        // Codex round 20 (HIGH) + round 21 (HIGH refinement): two
        // failure modes the original code created and one accounting
        // bug round 20 left open.
        //   * `pool.disconnect().await` inside the work future deadlocks
        //     because the pool waits for `conn` to return but `conn` is
        //     still borrowed by this scope.
        //   * Removing the disconnect entirely lets Pool::drop close
        //     only the recycler channel — reset/QUIT keep running
        //     asynchronously while `_permit` releases immediately.
        //   * Wrapping disconnect in a stack-bound `timeout(...)` is
        //     still wrong: on elapsed, the permit drops with the scope
        //     even though the server-side session may still be alive.
        //     That makes `max_connections` a soft hint, not a bound.
        //
        // Fix: split into (a) bounded work, (b) bounded cleanup that
        // owns the permit. `release_pool_bounded_cleanup` spawns a
        // detached task holding both the permit and the pool; the
        // limiter only counts the slot free after disconnect actually
        // returns or POOL_CLEANUP_HARD_CAP fires.
        let mut conn =
            match acquire_conn_or_classify_overload(connect_timeout, pool.get_conn()).await {
                Ok(c) => c,
                Err(err) => {
                    // Codex round 24 + 30 (HIGH/MED): only hold the
                    // permit when the failure is ambiguous (could
                    // have left a half-built upstream session).
                    // Deterministic config errors release immediately.
                    if is_ambiguous_acquire_failure(&err) {
                        permit_hold_after_acquire_failure(permit, "explain_acquire");
                    } else {
                        drop(permit);
                    }
                    let _ = pool;
                    return Err(err);
                }
            };

        let work = async {
            let explain_sql = format!("EXPLAIN FORMAT=JSON {sql}");
            let raw: Option<String> = conn.query_first(explain_sql).await?;
            let raw = raw.ok_or_else(|| anyhow::anyhow!("EXPLAIN returned no rows"))?;
            explain_summary_from_json(&raw)
        };
        let work_outcome: anyhow::Result<ExplainSummary> =
            match tokio::time::timeout(Duration::from_millis(timeout_ms), work).await {
                Ok(o) => o,
                Err(_) => Err(anyhow::anyhow!("EXPLAIN timed out")),
            };

        drop(conn);
        release_pool_bounded_cleanup(permit, pool, cleanup_budget, "explain").await;

        work_outcome
    }

    async fn query(
        &self,
        connection: &DatabaseConnectionConfig,
        secret: &DatabaseSecret,
        sql: &str,
        timeout_ms: u64,
    ) -> anyhow::Result<QueryRows> {
        use mysql_async::prelude::Queryable;

        let permit = self.acquire_connection_permit(connection).await?;
        let pool = mysql_pool(connection, secret)?;
        let connect_timeout = Duration::from_millis(connection.connect_timeout_ms);
        let cleanup_budget = connect_timeout;

        // Codex round 20 + round 21 (HIGH): see `explain()` for the
        // full rationale. Phase-split: bounded work, then permit-aware
        // cleanup via `release_pool_bounded_cleanup` so a wedged
        // upstream cannot release the permit prematurely.
        let mut conn =
            match acquire_conn_or_classify_overload(connect_timeout, pool.get_conn()).await {
                Ok(c) => c,
                Err(err) => {
                    // Codex round 24 + 30 (HIGH/MED): see `explain()`.
                    if is_ambiguous_acquire_failure(&err) {
                        permit_hold_after_acquire_failure(permit, "query_acquire");
                    } else {
                        drop(permit);
                    }
                    let _ = pool;
                    return Err(err);
                }
            };

        let work = async {
            conn.query_drop(format!(
                "SET SESSION max_execution_time = {}",
                timeout_ms.min(u64::from(u32::MAX))
            ))
            .await?;
            // Cap GROUP_CONCAT server-side. `max_allowed_packet` cannot be
            // set per-session (MySQL exposes it as a read-only session
            // variable), so the protocol-level cap is wired into the
            // mysql_async client opts in `mysql_pool` instead.
            conn.query_drop(format!(
                "SET SESSION group_concat_max_len = {}",
                MAX_CELL_BYTES
            ))
            .await?;
            conn.query_drop("SET SESSION TRANSACTION READ ONLY").await?;
            let mut result = conn.query_iter(sql).await?;
            let columns = result
                .columns()
                .as_ref()
                .iter()
                .flat_map(|cols| cols.iter())
                .map(|col| col.name_str().to_string())
                .collect::<Vec<_>>();
            let mut rows = Vec::new();
            let mut total_bytes: usize = 0;
            let mut truncated_by_byte_budget = false;
            while let Some(row) = result.next().await? {
                let parsed_row: Vec<JsonValue> =
                    row.unwrap().into_iter().map(mysql_value_to_json).collect();
                let row_bytes = approximate_row_bytes(&parsed_row);
                if total_bytes.saturating_add(row_bytes) > MAX_QUERY_RESPONSE_BYTES {
                    truncated_by_byte_budget = true;
                    break;
                }
                total_bytes = total_bytes.saturating_add(row_bytes);
                rows.push(parsed_row);
            }
            drop(result);
            Ok(QueryRows {
                columns,
                rows,
                truncated_by_byte_budget,
            })
        };
        let work_outcome: anyhow::Result<QueryRows> =
            match tokio::time::timeout(Duration::from_millis(timeout_ms), work).await {
                Ok(o) => o,
                Err(_) => Err(anyhow::anyhow!("query timed out")),
            };

        drop(conn);
        release_pool_bounded_cleanup(permit, pool, cleanup_budget, "query").await;

        work_outcome
    }

    async fn fetch_table_types(
        &self,
        connection: &DatabaseConnectionConfig,
        secret: &DatabaseSecret,
        tables: &[TableTypeQuery],
        timeout_ms: u64,
    ) -> anyhow::Result<HashMap<(String, String), TableType>> {
        use mysql_async::prelude::Queryable;

        let mut result_map: HashMap<(String, String), TableType> = HashMap::new();
        if tables.is_empty() {
            return Ok(result_map);
        }

        let (pending, cached) = self.partition_pending_and_cached(connection, tables);
        for (key, kind) in cached {
            result_map.insert(key, kind);
        }

        if pending.is_empty() {
            return Ok(result_map);
        }

        let permit = self.acquire_connection_permit(connection).await?;
        let pool = mysql_pool(connection, secret)?;
        let connect_timeout = Duration::from_millis(connection.connect_timeout_ms);
        let cleanup_budget = connect_timeout;

        // Codex round 20 + round 21 (HIGH): same phase split as
        // `explain()` / `query()`. Without it `max_connections` no
        // longer bounds server-side sessions on a stalled upstream;
        // `release_pool_bounded_cleanup` keeps the permit held until
        // disconnect actually completes (or the hard cap fires).
        let mut conn =
            match acquire_conn_or_classify_overload(connect_timeout, pool.get_conn()).await {
                Ok(c) => c,
                Err(err) => {
                    // Codex round 24 + 30 (HIGH/MED): see `explain()`.
                    if is_ambiguous_acquire_failure(&err) {
                        permit_hold_after_acquire_failure(permit, "fetch_table_types_acquire");
                    } else {
                        drop(permit);
                    }
                    let _ = pool;
                    return Err(err);
                }
            };

        let lookup = async {
            conn.query_drop(format!(
                "SET SESSION max_execution_time = {}",
                timeout_ms.min(u64::from(u32::MAX))
            ))
            .await?;
            conn.query_drop("SET SESSION TRANSACTION READ ONLY").await?;
            let rows = lookup_table_types_on_conn(&mut conn, &pending).await?;
            anyhow::Ok(rows)
        };
        let lookup_outcome: anyhow::Result<Vec<((String, String), TableType)>> =
            match tokio::time::timeout(Duration::from_millis(timeout_ms), lookup).await {
                Ok(o) => o,
                Err(_) => Err(anyhow::anyhow!("information_schema lookup timed out")),
            };

        drop(conn);
        release_pool_bounded_cleanup(permit, pool, cleanup_budget, "fetch_table_types").await;

        let fetched = lookup_outcome?;

        let now = Instant::now();
        for (key, kind) in fetched {
            if !matches!(kind, TableType::BaseTable) {
                // Negative-only cache — positive answers always re-query.
                self.table_type_negative_cache.insert(
                    (
                        connection_limit_key(connection),
                        key.0.clone(),
                        key.1.clone(),
                    ),
                    (kind, now),
                );
            }
            result_map.insert(key, kind);
        }

        Ok(result_map)
    }

    async fn query_with_view_check(
        &self,
        connection: &DatabaseConnectionConfig,
        secret: &DatabaseSecret,
        scope: &DatabaseScope,
        view_targets: &[TableTypeQuery],
        sql: &str,
        explain_timeout_ms: u64,
        statement_timeout_ms: u64,
    ) -> anyhow::Result<ViewCheckedQueryOutcome> {
        use mysql_async::prelude::Queryable;

        if view_targets.is_empty() {
            anyhow::bail!(
                "query_with_view_check called with empty view_targets; call query() instead"
            );
        }
        if view_targets.len() > MAX_VIEW_TARGETS_PER_QUERY {
            anyhow::bail!(
                "query_with_view_check refused: {} view targets exceeds the hard cap of {}; \
                 narrow the SELECT or split it across requests",
                view_targets.len(),
                MAX_VIEW_TARGETS_PER_QUERY
            );
        }

        // Normalize to the same lowercase keys the route used for Layer A.
        // We deliberately bypass the negative cache: Layer B must see the
        // same MDL-pinned reality the SELECT will, and a Layer-A denial
        // would already have aborted the request before we got here.
        let mut requested: Vec<(String, String)> = Vec::with_capacity(view_targets.len());
        let mut seen: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();
        for entry in view_targets {
            let key = (
                entry.schema.to_ascii_lowercase(),
                entry.table.to_ascii_lowercase(),
            );
            if seen.insert(key.clone()) {
                requested.push(key);
            }
        }
        if requested.len() > MAX_VIEW_TARGETS_PER_QUERY {
            anyhow::bail!(
                "view_targets contains more than {} distinct (schema, table) pairs",
                MAX_VIEW_TARGETS_PER_QUERY
            );
        }

        let permit = self.acquire_connection_permit(connection).await?;
        // The MDL-protected path bypasses the mysql_async pool by opening
        // its connection via `mysql_async::Conn::new(opts)` directly. This
        // avoids the pool recycler entirely for the request-return wall
        // clock.
        //
        // Codex round 22 (HIGH): the permit (`permit`) is no longer
        // released by stack drop on this path. It is handed off to
        // `release_conn_bounded_cleanup` at the end of the method,
        // which spawns a detached task that owns both the `Conn` and
        // the permit. The limiter slot is released only after
        // `conn.disconnect()` returns or POOL_CLEANUP_HARD_CAP fires —
        // matching the pool variant used by explain/query/fetch and
        // making `max_connections` a hard bound even when the MDL-
        // protected SELECT is the one whose disconnect stalls.
        //
        // Caveat: mysql_async 0.34.2's
        // `impl Drop for Conn` ALWAYS spawns a background async task to
        // run `cleanup_for_pool()` (drop pending result, send QUIT,
        // close socket), regardless of whether the `Conn` came from a
        // `Pool` or `Conn::new`. We cannot make Drop fully synchronous
        // without replacing the driver. What this method DOES guarantee:
        //   * The async fn returns within the documented wall clock.
        //   * The executor's semaphore permit is NOT released until
        //     the bounded background cleanup task finishes
        //     (success, error, or hard-cap-elapsed) — see
        //     `release_conn_bounded_cleanup`.
        //   * The user SELECT does not execute if the cleanup phase was
        //     entered early (timeout or error).
        // What we cannot guarantee: server-side MDL release timing.
        // Under a wedged-server worst case, mysql_async's background
        // cleanup task may continue holding the connection open past
        // POOL_CLEANUP_HARD_CAP; the server eventually times out its
        // own end (`wait_timeout`, default 8h). Operators who need a
        // tighter server-side ceiling should pair Canopy with a
        // low-value `wait_timeout` on the read-only database role.
        let opts: mysql_async::Opts = mysql_opts_for_conn(connection, secret)?.into();
        let default_schema = connection.database.clone();
        let connect_timeout = Duration::from_millis(connection.connect_timeout_ms);
        let cleanup_budget = connect_timeout;

        // The connection lifecycle has several safety constraints around
        // wall-clock bounding. The hard rules the structure below
        // enforces:
        //
        //   * Every awaitable that talks to the server lives under an
        //     explicit `tokio::time::timeout`.
        //   * The semaphore wait is bounded too — the `permit`
        //     acquired above already burned at most
        //     `connect_timeout_ms` on the connection-limiter queue.
        //   * The cleanup path NEVER shares a timeout boundary with the
        //     work it is cleaning up after.
        //   * The disconnect path is its own bounded phase so even a
        //     `conn.disconnect()` that the server stalls does not
        //     extend the caller's wall clock; the permit accounting
        //     is decoupled from caller wall clock via
        //     `release_conn_bounded_cleanup` (round 22 HIGH fix).
        //
        //   0. (Already done above.) Permit acquisition bounded by
        //      `connect_timeout_ms`.
        //   1. Acquire connection (bounded by `connect_timeout`).
        //   2. Session setup + transaction start + preflight + user
        //      SELECT — ALL within one `work_budget` timeout. A wedged
        //      server expires this WITHOUT cancelling cleanup.
        //   3. Best-effort COMMIT/ROLLBACK with its own `cleanup_budget`
        //      timeout. Runs even if step 2 timed out.
        //   4. `release_conn_bounded_cleanup(permit, conn, …)` —
        //      bounded `conn.disconnect()` AND permit lifetime control.
        //      The caller waits up to `cleanup_budget`; on overflow,
        //      the permit is held by a detached task until disconnect
        //      actually completes (or `POOL_CLEANUP_HARD_CAP` fires).
        //
        // Caller-side worst-case wall clock:
        // `queue + connect + work_budget + cleanup_budget + cleanup_budget`.
        // With production defaults
        // (3000 / 3000 / 3000+5000+3000 / 3000 / 3000) that is ~23s,
        // versus an unbounded prior worst case. The permit may stay
        // held in the background for up to POOL_CLEANUP_HARD_CAP after
        // the caller returns, which is exactly the property
        // `max_connections` needs to be a hard bound.

        // Phase 1: acquire a standalone connection (no pool). The
        // `acquire_conn_or_classify_overload` helper wraps both timeout
        // and server-side capacity errors (MySQL `Too many connections`
        // / RDS Proxy borrow exhaustion) in `DatabaseConnectionUnavailable`
        // so the route can translate them into 503 overload responses —
        // matching the shape of the `ConnectionQueueFull` path. Same
        // helper used by `explain` / `query` / `fetch_table_types`.
        //
        // Codex round 24 (HIGH): on the failure branch we cannot
        // assume "no upstream session was created." `Conn::new` runs
        // TCP connect + handshake + AUTH + init SQL before returning,
        // so an acquire-timeout fired mid-handshake/mid-init may have
        // already left a half-built authenticated session on the
        // server. Releasing the limiter permit immediately would let
        // a fresh request open another session before MySQL reaps
        // that orphan, putting us back over `max_connections`. The
        // safer accounting is `permit_hold_after_acquire_failure`,
        // which holds the permit for `POOL_CLEANUP_HARD_CAP` so the
        // server has time to drop the partial session under its own
        // (operator-configured) timeouts.
        let mut conn =
            match acquire_conn_or_classify_overload(connect_timeout, mysql_async::Conn::new(opts))
                .await
            {
                Ok(c) => c,
                Err(err) => {
                    // Codex round 30 (MED): only hold the permit when
                    // the failure is ambiguous (partial server
                    // session plausible). See helper docstring for
                    // why deterministic config errors release
                    // immediately.
                    if is_ambiguous_acquire_failure(&err) {
                        permit_hold_after_acquire_failure(permit, "query_with_view_check_acquire");
                    } else {
                        drop(permit);
                    }
                    return Err(err);
                }
            };

        // `PreflightOutcome` distinguishes the early-bail variants
        // (`ViewSwapDetected` / `ExplainRejected`) from the
        // "preflight passed; continue to the SELECT" path. Keeping
        // both inside the work block avoids leaking a second
        // outcome shape into the cleanup phase below.
        enum PreflightOutcome {
            Done(ViewCheckedQueryOutcome),
            Continue {
                types: HashMap<(String, String), TableType>,
                explain: ExplainSummary,
            },
        }

        // Phase 2: work. Wall-clock cap covers every server round-trip
        // from `SET SESSION` through `COMMIT`-adjacent statements. Note
        // that individual sub-phases also have server-side caps
        // (`max_execution_time`, `lock_wait_timeout`) and a finer
        // client-side cap around the preflight; this outer cap is the
        // belt that catches even a wedged single-statement.
        let work_budget = Duration::from_millis(
            explain_timeout_ms
                .saturating_add(statement_timeout_ms)
                .saturating_add(connection.connect_timeout_ms),
        );
        let work_result: Result<anyhow::Result<ViewCheckedQueryOutcome>, _> =
            tokio::time::timeout(work_budget, async {
                // 2.1) Session caps. `group_concat_max_len` protects the
                //      response-byte budget; `max_execution_time` +
                //      `lock_wait_timeout` keep individual statements and
                //      MDL waits inside the EXPLAIN budget.
                conn.query_drop(format!(
                    "SET SESSION group_concat_max_len = {}",
                    MAX_CELL_BYTES
                ))
                .await?;
                let explain_cap_ms = explain_timeout_ms.min(u64::from(u32::MAX));
                let lock_wait_secs = (explain_timeout_ms / 1000).max(1);
                conn.query_drop(format!("SET SESSION max_execution_time = {explain_cap_ms}"))
                    .await?;
                conn.query_drop(format!("SET SESSION lock_wait_timeout = {lock_wait_secs}"))
                    .await?;
                conn.query_drop("START TRANSACTION READ ONLY").await?;

                // 2.2) Preflight (MDL touches + information_schema +
                //      EXPLAIN + evaluate). The inner client-side cap is
                //      the EXPLAIN budget — this is included so
                //      a stall after the first MDL touch but before
                //      EXPLAIN finishes cannot extend the preflight past
                //      the operator-configured plan budget.
                let preflight_result: Result<anyhow::Result<PreflightOutcome>, _> =
                    tokio::time::timeout(Duration::from_millis(explain_timeout_ms), async {
                        for (schema, table) in &requested {
                            let touch = format!("SELECT 1 FROM `{schema}`.`{table}` LIMIT 0");
                            conn.query_drop(&touch).await?;
                        }
                        let fetched = lookup_table_types_on_conn(&mut conn, &requested).await?;
                        let types: HashMap<(String, String), TableType> =
                            fetched.into_iter().collect();
                        if !scope.allow_views {
                            for key in &requested {
                                let offender = match types.get(key) {
                                    Some(TableType::BaseTable) => None,
                                    Some(kind) => Some((key.0.clone(), key.1.clone(), *kind)),
                                    None => Some((key.0.clone(), key.1.clone(), TableType::Other)),
                                };
                                if let Some(offender) = offender {
                                    return anyhow::Ok(PreflightOutcome::Done(
                                        ViewCheckedQueryOutcome::ViewSwapDetected {
                                            types,
                                            offender,
                                        },
                                    ));
                                }
                            }
                        }
                        let explain_sql = format!("EXPLAIN FORMAT=JSON {sql}");
                        let raw: Option<String> = conn.query_first(explain_sql).await?;
                        let raw = raw.ok_or_else(|| anyhow::anyhow!("EXPLAIN returned no rows"))?;
                        let explain = explain_summary_from_json(&raw)?;
                        if let Err(error) = evaluate_explain(scope, &explain, &default_schema) {
                            return anyhow::Ok(PreflightOutcome::Done(
                                ViewCheckedQueryOutcome::ExplainRejected {
                                    types,
                                    explain,
                                    error,
                                },
                            ));
                        }
                        anyhow::Ok(PreflightOutcome::Continue { types, explain })
                    })
                    .await;
                let preflight = match preflight_result {
                    Ok(inner) => inner?,
                    Err(_) => anyhow::bail!(
                        "MDL-protected preflight (touches + information_schema + EXPLAIN) \
                         timed out under explain budget"
                    ),
                };
                let (types, explain) = match preflight {
                    PreflightOutcome::Done(outcome) => return anyhow::Ok(outcome),
                    PreflightOutcome::Continue { types, explain } => (types, explain),
                };

                // 2.3) Switch the per-statement cap to the SELECT budget
                // and run the user SELECT.
                conn.query_drop(format!(
                    "SET SESSION max_execution_time = {}",
                    statement_timeout_ms.min(u64::from(u32::MAX))
                ))
                .await?;

                let mut result = conn.query_iter(sql).await?;
                let columns = result
                    .columns()
                    .as_ref()
                    .iter()
                    .flat_map(|cols| cols.iter())
                    .map(|col| col.name_str().to_string())
                    .collect::<Vec<_>>();
                let mut rows = Vec::new();
                let mut total_bytes: usize = 0;
                let mut truncated_by_byte_budget = false;
                while let Some(row) = result.next().await? {
                    let parsed_row: Vec<JsonValue> =
                        row.unwrap().into_iter().map(mysql_value_to_json).collect();
                    let row_bytes = approximate_row_bytes(&parsed_row);
                    if total_bytes.saturating_add(row_bytes) > MAX_QUERY_RESPONSE_BYTES {
                        truncated_by_byte_budget = true;
                        break;
                    }
                    total_bytes = total_bytes.saturating_add(row_bytes);
                    rows.push(parsed_row);
                }
                drop(result);
                anyhow::Ok(ViewCheckedQueryOutcome::Ok {
                    types,
                    explain,
                    rows: QueryRows {
                        columns,
                        rows,
                        truncated_by_byte_budget,
                    },
                })
            })
            .await;
        let inner_outcome: anyhow::Result<ViewCheckedQueryOutcome> = match work_result {
            Ok(o) => o,
            Err(_) => Err(anyhow::anyhow!("MDL-protected work timed out")),
        };

        // Phase 3: cleanup. ALWAYS runs even if Phase 2 timed out.
        // the previous arrangement put the
        // cleanup match inside the outer timeout, so an outer expiry
        // cancelled cleanup entirely — re-introducing the very
        // condition this structure is meant to bound.
        let cleanup_stmt = match &inner_outcome {
            Ok(ViewCheckedQueryOutcome::Ok { .. }) => "COMMIT",
            _ => "ROLLBACK",
        };
        match tokio::time::timeout(cleanup_budget, conn.query_drop(cleanup_stmt)).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::warn!(
                error = %err,
                stmt = cleanup_stmt,
                "transaction cleanup statement failed; server will roll back on connection close"
            ),
            Err(_) => tracing::warn!(
                budget_ms = connection.connect_timeout_ms,
                stmt = cleanup_stmt,
                "transaction cleanup statement exceeded its budget; dropping the pool \
                 to force socket close and let the server roll back"
            ),
        }

        // Phase 4: explicit, bounded graceful close + permit hand-off.
        // `release_conn_bounded_cleanup` sends `conn.disconnect()` (MySQL
        // QUIT + socket close) under `POOL_CLEANUP_HARD_CAP` and keeps
        // the permit live until either disconnect actually completes or
        // the hard cap fires. The current task waits up to
        // `cleanup_budget` for that to happen; on overflow the helper
        // detaches the cleanup task and returns. The caller's wall
        // clock is therefore bounded by `cleanup_budget` while the
        // limiter slot accounting is bounded by `POOL_CLEANUP_HARD_CAP`
        // — both of which matter, but for different invariants
        // (latency vs. max_connections honesty).
        release_conn_bounded_cleanup(permit, conn, cleanup_budget, "query_with_view_check").await;

        inner_outcome
    }
}

impl MySqlDatabaseExecutor {
    /// Returns `(pending_requests, cached_results)`. The pending vector
    /// preserves declaration order and is de-duplicated; the cached vector
    /// contains lowercase-key entries the negative cache could serve.
    #[allow(clippy::type_complexity)]
    fn partition_pending_and_cached(
        &self,
        connection: &DatabaseConnectionConfig,
        tables: &[TableTypeQuery],
    ) -> (Vec<(String, String)>, Vec<((String, String), TableType)>) {
        let mut pending: Vec<(String, String)> = Vec::with_capacity(tables.len());
        let mut cached: Vec<((String, String), TableType)> = Vec::new();
        let mut seen: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();

        for entry in tables {
            let key = (
                entry.schema.to_ascii_lowercase(),
                entry.table.to_ascii_lowercase(),
            );
            if !seen.insert(key.clone()) {
                continue;
            }
            let cache_key = (
                connection_limit_key(connection),
                key.0.clone(),
                key.1.clone(),
            );
            if let Some(entry) = self.table_type_negative_cache.get(&cache_key) {
                let (kind, fetched_at) = *entry;
                debug_assert!(
                    !matches!(kind, TableType::BaseTable),
                    "positive BaseTable entries must never enter table_type_negative_cache"
                );
                if fetched_at.elapsed() < TABLE_TYPE_NEGATIVE_CACHE_TTL
                    && !matches!(kind, TableType::BaseTable)
                {
                    cached.push((key, kind));
                    continue;
                }
            }
            pending.push(key);
        }

        (pending, cached)
    }
}

/// Resolve `(schema, table)` pairs against `information_schema.tables` on
/// an already-open connection. Two adversarial considerations from prior
/// The implementation is shaped by these safety constraints:
///
///   * Round 4 / 5 #1 — case collation hazards: on
///     `lower_case_table_names = 0` MySQL with the default `_ci`
///     collation, a lowercase VIEW `orders` and a mixed-case BASE TABLE
///     `Orders` can coexist and a naive `WHERE table_schema = ? AND
///     table_name = ?` would collapse them. We force byte-level
///     comparison with the `BINARY` keyword (standard MySQL/MariaDB
///     since 4.1) so each requested pair matches at most one row.
///
///   * Round 5 #2 — charset portability: the `COLLATE utf8mb4_bin`
///     approach can fail on older deployments where the
///     information_schema columns are stored in `utf8mb3`. `BINARY` is
///     charset-agnostic; it casts both sides to binary strings and
///     compares bytes.
///
///   * Round 6 #3 — DOS amplification: the previous "fetch all rows in
///     these schemas then filter in Rust" design would scan up to N
///     tables per schema even when the caller asked for one specific
///     pair. We now query EXACT pairs, capped by
///     `MAX_VIEW_TARGETS_PER_QUERY`, so the worst-case row count is
///     bounded by the caller's request size.
///
/// Defensive note: rows whose `(schema, table)` does not byte-match a
/// requested pair are still tolerated — collation surprises (e.g. utf8mb4
/// vs utf8mb3 surrogate handling) can occasionally surface unexpected
/// rows. We just drop them and continue. Duplicates after byte-matching,
/// however, are fail-closed: that signals a real collation collision and
/// the safe response is to refuse the lookup.
async fn lookup_table_types_on_conn(
    conn: &mut mysql_async::Conn,
    requested: &[(String, String)],
) -> anyhow::Result<Vec<((String, String), TableType)>> {
    use mysql_async::prelude::Queryable;
    use mysql_async::Value as MyValue;

    if requested.is_empty() {
        return Ok(Vec::new());
    }
    if requested.len() > MAX_VIEW_TARGETS_PER_QUERY {
        anyhow::bail!(
            "lookup_table_types_on_conn refused: {} requested pairs exceeds the hard cap of {}",
            requested.len(),
            MAX_VIEW_TARGETS_PER_QUERY
        );
    }

    let mut where_clauses: Vec<&str> = Vec::with_capacity(requested.len());
    let mut params: Vec<MyValue> = Vec::with_capacity(requested.len() * 2);
    for (schema, table) in requested {
        where_clauses.push("(BINARY table_schema = BINARY ? AND BINARY table_name = BINARY ?)");
        params.push(MyValue::Bytes(schema.as_bytes().to_vec()));
        params.push(MyValue::Bytes(table.as_bytes().to_vec()));
    }
    let sql = format!(
        "SELECT table_schema, table_name, table_type \
         FROM information_schema.tables \
         WHERE {}",
        where_clauses.join(" OR ")
    );
    let rows: Vec<(String, String, String)> = conn.exec(sql, params).await?;

    let requested_set: std::collections::HashSet<(String, String)> =
        requested.iter().cloned().collect();
    let mut found: HashMap<(String, String), TableType> = HashMap::new();
    for (schema_raw, table_raw, table_type) in rows {
        let key = (schema_raw, table_raw);
        if !requested_set.contains(&key) {
            tracing::debug!(
                schema = %key.0,
                table = %key.1,
                "information_schema returned a row that does not byte-match any requested pair; skipping"
            );
            continue;
        }
        if found.contains_key(&key) {
            anyhow::bail!(
                "information_schema returned multiple rows for ({}, {}); \
                 refusing to pick a winner",
                key.0,
                key.1
            );
        }
        let kind = classify_table_type(&table_type);
        found.insert(key, kind);
    }
    Ok(found.into_iter().collect())
}

/// Map the raw `information_schema.tables.table_type` text (case-insensitive)
/// onto the typed enum. Centralized so the executor and any future caller
/// (e.g. an admin diagnostics route) classify the same way.
fn classify_table_type(raw: &str) -> TableType {
    let upper = raw.trim().to_ascii_uppercase();
    match upper.as_str() {
        "BASE TABLE" => TableType::BaseTable,
        "VIEW" | "SYSTEM VIEW" => TableType::View,
        _ => TableType::Other,
    }
}

/// Build the connection-level `OptsBuilder` shared by both pooled access
/// (used by `explain` / `query` / `fetch_table_types`) and direct
/// `Conn::new` access (used by `query_with_view_check`). The split exists
/// because a previous implementation allowed dropping a pooled `Conn`
/// hands it to `mysql_async`'s recycler, whose `cleanup_for_pool` work
/// (`drop_result` + rollback) runs unbounded in the background — so even
/// our `pool.disconnect()` timeout would not actually release MDL on a
/// wedged server. `query_with_view_check` avoids the recycler entirely
/// by owning a non-pool `Conn`; dropping that `Conn` closes the socket
/// immediately and the server tears down its end.
///
/// Codex round 23 (HIGH): the `init` SQL below pins server-side
/// timeouts so the server is guaranteed to drop the session within
/// `POOL_CLEANUP_HARD_CAP` even if the client-side `Conn::disconnect()`
/// stalls past the cap. Without this, `release_*_bounded_cleanup`
/// could release the limiter permit at the cap while the MySQL
/// session still held an MDL and consumed a slot in the upstream's
/// `max_connections`, so the limiter would not bound real concurrent
/// server-side sessions. The chosen values bracket the cap from
/// below — server-side timeout < cap < hard cap + headroom — so
/// "permit released" implies "server session is gone or about to be".
fn mysql_opts_for_conn(
    connection: &DatabaseConnectionConfig,
    secret: &DatabaseSecret,
) -> anyhow::Result<mysql_async::OptsBuilder> {
    let _ = connection.max_connections; // referenced by `mysql_pool` only.
    let mut opts = mysql_async::OptsBuilder::default()
        .ip_or_hostname(connection.host.clone())
        .tcp_port(connection.port)
        .db_name(Some(connection.database.clone()))
        .user(Some(secret.username.clone()))
        .pass(Some(secret.password.clone()))
        .init(vec![
            // `net_read_timeout` / `net_write_timeout` — bound how
            // long the server is willing to wait on either direction
            // of the TCP socket. With `POOL_CLEANUP_HARD_CAP` = 30s,
            // capping these at 10s gives the server up to 20s of
            // headroom to actually close before the limiter releases
            // its slot in the worst case. Default values (30s/60s)
            // would let the server keep a session past the cap on a
            // half-broken socket and re-open the over-admission hole
            // the bounded cleanup is supposed to close.
            String::from("SET SESSION net_read_timeout = 10"),
            String::from("SET SESSION net_write_timeout = 10"),
            // `wait_timeout` — idle-session reaper. Canopy never
            // pools idle, so this is purely a safety net for the
            // window between cleanup cap elapsing on the client and
            // the server noticing the socket is dead. 25s gives the
            // server ~5s to reap before the hard cap fires.
            String::from("SET SESSION wait_timeout = 25"),
        ])
        // `max_allowed_packet` is the MySQL protocol packet ceiling. By
        // setting it here at connection time (instead of via the read-
        // only session variable) we tell `mysql_async` to abort the
        // connection rather than materialize a packet larger than
        // `MAX_QUERY_RESPONSE_BYTES`. Combined with the post-
        // materialization clamp in `mysql_value_to_json`, this bounds
        // peak memory per connection regardless of column type.
        .max_allowed_packet(Some(MAX_QUERY_RESPONSE_BYTES));
    // Default to verified TLS so Secrets-Manager-sourced credentials and
    // query payloads never traverse the network in cleartext. The two
    // `accept_invalid_tls_certs` / `skip_tls_hostname_verification`
    // flags exist only as explicit opt-ins for local development.
    if connection.require_tls {
        let mut ssl_opts = mysql_async::SslOpts::default();
        if connection.accept_invalid_tls_certs {
            ssl_opts = ssl_opts.with_danger_accept_invalid_certs(true);
        }
        if connection.skip_tls_hostname_verification {
            ssl_opts = ssl_opts.with_danger_skip_domain_validation(true);
        }
        opts = opts.ssl_opts(Some(ssl_opts));
    }
    Ok(opts)
}

fn mysql_pool(
    connection: &DatabaseConnectionConfig,
    secret: &DatabaseSecret,
) -> anyhow::Result<mysql_async::Pool> {
    let max_connections = connection.max_connections.max(1) as usize;
    let pool_constraints = mysql_async::PoolConstraints::new(0, max_connections)
        .ok_or_else(|| anyhow::anyhow!("invalid database pool constraints"))?;
    let pool_opts = mysql_async::PoolOpts::default().with_constraints(pool_constraints);
    let opts = mysql_opts_for_conn(connection, secret)?.pool_opts(pool_opts);
    Ok(mysql_async::Pool::new(opts))
}

fn connection_limit_key(connection: &DatabaseConnectionConfig) -> String {
    format!(
        "{}:{}:{}:{}",
        connection.host, connection.port, connection.database, connection.secret_arn
    )
}

/// Hard per-cell byte cap. Stops a single oversized TEXT/BLOB column or
/// `GROUP_CONCAT` result from forcing the control-plane to allocate a giant
/// `String` before the row-level budget check sees it. Anything beyond this
/// is replaced with a sentinel string before the JSON conversion.
const MAX_CELL_BYTES: usize = 64 * 1024;

fn mysql_value_to_json(value: mysql_async::Value) -> JsonValue {
    match value {
        mysql_async::Value::NULL => JsonValue::Null,
        mysql_async::Value::Bytes(bytes) => {
            // Bound the raw byte length BEFORE converting to a UTF-8
            // String. Without this a `SELECT very_large_text_col FROM ...`
            // or `SELECT GROUP_CONCAT(...)` against a single row could
            // allocate megabytes/gigabytes inside this function before the
            // row-level cap can fire.
            if bytes.len() > MAX_CELL_BYTES {
                return JsonValue::String(format!(
                    "[truncated: cell exceeded {MAX_CELL_BYTES} byte cell-byte cap; \
                     {} bytes total]",
                    bytes.len()
                ));
            }
            match String::from_utf8(bytes) {
                Ok(s) => JsonValue::String(s),
                Err(err) => {
                    let raw = err.into_bytes();
                    JsonValue::String(format!("[binary: {} bytes]", raw.len()))
                }
            }
        }
        mysql_async::Value::Int(v) => JsonValue::from(v),
        mysql_async::Value::UInt(v) => JsonValue::from(v),
        mysql_async::Value::Float(v) => JsonValue::from(v),
        mysql_async::Value::Double(v) => JsonValue::from(v),
        mysql_async::Value::Date(year, month, day, hour, minute, second, micros) => {
            JsonValue::String(format!(
                "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{micros:06}"
            ))
        }
        mysql_async::Value::Time(is_neg, days, hours, minutes, seconds, micros) => {
            JsonValue::String(format!(
                "{}{} {hours:02}:{minutes:02}:{seconds:02}.{micros:06}",
                if is_neg { "-" } else { "" },
                days
            ))
        }
    }
}

fn validate_select_sql(sql: &str, scope: &DatabaseScope) -> Result<ValidatedQuery, DatabaseError> {
    validate_select_sql_inner(sql, scope, None)
}

/// Validate SQL for an actual configured connection.
///
/// Production call sites must pass the connection's configured database as
/// `default_schema`. Unqualified table names are evaluated against that
/// schema, which prevents a query from bypassing `allowed_schemas` simply by
/// omitting the schema qualifier. The private `validate_select_sql` wrapper is
/// kept only for parser-focused unit tests that do not model a connection.
pub fn validate_select_sql_for_connection(
    sql: &str,
    scope: &DatabaseScope,
    default_schema: &str,
) -> Result<ValidatedQuery, DatabaseError> {
    validate_select_sql_inner(sql, scope, Some(default_schema))
}

fn validate_select_sql_inner(
    sql: &str,
    scope: &DatabaseScope,
    default_schema: Option<&str>,
) -> Result<ValidatedQuery, DatabaseError> {
    if !scope
        .allowed_actions
        .iter()
        .any(|action| action.eq_ignore_ascii_case("select"))
    {
        return Err(DatabaseError::Denied(
            "database scope does not allow select".into(),
        ));
    }

    let trimmed = sql.trim().trim_end_matches(';').trim();
    if trimmed.is_empty() {
        return Err(DatabaseError::BadRequest("sql is empty".into()));
    }
    // Reject MySQL optimizer-hint comments like `/*+ MAX_EXECUTION_TIME(...) */`
    // and `/*+ SET_VAR(...) */`. They survive AST validation because they are
    // attached to the statement as comments, but at execution time MySQL
    // honors them and could override the session caps Canopy just set. We
    // reject the entire comment surface (both block and line comments) so
    // there is no way to smuggle a hint past the validator.
    if trimmed.contains("/*") {
        return Err(DatabaseError::Denied(
            "SQL comments and optimizer hints are not allowed; remove all /*...*/ blocks".into(),
        ));
    }
    if trimmed.contains("--") {
        return Err(DatabaseError::Denied(
            "SQL comments are not allowed; remove all -- comments".into(),
        ));
    }

    let dialect = MySqlDialect {};
    let statements = Parser::parse_sql(&dialect, trimmed)
        .map_err(|err| DatabaseError::BadRequest(format!("invalid SQL: {err}")))?;
    if statements.len() != 1 {
        return Err(DatabaseError::BadRequest(
            "exactly one SQL statement is allowed".into(),
        ));
    }

    let Statement::Query(query) = &statements[0] else {
        return Err(DatabaseError::Denied(
            "only SELECT statements are allowed".into(),
        ));
    };

    reject_expression_subqueries(query)?;
    reject_denied_functions(query)?;
    validate_query_bounds(query, scope)?;

    let mut collector = TableCollector::default();
    collector.collect_query(query)?;
    let tables = collector.tables.into_iter().collect::<Vec<_>>();
    enforce_tables(&tables, scope, default_schema)?;

    let limit = query_limit(query)?;
    let normalized_sql = match limit {
        Some(limit) if limit <= scope.max_rows => trimmed.to_string(),
        Some(_) => {
            return Err(DatabaseError::BadRequest(format!(
                "LIMIT exceeds max_rows {} for scope {}",
                scope.max_rows, scope.name
            )))
        }
        None => format!("{trimmed} LIMIT {}", scope.max_rows),
    };

    Ok(ValidatedQuery {
        normalized_sql,
        tables,
    })
}

fn validate_query_bounds(query: &Query, scope: &DatabaseScope) -> Result<(), DatabaseError> {
    validate_single_query_bounds(query, scope)?;

    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            validate_query_bounds(&cte.query, scope)?;
        }
    }

    validate_set_expr_bounds(&query.body, scope)
}

fn validate_single_query_bounds(query: &Query, scope: &DatabaseScope) -> Result<(), DatabaseError> {
    if let Some(offset) = query_offset(query)? {
        if offset > 0 {
            return Err(DatabaseError::BadRequest(
                "OFFSET is not allowed for database MCP queries".into(),
            ));
        }
    }

    if let Some(limit) = query_limit(query)? {
        if limit > scope.max_rows {
            return Err(DatabaseError::BadRequest(format!(
                "LIMIT exceeds max_rows {} for scope {}",
                scope.max_rows, scope.name
            )));
        }
    }

    Ok(())
}

fn validate_set_expr_bounds(
    set_expr: &SetExpr,
    scope: &DatabaseScope,
) -> Result<(), DatabaseError> {
    match set_expr {
        SetExpr::Select(select) => validate_select_bounds(select, scope),
        SetExpr::Query(query) => validate_query_bounds(query, scope),
        SetExpr::SetOperation { left, right, .. } => {
            validate_set_expr_bounds(left, scope)?;
            validate_set_expr_bounds(right, scope)
        }
        _ => Ok(()),
    }
}

fn validate_select_bounds(select: &Select, scope: &DatabaseScope) -> Result<(), DatabaseError> {
    for table in &select.from {
        validate_table_with_joins_bounds(table, scope)?;
    }
    Ok(())
}

fn validate_table_with_joins_bounds(
    table: &TableWithJoins,
    scope: &DatabaseScope,
) -> Result<(), DatabaseError> {
    validate_table_factor_bounds(&table.relation, scope)?;
    for join in &table.joins {
        validate_table_factor_bounds(&join.relation, scope)?;
    }
    Ok(())
}

fn validate_table_factor_bounds(
    factor: &TableFactor,
    scope: &DatabaseScope,
) -> Result<(), DatabaseError> {
    match factor {
        TableFactor::Derived { subquery, .. } => validate_query_bounds(subquery, scope),
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => validate_table_with_joins_bounds(table_with_joins, scope),
        _ => Ok(()),
    }
}

fn query_limit(query: &Query) -> Result<Option<u64>, DatabaseError> {
    let Some(limit) = &query.limit else {
        return Ok(None);
    };
    match limit {
        Expr::Value(SqlValue::Number(raw, _)) => raw
            .parse::<u64>()
            .map(Some)
            .map_err(|_| DatabaseError::BadRequest("LIMIT must be a positive integer".into())),
        _ => Err(DatabaseError::BadRequest(
            "LIMIT must be a positive integer literal".into(),
        )),
    }
}

fn query_offset(query: &Query) -> Result<Option<u64>, DatabaseError> {
    let Some(offset) = &query.offset else {
        return Ok(None);
    };
    match &offset.value {
        Expr::Value(SqlValue::Number(raw, _)) => raw
            .parse::<u64>()
            .map(Some)
            .map_err(|_| DatabaseError::BadRequest("OFFSET must be a positive integer".into())),
        _ => Err(DatabaseError::BadRequest(
            "OFFSET must be a positive integer literal".into(),
        )),
    }
}

#[derive(Default)]
struct TableCollector {
    tables: BTreeSet<String>,
    cte_scopes: Vec<BTreeSet<String>>,
}

impl TableCollector {
    fn collect_query(&mut self, query: &Query) -> Result<(), DatabaseError> {
        if !query.locks.is_empty() {
            return Err(DatabaseError::Denied(
                "SELECT locking clauses are not allowed for database MCP".into(),
            ));
        }
        if query.for_clause.is_some() {
            return Err(DatabaseError::Denied(
                "FOR clauses are not allowed for database MCP".into(),
            ));
        }
        let mut cte_aliases = BTreeSet::new();
        if let Some(with) = &query.with {
            if with.recursive {
                return Err(DatabaseError::Denied(
                    "recursive CTEs are not allowed for database MCP".into(),
                ));
            }
            for cte in &with.cte_tables {
                let visible_ctes = cte_aliases.clone();
                self.with_cte_scope(visible_ctes, |collector| {
                    collector.collect_query(&cte.query)
                })?;
                cte_aliases.insert(cte.alias.name.value.to_ascii_lowercase());
            }
        }
        self.with_cte_scope(cte_aliases, |collector| {
            collector.collect_set_expr(&query.body)
        })
    }

    fn with_cte_scope<F>(&mut self, aliases: BTreeSet<String>, f: F) -> Result<(), DatabaseError>
    where
        F: FnOnce(&mut Self) -> Result<(), DatabaseError>,
    {
        let has_aliases = !aliases.is_empty();
        if has_aliases {
            self.cte_scopes.push(aliases);
        }
        let result = f(self);
        if has_aliases {
            self.cte_scopes.pop();
        }
        result
    }

    fn collect_set_expr(&mut self, set_expr: &SetExpr) -> Result<(), DatabaseError> {
        match set_expr {
            SetExpr::Select(select) => self.collect_select(select),
            SetExpr::Query(query) => self.collect_query(query),
            SetExpr::SetOperation { left, right, .. } => {
                self.collect_set_expr(left)?;
                self.collect_set_expr(right)
            }
            _ => Err(DatabaseError::Denied(
                "only SELECT queries are allowed for database MCP".into(),
            )),
        }
    }

    fn collect_select(&mut self, select: &Select) -> Result<(), DatabaseError> {
        if select.into.is_some() {
            return Err(DatabaseError::Denied(
                "SELECT INTO is not allowed for database MCP".into(),
            ));
        }
        if !select.lateral_views.is_empty() {
            return Err(DatabaseError::Denied(
                "lateral views are not allowed for database MCP".into(),
            ));
        }
        for table in &select.from {
            self.collect_table_with_joins(table)?;
        }
        Ok(())
    }

    fn collect_table_with_joins(&mut self, table: &TableWithJoins) -> Result<(), DatabaseError> {
        self.collect_table_factor(&table.relation)?;
        for join in &table.joins {
            self.collect_table_factor(&join.relation)?;
        }
        Ok(())
    }

    fn collect_table_factor(&mut self, factor: &TableFactor) -> Result<(), DatabaseError> {
        match factor {
            TableFactor::Table { name, .. } => {
                // per-part shape check. The
                // sqlparser `ObjectName` preserves quote_style, so a
                // backticked identifier like `\`orders.orders\`` arrives
                // here as a SINGLE Ident with `value = "orders.orders"`.
                // The previous code flattened parts with `.` and let
                // `enforce_tables` split with rsplitn, which then treated
                // the backticked dotted name as a schema-qualified
                // reference `orders.orders` — bypassing the view guard
                // (it'd look up `(orders, orders)`) and the scope check
                // (both halves are allowed). Reject anything that is not a
                // bare lowercase ASCII identifier.
                for part in &name.0 {
                    if !is_canonical_sql_identifier(&part.value) {
                        return Err(DatabaseError::Denied(format!(
                            "table identifier '{}' must match [a-z0-9_]+; uppercase, dots, \
                             whitespace, hyphens, and other characters are not allowed in \
                             database MCP SELECT queries (this protects scope authorization \
                             from quoted-identifier bypasses)",
                            part.value
                        )));
                    }
                }
                let table = object_name(name);
                // Only unqualified references can resolve to a CTE alias.
                // `WITH orders AS (...) SELECT * FROM other_schema.orders`
                // must NOT be conflated with the CTE just because the leaf
                // matches: the qualified form resolves to a real schema
                // table and has to be authorized by `enforce_tables`. This
                // closes a cross-schema authorization bypass.
                let is_unqualified = !table.contains('.');
                let table_leaf = table.to_ascii_lowercase();
                if is_unqualified && self.is_cte_alias(&table_leaf) {
                    return Ok(());
                }
                self.tables.insert(table);
                Ok(())
            }
            TableFactor::Derived { subquery, .. } => self.collect_query(subquery),
            TableFactor::NestedJoin {
                table_with_joins, ..
            } => self.collect_table_with_joins(table_with_joins),
            _ => Err(DatabaseError::Denied(
                "unsupported table expression in SELECT".into(),
            )),
        }
    }

    fn is_cte_alias(&self, table_leaf: &str) -> bool {
        self.cte_scopes
            .iter()
            .rev()
            .any(|scope| scope.contains(table_leaf))
    }
}

fn reject_expression_subqueries(query: &Query) -> Result<(), DatabaseError> {
    let found = visit_expressions(query, |expr| match expr {
        Expr::InSubquery { .. }
        | Expr::Exists { .. }
        | Expr::Subquery(_)
        | Expr::ArraySubquery(_) => ControlFlow::Break(()),
        _ => ControlFlow::Continue(()),
    });

    if found.is_break() {
        return Err(DatabaseError::Denied(
            "subqueries inside expressions are not supported for database MCP".into(),
        ));
    }

    Ok(())
}

/// Allow-list of pure / side-effect-free MySQL functions that Canopy MCP
/// SELECT queries may call. the previous deny-list was
/// bypass-prone: an allowed-table SELECT could still invoke UDFs, stored
/// functions, or any MySQL built-in not specifically denied (`MASTER_POS_WAIT`,
/// `WAIT_FOR_EXECUTED_GTID_SET`, `SLEEP`, custom `def_<name>` UDFs…). An
/// allow-list inverts that risk: anything we haven't reviewed is rejected,
/// even if a misconfigured DB role still has EXECUTE on it.
///
/// This list intentionally covers the everyday surface needed for ops
/// dashboards (aggregates, string, numeric, date/time, conditionals, JSON,
/// cast). If a query legitimately needs a function not on the list, the
/// reviewer must (a) confirm it has no side effects / DB-server-state
/// reads, and (b) add the name here in a follow-up PR.
const ALLOWED_SQL_FUNCTIONS: &[&str] = &[
    // Aggregates
    "count",
    "sum",
    "avg",
    "min",
    "max",
    "group_concat",
    "std",
    "stddev",
    "stddev_samp",
    "stddev_pop",
    "var_pop",
    "var_samp",
    "variance",
    "bit_and",
    "bit_or",
    "bit_xor",
    // String
    "concat",
    "concat_ws",
    "coalesce",
    "ifnull",
    "nullif",
    "isnull",
    "substring",
    "substr",
    "substring_index",
    "left",
    "right",
    "length",
    "char_length",
    "character_length",
    "octet_length",
    "lower",
    "upper",
    "ucase",
    "lcase",
    "trim",
    "ltrim",
    "rtrim",
    "replace",
    "locate",
    "instr",
    "regexp_like",
    "regexp_replace",
    "regexp_substr",
    "regexp_instr",
    "reverse",
    // NOTE: `repeat`, `space`, `lpad`, `rpad` are intentionally NOT on the
    // allow-list. They can produce unbounded-size output from a tiny query
    // (e.g. `repeat('x', 50000000)`) and OOM both MySQL and the
    // control-plane before the response cap can clamp it. Add back only
    // with a literal-size-arg validator that caps the integer argument.
    "format",
    "position",
    "field",
    "elt",
    "find_in_set",
    "soundex",
    // Numeric
    "abs",
    "round",
    "floor",
    "ceil",
    "ceiling",
    "mod",
    "sign",
    "power",
    "pow",
    "sqrt",
    "exp",
    "log",
    "log10",
    "log2",
    "ln",
    "truncate",
    "greatest",
    "least",
    // Date / time (pure — never read server state beyond clock)
    "now",
    "curdate",
    "curtime",
    "current_date",
    "current_time",
    "current_timestamp",
    "sysdate",
    "date_format",
    "str_to_date",
    "date_add",
    "date_sub",
    "adddate",
    "subdate",
    "timestampdiff",
    "timestampadd",
    "unix_timestamp",
    "from_unixtime",
    "year",
    "month",
    "day",
    "hour",
    "minute",
    "second",
    "dayofweek",
    "dayofmonth",
    "dayofyear",
    "dayname",
    "monthname",
    "week",
    "weekofyear",
    "quarter",
    "last_day",
    "date",
    "time",
    "datediff",
    "timediff",
    "microsecond",
    "extract",
    "from_days",
    "to_days",
    // Conditional / control flow as function (CASE is its own Expr, not here)
    "if",
    // Cast / type conversion
    "cast",
    "convert",
    "hex",
    "unhex",
    "binary",
    // JSON (read-only access)
    "json_extract",
    "json_unquote",
    "json_value",
    "json_object",
    "json_array",
    "json_contains",
    "json_contains_path",
    "json_keys",
    "json_length",
    "json_type",
    "json_valid",
    "json_quote",
    "json_search",
    // Hash / encoding (pure)
    "md5",
    "sha1",
    "sha2",
    "crc32",
];

/// Well-known dangerous MySQL built-ins. They are already rejected by the
/// allow-list above (since they are not on it), but listing them explicitly
/// gives reviewers a clear error message that includes the failure class
/// rather than a generic "function not on allow-list" string.
const EXPLICITLY_DENIED_SQL_FUNCTIONS: &[&str] = &[
    "load_file",
    "sleep",
    "benchmark",
    "get_lock",
    "release_lock",
    "release_all_locks",
    "is_free_lock",
    "is_used_lock",
    "master_pos_wait",
    "wait_for_executed_gtid_set",
    "current_user",
    "session_user",
    "system_user",
    "user",
    "version",
    "database",
    "schema",
    "connection_id",
    "found_rows",
    "row_count",
    "last_insert_id",
    "uuid",
    "uuid_short",
];

fn reject_denied_functions(query: &Query) -> Result<(), DatabaseError> {
    let mut rejection: Option<DatabaseError> = None;
    let _ = visit_expressions(query, |expr| {
        if let Expr::Function(func) = expr {
            // sqlparser stores the function name as an `ObjectName`; the
            // leaf (rightmost) identifier is the actual function. We
            // compare case-insensitively because MySQL function names are
            // not case-sensitive.
            if let Some(part) = func.name.0.last() {
                let lower = part.value.to_ascii_lowercase();
                if EXPLICITLY_DENIED_SQL_FUNCTIONS.contains(&lower.as_str()) {
                    rejection = Some(DatabaseError::Denied(format!(
                        "function '{}' is not allowed for database MCP queries (denied: \
                         filesystem / lock / DoS / server-introspection / replication-wait \
                         functions)",
                        part.value
                    )));
                    return ControlFlow::Break(());
                }
                if !ALLOWED_SQL_FUNCTIONS.contains(&lower.as_str()) {
                    rejection = Some(DatabaseError::Denied(format!(
                        "function '{}' is not on the Canopy MCP allow-list; only pure \
                         aggregate / string / numeric / date / cast / json functions are \
                         permitted. If this function is needed, request a security review \
                         to add it to ALLOWED_SQL_FUNCTIONS.",
                        part.value
                    )));
                    return ControlFlow::Break(());
                }
            }
        }
        ControlFlow::Continue(())
    });

    if let Some(err) = rejection {
        return Err(err);
    }

    Ok(())
}

fn object_name(name: &sqlparser::ast::ObjectName) -> String {
    // Preserve original case so `enforce_tables` can reject mixed-case
    // identifiers explicitly. Case normalization happens at the comparison
    // boundary (allowed_tables / allowed_schemas are lowercased there), not
    // at parse time — collapsing case here would let `Orders` silently match
    // a scope that grants `orders` on MySQL deployments with case-sensitive
    // identifiers (`lower_case_table_names=0`, the Unix default).
    name.0
        .iter()
        .map(|part| part.value.clone())
        .collect::<Vec<_>>()
        .join(".")
}

/// Canonical lowercase SQL identifier shape accepted by the MCP database
/// validator: `[a-z0-9_]+`. Used by `collect_table_factor` to reject
/// quoted identifiers whose contents would bypass the scope authorizer
/// after flattening — see the bypass class for backticked
/// dotted names. Keeping the rule strict and centralised here also stops
/// future parser entry points from re-introducing the bypass.
fn is_canonical_sql_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c == '_' || c.is_ascii_lowercase() || c.is_ascii_digit())
}

fn enforce_tables(
    tables: &[String],
    scope: &DatabaseScope,
    default_schema: Option<&str>,
) -> Result<(), DatabaseError> {
    if tables.is_empty() {
        return Err(DatabaseError::BadRequest(
            "query must reference at least one table".into(),
        ));
    }

    // Reject mixed-case identifiers from the query side. MySQL deployments
    // with `lower_case_table_names=0` (the Unix default) treat `orders` and
    // `Orders` as distinct tables, but a naïve case-insensitive scope check
    // would conflate them. Forcing lowercase identifiers in queries — and
    // forcing the entitlement table list to be lowercase below — guarantees
    // one canonical form on both sides.
    fn lowercase_or_reject<'a>(
        kind: &'static str,
        identifier: &'a str,
        scope_name: &str,
    ) -> Result<&'a str, DatabaseError> {
        if identifier.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(DatabaseError::Denied(format!(
                "{kind} '{identifier}' contains uppercase characters; use lowercase identifiers \
                 to match database scope '{scope_name}'"
            )));
        }
        Ok(identifier)
    }

    // Compare allowed_tables / allowed_schemas / default_schema
    // case-sensitively. Mixed-case grants are rejected at entitlement load
    // time by `validate_database_scope_identifiers`, mixed-case
    // `connection.database` is rejected at config load time, and mixed-case
    // identifiers from the query are rejected by `lowercase_or_reject`
    // above. Comparing without further normalization here means a forged
    // `"Orders"` in any layer cannot silently match a lowercase `orders` on
    // case-sensitive MySQL deployments.
    let allowed_tables: BTreeSet<&str> = scope.allowed_tables.iter().map(String::as_str).collect();
    let allowed_schemas: BTreeSet<&str> =
        scope.allowed_schemas.iter().map(String::as_str).collect();

    for table in tables {
        let mut parts = table.rsplitn(2, '.');
        let table_name = parts.next().unwrap_or(table);
        let schema = parts.next();
        // Explicit schema qualifiers take precedence over the connection's
        // default database. Cross-database reads are allowed only when the
        // entitlement's allowed_schemas includes that explicit schema.
        let table_name = lowercase_or_reject("table", table_name, &scope.name)?;
        if !allowed_tables.contains(table_name) {
            return Err(DatabaseError::Denied(format!(
                "table '{table}' is not allowed by database scope '{}'",
                scope.name
            )));
        }
        let explicit_schema = match schema {
            Some(s) => Some(lowercase_or_reject("schema", s, &scope.name)?),
            None => None,
        };
        if let Some(explicit_schema) = explicit_schema {
            if allowed_schemas.is_empty() {
                if let Some(default_schema) = default_schema {
                    if explicit_schema != default_schema {
                        return Err(DatabaseError::Denied(format!(
                            "schema '{explicit_schema}' is not allowed by database scope '{}'",
                            scope.name
                        )));
                    }
                }
            } else if !allowed_schemas.contains(explicit_schema) {
                return Err(DatabaseError::Denied(format!(
                    "schema '{explicit_schema}' is not allowed by database scope '{}'",
                    scope.name
                )));
            }
        } else if let Some(default_schema) = default_schema {
            if !allowed_schemas.is_empty() && !allowed_schemas.contains(default_schema) {
                return Err(DatabaseError::Denied(format!(
                    "schema '{default_schema}' is not allowed by database scope '{}'",
                    scope.name
                )));
            }
        }
    }
    Ok(())
}

/// Validate that an EXPLAIN-discovered plan stays inside the scope.
///
/// **Defense-in-depth design**. The full chain of database safeguards is:
///
/// 1. Entitlement scope (allowed_schemas / allowed_tables, lowercase-validated
///    at load time).
/// 2. Syntactic SQL validator: SELECT-only, single-statement, no comments,
///    no optimizer hints, no UDFs / stored functions, allow-listed pure
///    functions only, OFFSET denied, LIMIT bounded, CTE aliases cannot mask
///    qualified cross-schema references.
/// 3. THIS function: every EXPLAIN-reported table must satisfy
///    allowed_tables AND allowed_schemas. Catches views whose base table
///    is out of scope.
/// 4. `mysql_value_to_json` post-materialization per-cell clamp at
///    `MAX_CELL_BYTES`.
/// 5. Connection-level `max_allowed_packet` (mysql_async OptsBuilder).
/// 6. Session `group_concat_max_len` cap.
/// 7. `SET SESSION TRANSACTION READ ONLY`.
/// 8. `SET SESSION max_execution_time` per request.
/// 9. TLS required for the MySQL connection (config-validated outside
///    `dev_mode`).
/// 10. **Least-privilege DB role (operator responsibility, NOT Canopy-side)**:
///     the MySQL user behind `secret_arn` MUST be granted SELECT only on
///     base tables in the allowed_schemas — never on views, system tables,
///     or other schemas. This is the residual control for the cases where
///     EXPLAIN's reported `table_name` cannot prove schema provenance (e.g.
///     materialized subqueries, ambiguous aliases). Document this in your
///     IAM / Secrets-Manager runbook.
///
/// **Phase 1 known limitation**: information_schema lookup of view
/// definitions is intentionally deferred. Operators MUST enforce
/// least-privilege at the DB role level (item 10).
pub fn evaluate_explain(
    scope: &DatabaseScope,
    summary: &ExplainSummary,
    default_schema: &str,
) -> Result<(), DatabaseError> {
    // Unconditionally reject empty plans. a previous implementation allowed a
    // scope with `require_explain = false` would fall through here with
    // an empty `summary.tables`, skipping every EXPLAIN-driven check
    // (full-table-scan, row cap, view base table, cross-schema).
    // `require_explain` is now advisory metadata for audit only; the gate
    // itself is mandatory.
    if summary.tables.is_empty() {
        return Err(DatabaseError::QueryPlanRejected {
            message: "Query rejected before execution: EXPLAIN returned no table plan".into(),
            table: None,
            access_type: None,
            estimated_rows: None,
            reason: "empty_explain",
        });
    }

    // Re-validate every table EXPLAIN discovered against the scope's
    // allowed_tables. The syntactic SQL-validator only sees what the user
    // typed; a view authorized in `allowed_tables` would otherwise let an
    // EXPLAIN-expanded base table escape the table boundary. Forcing every
    // EXPLAIN table to satisfy the scope closes that gap.
    let allowed_tables: BTreeSet<&str> = scope.allowed_tables.iter().map(String::as_str).collect();
    let allowed_schemas: BTreeSet<&str> =
        scope.allowed_schemas.iter().map(String::as_str).collect();
    for table in &summary.tables {
        // Split out an explicit schema qualifier (if present) so we can
        // validate both axes — base table AND schema — against the scope.
        // Stripping the schema before the comparison would let
        // `other.orders` slip through a scope authorizing `orders`.
        let mut parts = table.table.rsplitn(2, '.');
        let leaf = parts.next().unwrap_or(&table.table);
        let explicit_schema = parts.next();
        if leaf.chars().any(|c| c.is_ascii_uppercase())
            || explicit_schema.is_some_and(|s| s.chars().any(|c| c.is_ascii_uppercase()))
        {
            return Err(DatabaseError::QueryPlanRejected {
                message: format!(
                    "Query rejected before execution: EXPLAIN-discovered table '{}' contains \
                     uppercase characters; case-sensitive identifiers cannot be reconciled with \
                     the lowercase entitlement scope",
                    table.table
                ),
                table: Some(table.table.clone()),
                access_type: table.access_type.clone(),
                estimated_rows: table.estimated_rows,
                reason: "explain_table_case_mismatch",
            });
        }
        // Aliases (`FROM orders o`), derived tables, and materialized
        // subqueries surface in EXPLAIN under names that are NOT in
        // `allowed_tables`. The syntactic SQL validator (`enforce_tables`)
        // already proved every actually-referenced table is allowed, so
        // here we only WARN on unfamiliar leaves rather than reject them —
        // the schema check below still binds them to the scope's database.
        // The view-expansion catch is preserved by `allowed_schemas`
        // enforcement combined with the operator's least-privilege DB role.
        if !allowed_tables.contains(leaf) {
            tracing::debug!(
                explain_table = %table.table,
                scope = %scope.name,
                "EXPLAIN reported a table name not in allowed_tables (likely an alias / \
                 derived table / pseudo plan node); leaving identity enforcement to the \
                 syntactic validator + DB role"
            );
        }
        // Determine which schema the EXPLAIN row "belongs to". MySQL may
        // emit unqualified table names whose true schema is the connection
        // default; we treat the connection's default database as the
        // implicit schema for those rows so the scope check has full
        // provenance to validate.
        let effective_schema = explicit_schema.unwrap_or(default_schema);
        if allowed_schemas.is_empty() {
            // Scope has no allowed_schemas declared → "stay inside the
            // connection's default database". Any EXPLAIN row that
            // resolves to a schema OTHER than the connection's default
            // (whether the qualifier was explicit or implicit) is a
            // cross-database read attempt and must be rejected.
            if effective_schema != default_schema {
                return Err(DatabaseError::QueryPlanRejected {
                    message: format!(
                        "Query rejected before execution: EXPLAIN-discovered table '{}' \
                         resolves to schema '{}' but scope '{}' (default-database mode) is \
                         pinned to '{}'.",
                        table.table, effective_schema, scope.name, default_schema
                    ),
                    table: Some(table.table.clone()),
                    access_type: table.access_type.clone(),
                    estimated_rows: table.estimated_rows,
                    reason: "explain_schema_outside_default_db",
                });
            }
        } else if !allowed_schemas.contains(effective_schema) {
            return Err(DatabaseError::QueryPlanRejected {
                message: format!(
                    "Query rejected before execution: EXPLAIN-discovered table '{}' resolves \
                     to schema '{}' which is outside database scope '{}'.",
                    table.table, effective_schema, scope.name
                ),
                table: Some(table.table.clone()),
                access_type: table.access_type.clone(),
                estimated_rows: table.estimated_rows,
                reason: "explain_schema_out_of_scope",
            });
        }
    }

    for table in &summary.tables {
        if !scope.allow_full_table_scan && table.full_table_scan {
            return Err(DatabaseError::QueryPlanRejected {
                message: format!(
                    "Query rejected before execution: full table scan on {} is not allowed.",
                    table.table
                ),
                table: Some(table.table.clone()),
                access_type: table.access_type.clone(),
                estimated_rows: table.estimated_rows,
                reason: "full_table_scan",
            });
        }
        if let Some(rows) = table.estimated_rows {
            if rows > scope.max_examined_rows {
                return Err(DatabaseError::QueryPlanRejected {
                    message: format!(
                        "Query rejected before execution: estimated rows {rows} exceeds max_examined_rows {}.",
                        scope.max_examined_rows
                    ),
                    table: Some(table.table.clone()),
                    access_type: table.access_type.clone(),
                    estimated_rows: Some(rows),
                    reason: "max_examined_rows",
                });
            }
        }
    }
    Ok(())
}

pub fn explain_summary_from_json(raw: &str) -> anyhow::Result<ExplainSummary> {
    let json: JsonValue = serde_json::from_str(raw)?;
    let mut tables = Vec::new();
    collect_explain_tables(&json, &mut tables);
    let first = tables.first();
    Ok(ExplainSummary {
        access_type: first.and_then(|t| t.access_type.clone()),
        key_used: first.and_then(|t| t.key_used.clone()),
        estimated_rows: first.and_then(|t| t.estimated_rows),
        full_table_scan: tables.iter().any(|t| t.full_table_scan),
        tables,
    })
}

fn collect_explain_tables(value: &JsonValue, out: &mut Vec<ExplainTableSummary>) {
    match value {
        JsonValue::Object(map) => {
            if let Some(table) = map.get("table").and_then(JsonValue::as_object) {
                if let Some(name) = table.get("table_name").and_then(JsonValue::as_str) {
                    let access_type = table
                        .get("access_type")
                        .and_then(JsonValue::as_str)
                        .map(str::to_string);
                    let key_used = table
                        .get("key")
                        .and_then(JsonValue::as_str)
                        .map(str::to_string);
                    let estimated_rows = table
                        .get("rows_examined_per_scan")
                        .or_else(|| table.get("rows_produced_per_join"))
                        .or_else(|| table.get("rows"))
                        .and_then(JsonValue::as_u64);
                    let full_table_scan =
                        access_type.as_deref() == Some("ALL") && key_used.as_deref().is_none();
                    out.push(ExplainTableSummary {
                        table: name.to_string(),
                        access_type,
                        key_used,
                        estimated_rows,
                        full_table_scan,
                    });
                }
            }
            for child in map.values() {
                collect_explain_tables(child, out);
            }
        }
        JsonValue::Array(items) => {
            for child in items {
                collect_explain_tables(child, out);
            }
        }
        _ => {}
    }
}

pub fn scope_summary(scope: &DatabaseScope) -> shared::dto::database::DatabaseScopeSummary {
    shared::dto::database::DatabaseScopeSummary {
        name: scope.name.clone(),
        connection: scope.connection.clone(),
        environment: scope.environment.clone(),
        allowed_schemas: scope.allowed_schemas.clone(),
        allowed_tables: scope.allowed_tables.clone(),
        allowed_actions: scope.allowed_actions.clone(),
        max_rows: scope.max_rows,
        statement_timeout_ms: scope.statement_timeout_ms,
        require_explain: scope.require_explain,
        max_examined_rows: scope.max_examined_rows,
        allow_full_table_scan: scope.allow_full_table_scan,
    }
}

pub fn build_database_response(
    scope: &DatabaseScope,
    explain: ExplainSummary,
    query: QueryRows,
) -> QueryDatabaseResponse {
    let truncated = query.truncated_by_byte_budget;
    QueryDatabaseResponse {
        columns: query.columns,
        row_count: query.rows.len(),
        rows: query.rows,
        truncated,
        scope: scope.name.clone(),
        environment: scope.environment.clone(),
        explain,
    }
}

/// Approximate the on-the-wire JSON size of a row by summing per-cell
/// payload sizes. We intentionally over-approximate slightly (16 bytes per
/// non-string cell) so the byte budget stays conservative.
fn approximate_row_bytes(row: &[JsonValue]) -> usize {
    let payload: usize = row
        .iter()
        .map(|value| match value {
            JsonValue::String(s) => s.len(),
            JsonValue::Null => 4,
            // bool / number / json-array / json-object are tiny in
            // comparison; over-counting is preferred to under-counting.
            _ => 16,
        })
        .sum();
    // Add fixed per-row overhead for JSON `[]`, commas, and brackets.
    payload
        .saturating_add(row.len().saturating_mul(2))
        .saturating_add(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> DatabaseScope {
        DatabaseScope {
            name: "orders_prod_readonly".into(),
            connection: "orders_prod".into(),
            environment: "production".into(),
            allowed_schemas: vec!["orders".into()],
            allowed_tables: vec!["orders".into(), "order_items".into()],
            allowed_actions: vec!["select".into()],
            max_rows: 100,
            statement_timeout_ms: 5000,
            require_explain: true,
            max_examined_rows: 10000,
            allow_full_table_scan: false,
            allow_views: false,
        }
    }

    #[test]
    fn select_with_limit_validates() {
        let validated =
            validate_select_sql("select id from orders where id = 1 limit 10", &scope()).unwrap();
        assert_eq!(validated.tables, vec!["orders"]);
        assert!(validated.normalized_sql.ends_with("limit 10"));
    }

    #[test]
    fn missing_limit_adds_scope_limit() {
        let validated = validate_select_sql("select id from orders", &scope()).unwrap();
        assert!(validated.normalized_sql.ends_with("LIMIT 100"));
    }

    #[test]
    fn implicit_schema_uses_connection_database() {
        validate_select_sql_for_connection("select id from orders limit 10", &scope(), "orders")
            .unwrap();

        let err =
            validate_select_sql_for_connection("select id from orders limit 10", &scope(), "users")
                .unwrap_err();
        assert!(matches!(err, DatabaseError::Denied(_)));
    }

    #[test]
    fn explicit_schema_must_match_default_when_scope_has_no_allowed_schemas() {
        let mut scope = scope();
        scope.allowed_schemas = vec![];

        validate_select_sql_for_connection(
            "select id from orders.orders limit 10",
            &scope,
            "orders",
        )
        .unwrap();

        let err = validate_select_sql_for_connection(
            "select id from other.orders limit 10",
            &scope,
            "orders",
        )
        .unwrap_err();
        assert!(matches!(err, DatabaseError::Denied(_)));
    }

    #[test]
    fn semicolon_inside_string_literal_is_allowed() {
        let validated = validate_select_sql(
            "select id from orders where status = 'paid;ok' limit 10",
            &scope(),
        )
        .unwrap();
        assert_eq!(validated.tables, vec!["orders"]);
    }

    #[test]
    fn too_large_limit_rejected() {
        let err = validate_select_sql("select id from orders limit 101", &scope()).unwrap_err();
        assert!(matches!(err, DatabaseError::BadRequest(_)));
    }

    #[test]
    fn offset_is_rejected() {
        let err =
            validate_select_sql("select id from orders limit 10 offset 1", &scope()).unwrap_err();
        assert!(matches!(err, DatabaseError::BadRequest(_)));
    }

    #[test]
    fn cte_offset_is_rejected() {
        let err = validate_select_sql(
            "with page as (select id from orders limit 10 offset 1) select id from page limit 10",
            &scope(),
        )
        .unwrap_err();
        assert!(matches!(err, DatabaseError::BadRequest(_)));
    }

    #[test]
    fn derived_table_limit_is_bounded() {
        let err = validate_select_sql(
            "select id from (select id from orders limit 101) page limit 10",
            &scope(),
        )
        .unwrap_err();
        assert!(matches!(err, DatabaseError::BadRequest(_)));
    }

    #[test]
    fn update_is_rejected() {
        let err = validate_select_sql("update orders set status = 'x'", &scope()).unwrap_err();
        assert!(matches!(err, DatabaseError::Denied(_)));
    }

    #[test]
    fn select_into_is_rejected() {
        let err = validate_select_sql("select id into temp_orders from orders limit 10", &scope())
            .unwrap_err();
        assert!(matches!(err, DatabaseError::Denied(_)));
    }

    #[test]
    fn select_for_update_is_rejected() {
        let err = validate_select_sql("select id from orders where id = 1 for update", &scope())
            .unwrap_err();
        assert!(matches!(err, DatabaseError::Denied(_)));
    }

    #[test]
    fn multi_statement_is_rejected() {
        let err = validate_select_sql("select id from orders; select id from orders", &scope())
            .unwrap_err();
        assert!(matches!(err, DatabaseError::BadRequest(_)));
    }

    #[test]
    fn unauthorized_table_is_rejected() {
        let err = validate_select_sql("select id from users limit 10", &scope()).unwrap_err();
        assert!(matches!(err, DatabaseError::Denied(_)));
    }

    #[test]
    fn backticked_dotted_identifier_is_rejected() {
        // a single backticked identifier whose value
        // contains a `.` was flattened by `object_name` into the same
        // string as an explicit `schema.table` qualifier. The view guard
        // would then look up `(orders, orders)` and find the BASE TABLE in
        // the default schema, even though the actual SQL referenced an
        // out-of-scope object named `orders.orders`. After the fix,
        // `collect_table_factor` rejects any identifier part whose value
        // is not `[a-z0-9_]+` — even though both halves of `orders.orders`
        // are in the scope, the `.` inside a single quoted ident is now
        // refused up front.
        for sql in [
            "select id from `orders.orders` limit 10",
            "select id from `orders`.`orders.orders` limit 10",
        ] {
            let err = validate_select_sql(sql, &scope()).unwrap_err();
            match err {
                DatabaseError::Denied(message) => assert!(
                    message.contains("[a-z0-9_]"),
                    "{sql} → expected denial mentioning the identifier shape, got: {message}"
                ),
                other => panic!("{sql} → expected Denied, got: {other:?}"),
            }
        }
    }

    #[test]
    fn quoted_identifier_with_special_chars_is_rejected() {
        // Generalized identifier-shape regression — hyphens, spaces,
        // and uppercase characters inside backticks must also be refused.
        for sql in [
            "select id from `my-table` limit 10",
            "select id from `my table` limit 10",
            "select id from `Orders` limit 10",
        ] {
            let err = validate_select_sql(sql, &scope()).unwrap_err();
            match err {
                DatabaseError::Denied(message) => assert!(
                    message.contains("[a-z0-9_]"),
                    "{sql} → expected denial about identifier shape, got: {message}"
                ),
                other => panic!("{sql} → expected Denied, got: {other:?}"),
            }
        }
    }

    #[test]
    fn dangerous_mysql_functions_are_rejected() {
        // a previous implementation allowed table-scope enforcement does not stop
        // an allowed-table SELECT from calling MySQL functions that read
        // the filesystem (LOAD_FILE), block the connection (SLEEP /
        // BENCHMARK), manipulate user-level locks, or leak server identity
        // (USER / VERSION / DATABASE). Each must be rejected up front; the
        // least-privilege DB role is only the second line of defense.
        for sql in [
            "select LOAD_FILE('/etc/passwd') from orders limit 1",
            "select sleep(5) from orders limit 1",
            "select benchmark(1000000, md5('x')) from orders limit 1",
            "select get_lock('x', 1) from orders limit 1",
            "select user() from orders limit 1",
            "select version() from orders limit 1",
            "select database() from orders limit 1",
            "select connection_id() from orders limit 1",
        ] {
            let err = validate_select_sql(sql, &scope()).unwrap_err();
            match err {
                DatabaseError::Denied(message) => assert!(
                    message.contains("not allowed for database MCP queries"),
                    "{sql} → expected denial mentioning denied functions, got: {message}"
                ),
                other => panic!("{sql} → expected Denied, got: {other:?}"),
            }
        }
    }

    #[test]
    fn mysql_value_caps_oversized_cells_before_string_alloc() {
        // a previous implementation allowed a single oversized TEXT/BLOB cell could
        // still be fully materialized before the row-budget check. The
        // per-cell cap in `mysql_value_to_json` clamps each value to a
        // sentinel string before the JSON conversion, so no string
        // exceeding `MAX_CELL_BYTES` is ever allocated as a full payload.
        let oversized = vec![b'x'; MAX_CELL_BYTES + 1];
        let result = mysql_value_to_json(mysql_async::Value::Bytes(oversized));
        match result {
            JsonValue::String(s) => {
                assert!(
                    s.contains("truncated"),
                    "expected truncation sentinel, got: {s}"
                );
                assert!(
                    s.len() < MAX_CELL_BYTES,
                    "sentinel string itself must be small, got {} bytes",
                    s.len()
                );
            }
            other => panic!("expected truncation string, got: {other:?}"),
        }

        // Non-oversized strings round-trip unchanged.
        let small = "hello world".as_bytes().to_vec();
        let result = mysql_value_to_json(mysql_async::Value::Bytes(small));
        assert_eq!(result, JsonValue::String("hello world".into()));
    }

    #[test]
    fn cte_alias_does_not_mask_qualified_cross_schema_table() {
        // `WITH orders AS (...) SELECT FROM other.orders`
        // must NOT be treated as the CTE. The qualified name resolves to
        // a real table in another schema; the schema check in
        // `enforce_tables` then rejects it because the scope only allows
        // schema `orders`.
        let sql = "with orders as (select 1 as id) select id from other.orders limit 10";
        let err = validate_select_sql(sql, &scope()).unwrap_err();
        match err {
            DatabaseError::Denied(message) => assert!(
                message.contains("schema 'other'"),
                "expected schema denial, got: {message}"
            ),
            other => panic!("expected Denied, got: {other:?}"),
        }
    }

    #[test]
    fn unbounded_string_constructors_are_not_on_allow_list() {
        // a previous implementation allowed `repeat('x', 50000000)` etc. can OOM
        // both MySQL and the control-plane long before the response cap
        // can clamp. Phase 1 removes these from the allow-list entirely;
        // they can come back with a literal-size-arg validator later.
        for sql in [
            "select repeat('x', 1000000) from orders limit 1",
            "select space(1000000) from orders limit 1",
            "select lpad('x', 1000000, '_') from orders limit 1",
            "select rpad('x', 1000000, '_') from orders limit 1",
        ] {
            let err = validate_select_sql(sql, &scope()).unwrap_err();
            match err {
                DatabaseError::Denied(message) => assert!(
                    message.contains("not on the Canopy MCP allow-list"),
                    "{sql} → expected allow-list rejection, got: {message}"
                ),
                other => panic!("{sql} → expected Denied, got: {other:?}"),
            }
        }
    }

    #[test]
    fn unknown_or_stored_functions_are_rejected_by_allow_list() {
        // a previous implementation allowed a deny-list approach leaves stored
        // functions, UDFs, and uncommon built-ins (e.g. MASTER_POS_WAIT)
        // outside the table-read boundary. The allow-list rejects anything
        // not on the reviewed surface, including arbitrary stored-routine
        // names and replication-wait functions.
        for sql in [
            "select master_pos_wait('binlog', 0) from orders limit 1",
            "select wait_for_executed_gtid_set('GTID') from orders limit 1",
            "select some_custom_udf(id) from orders limit 1",
            "select definer_routine.do_thing(id) from orders limit 1",
        ] {
            let err = validate_select_sql(sql, &scope()).unwrap_err();
            match err {
                DatabaseError::Denied(message) => assert!(
                    message.contains("not on the Canopy MCP allow-list")
                        || message.contains("not allowed for database MCP queries"),
                    "{sql} → expected allow-list rejection, got: {message}"
                ),
                other => panic!("{sql} → expected Denied, got: {other:?}"),
            }
        }
    }

    #[test]
    fn safe_aggregate_functions_are_allowed() {
        // Sanity check: the deny-list does not accidentally trip on common
        // aggregates / built-ins that ops actually need.
        for sql in [
            "select count(*) from orders limit 1",
            "select sum(id) from orders limit 1",
            "select max(id), min(id) from orders limit 1",
            "select coalesce(id, 0) from orders limit 1",
            "select now() from orders limit 1",
        ] {
            validate_select_sql(sql, &scope())
                .unwrap_or_else(|err| panic!("{sql} unexpectedly rejected: {err:?}"));
        }
    }

    #[test]
    fn uppercase_table_identifier_is_rejected() {
        // The entitlement only allows `orders` (lowercase). On MySQL with
        // `lower_case_table_names=0` a query against `Orders` is a different
        // table. Reject mixed-case identifiers up front rather than silently
        // collapsing them to the entitlement's canonical form.
        let err = validate_select_sql("select id from Orders limit 10", &scope()).unwrap_err();
        match err {
            DatabaseError::Denied(message) => {
                assert!(
                    message.contains("uppercase"),
                    "expected uppercase rejection, got: {message}"
                );
            }
            other => panic!("expected Denied, got: {other:?}"),
        }
    }

    #[test]
    fn uppercase_schema_qualifier_is_rejected() {
        let err =
            validate_select_sql("select id from Orders_DB.orders limit 10", &scope()).unwrap_err();
        match err {
            DatabaseError::Denied(message) => {
                assert!(
                    message.contains("uppercase"),
                    "expected uppercase rejection, got: {message}"
                );
            }
            other => panic!("expected Denied, got: {other:?}"),
        }
    }

    #[test]
    fn scalar_subquery_is_rejected_before_table_enforcement_can_be_bypassed() {
        let err = validate_select_sql(
            "select (select password from users limit 1) as leaked from orders limit 10",
            &scope(),
        )
        .unwrap_err();
        assert!(matches!(err, DatabaseError::Denied(_)));
    }

    #[test]
    fn canonical_identifier_accepts_lowercase_alphanumeric_and_underscore_only() {
        // Positive cases — every shape the validator promises to accept.
        for good in ["orders", "order_items", "tbl_42", "a", "x9_y"] {
            assert!(
                super::is_canonical_sql_identifier(good),
                "expected '{good}' to be a canonical identifier"
            );
        }
        // Negative cases — every unsupported identifier shape.
        for bad in [
            "",
            "Orders",     // uppercase
            "orders ",    // whitespace
            "orders.foo", // dot inside a single identifier (backticked bypass)
            "my-table",   // hyphen
            "users👀",    // non-ASCII
            "5",          // legal alone but reserved for future digit-only rule check
        ] {
            // The "legal alone but reserved" comment above is a note for the
            // reader — purely digit identifiers are accepted today since
            // MySQL allows them; bail only on the other shapes.
            if bad == "5" {
                continue;
            }
            assert!(
                !super::is_canonical_sql_identifier(bad),
                "expected '{bad}' to be rejected"
            );
        }
    }

    #[test]
    fn predicate_subquery_is_rejected_before_table_enforcement_can_be_bypassed() {
        let err = validate_select_sql(
            "select id from orders where exists (select 1 from users where users.id = orders.id) limit 10",
            &scope(),
        )
        .unwrap_err();
        assert!(matches!(err, DatabaseError::Denied(_)));
    }

    /// Construct a `mysql_async::Error::Server` instance carrying the
    /// supplied error code so we can exercise the capacity classifier
    /// against codes we cannot exercise via a real connection in unit
    /// tests. Uses the public `ServerError` struct, falling back to
    /// `..Default::default()` for the fields the test does not care
    /// about.
    fn fake_server_error(code: u16) -> mysql_async::Error {
        let server_err = mysql_async::ServerError {
            code,
            message: "test".to_string(),
            state: "HY000".to_string(),
        };
        mysql_async::Error::Server(server_err)
    }

    #[test]
    fn mysql_capacity_classifier_covers_known_overload_codes() {
        for code in [1037u16, 1040, 1041, 1203] {
            let err: anyhow::Error = fake_server_error(code).into();
            assert!(
                super::is_mysql_capacity_error(&err),
                "code {code} should classify as capacity overload"
            );
        }
    }

    #[test]
    fn mysql_capacity_classifier_excludes_non_capacity_codes() {
        // 1129 (host blocked) is a security signal; 1205 (lock wait) is
        // transient lock contention. Neither should be mapped to
        // `database_connection_unavailable` overload.
        for code in [1129u16, 1205, 1062, 1146] {
            let err: anyhow::Error = fake_server_error(code).into();
            assert!(
                !super::is_mysql_capacity_error(&err),
                "code {code} must NOT classify as capacity overload"
            );
        }
    }

    #[test]
    fn mysql_capacity_classifier_ignores_non_server_errors() {
        let err: anyhow::Error = anyhow::anyhow!("plain anyhow error");
        assert!(!super::is_mysql_capacity_error(&err));
    }

    #[test]
    fn join_collects_all_tables() {
        let validated = validate_select_sql(
            "select o.id from orders o join order_items i on i.order_id = o.id limit 10",
            &scope(),
        )
        .unwrap();
        assert_eq!(validated.tables, vec!["order_items", "orders"]);
    }

    #[test]
    fn cte_collects_base_tables_without_requiring_cte_name() {
        let validated = validate_select_sql(
            "with recent_orders as (select id from orders where id = 1) select id from recent_orders limit 10",
            &scope(),
        )
        .unwrap();
        assert_eq!(validated.tables, vec!["orders"]);
    }

    #[test]
    fn cte_can_reference_previous_cte_without_requiring_cte_name() {
        let validated = validate_select_sql(
            "with base_orders as (select id from orders), recent_orders as (select id from base_orders) select id from recent_orders limit 10",
            &scope(),
        )
        .unwrap();
        assert_eq!(validated.tables, vec!["orders"]);
    }

    #[test]
    fn cte_alias_scope_does_not_leak_to_outer_query() {
        let err = validate_select_sql(
            "select d.id from (with hidden as (select id from orders) select id from hidden) d join hidden on hidden.id = d.id limit 10",
            &scope(),
        )
        .unwrap_err();
        assert!(matches!(err, DatabaseError::Denied(_)));
    }

    #[test]
    fn explain_unknown_leaf_warns_but_schema_check_still_binds() {
        // a previous implementation allowed strict EXPLAIN leaf-name enforcement
        // breaks legitimate alias / derived-table queries
        // (`SELECT o.id FROM orders o`). Phase 1 relaxes the leaf check to
        // a debug log; the view-expansion defense is preserved by the
        // schema gate (next test) + the operator's least-privilege DB role.
        let summary = ExplainSummary {
            tables: vec![ExplainTableSummary {
                table: "o".into(), // alias for orders
                access_type: Some("ref".into()),
                key_used: Some("PRIMARY".into()),
                estimated_rows: Some(1),
                full_table_scan: false,
            }],
            ..Default::default()
        };
        // Should NOT reject — schema check still validates that `o`
        // resolves into the scope's `allowed_schemas` via default_schema.
        evaluate_explain(&scope(), &summary, "orders").unwrap();
    }

    #[test]
    fn explain_schema_check_still_blocks_view_into_other_schema() {
        // EXPLAIN reports a base table in an out-of-scope schema. The
        // leaf-name relaxation does NOT undo the schema check: an
        // explicit qualifier `other.orders` is still rejected.
        let summary = ExplainSummary {
            tables: vec![ExplainTableSummary {
                table: "other.orders".into(),
                access_type: Some("ref".into()),
                key_used: Some("PRIMARY".into()),
                estimated_rows: Some(1),
                full_table_scan: false,
            }],
            ..Default::default()
        };
        let err = evaluate_explain(&scope(), &summary, "orders").unwrap_err();
        assert!(matches!(
            err,
            DatabaseError::QueryPlanRejected {
                reason: "explain_schema_out_of_scope",
                ..
            }
        ));
    }

    #[test]
    fn explain_rejects_uppercase_base_table() {
        let summary = ExplainSummary {
            tables: vec![ExplainTableSummary {
                table: "Orders".into(),
                access_type: Some("ref".into()),
                key_used: Some("PRIMARY".into()),
                estimated_rows: Some(1),
                full_table_scan: false,
            }],
            ..Default::default()
        };
        let err = evaluate_explain(&scope(), &summary, "orders").unwrap_err();
        assert!(matches!(
            err,
            DatabaseError::QueryPlanRejected {
                reason: "explain_table_case_mismatch",
                ..
            }
        ));
    }

    #[test]
    fn explain_rejects_full_table_scan() {
        let summary = ExplainSummary {
            tables: vec![ExplainTableSummary {
                table: "orders".into(),
                access_type: Some("ALL".into()),
                key_used: None,
                estimated_rows: Some(200),
                full_table_scan: true,
            }],
            full_table_scan: true,
            ..Default::default()
        };
        let err = evaluate_explain(&scope(), &summary, "orders").unwrap_err();
        assert!(matches!(
            err,
            DatabaseError::QueryPlanRejected {
                reason: "full_table_scan",
                ..
            }
        ));
    }

    #[test]
    fn explain_rejects_too_many_estimated_rows() {
        let summary = ExplainSummary {
            tables: vec![ExplainTableSummary {
                table: "orders".into(),
                access_type: Some("range".into()),
                key_used: Some("idx_orders_created_at".into()),
                estimated_rows: Some(10001),
                full_table_scan: false,
            }],
            ..Default::default()
        };
        let err = evaluate_explain(&scope(), &summary, "orders").unwrap_err();
        assert!(matches!(
            err,
            DatabaseError::QueryPlanRejected {
                reason: "max_examined_rows",
                ..
            }
        ));
    }

    #[test]
    fn explain_json_extracts_summary() {
        let raw = r#"{
          "query_block": {
            "table": {
              "table_name": "orders",
              "access_type": "const",
              "key": "PRIMARY",
              "rows_examined_per_scan": 1
            }
          }
        }"#;
        let summary = explain_summary_from_json(raw).unwrap();
        assert_eq!(summary.access_type.as_deref(), Some("const"));
        assert_eq!(summary.key_used.as_deref(), Some("PRIMARY"));
        assert_eq!(summary.estimated_rows, Some(1));
        assert!(!summary.full_table_scan);
    }
}
