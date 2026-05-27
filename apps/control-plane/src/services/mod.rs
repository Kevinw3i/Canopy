pub mod audit;
pub mod auth;
pub mod cloudwatch;
pub mod database;
pub mod ec2;
pub mod ecs;
pub mod entitlements;
pub mod oidc;
pub mod step_up;

use crate::config::AppConfig;
use crate::models::entitlements::EntitlementStore;
use crate::models::mfa::MfaStore;
use aws_config::SdkConfig;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use database::{
    AwsSecretsDatabaseSecretProvider, DatabaseExecutor, DatabaseSecretProvider,
    MySqlDatabaseExecutor,
};
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Tracks who started a Logs Insights query and which log groups were approved.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QueryAuthorization {
    pub user_id: String,
    pub log_group_names: Vec<String>,
}

/// Durable MCP session state lives in control-plane for authorization/audit
/// decisions. The TUI-local MCP server can cache this for UX, but it is not
/// the authority for guidance gates.
#[derive(Debug, Clone)]
pub struct McpSessionRecord {
    pub actor: String,
    pub actor_email: String,
    pub local_secret_generation: String,
    pub forwarding_key: String,
    pub protocol_version: String,
    pub client_name: String,
    pub client_version: String,
    pub product_phase: String,
    pub guidance_delivered: BTreeSet<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Encode query authorization into a signed token that can survive restarts.
/// Format: `{aws_query_id}.{base64url(json)}.{hmac_hex}`
pub fn sign_query_token(aws_query_id: &str, auth: &QueryAuthorization, secret: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let payload = serde_json::to_string(auth).unwrap_or_default();
    let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());

    let msg = format!("{}.{}", aws_query_id, encoded);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC key length");
    mac.update(msg.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());

    format!("{}.{}", msg, sig)
}

/// Verify and extract authorization from a signed query token.
pub fn verify_query_token(token: &str, secret: &str) -> Option<(String, QueryAuthorization)> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let parts: Vec<&str> = token.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return None;
    }
    let sig_hex = parts[0];
    let msg = parts[1]; // "{aws_query_id}.{encoded_payload}"

    // Verify HMAC
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(msg.as_bytes());
    let expected_sig = hex::encode(mac.finalize().into_bytes());
    if sig_hex != expected_sig {
        return None;
    }

    // Split msg into aws_query_id and encoded payload
    let dot_pos = msg.find('.')?;
    let aws_query_id = &msg[..dot_pos];
    let encoded = &msg[dot_pos + 1..];

    let payload_bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let auth: QueryAuthorization = serde_json::from_slice(&payload_bytes).ok()?;

    Some((aws_query_id.to_string(), auth))
}

/// Shared application state passed to all handlers
pub struct AppState {
    pub config: AppConfig,
    pub entitlement_store: Arc<RwLock<EntitlementStore>>,
    pub audit_service: audit::AuditService,
    pub oidc_client: oidc::OidcClient,
    pub mfa_store: MfaStore,
    pub step_up_sessions: step_up::StepUpSessionStore,
    pub base_aws_config: SdkConfig,
    pub database_secret_provider: Arc<dyn DatabaseSecretProvider>,
    pub database_executor: Arc<dyn DatabaseExecutor>,
    pub mcp_sessions: DashMap<String, McpSessionRecord>,
    /// Set to true after startup preflight checks (OIDC discovery + STS identity) succeed.
    /// This is the **global** readiness signal (drives `/health`); a failed database
    /// connection does NOT clear it (Codex round 30 HIGH — one bad DB scope should not
    /// take EC2/CloudWatch/auth paths offline).
    pub ready: std::sync::atomic::AtomicBool,
    /// Per-database-connection readiness map. Entry is present (true) after that
    /// connection passed `preflight_session_safety`; absent / false means the
    /// `@@session`/`@@global.wait_timeout` invariant could not be proved on that
    /// upstream, so routes that touch that connection must fail-closed. Other
    /// connections and non-DB routes are unaffected.
    pub db_connection_ready: DashMap<String, bool>,
    /// Codex round 33 (HIGH): per-connection reprobe cool-down. When a
    /// preflight `Conn::new` is cancelled mid-handshake (timeout or
    /// ambiguous error), the upstream may have allocated a session
    /// it doesn't know is orphaned. Hammering the reprobe loop at
    /// the default 60 s interval would stack orphan sessions until
    /// the role's `wait_timeout` reaps them, exhausting
    /// `max_connections` on a misconfigured upstream. After a failed
    /// preflight we set this entry to a future `Instant`; the
    /// reprobe loop skips that connection until the cool-down has
    /// elapsed. Successful preflights clear the entry.
    pub db_connection_next_probe: DashMap<String, std::time::Instant>,
}

impl AppState {
    pub async fn new(config: AppConfig) -> anyhow::Result<Self> {
        if config.entitlements_file.is_some() && config.entitlements_database_url.is_some() {
            anyhow::bail!("entitlements_file and entitlements_database_url are mutually exclusive");
        }

        let mut entitlement_store = if let Some(ref url) = config.entitlements_database_url {
            EntitlementStore::load_from_database_url_allowing_organization_account_placeholders(
                url,
            )?
        } else if let Some(ref path) = config.entitlements_file {
            EntitlementStore::load_from_file_allowing_organization_account_placeholders(
                std::path::Path::new(path),
            )?
        } else if config.dev_mode {
            EntitlementStore::dev_defaults()
        } else {
            anyhow::bail!(
                "entitlements_file or entitlements_database_url is required in production mode. \
                 Set dev_mode = true or provide an entitlement backend."
            );
        };

        let oidc_client = oidc::OidcClient::new(config.oidc.clone());
        let mfa_store = MfaStore::from_optional_config(
            config.mfa_database_url.as_deref(),
            config.mfa_secret_key.as_deref(),
        )?;

        // Load the base AWS SDK config (uses ambient credentials: env vars,
        // instance profile, ~/.aws/credentials, etc.).
        let base_aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(
                config
                    .aws
                    .default_region
                    .clone()
                    .unwrap_or_else(|| "us-east-1".to_string()),
            ))
            .load()
            .await;
        let secrets_client = aws_sdk_secretsmanager::Client::new(&base_aws_config);

        if entitlement_store.has_organization_account_placeholders() {
            tracing::info!("Discovering AWS Organizations accounts for entitlement expansion");
            let accounts =
                crate::aws::organizations::discover_active_accounts(&base_aws_config).await?;
            let discovered_count = accounts.len();
            if discovered_count == 0 {
                anyhow::bail!(
                    "AWS Organizations account discovery returned no ACTIVE accounts for entitlement expansion"
                );
            }
            let expanded_count =
                entitlement_store.expand_organization_account_placeholders(&accounts)?;
            tracing::info!(
                discovered_accounts = discovered_count,
                expanded_accounts = expanded_count,
                "Expanded AWS Organizations entitlement accounts"
            );
        }
        entitlement_store.validate()?;

        let audit_service = audit::AuditService::from_config(
            config.audit_log.as_deref(),
            &config.audit_export,
            &base_aws_config,
        )?;

        Ok(Self {
            config,
            entitlement_store: Arc::new(RwLock::new(entitlement_store)),
            audit_service,
            oidc_client,
            mfa_store,
            step_up_sessions: step_up::StepUpSessionStore::default(),
            base_aws_config,
            database_secret_provider: Arc::new(AwsSecretsDatabaseSecretProvider::new(
                secrets_client,
            )),
            database_executor: Arc::new(MySqlDatabaseExecutor::new()),
            mcp_sessions: DashMap::new(),
            ready: std::sync::atomic::AtomicBool::new(false),
            db_connection_ready: DashMap::new(),
            db_connection_next_probe: DashMap::new(),
        })
    }

    /// Whether the given database connection passed its startup
    /// `wait_timeout` preflight. Used by `/api/mcp/database/*` to fail
    /// closed only on the affected scope rather than the whole service.
    pub fn db_connection_is_ready(&self, connection_name: &str) -> bool {
        self.db_connection_ready
            .get(connection_name)
            .map(|v| *v)
            .unwrap_or(false)
    }

    /// Run startup preflight: verify OIDC discovery, STS identity, and
    /// database wait_timeout invariant. Retries with exponential
    /// backoff (up to ~30s total). Sets `ready` to true on success.
    ///
    /// Dev-mode shortcut: OIDC + STS are skipped because the typical
    /// dev config uses placeholder OIDC and no STS. **Database
    /// preflight is NOT skipped** when `database_connections` is
    /// non-empty — the limiter's `permit_hold_after_acquire_failure`
    /// correctness depends on the @@session AND @@global
    /// `wait_timeout` invariant regardless of dev/prod, and a
    /// dev-mode + `ALLOW_DEV_MODE_REMOTE` + real DB deployment would
    /// otherwise bypass it (Codex round 28 HIGH).
    pub async fn run_preflight(&self) -> anyhow::Result<()> {
        if self.config.dev_mode {
            tracing::warn!(
                "dev_mode: skipping OIDC + STS preflight (placeholder issuer / no real STS)"
            );
            // Even in dev_mode we must verify the database
            // wait_timeout invariant — otherwise a dev-mode-with-
            // remote-override + database_connections deployment
            // could serve `/api/mcp/database/*` against an upstream
            // whose @@global.wait_timeout is the 28 800 s default,
            // breaking the limiter contract.
            if !self.config.database_connections.is_empty() {
                tracing::info!(
                    "dev_mode preflight: verifying @@session/@@global wait_timeout on {} database \
                     connection(s)...",
                    self.config.database_connections.len()
                );
                for (name, conn_cfg) in &self.config.database_connections {
                    if let Some(next) = self.db_connection_next_probe.get(name) {
                        if std::time::Instant::now() < *next {
                            tracing::debug!(
                                connection = %name,
                                "dev_mode preflight: connection is in DB_REPROBE_COOLDOWN, skipping"
                            );
                            continue;
                        }
                    }
                    probe_single_db_connection_and_update(self, name, conn_cfg).await;
                }
            }
            self.ready.store(true, std::sync::atomic::Ordering::Release);
            return Ok(());
        }
        let max_attempts = 3u32;
        let mut last_err = None;

        for attempt in 0..max_attempts {
            if attempt > 0 {
                let delay = std::time::Duration::from_secs(2u64.pow(attempt.min(4)));
                tracing::warn!(
                    "Preflight attempt {} failed, retrying in {:?}...",
                    attempt,
                    delay
                );
                tokio::time::sleep(delay).await;
            }

            let step_timeout = std::time::Duration::from_secs(10);

            // 1. OIDC discovery (bounded by timeout)
            tracing::info!(
                "Preflight (attempt {}): verifying OIDC discovery...",
                attempt + 1
            );
            match tokio::time::timeout(step_timeout, self.oidc_client.endpoints()).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    last_err = Some(format!("OIDC discovery: {e}"));
                    continue;
                }
                Err(_) => {
                    last_err = Some("OIDC discovery timed out".into());
                    continue;
                }
            }
            tracing::info!("Preflight: OIDC discovery OK");

            // 2. STS GetCallerIdentity (bounded by timeout)
            tracing::info!("Preflight: verifying STS identity...");
            let sts = aws_sdk_sts::Client::new(&self.base_aws_config);
            match tokio::time::timeout(step_timeout, sts.get_caller_identity().send()).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    last_err = Some(format!("STS GetCallerIdentity: {e}"));
                    continue;
                }
                Err(_) => {
                    last_err = Some("STS GetCallerIdentity timed out".into());
                    continue;
                }
            }
            tracing::info!("Preflight: STS identity OK");

            // 3. Database wait_timeout invariant (Codex round 26).
            //
            // For each configured database connection, open a
            // pre-init connection and assert both `@@session` and
            // `@@global.wait_timeout <= 30`. Codex round 30 (HIGH):
            // per-connection results — one bad upstream sets its
            // entry in `db_connection_ready` to `false` (the affected
            // database scope will 503) but does NOT take the global
            // `ready` flag (and therefore EC2/CloudWatch/auth paths)
            // down. Empty `database_connections` is a no-op.
            if !self.config.database_connections.is_empty() {
                tracing::info!(
                    "Preflight: verifying @@session/@@global wait_timeout on {} database \
                     connection(s)...",
                    self.config.database_connections.len()
                );
                for (name, conn_cfg) in &self.config.database_connections {
                    if let Some(next) = self.db_connection_next_probe.get(name) {
                        if std::time::Instant::now() < *next {
                            tracing::debug!(
                                connection = %name,
                                "preflight: connection is in DB_REPROBE_COOLDOWN, skipping"
                            );
                            continue;
                        }
                    }
                    probe_single_db_connection_and_update(self, name, conn_cfg).await;
                }
            }

            self.ready.store(true, std::sync::atomic::Ordering::Release);
            return Ok(());
        }

        Err(anyhow::anyhow!(
            "Preflight failed after {} attempts: {}",
            max_attempts,
            last_err.unwrap_or_default()
        ))
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Re-run `preflight_session_safety` against every configured database
/// connection once and update `state.db_connection_ready`.
///
/// Codex round 31 (HIGH): the initial preflight in `run_preflight`
/// only ran once. A transient Secrets Manager or MySQL blip during
/// startup left `db_connection_ready[name] = false` until the process
/// was restarted, while `/health` reported OK — a partial outage
/// that was both invisible and unbounded. This helper is the
/// "one tick of the self-heal loop": call it periodically (see
/// `run_db_connection_reprobe_loop` below) so a previously-down
/// connection comes back online without operator action, and a newly-
/// regressed one flips off before too many queries 503.
///
/// Per-connection state transitions are logged at info/error so
/// operators can grep for them.
/// Cool-down applied to a database connection after a failed
/// preflight (Codex round 33 HIGH). Without this, the 60 s reprobe
/// loop would issue a fresh `Conn::new` against the misconfigured
/// upstream every cycle, and a Conn::new cancelled mid-handshake
/// leaks a session on the server side that lives until the role's
/// `wait_timeout` reaps it. 5 minutes is large enough that a
/// default 8 h `wait_timeout` upstream cannot accumulate more than
/// ~96 orphans per day, while still letting a healthy upstream
/// recover automatically within minutes once operators fix the
/// configuration. Choosing this in time (not in fail-count) avoids
/// the need to persist counters across restarts.
pub const DB_REPROBE_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(300);

/// Probe a single database connection (secret load → preflight) and
/// update `db_connection_ready` / `db_connection_next_probe`. Shared
/// by `run_preflight` (startup) and `reprobe_db_connections_once`
/// (60 s background loop) so the cool-down + classification logic is
/// a single-writer invariant (Codex round 34 HIGH).
///
/// Phase A — secret load — is bounded by `SECRET_LOAD_BUDGET` and
/// CANNOT touch MySQL, so its failure neither creates an orphan
/// session nor warrants a cool-down (Codex round 35 HIGH).
///
/// Phase B — `preflight_session_safety` — enforces its OWN internal
/// budgets (connect + probe + disconnect) so the outer caller does
/// NOT wrap it in `tokio::time::timeout`; an outer cancellation
/// could drop the future mid-cleanup, abandoning an authenticated
/// server-side session (Codex round 39 HIGH). Failures are
/// inspected via `database::is_ambiguous_acquire_failure`: only
/// connect/handshake/auth failures (which carry the
/// `DatabaseConnectionUnavailable` marker) set the cool-down,
/// because only those can leave an upstream session that needs the
/// role's `wait_timeout` to reap. Clean post-connect failures
/// (e.g. wait_timeout invariant violation with proven disconnect)
/// are retried on the normal 60 s cadence.
///
/// The caller is responsible for skipping when the connection is in
/// cool-down; this function unconditionally probes when called.
async fn probe_single_db_connection_and_update(
    state: &AppState,
    name: &str,
    conn_cfg: &crate::config::DatabaseConnectionConfig,
) {
    const SECRET_LOAD_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);
    let was_ready = state.db_connection_is_ready(name);

    let secret = match tokio::time::timeout(
        SECRET_LOAD_BUDGET,
        state
            .database_secret_provider
            .load_secret(&conn_cfg.secret_arn),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            state.db_connection_ready.insert(name.to_string(), false);
            if was_ready {
                tracing::error!(
                    connection = %name,
                    error = %e,
                    "DB preflight: secret load failed — connection marked not-ready; no cooldown (no upstream session at risk)"
                );
            } else {
                tracing::warn!(
                    connection = %name,
                    error = %e,
                    "DB preflight: secret load still failing"
                );
            }
            return;
        }
        Err(_) => {
            state.db_connection_ready.insert(name.to_string(), false);
            tracing::error!(
                connection = %name,
                budget_secs = SECRET_LOAD_BUDGET.as_secs(),
                "DB preflight: secret load timed out — no cooldown (no upstream session)"
            );
            return;
        }
    };

    // Codex round 39 (HIGH): no outer tokio::time::timeout here.
    // `preflight_session_safety` enforces internal budgets
    // (connect + probe + disconnect) and an outer cancellation
    // could drop the future mid-cleanup, abandoning an
    // authenticated server-side session and bypassing the
    // round-38 invariant that all post-connect errors must be
    // tagged ambiguous before reaching the caller.
    let result: Result<(), anyhow::Error> =
        database::preflight_session_safety(conn_cfg, &secret).await;
    match result {
        Ok(()) => {
            state.db_connection_ready.insert(name.to_string(), true);
            state.db_connection_next_probe.remove(name);
            if !was_ready {
                tracing::info!(
                    connection = %name,
                    "DB preflight recovered: connection now serving traffic"
                );
            } else {
                tracing::info!(
                    connection = %name,
                    "DB preflight: wait_timeout invariant OK"
                );
            }
        }
        Err(e) => {
            state.db_connection_ready.insert(name.to_string(), false);
            let ambiguous = database::is_ambiguous_acquire_failure(&e);
            if ambiguous {
                state.db_connection_next_probe.insert(
                    name.to_string(),
                    std::time::Instant::now() + DB_REPROBE_COOLDOWN,
                );
            }
            if was_ready {
                tracing::error!(
                    connection = %name,
                    error = %e,
                    cooldown_applied = ambiguous,
                    "DB preflight regressed: connection now in 503 state"
                );
            } else {
                tracing::warn!(
                    connection = %name,
                    error = %e,
                    cooldown_applied = ambiguous,
                    "DB preflight still failing"
                );
            }
        }
    }
}

pub async fn reprobe_db_connections_once(state: &AppState) {
    if state.config.database_connections.is_empty() {
        return;
    }
    for (name, conn_cfg) in &state.config.database_connections {
        // Codex round 33 (HIGH): cool-down check. If the previous
        // tick set a future probe time on this connection, skip it
        // — letting a possibly-orphaned upstream session age out
        // before we open a new one.
        if let Some(next) = state.db_connection_next_probe.get(name) {
            if std::time::Instant::now() < *next {
                tracing::debug!(
                    connection = %name,
                    remaining_ms = next.saturating_duration_since(std::time::Instant::now()).as_millis() as u64,
                    "skipping reprobe; connection is in DB_REPROBE_COOLDOWN"
                );
                continue;
            }
        }
        probe_single_db_connection_and_update(state, name, conn_cfg).await;
    }
}

/// Long-running task that keeps `db_connection_ready` self-healing.
/// Each tick re-runs `reprobe_db_connections_once`; the interval is
/// short enough that an upstream that comes back recovers within ~1
/// minute and long enough that we don't hammer Secrets Manager on
/// healthy steady state.
pub async fn run_db_connection_reprobe_loop(state: Arc<AppState>) {
    const REPROBE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
    if state.config.database_connections.is_empty() {
        return;
    }
    tracing::info!(
        connections = state.config.database_connections.len(),
        interval_secs = REPROBE_INTERVAL.as_secs(),
        "starting DB connection reprobe loop"
    );
    loop {
        tokio::time::sleep(REPROBE_INTERVAL).await;
        reprobe_db_connections_once(&state).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_token_roundtrip() {
        let auth = QueryAuthorization {
            user_id: "alice".into(),
            log_group_names: vec!["/app/web".into(), "/app/api".into()],
        };
        let token = sign_query_token("query-abc-123", &auth, "my-secret");
        let (id, decoded) = verify_query_token(&token, "my-secret").unwrap();
        assert_eq!(id, "query-abc-123");
        assert_eq!(decoded.user_id, "alice");
        assert_eq!(decoded.log_group_names, vec!["/app/web", "/app/api"]);
    }

    #[test]
    fn test_query_token_rejects_wrong_secret() {
        let auth = QueryAuthorization {
            user_id: "alice".into(),
            log_group_names: vec![],
        };
        let token = sign_query_token("q1", &auth, "secret-a");
        assert!(verify_query_token(&token, "secret-b").is_none());
    }

    #[test]
    fn test_query_token_rejects_tampered_payload() {
        let auth = QueryAuthorization {
            user_id: "alice".into(),
            log_group_names: vec!["/app/x".into()],
        };
        let token = sign_query_token("q1", &auth, "secret");
        // Tamper with the query ID portion (before first dot)
        let tampered = token.replacen("q1", "q2", 1);
        assert!(verify_query_token(&tampered, "secret").is_none());
    }

    #[test]
    fn test_query_token_rejects_malformed() {
        assert!(verify_query_token("", "secret").is_none());
        assert!(verify_query_token("no-dots-at-all", "secret").is_none());
        assert!(verify_query_token("one.two", "secret").is_none());
    }

    // ── Codex round 32 (HIGH): bound load_secret + preflight ─────────
    //
    // A hung `DatabaseSecretProvider::load_secret` must not stall
    // `reprobe_db_connections_once` past `PER_CONNECTION_BUDGET`.
    // This test stands up a minimal `AppState` with a mock provider
    // that simulates Secrets Manager hanging for an hour, fires the
    // reprobe, and asserts that the call returns within the
    // budget + a small fudge and that `db_connection_ready` was
    // updated to false (not left stale at its pre-call value).
    struct HangingSecretProvider;

    #[async_trait::async_trait]
    impl database::DatabaseSecretProvider for HangingSecretProvider {
        async fn load_secret(&self, _secret_arn: &str) -> anyhow::Result<database::DatabaseSecret> {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            unreachable!("HangingSecretProvider must be timed out by the per-connection budget")
        }
    }

    struct UnreachableExecutor;

    #[async_trait::async_trait]
    impl database::DatabaseExecutor for UnreachableExecutor {
        async fn explain(
            &self,
            _: &crate::config::DatabaseConnectionConfig,
            _: &database::DatabaseSecret,
            _: &str,
            _: u64,
        ) -> anyhow::Result<shared::dto::database::ExplainSummary> {
            unreachable!("UnreachableExecutor must not be called from reprobe path")
        }
        async fn query(
            &self,
            _: &crate::config::DatabaseConnectionConfig,
            _: &database::DatabaseSecret,
            _: &str,
            _: u64,
        ) -> anyhow::Result<database::QueryRows> {
            unreachable!()
        }
        async fn fetch_table_types(
            &self,
            _: &crate::config::DatabaseConnectionConfig,
            _: &database::DatabaseSecret,
            _: &[database::TableTypeQuery],
            _: u64,
        ) -> anyhow::Result<std::collections::HashMap<(String, String), database::TableType>>
        {
            unreachable!()
        }
        async fn query_with_view_check(
            &self,
            _: &crate::config::DatabaseConnectionConfig,
            _: &database::DatabaseSecret,
            _: &shared::dto::entitlements::DatabaseScope,
            _: &[database::TableTypeQuery],
            _: &str,
            _: u64,
            _: u64,
        ) -> anyhow::Result<database::ViewCheckedQueryOutcome> {
            unreachable!()
        }
    }

    /// Backward-compat wrapper — defaults to 3 s connect_timeout_ms
    /// (the original test fixture). Tests that need a specific
    /// connect-phase failure mode should call the `_ext` variant.
    fn minimal_appstate_with_one_db_connection(
        provider: Arc<dyn database::DatabaseSecretProvider>,
    ) -> AppState {
        minimal_appstate_with_one_db_connection_ext(provider, 3000)
    }

    /// Build a minimal AppState with one DB connection wired up.
    /// `connect_timeout_ms` controls the connect-phase failure mode:
    ///   - large value (e.g. 3000) → port=1 returns ECONNREFUSED
    ///     deterministically before timeout → preflight returns Err
    ///     without the `DatabaseConnectionUnavailable` marker
    ///     (Codex round 36: deterministic, no cool-down).
    ///   - tiny value (e.g. 1) → outer tokio timeout fires before
    ///     mysql_async resolves → preflight returns Err WITH the
    ///     marker (Codex round 35: ambiguous, set cool-down).
    fn minimal_appstate_with_one_db_connection_ext(
        provider: Arc<dyn database::DatabaseSecretProvider>,
        connect_timeout_ms: u64,
    ) -> AppState {
        let mut config = crate::config::AppConfig {
            bind_address: "127.0.0.1:0".into(),
            oidc: crate::config::OidcConfig {
                issuer_url: "https://placeholder.example.com".into(),
                client_id: "test".into(),
                client_secret: None,
                scopes: vec![],
                acr_values: vec![],
                prompt: None,
                max_age_seconds: None,
                required_acr_values: vec![],
                required_amr_values: vec![],
                authorization_endpoint: None,
                token_endpoint: None,
                device_authorization_endpoint: None,
                userinfo_endpoint: None,
                jwks_uri: None,
            },
            jwt: crate::config::JwtConfig {
                secret: "test-secret-at-least-32-chars-long-12345".into(),
                expiry_seconds: 3600,
            },
            aws: crate::config::AwsConfig {
                default_region: Some("us-east-1".into()),
                session_duration_seconds: Some(3600),
                sts_external_id: Some("test".into()),
            },
            database_connections: std::collections::HashMap::new(),
            dev_mode: true,
            mock_aws_data: None,
            entitlements_file: None,
            entitlements_database_url: None,
            mfa_database_url: None,
            mfa_secret_key: None,
            audit_log: None,
            audit_export: crate::config::AuditExportConfig::default(),
            cors_allowed_origins: vec![],
        };
        config.database_connections.insert(
            "orders_prod".into(),
            crate::config::DatabaseConnectionConfig {
                engine: crate::config::DatabaseEngine::Mysql,
                host: "127.0.0.1".into(),
                port: 1, // unreachable; doesn't matter — we never get past load_secret
                database: "orders".into(),
                secret_arn: "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:test".into(),
                readonly: true,
                connect_timeout_ms,
                statement_timeout_ms: 5000,
                explain_timeout_ms: 3000,
                max_connections: 4,
                require_tls: false,
                accept_invalid_tls_certs: true,
                skip_tls_hostname_verification: true,
            },
        );
        let base_aws_config = aws_config::SdkConfig::builder()
            .region(aws_types::region::Region::new("us-east-1"))
            .build();
        AppState {
            config,
            entitlement_store: Arc::new(RwLock::new(EntitlementStore::dev_defaults())),
            audit_service: audit::AuditService::new(),
            oidc_client: oidc::OidcClient::new(crate::config::OidcConfig {
                issuer_url: "https://placeholder.example.com".into(),
                client_id: "test".into(),
                client_secret: None,
                scopes: vec![],
                acr_values: vec![],
                prompt: None,
                max_age_seconds: None,
                required_acr_values: vec![],
                required_amr_values: vec![],
                authorization_endpoint: None,
                token_endpoint: None,
                device_authorization_endpoint: None,
                userinfo_endpoint: None,
                jwks_uri: None,
            }),
            mfa_store: crate::models::mfa::MfaStore::disabled(),
            step_up_sessions: step_up::StepUpSessionStore::default(),
            base_aws_config,
            database_secret_provider: provider,
            database_executor: Arc::new(UnreachableExecutor),
            mcp_sessions: DashMap::new(),
            ready: std::sync::atomic::AtomicBool::new(false),
            db_connection_ready: DashMap::new(),
            db_connection_next_probe: DashMap::new(),
        }
    }

    /// Codex round 35 (HIGH): secret-provider failures must NOT
    /// trigger the orphan-protection cooldown. Those failures
    /// happen before MySQL is touched, so there is no upstream
    /// session at risk and a 5-minute cool-down would needlessly
    /// extend the outage. Failing-secret tick must mark the
    /// connection not-ready but leave `db_connection_next_probe`
    /// empty, so the very next tick retries.
    #[tokio::test]
    async fn reprobe_secret_failure_does_not_set_cooldown() {
        struct AlwaysFailingProvider;
        #[async_trait::async_trait]
        impl database::DatabaseSecretProvider for AlwaysFailingProvider {
            async fn load_secret(&self, _arn: &str) -> anyhow::Result<database::DatabaseSecret> {
                Err(anyhow::anyhow!("secrets manager 5xx"))
            }
        }
        let state = minimal_appstate_with_one_db_connection(Arc::new(AlwaysFailingProvider));
        reprobe_db_connections_once(&state).await;
        assert!(
            !state.db_connection_is_ready("orders_prod"),
            "secret failure should mark connection not-ready"
        );
        assert!(
            !state.db_connection_next_probe.contains_key("orders_prod"),
            "secret-only failure must NOT set cooldown — no upstream session to protect"
        );
    }

    /// Codex round 37 + 38 (HIGH): the `is_pre_session_mysql_error`
    /// classifier is an allowlist. Only the known-safe variants
    /// (auth fail, connection refused, etc.) return true; every
    /// other mysql_async error — including Driver / TLS / Io with
    /// an unknown ErrorKind / Other — must default to "ambiguous"
    /// so post-connect failures during the probe are still treated
    /// as orphan-risk and trigger the cool-down.
    #[test]
    fn classifier_connection_refused_is_pre_session() {
        let io = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "no listener");
        let err = mysql_async::Error::Io(mysql_async::IoError::Io(io));
        assert!(
            database::is_pre_session_mysql_error(&err),
            "ECONNREFUSED never produces an authenticated session"
        );
    }

    #[test]
    fn classifier_timed_out_io_is_ambiguous() {
        let io = std::io::Error::new(std::io::ErrorKind::TimedOut, "stalled");
        let err = mysql_async::Error::Io(mysql_async::IoError::Io(io));
        assert!(
            !database::is_pre_session_mysql_error(&err),
            "an IO TimedOut after the TCP layer started talking could have allocated a session — must stay ambiguous"
        );
    }

    #[test]
    fn classifier_other_variant_is_ambiguous() {
        let inner: Box<dyn std::error::Error + Send + Sync + 'static> =
            Box::new(std::io::Error::other("uncategorized"));
        let err = mysql_async::Error::Other(inner);
        assert!(
            !database::is_pre_session_mysql_error(&err),
            "Other variant must default to ambiguous so unclassified mysql_async errors don't bypass cool-down"
        );
    }

    #[test]
    fn classifier_server_access_denied_is_pre_session() {
        let server_err = mysql_async::ServerError {
            code: 1045,
            message: "Access denied".into(),
            state: "28000".into(),
        };
        let err = mysql_async::Error::Server(server_err);
        assert!(
            database::is_pre_session_mysql_error(&err),
            "ER_ACCESS_DENIED_ERROR is resolved during auth before the server allocates a session"
        );
    }

    /// Codex round 41 (HIGH): a capacity error during preflight must
    /// be tagged with BOTH `DatabaseConnectionUnavailable` (so the
    /// route still 503s) AND `DatabaseOverloadRetryable` (so the
    /// reprobe cool-down does NOT fire — there is no orphan
    /// session, only an upstream capacity refusal). Verifies via
    /// `is_ambiguous_acquire_failure`.
    #[test]
    fn classifier_capacity_error_is_overload_retryable_not_ambiguous() {
        let server_err = mysql_async::ServerError {
            // ER_CON_COUNT_ERROR — MySQL max_connections exhausted.
            code: 1040,
            message: "Too many connections".into(),
            state: "08004".into(),
        };
        let inner = mysql_async::Error::Server(server_err);
        // Reconstruct the chain `preflight_session_safety` and
        // `acquire_conn_or_classify_overload` produce: the
        // mysql_async error is at the root with the
        // `DatabaseConnectionUnavailable` marker on top.
        let with_markers =
            anyhow::Error::new(inner).context(database::DatabaseConnectionUnavailable);
        assert!(
            !database::is_ambiguous_acquire_failure(&with_markers),
            "capacity errors must NOT be treated as ambiguous (they would otherwise burn 60s permit holds and 5min reprobe cool-downs)"
        );
    }

    #[test]
    fn classifier_non_capacity_unavailable_is_ambiguous() {
        // Sanity: a generic acquire timeout (no underlying
        // mysql_async error) carrying only the
        // `DatabaseConnectionUnavailable` marker still classifies
        // as ambiguous → cool-down. Without this we could regress
        // is_ambiguous_acquire_failure to false for all errors.
        let err = anyhow::Error::new(database::DatabaseConnectionUnavailable)
            .context("acquire timed out");
        assert!(
            database::is_ambiguous_acquire_failure(&err),
            "a non-capacity DatabaseConnectionUnavailable failure must remain ambiguous"
        );
    }

    #[test]
    fn classifier_server_unknown_code_is_ambiguous() {
        // A server error code we have not explicitly allow-listed must
        // default to ambiguous so a post-auth server-side failure
        // does not bypass the cool-down.
        let server_err = mysql_async::ServerError {
            code: 9999,
            message: "some uncategorized server-side failure".into(),
            state: "HY000".into(),
        };
        let err = mysql_async::Error::Server(server_err);
        assert!(
            !database::is_pre_session_mysql_error(&err),
            "unknown server error code must default to ambiguous (allowlist, not denylist)"
        );
    }

    /// Codex round 36 (HIGH): mysql_async resolving Conn::new with a
    /// deterministic error (wrong credentials, unknown DB, TLS
    /// reject, ECONNREFUSED) must NOT set the orphan cool-down —
    /// no upstream session was created, and a 5-minute lock-out
    /// would extend the outage after an operator fixes the config.
    /// We simulate ECONNREFUSED by connecting to port=1 with a
    /// realistic connect_timeout (3 s) so the failure resolves
    /// before our outer timeout would fire.
    #[tokio::test]
    async fn reprobe_deterministic_connect_failure_does_not_set_cooldown() {
        struct ValidProvider;
        #[async_trait::async_trait]
        impl database::DatabaseSecretProvider for ValidProvider {
            async fn load_secret(&self, _arn: &str) -> anyhow::Result<database::DatabaseSecret> {
                Ok(database::DatabaseSecret {
                    username: "noop".into(),
                    password: "noop".into(),
                })
            }
        }
        let state = minimal_appstate_with_one_db_connection_ext(Arc::new(ValidProvider), 3000);

        reprobe_db_connections_once(&state).await;
        assert!(
            !state.db_connection_is_ready("orders_prod"),
            "deterministic connect failure should mark connection not-ready"
        );
        assert!(
            !state.db_connection_next_probe.contains_key("orders_prod"),
            "deterministic connect failure (ECONNREFUSED) must NOT set cool-down — \
             no upstream session was allocated"
        );
    }

    /// Codex round 33 (HIGH): after a failed reprobe, the cool-down
    /// must skip the next tick(s) so a `Conn::new` cancelled mid-
    /// handshake doesn't leak an upstream session every cycle.
    /// Second invocation immediately after a failed first one must
    /// not call the secret provider (i.e. not produce another
    /// would-be orphan).
    #[tokio::test]
    async fn reprobe_failure_sets_cooldown_and_skips_subsequent_tick() {
        // A valid-but-useless secret pushes the failure into phase B
        // (Conn::new against port=1 in the test fixture fails with
        // a connect error). That carries the
        // `DatabaseConnectionUnavailable` marker and is exactly the
        // ambiguous case round-33 cool-down targets. Counting
        // load_secret calls lets us assert the second tick is
        // skipped by the cool-down rather than by some other path.
        struct CountingProvider {
            call_count: std::sync::atomic::AtomicUsize,
        }
        #[async_trait::async_trait]
        impl database::DatabaseSecretProvider for CountingProvider {
            async fn load_secret(&self, _arn: &str) -> anyhow::Result<database::DatabaseSecret> {
                self.call_count
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(database::DatabaseSecret {
                    username: "noop".into(),
                    password: "noop".into(),
                })
            }
        }
        let provider = Arc::new(CountingProvider {
            call_count: std::sync::atomic::AtomicUsize::new(0),
        });
        // We want the outer tokio timeout to fire while mysql_async
        // is still waiting on the TCP handshake — the ambiguous
        // case the round-33 cool-down targets. Pointing the
        // connection at an unroutable address (10.255.255.255 is
        // reserved/unreachable on virtually every network so the
        // TCP stack hangs in SYN_SENT) with a 100 ms timeout makes
        // that race deterministic in unit tests. A reachable but
        // non-listening port instead returns ECONNREFUSED almost
        // instantly, which is the round-36 deterministic case
        // covered by a separate test.
        let mut state = minimal_appstate_with_one_db_connection_ext(provider.clone(), 100);
        {
            let cfg = state
                .config
                .database_connections
                .get_mut("orders_prod")
                .expect("seeded connection");
            cfg.host = "10.255.255.255".into();
            cfg.port = 9999;
        }
        let state = state; // freeze

        // First reprobe: outer timeout fires → ambiguous → cool-down.
        reprobe_db_connections_once(&state).await;
        assert!(
            !state.db_connection_is_ready("orders_prod"),
            "first reprobe should mark connection not ready"
        );
        assert_eq!(
            provider
                .call_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "first reprobe should have called load_secret exactly once"
        );
        assert!(
            state.db_connection_next_probe.contains_key("orders_prod"),
            "first reprobe must have set the cool-down entry (ambiguous connect failure)"
        );

        // Second reprobe immediately after: cool-down must skip the
        // provider entirely. If this fails, the reprobe loop is
        // hammering the upstream — defeating the round-33 fix.
        reprobe_db_connections_once(&state).await;
        assert_eq!(
            provider
                .call_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "subsequent reprobe within DB_REPROBE_COOLDOWN must NOT call the provider"
        );
    }

    #[tokio::test]
    async fn reprobe_bounds_total_unit_when_secret_load_hangs() {
        let state = minimal_appstate_with_one_db_connection(Arc::new(HangingSecretProvider));
        // Pre-seed the connection as true so we can also detect that
        // the timeout transition to false is observable.
        state.db_connection_ready.insert("orders_prod".into(), true);

        let started = std::time::Instant::now();
        // After round 35 the secret load is bounded by 10 s
        // separately from the preflight (15 s). A hanging secret
        // provider should be cut off at the 10 s mark — well under
        // the 25 s outer test bound. If load_secret could escape
        // the timeout (the round-32 bug), the outer timeout would
        // fire instead.
        tokio::time::timeout(
            std::time::Duration::from_secs(25),
            reprobe_db_connections_once(&state),
        )
        .await
        .expect(
            "reprobe must return within 25s even when load_secret hangs; \
             otherwise a degraded Secrets Manager could stall the self-heal loop",
        );
        let elapsed = started.elapsed();

        // Sanity: must have actually waited for the secret-load budget
        // (i.e. not returned in milliseconds before any timeout
        // fired). 9-15 s is the legitimate window: 9 s lower bound
        // because SECRET_LOAD_BUDGET = 10 s minus a small fudge,
        // 15 s upper bound because no other phase would have run.
        assert!(
            elapsed >= std::time::Duration::from_secs(9),
            "reprobe returned too quickly ({:?}); did it not actually call load_secret?",
            elapsed
        );
        // The state transition: a previously-healthy entry must flip
        // to false when its secret load times out.
        assert!(
            !state.db_connection_is_ready("orders_prod"),
            "after a timed-out reprobe, the connection must be marked not-ready"
        );
        // Codex round 35 (HIGH): a secret-load timeout does NOT
        // touch MySQL, so it must NOT set the cool-down.
        assert!(
            !state.db_connection_next_probe.contains_key("orders_prod"),
            "secret-load timeout must NOT set cooldown (no upstream session at risk)"
        );
    }
}
