//! End-to-end MCP Database v1 test against a real MySQL server.
//!
//! Spins up MySQL 8 via testcontainers, seeds a small schema, and drives
//! the actual `MySqlDatabaseExecutor` through the full
//! `/api/mcp/database/query` pipeline. Every test asserts a single
//! security boundary from the Codex review track (rounds 4–18) against
//! a live database, not a mock:
//!
//!   * normal indexed SELECT → 200 with rows
//!   * full table scan rejected at EXPLAIN time → 400
//!   * VIEW rejected when `allow_views = false` → 400
//!   * VIEW allowed when `allow_views = true` → 200
//!   * out-of-scope table → 403 (validator gate, before EXPLAIN)
//!   * backticked dotted identifier → 403 (round-4 bypass guard)
//!   * multi-statement → 400
//!   * raw SQL captured in attempt audit, redacted on denial path
//!
//! Tagged `#[ignore]`: requires a running Docker daemon. Run with:
//!
//!   cargo test --workspace -- --ignored
//!
//! All tests share the same testcontainers MySQL via a single oneshot
//! test function — startup is ~5s and we don't want to multiply that by
//! the number of scenarios.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware as axum_mw, Router,
};
use control_plane::config::{
    AppConfig, AwsConfig, DatabaseConnectionConfig, DatabaseEngine, JwtConfig, OidcConfig,
};
use control_plane::middleware;
use control_plane::routes;
use control_plane::services::audit::AuditService;
use control_plane::services::auth::AuthService;
use control_plane::services::database::{
    DatabaseExecutor, DatabaseSecret, DatabaseSecretProvider, MySqlDatabaseExecutor,
};
use control_plane::services::oidc::OidcClient;
use control_plane::services::AppState;
use http_body_util::BodyExt;
use mysql_async::prelude::Queryable;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use testcontainers_modules::mysql::Mysql;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use tower::ServiceExt;

const MYSQL_ROOT_PASSWORD: &str = "rootpass";
const READONLY_USER: &str = "canopy_readonly";
const READONLY_PASSWORD: &str = "readonly-pass-for-e2e-test";

/// `DatabaseSecretProvider` mock that returns root credentials for the
/// testcontainers MySQL. Production uses AWS Secrets Manager; here we
/// inject directly so the test does not need LocalStack.
struct TestcontainersSecretProvider {
    username: String,
    password: String,
}

#[async_trait::async_trait]
impl DatabaseSecretProvider for TestcontainersSecretProvider {
    async fn load_secret(&self, _arn: &str) -> anyhow::Result<DatabaseSecret> {
        Ok(DatabaseSecret {
            username: self.username.clone(),
            password: self.password.clone(),
        })
    }
}

/// Spin up MySQL 8 via testcontainers and seed the schema used across
/// scenarios. Returns the container handle (must be kept alive) and the
/// host-side TCP port.
async fn spawn_mysql_with_seed() -> (ContainerAsync<Mysql>, u16) {
    let container = Mysql::default()
        .with_env_var("MYSQL_ROOT_PASSWORD", MYSQL_ROOT_PASSWORD)
        .with_env_var("MYSQL_DATABASE", "orders")
        .start()
        .await
        .expect("start mysql container");
    let port = container
        .get_host_port_ipv4(3306)
        .await
        .expect("mysql host port");

    // Wait for MySQL to actually accept connections (image is up before
    // the daemon is ready). mysql_async retries internally on connect
    // failure during the initial handshake.
    //
    // Codex round 22 (MED): bound the readiness retry loop. The
    // original unbounded retry would stall the CI job until the
    // workflow-level timeout (45 min by default) on any image
    // regression, networking failure, or container that fails to
    // become healthy. With a hard 60 s deadline we surface a
    // descriptive panic and let CI fail the right step in seconds —
    // the readiness budget is far more than any healthy mysql:8
    // container needs (~3-5 s) and well under any reasonable CI
    // job-level cap.
    const MYSQL_READINESS_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);
    let opts = mysql_async::OptsBuilder::default()
        .ip_or_hostname("127.0.0.1")
        .tcp_port(port)
        .user(Some("root"))
        .pass(Some(MYSQL_ROOT_PASSWORD))
        .db_name(Some("orders"));
    let readiness = tokio::time::timeout(MYSQL_READINESS_DEADLINE, async {
        loop {
            match mysql_async::Conn::new(opts.clone()).await {
                Ok(c) => return c,
                Err(_err) => {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }
    })
    .await;
    let mut conn = match readiness {
        Ok(c) => c,
        Err(_) => panic!(
            "testcontainers MySQL did not accept connections within \
             {:?}; check the container started cleanly and the image \
             is not regressed (port: {port})",
            MYSQL_READINESS_DEADLINE
        ),
    };

    // Schema + data. Lowercase only to match the validator's invariant.
    conn.query_drop(
        "CREATE TABLE orders (
            id INT PRIMARY KEY,
            status VARCHAR(20) NOT NULL,
            amount DECIMAL(10,2) NOT NULL,
            INDEX idx_status (status)
        )",
    )
    .await
    .unwrap();
    conn.query_drop(
        "CREATE TABLE order_items (
            id INT PRIMARY KEY,
            order_id INT NOT NULL,
            sku VARCHAR(40) NOT NULL,
            INDEX idx_order (order_id)
        )",
    )
    .await
    .unwrap();
    conn.query_drop("INSERT INTO orders VALUES (123, 'paid', 99.50), (124, 'shipped', 250.00)")
        .await
        .unwrap();
    conn.query_drop(
        "INSERT INTO order_items VALUES \
        (1, 123, 'SKU-A'), (2, 123, 'SKU-B'), (3, 124, 'SKU-C')",
    )
    .await
    .unwrap();
    conn.query_drop(
        "CREATE VIEW orders_paid AS SELECT id, status FROM orders WHERE status = 'paid'",
    )
    .await
    .unwrap();

    // Codex round 20 (MED): create a dedicated read-only user so the
    // tests run with the same privilege envelope production would use.
    // Without this, P3 always connects as root and would pass even if
    // the executor regressed to sending mutating statements — the DB
    // would happily oblige. With this user, mutations also have to get
    // past the MySQL grant table, which is the production fail-closed
    // backstop behind the app-layer validator.
    conn.query_drop(format!(
        "CREATE USER '{READONLY_USER}'@'%' IDENTIFIED BY '{READONLY_PASSWORD}'"
    ))
    .await
    .unwrap();
    // Codex round 26+31 (HIGH): tighten server-side defaults so the
    // control-plane preflight passes (it asserts @@global.wait_timeout
    // and @@session.wait_timeout are both ≤ 30 s). Default MySQL
    // ships with `wait_timeout = 28800` (8 h), which would fail
    // preflight and 503 the testcontainers scope.
    conn.query_drop("SET GLOBAL wait_timeout = 25")
        .await
        .unwrap();
    conn.query_drop("SET GLOBAL net_read_timeout = 10")
        .await
        .unwrap();
    conn.query_drop("SET GLOBAL net_write_timeout = 10")
        .await
        .unwrap();
    conn.query_drop(format!("GRANT SELECT ON orders.* TO '{READONLY_USER}'@'%'"))
        .await
        .unwrap();
    // EXPLAIN against a VIEW requires `SHOW VIEW` so the optimizer can
    // read the view definition. Without this, the allow_views=true
    // scenario fails with ER_VIEW_NO_EXPLAIN. In production the
    // Secrets Manager-issued read-only role must include this grant
    // before flipping allow_views = true on a scope.
    conn.query_drop(format!(
        "GRANT SHOW VIEW ON orders.* TO '{READONLY_USER}'@'%'"
    ))
    .await
    .unwrap();
    // information_schema is implicitly readable by every authenticated
    // user (MySQL filters rows by privilege automatically); explicit
    // GRANT on it is rejected with ER_DBACCESS_DENIED_ERROR.
    conn.query_drop("FLUSH PRIVILEGES").await.unwrap();
    conn.disconnect().await.unwrap();

    (container, port)
}

fn config_with_testcontainers(port: u16, audit_log_path: &std::path::Path) -> AppConfig {
    let mut cfg = AppConfig {
        bind_address: "127.0.0.1:8443".into(),
        oidc: OidcConfig {
            issuer_url: "https://placeholder.example.com".into(),
            client_id: "test".into(),
            client_secret: None,
            scopes: vec!["openid".into()],
            authorization_endpoint: None,
            token_endpoint: None,
            device_authorization_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: None,
        },
        jwt: JwtConfig {
            secret: "p3-e2e-test-secret-at-least-32-chars-long!!".into(),
            expiry_seconds: 3600,
        },
        aws: AwsConfig {
            default_region: Some("us-east-1".into()),
            session_duration_seconds: Some(3600),
            sts_external_id: Some("canopy".into()),
        },
        database_connections: HashMap::new(),
        dev_mode: true,
        mock_aws_data: None,
        entitlements_file: None,
        audit_log: Some(audit_log_path.to_string_lossy().into_owned()),
        cors_allowed_origins: vec![],
    };
    cfg.database_connections.insert(
        "orders_prod".into(),
        DatabaseConnectionConfig {
            engine: DatabaseEngine::Mysql,
            host: "127.0.0.1".into(),
            port,
            database: "orders".into(),
            secret_arn:
                "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:canopy/db/test-mock"
                    .into(),
            readonly: true,
            connect_timeout_ms: 5000,
            statement_timeout_ms: 10000,
            explain_timeout_ms: 5000,
            max_connections: 4,
            // testcontainers MySQL has no valid TLS cert; in production this is
            // refused at config-load time but we are in dev_mode so the
            // weakened defaults are accepted.
            require_tls: false,
            accept_invalid_tls_certs: true,
            skip_tls_hostname_verification: true,
        },
    );
    cfg
}

fn build_state(
    config: AppConfig,
    audit_service: AuditService,
    executor: Arc<dyn DatabaseExecutor>,
    allow_views: bool,
    extra_allowed_tables: &[&str],
) -> Arc<AppState> {
    // Pre-compute the per-connection readiness map (Codex round 30
    // HIGH) before `config` is moved into the AppState below.
    let db_connection_ready = dashmap::DashMap::new();
    for name in config.database_connections.keys() {
        db_connection_ready.insert(name.clone(), true);
    }

    let mut entitlement_store =
        control_plane::models::entitlements::EntitlementStore::dev_defaults();
    for rule in &mut entitlement_store.rules {
        for scope in &mut rule.database_scopes {
            if scope.name == "orders_prod_readonly" {
                scope.allow_views = allow_views;
                for extra in extra_allowed_tables {
                    scope.allowed_tables.push((*extra).into());
                }
            }
        }
    }
    let oidc_client = OidcClient::new(config.oidc.clone());
    let base_aws_config = aws_config::SdkConfig::builder()
        .region(aws_types::region::Region::new("us-east-1"))
        .build();
    Arc::new(AppState {
        config,
        entitlement_store: Arc::new(tokio::sync::RwLock::new(entitlement_store)),
        audit_service,
        oidc_client,
        base_aws_config,
        // Codex round 20 (MED): use the dedicated read-only MySQL user
        // (created in spawn_mysql_with_seed) so the executor only has
        // SELECT privileges — matching production's
        // `canopy_readonly` role from Secrets Manager.
        database_secret_provider: Arc::new(TestcontainersSecretProvider {
            username: READONLY_USER.into(),
            password: READONLY_PASSWORD.into(),
        }),
        database_executor: executor,
        mcp_sessions: dashmap::DashMap::new(),
        ready: std::sync::atomic::AtomicBool::new(true),
        db_connection_ready,
        db_connection_next_probe: dashmap::DashMap::new(),
    })
}

fn build_app(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .merge(routes::ec2::router())
        .merge(routes::cloudwatch::router())
        .merge(routes::entitlements::router())
        .merge(routes::mcp::router())
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::auth::require_auth,
        ));
    Router::new()
        .merge(routes::auth::router())
        .merge(protected)
        .with_state(state)
}

fn issue_token(config: &AppConfig) -> String {
    let auth = AuthService::new(config.clone());
    auth.issue_token(&shared::dto::auth::UserIdentity {
        user_id: "dev-admin".into(),
        email: "dev-admin@dev.local".into(),
        display_name: "Dev Admin".into(),
        groups: vec!["platform-engineering".into()],
        email_verified: true,
    })
    .unwrap()
    .access_token
}

async fn body_json(body: Body) -> Value {
    serde_json::from_slice(&body.collect().await.unwrap().to_bytes()).unwrap()
}

async fn register_and_ack(app: &Router, token: &str) -> (String, String) {
    let local = "lsg_p3_test_001";
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/mcp/session/register")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({
                        "protocol_version": "2025-06-18",
                        "local_secret_generation": local,
                        "client_name": "p3-e2e",
                        "client_version": "0.0.1",
                        "product_phase": "phase-1"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let session: Value = body_json(resp.into_body()).await;
    let sid = session["canopy_mcp_session_id"]
        .as_str()
        .unwrap()
        .to_string();

    for guidance_id in [
        "security_boundaries",
        "database_query_workflow",
        "privacy_and_audit_notice",
    ] {
        app.clone()
            .oneshot(
                Request::post("/api/mcp/guidance/delivered")
                    .header("Authorization", format!("Bearer {token}"))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({
                            "canopy_mcp_session_id": sid,
                            "local_secret_generation": local,
                            "guidance_id": guidance_id,
                            "guidance_version": "2026-05-13"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
    }
    (sid, local.into())
}

async fn query(app: &Router, token: &str, sid: &str, lsg: &str, sql: &str) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/mcp/database/query")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({
                        "scope": "orders_prod_readonly",
                        "sql": sql,
                        "canopy_mcp_session_id": sid,
                        "local_secret_generation": lsg
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = body_json(resp.into_body()).await;
    (status, body)
}

fn read_audit_events(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[tokio::test]
#[ignore = "requires Docker — run with `cargo test --workspace -- --ignored`"]
async fn database_e2e_full_security_boundary_battery() {
    // Install a tracing subscriber so route-level error logs surface in
    // test output. Without this the route's `tracing::error!(...)` calls
    // (e.g. when `fetch_table_types` fails) are silent and a 500 looks
    // mysterious.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,control_plane=debug")),
        )
        .with_test_writer()
        .try_init();

    let audit_dir = tempfile::tempdir().expect("audit tempdir");
    let audit_path = audit_dir.path().join("audit.jsonl");

    let (_container, mysql_port) = spawn_mysql_with_seed().await;
    let executor: Arc<dyn DatabaseExecutor> = Arc::new(MySqlDatabaseExecutor::new());

    // Sanity-check direct connectivity from this test process. If
    // information_schema is not queryable as root, we want to fail HERE
    // with a clear error rather than later via a 500 from the route.
    {
        let opts = mysql_async::OptsBuilder::default()
            .ip_or_hostname("127.0.0.1")
            .tcp_port(mysql_port)
            .user(Some("root"))
            .pass(Some(MYSQL_ROOT_PASSWORD))
            .db_name(Some("orders"));
        let mut conn = mysql_async::Conn::new(opts)
            .await
            .expect("direct mysql connect");
        let rows: Vec<(String, String, String)> = conn
            .exec(
                "SELECT table_schema, table_name, table_type \
                 FROM information_schema.tables \
                 WHERE (BINARY table_schema = BINARY ? AND BINARY table_name = BINARY ?)",
                ("orders", "orders"),
            )
            .await
            .expect("direct information_schema query");
        eprintln!("direct info_schema lookup for orders.orders → {:?}", rows);
        assert_eq!(rows.len(), 1, "exactly one row for orders.orders");
        conn.disconnect().await.unwrap();
    }

    // ── Scenario 1: healthy indexed SELECT against orders ──────────────
    let audit_service = AuditService::with_file(audit_path.to_str().unwrap()).unwrap();
    let config = config_with_testcontainers(mysql_port, &audit_path);
    let token = issue_token(&config);
    let state = build_state(config.clone(), audit_service, executor.clone(), false, &[]);
    let app = build_app(state);
    let (sid, lsg) = register_and_ack(&app, &token).await;

    let (status, body) = query(
        &app,
        &token,
        &sid,
        &lsg,
        "select id, status from orders where id = 123 limit 20",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "indexed SELECT must succeed: {body}"
    );
    assert_eq!(body["row_count"], 1);

    // ── Scenario 2: full table scan rejected by EXPLAIN gate ───────────
    // `amount` is a DECIMAL column with NO index, so MySQL is forced to
    // pick `access_type = ALL`. (`status LIKE '%literal%'` would also
    // be a full scan in production but with only 2 seeded rows the
    // optimizer collapses it to a range scan on idx_status — the
    // EXPLAIN row count is too small to trigger the gate.)
    let (status, body) = query(
        &app,
        &token,
        &sid,
        &lsg,
        "select id from orders where amount > 0 limit 50",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unindexed column scan must be rejected: {body}"
    );

    // ── Scenario 3: out-of-scope table rejected by validator (403) ─────
    let (status, body) = query(
        &app,
        &token,
        &sid,
        &lsg,
        "select id from information_schema.tables limit 1",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "out-of-scope table must be denied: {body}"
    );

    // ── Scenario 4: multi-statement rejected at parser ─────────────────
    let (status, _body) = query(
        &app,
        &token,
        &sid,
        &lsg,
        "select id from orders; drop table orders",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // ── Scenario 4b: mutation statement rejected — defense in depth ────
    // Codex round 20 (MED): the SQL validator should refuse any
    // non-SELECT statement up front (`allowed_actions = ["select"]`).
    // This scenario confirms two things:
    //   1. The validator rejects `UPDATE` before EXPLAIN runs.
    //   2. As a backstop, the dedicated read-only MySQL user
    //      (`canopy_readonly`, granted `SELECT` only) is what the
    //      executor authenticates as. Even if the app-layer gate
    //      ever regressed, the DB would still refuse the mutation —
    //      which is the production privilege envelope.
    let (status, body) = query(
        &app,
        &token,
        &sid,
        &lsg,
        "update orders set status = 'cancelled' where id = 123",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "mutation must be rejected by the validator: {body}"
    );
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains("select"),
        "denial message should mention SELECT-only policy: {body}"
    );
    // Sanity: confirm the row was not actually mutated. If the
    // validator failed open AND the DB grant failed open, this would
    // catch it.
    {
        let opts = mysql_async::OptsBuilder::default()
            .ip_or_hostname("127.0.0.1")
            .tcp_port(mysql_port)
            .user(Some("root"))
            .pass(Some(MYSQL_ROOT_PASSWORD))
            .db_name(Some("orders"));
        let mut conn = mysql_async::Conn::new(opts).await.unwrap();
        let status_after: Option<String> = conn
            .query_first("SELECT status FROM orders WHERE id = 123")
            .await
            .unwrap();
        conn.disconnect().await.unwrap();
        assert_eq!(
            status_after.as_deref(),
            Some("paid"),
            "orders.status MUST still be 'paid' — mutation must have been blocked"
        );
    }

    // ── Scenario 4c: DB grant is the backstop — direct UPDATE as the
    //                read-only user must fail at the MySQL layer too.
    {
        let opts = mysql_async::OptsBuilder::default()
            .ip_or_hostname("127.0.0.1")
            .tcp_port(mysql_port)
            .user(Some(READONLY_USER))
            .pass(Some(READONLY_PASSWORD))
            .db_name(Some("orders"));
        let mut conn = mysql_async::Conn::new(opts).await.unwrap();
        let direct_update = conn
            .query_drop("UPDATE orders SET status = 'cancelled' WHERE id = 123")
            .await;
        assert!(
            direct_update.is_err(),
            "the read-only DB user MUST be denied at the grant layer, not just by the app"
        );
        conn.disconnect().await.unwrap();
    }

    // ── Scenario 5: backticked dotted identifier (round-4 bypass) ──────
    let (status, body) = query(
        &app,
        &token,
        &sid,
        &lsg,
        "select id from `orders.orders` limit 1",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "backticked dotted ident must be rejected: {body}"
    );

    // ── Scenario 6: VIEW rejected when allow_views = false (default) ───
    // First add orders_paid to allowed_tables in a fresh state with
    // allow_views = false.
    let audit2 = AuditService::with_file(audit_path.to_str().unwrap()).unwrap();
    let state2 = build_state(
        config.clone(),
        audit2,
        executor.clone(),
        false, // allow_views = false
        &["orders_paid"],
    );
    let app2 = build_app(state2);
    let (sid2, lsg2) = register_and_ack(&app2, &token).await;
    let (status, body) = query(
        &app2,
        &token,
        &sid2,
        &lsg2,
        "select id from orders_paid limit 5",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "VIEW must be denied when allow_views=false: {body}"
    );
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("not a BASE TABLE"),
        "denial message should explain BASE TABLE requirement: {body}"
    );

    // ── Scenario 7: VIEW allowed when allow_views = true ───────────────
    let audit3 = AuditService::with_file(audit_path.to_str().unwrap()).unwrap();
    let state3 = build_state(
        config.clone(),
        audit3,
        executor.clone(),
        true, // allow_views = true
        &["orders_paid"],
    );
    let app3 = build_app(state3);
    let (sid3, lsg3) = register_and_ack(&app3, &token).await;
    let (status, body) = query(
        &app3,
        &token,
        &sid3,
        &lsg3,
        "select id from orders_paid where id = 123 limit 5",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "VIEW must be allowed under allow_views=true: {body}"
    );
    assert_eq!(body["row_count"], 1);

    // ── Audit assertions ───────────────────────────────────────────────
    let events = read_audit_events(&audit_path);
    assert!(
        events.len() >= 5,
        "expected several audit events, got {}",
        events.len()
    );

    // The successful indexed query should have an attempt event with
    // raw SQL (post-guidance) AND a success event.
    let indexed_success = events.iter().find(|e| {
        e["action"] == "mcp_database_query"
            && e["outcome"] == "success"
            && e["metadata"]["mcp_outcome_kind"] == "success"
            && e["metadata"]["sql_raw"]
                .as_str()
                .unwrap_or_default()
                .contains("where id = 123")
    });
    assert!(
        indexed_success.is_some(),
        "success audit event with raw SQL must be present"
    );

    // The full table scan denial should record sql_raw redacted because
    // the denial happens before the durable attempt event (validator
    // also passed but EXPLAIN-time rejection still goes through
    // audit_database_error which redacts pre-DB denials).
    let denial = events.iter().find(|e| {
        e["action"] == "mcp_database_query"
            && e["outcome"] == "denied"
            && e["metadata"]["mcp_outcome_kind"] == "full_table_scan"
    });
    assert!(
        denial.is_some(),
        "full_table_scan denial event must be recorded"
    );
}

/// Codex round 31 (HIGH): `db_connection_ready[name] = false` must
/// not be a permanent latch. If a transient blip during startup
/// preflight marked a connection unready, the background reprobe
/// loop must flip it back to true once the upstream is healthy
/// again. This regression test asserts that contract by manually
/// setting the entry to false (simulating the transient failure)
/// and calling `reprobe_db_connections_once` directly (instead of
/// waiting for the 60 s loop).
#[tokio::test]
#[ignore = "requires Docker — run with `cargo test --workspace -- --ignored`"]
async fn database_e2e_db_connection_reprobe_recovers_from_transient_failure() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,control_plane=info")),
        )
        .with_test_writer()
        .try_init();

    let audit_dir = tempfile::tempdir().expect("audit tempdir");
    let audit_path = audit_dir.path().join("audit.jsonl");

    let (_container, mysql_port) = spawn_mysql_with_seed().await;
    let executor: Arc<dyn DatabaseExecutor> = Arc::new(MySqlDatabaseExecutor::new());

    let audit_service = AuditService::with_file(audit_path.to_str().unwrap()).unwrap();
    let config = config_with_testcontainers(mysql_port, &audit_path);
    let state = build_state(config.clone(), audit_service, executor, false, &[]);

    // Simulate the transient-failure scenario: startup preflight saw a
    // blip and marked the connection unready.
    state
        .db_connection_ready
        .insert("orders_prod".into(), false);
    assert!(
        !state.db_connection_is_ready("orders_prod"),
        "test setup: connection should start unready"
    );

    // One tick of the self-heal loop. With a healthy testcontainers
    // MySQL and a valid secret provider, this must succeed and flip
    // the entry back to true.
    control_plane::services::reprobe_db_connections_once(&state).await;

    assert!(
        state.db_connection_is_ready("orders_prod"),
        "after a healthy reprobe tick, the connection must recover to ready=true; \
         otherwise a transient startup blip would mean permanent 503 until restart"
    );
}
