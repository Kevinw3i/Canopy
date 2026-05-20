//! End-to-end test that spawns the real `control-plane` binary, talks to
//! it over a real HTTP socket, and walks the full MCP Database v1 session
//! lifecycle. Complements the in-process `route_tests.rs` integration tests
//! by also exercising:
//!
//!   * binary boot path (config load, app state init, preflight kickoff)
//!   * real TCP listener binding (not `tower::ServiceExt::oneshot`)
//!   * audit log file output (the in-process tests can write to file too,
//!     but only the binary path exercises `services::audit::AuditService`
//!     under a freshly spawned tokio runtime + stdout tracing wiring)
//!
//! All external dependencies are mocked: `dev_mode = true` skips OIDC /
//! STS for auth, `database_connections` is empty so the database query
//! deterministically rejects with `connection_not_configured` before any
//! MySQL round-trip. P3 (`database_e2e_test.rs`) covers the real-MySQL
//! path via testcontainers.

use serde_json::{json, Value};
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::io::AsyncBufReadExt;
use tokio::process::{Child, Command};

/// Spawn the `control-plane` binary on a free local port and wait for it
/// to accept TCP connections. Returns a guard that kills the child on
/// drop so test failures cannot strand a process.
struct Spawned {
    child: Child,
    base_url: String,
    audit_log: PathBuf,
    _tempdir: tempfile::TempDir,
}

impl Drop for Spawned {
    fn drop(&mut self) {
        // best-effort kill; child::start_kill is non-blocking and async,
        // but tokio::process::Child also supports start_kill() in sync
        // contexts via `let _ = self.child.start_kill();`. Errors are
        // logged via test output but do not fail Drop.
        let _ = self.child.start_kill();
    }
}

impl Spawned {
    async fn launch() -> Self {
        // 1. Reserve a free port. We bind a throwaway listener to ":0",
        //    read the OS-assigned port, then drop the listener. There is
        //    a small race window between drop and the child binding the
        //    same port, but on a developer/CI machine the chance of
        //    another process grabbing it within microseconds is
        //    vanishingly small.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        // 2. Write a config.toml that pins bind_address to the free port
        //    and points audit_log at a temp file we can read back later.
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let audit_log = tempdir.path().join("audit.jsonl");
        let config_path = tempdir.path().join("config.toml");
        let config_body = format!(
            r#"
bind_address = "127.0.0.1:{port}"
dev_mode = true
mock_aws_data = true
audit_log = "{audit}"
cors_allowed_origins = []

[oidc]
issuer_url = "https://placeholder.example.com"
client_id = "dev-client-id"

[jwt]
secret = "e2e-binary-test-secret-at-least-32-chars-long!!"
expiry_seconds = 7200

[aws]
default_region = "us-east-1"
session_duration_seconds = 3600
"#,
            port = port,
            audit = audit_log.display(),
        );
        std::fs::write(&config_path, config_body).expect("write config.toml");

        // 3. Spawn the binary with CONFIG_PATH pointing at the temp
        //    config + DEV_MODE=1. We pipe stdout so the test can wait
        //    for the "listening" log line, but also fall back to a TCP
        //    probe loop in case logs are buffered.
        let bin = env!("CARGO_BIN_EXE_control-plane");
        let mut child = Command::new(bin)
            .env("CONFIG_PATH", &config_path)
            .env("DEV_MODE", "1")
            .env("RUST_LOG", "error")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn control-plane");

        // 4. Wait for the port to be listening. The preflight (OIDC /
        //    STS) happens asynchronously after the listener binds, so we
        //    do NOT wait for /health — we wait for any TCP connection
        //    to succeed. Dev-mode endpoints (dev-login, MCP) only
        //    require `audit_service.is_healthy()`, not preflight
        //    readiness.
        let base_url = format!("http://127.0.0.1:{port}");
        let deadline = Instant::now() + Duration::from_secs(15);
        let probe = format!("127.0.0.1:{port}");
        loop {
            if Instant::now() > deadline {
                // Drain whatever child wrote so the test failure message
                // is useful instead of an opaque "didn't start".
                if let Some(mut stderr) = child.stderr.take() {
                    let mut buf = Vec::new();
                    let _ = tokio::io::AsyncReadExt::read_to_end(&mut stderr, &mut buf).await;
                    eprintln!("child stderr:\n{}", String::from_utf8_lossy(&buf));
                }
                let _ = child.start_kill();
                panic!("control-plane failed to start within 15s");
            }
            if tokio::net::TcpStream::connect(&probe).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // 5. Drain stdout in the background so the binary doesn't block on
        //    a full pipe under heavy logging. We don't assert on stdout
        //    content; audit assertions read the file directly.
        if let Some(stdout) = child.stdout.take() {
            tokio::spawn(async move {
                let mut reader = tokio::io::BufReader::new(stdout).lines();
                while let Ok(Some(_)) = reader.next_line().await {}
            });
        }

        Self {
            child,
            base_url,
            audit_log,
            _tempdir: tempdir,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    async fn shutdown(mut self) {
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
    }
}

fn require_field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("missing field {key:?} in {value}"))
}

#[tokio::test]
async fn binary_e2e_full_mcp_session_lifecycle() {
    let server = Spawned::launch().await;
    let client = reqwest::Client::new();

    // ── 1. dev-login → JWT ──────────────────────────────────────────────
    let login: Value = client
        .post(server.url("/auth/dev-login"))
        .json(&json!({"username": "dev-admin"}))
        .send()
        .await
        .expect("dev-login request")
        .error_for_status()
        .expect("dev-login non-success")
        .json()
        .await
        .expect("dev-login json");
    let token = require_field(&login, "access_token").as_str().unwrap();
    assert!(
        token.starts_with("eyJ"),
        "JWT should be JWS-encoded, got {token:?}"
    );
    let identity = require_field(&login, "identity");
    assert_eq!(identity["user_id"], "dev-admin");
    assert!(identity["email_verified"].as_bool().unwrap_or(false));

    // ── 2. register MCP session ─────────────────────────────────────────
    let session: Value = client
        .post(server.url("/api/mcp/session/register"))
        .bearer_auth(token)
        .json(&json!({
            "protocol_version": "2025-06-18",
            "local_secret_generation": "lsg_e2e_001",
            "client_name": "e2e-binary-test",
            "client_version": "0.0.1",
            "product_phase": "phase-1"
        }))
        .send()
        .await
        .expect("register session")
        .error_for_status()
        .expect("register session non-success")
        .json()
        .await
        .expect("register session json");
    let sid = require_field(&session, "canopy_mcp_session_id")
        .as_str()
        .unwrap()
        .to_string();
    assert!(sid.starts_with("mcp_"));
    assert!(
        require_field(&session, "forwarding_key")
            .as_str()
            .unwrap()
            .len()
            >= 32
    );

    // ── 3. ack three required guidance entries for database query ──────
    for guidance_id in [
        "security_boundaries",
        "database_query_workflow",
        "privacy_and_audit_notice",
    ] {
        let resp: Value = client
            .post(server.url("/api/mcp/guidance/delivered"))
            .bearer_auth(token)
            .json(&json!({
                "canopy_mcp_session_id": sid,
                "local_secret_generation": "lsg_e2e_001",
                "guidance_id": guidance_id,
                "guidance_version": "2026-05-13"
            }))
            .send()
            .await
            .expect("guidance delivered")
            .error_for_status()
            .expect("guidance delivered non-success")
            .json()
            .await
            .expect("guidance delivered json");
        assert_eq!(resp["guidance_issued"], true);
        assert_eq!(resp["guidance_delivered_for_gating"], true);
        assert_eq!(resp["guidance_id"], guidance_id);
    }

    // ── 4. list database scopes (no real DB needed) ─────────────────────
    let scopes: Value = client
        .post(server.url("/api/mcp/database/scopes"))
        .bearer_auth(token)
        .json(&json!({
            "canopy_mcp_session_id": sid,
            "local_secret_generation": "lsg_e2e_001"
        }))
        .send()
        .await
        .expect("list scopes")
        .error_for_status()
        .expect("list scopes non-success")
        .json()
        .await
        .expect("list scopes json");
    let scope_list = scopes["scopes"].as_array().expect("scopes array");
    let scope = scope_list
        .iter()
        .find(|s| s["name"] == "orders_prod_readonly")
        .expect("orders_prod_readonly scope present");
    // Defense-in-depth: assert the wire payload never carries DB host,
    // secret ARN, username, or password (Codex round 15 guarantee).
    let scope_str = serde_json::to_string(scope).unwrap();
    for forbidden in ["host", "secret_arn", "username", "password", "credentials"] {
        assert!(
            !scope_str.contains(forbidden),
            "scope payload leaks {forbidden:?}: {scope_str}"
        );
    }

    // ── 5. submit a query; dev defaults have no [database_connections.*]
    //      so we expect a deterministic 400 with rejection_reason =
    //      connection_not_configured ─────────────────────────────────────
    let query_resp = client
        .post(server.url("/api/mcp/database/query"))
        .bearer_auth(token)
        .json(&json!({
            "scope": "orders_prod_readonly",
            "sql": "select id, status from orders where id = 123 limit 20",
            "canopy_mcp_session_id": sid,
            "local_secret_generation": "lsg_e2e_001"
        }))
        .send()
        .await
        .expect("query request");
    assert_eq!(query_resp.status().as_u16(), 400);
    let query_err: Value = query_resp.json().await.expect("query error json");
    assert_eq!(query_err["code"], "BAD_REQUEST");
    assert!(query_err["message"]
        .as_str()
        .unwrap()
        .contains("Database connection is not configured"));

    // ── 6. read the audit log BEFORE shutting the binary down ──────────
    // `Spawned::shutdown` consumes `self`, which drops the `TempDir`
    // and deletes the audit file. Read it into memory first; we only
    // need the snapshot up to this point.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let audit_path = server.audit_log.clone();
    let audit = std::fs::read_to_string(&audit_path)
        .unwrap_or_else(|e| panic!("read audit log {}: {e}", audit_path.display()));
    server.shutdown().await;
    let events: Vec<Value> = audit
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("audit line {l:?}: {e}")))
        .collect();
    assert!(
        !events.is_empty(),
        "audit log should contain events, got {:?}",
        audit
    );

    let mcp_session_register = events
        .iter()
        .find(|e| e["action"] == "mcp_session_register" && e["outcome"] == "success")
        .expect("mcp_session_register success audit event");
    assert_eq!(
        mcp_session_register["metadata"]["mcp_event_kind"],
        "mcp_session_register"
    );

    let guidance_events: Vec<_> = events
        .iter()
        .filter(|e| e["action"] == "mcp_guidance_sync")
        .collect();
    assert!(
        guidance_events.len() >= 3,
        "expected at least 3 guidance audit events, got {}",
        guidance_events.len()
    );

    let database_denied = events
        .iter()
        .find(|e| {
            e["action"] == "mcp_database_query"
                && e["metadata"]["rejection_reason"] == "connection_not_configured"
        })
        .expect("database query denial with connection_not_configured reason");

    // Codex round 15: the denial path must redact sql_raw because the
    // request never crossed the durable `attempt` event threshold.
    assert!(
        database_denied["metadata"]["sql_raw"]
            .as_str()
            .unwrap_or_default()
            .starts_with("[redacted"),
        "sql_raw must be redacted on the denial path; got {:?}",
        database_denied["metadata"]["sql_raw"]
    );
    // Codex round 16: pre-DB denial events must NOT claim execution.
    assert_eq!(database_denied["metadata"]["db_execution_attempted"], false);
    assert_eq!(database_denied["metadata"]["explain_attempted"], false);
}

#[tokio::test]
async fn binary_e2e_database_query_requires_completed_guidance() {
    // Register a session, skip guidance ack, attempt to call
    // database/query → must be rejected with guidance_required (Codex
    // server-issued guidance enforcement) and the denial event must
    // also redact sql_raw.
    let server = Spawned::launch().await;
    let client = reqwest::Client::new();

    let token = client
        .post(server.url("/auth/dev-login"))
        .json(&json!({"username": "dev-admin"}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let session: Value = client
        .post(server.url("/api/mcp/session/register"))
        .bearer_auth(&token)
        .json(&json!({
            "protocol_version": "2025-06-18",
            "local_secret_generation": "lsg_e2e_no_guidance",
            "client_name": "e2e",
            "client_version": "0.0.1",
            "product_phase": "phase-1"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sid = session["canopy_mcp_session_id"].as_str().unwrap();

    // No guidance/delivered calls. Straight to query → 403.
    let resp = client
        .post(server.url("/api/mcp/database/query"))
        .bearer_auth(&token)
        .json(&json!({
            "scope": "orders_prod_readonly",
            "sql": "select id from orders limit 1",
            "canopy_mcp_session_id": sid,
            "local_secret_generation": "lsg_e2e_no_guidance"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    let err: Value = resp.json().await.unwrap();
    assert_eq!(err["code"], "FORBIDDEN");
    assert!(err["message"]
        .as_str()
        .unwrap()
        .contains("MCP database guidance"));

    tokio::time::sleep(Duration::from_millis(200)).await;
    let audit_path = server.audit_log.clone();
    let audit = std::fs::read_to_string(&audit_path).unwrap();
    server.shutdown().await;
    let denial = audit
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|e| {
            e["action"] == "mcp_database_query" && e["metadata"]["mcp_outcome_kind"] == "denied"
        })
        .expect("guidance-required denial audit event");
    assert_eq!(
        denial["metadata"]["rejection_reason"]
            .as_str()
            .unwrap_or_default(),
        "guidance_required"
    );
    // Pre-guidance denial path also redacts.
    assert!(denial["metadata"]["sql_raw"]
        .as_str()
        .unwrap_or_default()
        .starts_with("[redacted"));
}
