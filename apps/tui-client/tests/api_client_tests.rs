//! Integration tests for `ApiClient` against a mock HTTP server.
//!
//! Each test starts a local Axum server on an ephemeral port and exercises
//! the real `reqwest`-based ApiClient, covering the full HTTP round-trip.

use axum::{
    extract::{Json, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::net::TcpListener;

use tui_client::api_client::{ApiClient, ApiClientError};
use tui_client::auth::{device_code::DeviceCodeFlow, SessionTokens};

// ── Mock server helpers ─────────────────────────────────────────────────

async fn start_mock(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{}", addr)
}

// ── Mock handlers ───────────────────────────────────────────────────────

async fn dev_login_handler(headers: HeaderMap, Json(body): Json<Value>) -> impl IntoResponse {
    let user_agent = headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let tui_version = headers
        .get("X-Canopy-TUI-Version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if user_agent != ApiClient::user_agent() || tui_version != ApiClient::tui_version() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "code": "BAD_REQUEST",
                "message": "missing canopy client headers"
            })),
        )
            .into_response();
    }

    let username = body["username"].as_str().unwrap_or("unknown");
    Json(json!({
        "access_token": format!("tok-{}", username),
        "expires_in": 3600,
        "identity": {
            "user_id": username,
            "email": format!("{}@dev.local", username),
            "display_name": username,
            "groups": ["eng"],
            "email_verified": true
        }
    }))
    .into_response()
}

async fn dev_login_forbidden() -> impl IntoResponse {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "code": "FORBIDDEN",
            "message": "Dev login is disabled"
        })),
    )
}

async fn dev_login_unauthorized() -> impl IntoResponse {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "code": "UNAUTHORIZED",
            "message": "Login rejected"
        })),
    )
}

fn require_bearer(headers: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
    let auth = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if auth.starts_with("Bearer ") {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "code": "UNAUTHORIZED",
                "message": "Missing auth"
            })),
        ))
    }
}

async fn list_ec2_forbidden() -> impl IntoResponse {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "code": "FORBIDDEN",
            "message": "not authorized for this account"
        })),
    )
}

async fn list_ec2_handler(headers: HeaderMap, Json(_body): Json<Value>) -> impl IntoResponse {
    if let Err(e) = require_bearer(&headers) {
        return e.into_response();
    }

    Json(json!({
        "instances": [
            {
                "instance_id": "i-mock001",
                "account_id": "111111111111",
                "region": "us-east-1",
                "name": "mock-web",
                "private_ip": "10.0.0.1",
                "public_ip": null,
                "state": "running",
                "platform": "Linux/UNIX",
                "instance_type": "t3.micro",
                "ssm_managed": true,
                "instance_connect_capable": false,
                "environment": "dev",
                "tags": {"Name": "mock-web"},
                "launch_time": "2025-01-01T00:00:00Z",
                "vpc_id": "vpc-123",
                "subnet_id": "subnet-456",
                "security_groups": ["sg-789"],
                "iam_role": "MockRole"
            }
        ],
        "next_token": null,
        "total_count": 1
    }))
    .into_response()
}

async fn entitlements_handler(headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = require_bearer(&headers) {
        return e.into_response();
    }

    Json(json!({
        "user_id": "alice",
        "email": "alice@example.com",
        "display_name": "Alice",
        "groups": ["eng"],
        "features": {
            "can_view_ec2": true,
            "can_use_cloudwatch_search": true,
            "can_use_cloudwatch_tail": true,
            "can_use_ssm": true,
            "can_use_ec2_instance_connect": false
        },
        "allowed_accounts": [
            {"account_id": "111111111111", "account_name": "dev", "role_arn": "arn:aws:iam::111:role/X"}
        ],
        "allowed_regions": ["us-east-1"],
        "allowed_log_group_arns": [],
        "instance_tag_selectors": [],
        "allowed_os_users": ["ec2-user"]
    }))
    .into_response()
}

async fn mfa_status_handler(headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = require_bearer(&headers) {
        return e.into_response();
    }

    Json(json!({
        "user_id": "alice",
        "provider_step_up_configured": true,
        "local_step_up_available": false,
        "step_up_required": false,
        "factors": [
            {
                "kind": "totp",
                "available": false,
                "enrolled": false,
                "label": "Authenticator app"
            },
            {
                "kind": "web_authn",
                "available": false,
                "enrolled": false,
                "label": "Security key"
            }
        ],
        "message": "OIDC provider MFA/re-auth controls are configured."
    }))
    .into_response()
}

async fn totp_start_handler(headers: HeaderMap, Json(_body): Json<Value>) -> impl IntoResponse {
    if let Err(e) = require_bearer(&headers) {
        return e.into_response();
    }

    Json(json!({
        "factor_id": "factor-1",
        "secret_base32": "ABCDEFGHIJKLMNOP",
        "otpauth_url": "otpauth://totp/Canopy:alice?secret=ABCDEFGHIJKLMNOP&issuer=Canopy",
        "issuer": "Canopy",
        "account_name": "alice"
    }))
    .into_response()
}

async fn totp_confirm_handler(headers: HeaderMap, Json(body): Json<Value>) -> impl IntoResponse {
    if let Err(e) = require_bearer(&headers) {
        return e.into_response();
    }
    if body["factor_id"].as_str() != Some("factor-1") || body["code"].as_str() != Some("123456") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "code": "BAD_REQUEST",
                "message": "TOTP code is invalid"
            })),
        )
            .into_response();
    }

    Json(json!({
        "factor_id": "factor-1",
        "enrolled": true,
        "status": {
            "user_id": "alice",
            "provider_step_up_configured": true,
            "local_step_up_available": true,
            "step_up_required": false,
            "factors": [
                {
                    "kind": "totp",
                    "available": true,
                    "enrolled": true,
                    "label": "Authenticator app"
                },
                {
                    "kind": "web_authn",
                    "available": true,
                    "enrolled": false,
                    "label": "Security key"
                }
            ],
            "message": "Local MFA factor store and TOTP enrollment are configured."
        }
    }))
    .into_response()
}

async fn log_groups_handler(headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = require_bearer(&headers) {
        return e.into_response();
    }

    Json(json!({
        "log_groups": [
            {
                "name": "/aws/ecs/my-service",
                "arn": "arn:aws:logs:us-east-1:111:log-group:/aws/ecs/my-service",
                "stored_bytes": 1024,
                "retention_days": 30
            }
        ]
    }))
    .into_response()
}

async fn refresh_handler(Json(body): Json<Value>) -> impl IntoResponse {
    if body["refresh_token"].as_str() != Some("refresh-ok") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "code": "BAD_REQUEST",
                "message": "refresh token rejected"
            })),
        )
            .into_response();
    }

    Json(json!({
        "access_token": "fresh-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "refresh-next"
    }))
    .into_response()
}

async fn refresh_500_handler(Json(_body): Json<Value>) -> impl IntoResponse {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({
            "code": "INTERNAL_ERROR",
            "message": "temporary refresh failure"
        })),
    )
        .into_response()
}

async fn refresh_401_handler(Json(_body): Json<Value>) -> impl IntoResponse {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "code": "UNAUTHORIZED",
            "message": "refresh token revoked"
        })),
    )
        .into_response()
}

async fn device_code_start_handler() -> impl IntoResponse {
    Json(json!({
        "device_code": "device-ok",
        "user_code": "ABCD-EFGH",
        "verification_uri": "https://example.com/device",
        "expires_in": 60,
        "interval": 0
    }))
}

async fn device_code_poll_with_refresh(Json(_body): Json<Value>) -> impl IntoResponse {
    Json(json!({
        "status": "complete",
        "access_token": "device-access",
        "expires_in": 3600,
        "refresh_token": "device-refresh"
    }))
}

async fn device_code_poll_without_refresh(Json(_body): Json<Value>) -> impl IntoResponse {
    Json(json!({
        "status": "complete",
        "access_token": "device-access",
        "expires_in": 3600
    }))
}

#[derive(Clone)]
struct RefreshCounter {
    calls: Arc<AtomicUsize>,
}

async fn counted_refresh_handler(
    State(state): State<RefreshCounter>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let call = state.calls.fetch_add(1, Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    if body["refresh_token"].as_str() != Some("refresh-ok") || call > 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "code": "BAD_REQUEST",
                "message": "refresh token rejected"
            })),
        )
            .into_response();
    }

    Json(json!({
        "access_token": "fresh-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "refresh-next"
    }))
    .into_response()
}

async fn entitlements_requires_fresh_token(headers: HeaderMap) -> impl IntoResponse {
    let auth = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if auth != "Bearer fresh-token" {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "code": "UNAUTHORIZED",
                "message": "Invalid or expired token"
            })),
        )
            .into_response();
    }

    entitlements_handler(headers).await.into_response()
}

async fn entitlements_always_unauthorized(_headers: HeaderMap) -> impl IntoResponse {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "code": "UNAUTHORIZED",
            "message": "Invalid or expired token"
        })),
    )
        .into_response()
}

fn mock_app() -> Router {
    Router::new()
        .route("/auth/dev-login", post(dev_login_handler))
        .route("/api/ec2/list", post(list_ec2_handler))
        .route("/api/entitlements", get(entitlements_handler))
        .route("/api/auth/mfa/status", get(mfa_status_handler))
        .route("/api/auth/mfa/totp/start", post(totp_start_handler))
        .route("/api/auth/mfa/totp/confirm", post(totp_confirm_handler))
        .route("/api/cloudwatch/log-groups", post(log_groups_handler))
}

fn mock_app_refresh() -> Router {
    Router::new()
        .route("/auth/refresh", post(refresh_handler))
        .route("/api/entitlements", get(entitlements_requires_fresh_token))
}

fn mock_app_refresh_then_unauthorized() -> Router {
    Router::new()
        .route("/auth/refresh", post(refresh_handler))
        .route("/api/entitlements", get(entitlements_always_unauthorized))
}

fn mock_app_refresh_401() -> Router {
    Router::new()
        .route("/auth/refresh", post(refresh_401_handler))
        .route("/api/entitlements", get(entitlements_requires_fresh_token))
}

fn mock_app_device_code_with_refresh() -> Router {
    Router::new()
        .route("/auth/device-code/start", post(device_code_start_handler))
        .route(
            "/auth/device-code/poll",
            post(device_code_poll_with_refresh),
        )
}

fn mock_app_device_code_without_refresh() -> Router {
    Router::new()
        .route("/auth/device-code/start", post(device_code_start_handler))
        .route(
            "/auth/device-code/poll",
            post(device_code_poll_without_refresh),
        )
}

fn mock_app_no_refresh_needed(calls: Arc<AtomicUsize>) -> Router {
    Router::new()
        .route("/auth/refresh", post(counted_refresh_handler))
        .route("/api/entitlements", get(entitlements_handler))
        .with_state(RefreshCounter { calls })
}

fn mock_app_counted_refresh(calls: Arc<AtomicUsize>) -> Router {
    Router::new()
        .route("/auth/refresh", post(counted_refresh_handler))
        .route("/api/entitlements", get(entitlements_requires_fresh_token))
        .with_state(RefreshCounter { calls })
}

fn mock_app_refresh_500() -> Router {
    Router::new()
        .route("/auth/refresh", post(refresh_500_handler))
        .route("/api/entitlements", get(entitlements_requires_fresh_token))
}

fn mock_app_forbidden() -> Router {
    Router::new().route("/auth/dev-login", post(dev_login_forbidden))
}

fn mock_app_login_unauthorized() -> Router {
    Router::new().route("/auth/dev-login", post(dev_login_unauthorized))
}

fn mock_app_ec2_forbidden() -> Router {
    Router::new().route("/api/ec2/list", post(list_ec2_forbidden))
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn dev_login_returns_token() {
    let base_url = start_mock(mock_app()).await;
    let client = ApiClient::new(&base_url).unwrap();

    let resp = client.dev_login("alice").await.unwrap();
    assert_eq!(resp.access_token, "tok-alice");
    assert_eq!(resp.identity.user_id, "alice");
    assert_eq!(resp.identity.email, "alice@dev.local");
}

#[tokio::test]
async fn dev_login_error_propagates() {
    let base_url = start_mock(mock_app_forbidden()).await;
    let client = ApiClient::new(&base_url).unwrap();

    let err = client.dev_login("alice").await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("403"), "expected 403 in: {}", msg);
    assert!(msg.contains("FORBIDDEN"), "expected FORBIDDEN in: {}", msg);
}

#[tokio::test]
async fn auth_route_401_is_not_token_expired() {
    let base_url = start_mock(mock_app_login_unauthorized()).await;
    let client = ApiClient::new(&base_url).unwrap();

    let err = client.dev_login("alice").await.unwrap_err();
    assert!(
        matches!(err, ApiClientError::Api { status: 401, .. }),
        "expected normal API 401, got {err:?}"
    );
}

#[tokio::test]
async fn token_lifecycle_across_requests() {
    let base_url = start_mock(mock_app()).await;
    let client = ApiClient::new(&base_url).unwrap();

    // Without token, listing EC2 should fail (server returns 401)
    let err = client
        .list_ec2(&shared::dto::ec2::Ec2ListRequest {
            account_id: None,
            region: None,
            name_filter: None,
            state_filter: None,
            tag_filters: None,
            next_token: None,
            page_size: 50,
        })
        .await
        .unwrap_err();
    assert!(matches!(err, ApiClientError::TokenExpired));

    // Login and set token
    let login = client.dev_login("bob").await.unwrap();
    client.set_token(login.access_token);

    // Now listing should succeed
    let resp = client
        .list_ec2(&shared::dto::ec2::Ec2ListRequest {
            account_id: None,
            region: None,
            name_filter: None,
            state_filter: None,
            tag_filters: None,
            next_token: None,
            page_size: 50,
        })
        .await
        .unwrap();

    assert_eq!(resp.instances.len(), 1);
    assert_eq!(resp.instances[0].instance_id, "i-mock001");
    assert_eq!(resp.total_count, 1);
}

#[tokio::test]
async fn get_entitlements_requires_auth() {
    let base_url = start_mock(mock_app()).await;
    let client = ApiClient::new(&base_url).unwrap();

    // No token -> 401
    let err = client.get_entitlements().await.unwrap_err();
    assert!(matches!(err, ApiClientError::TokenExpired));

    // With token -> success
    client.set_token("test-token".into());
    let ent = client.get_entitlements().await.unwrap();
    assert_eq!(ent.user_id, "alice");
    assert_eq!(ent.groups, vec!["eng"]);
}

#[tokio::test]
async fn mfa_status_success() {
    let base_url = start_mock(mock_app()).await;
    let client = ApiClient::new(&base_url).unwrap();
    client.set_token("access-token".into());

    let status = client.mfa_status().await.unwrap();
    assert_eq!(status.user_id, "alice");
    assert!(status.provider_step_up_configured);
    assert!(!status.local_step_up_available);
    assert_eq!(
        status.factors[0].kind,
        shared::dto::auth::MfaFactorKind::Totp
    );
    assert_eq!(
        status.factors[1].kind,
        shared::dto::auth::MfaFactorKind::WebAuthn
    );
}

#[tokio::test]
async fn totp_enrollment_start_and_confirm_success() {
    let base_url = start_mock(mock_app()).await;
    let client = ApiClient::new(&base_url).unwrap();
    client.set_token("access-token".into());

    let started = client
        .start_totp_enrollment(&shared::dto::auth::TotpEnrollStartRequest { label: None })
        .await
        .unwrap();
    assert_eq!(started.factor_id, "factor-1");
    assert_eq!(started.issuer, "Canopy");
    assert!(started.otpauth_url.starts_with("otpauth://totp/"));

    let confirmed = client
        .confirm_totp_enrollment(&shared::dto::auth::TotpEnrollConfirmRequest {
            factor_id: started.factor_id,
            code: "123456".into(),
        })
        .await
        .unwrap();
    assert!(confirmed.enrolled);
    assert!(confirmed.status.local_step_up_available);
}

#[tokio::test]
async fn authenticated_401_refreshes_session_and_retries() {
    let base_url = start_mock(mock_app_refresh()).await;
    let client = ApiClient::new(&base_url).unwrap();
    let dir = std::env::temp_dir().join(format!("canopy-api-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let token_path = dir.join("token");
    client.set_session_store_path(token_path.clone());
    client.set_session(SessionTokens::new(
        "expired-token".into(),
        Some("refresh-ok".into()),
    ));

    let ent = client.get_entitlements().await.unwrap();
    assert_eq!(ent.user_id, "alice");
    assert_eq!(client.get_token().as_deref(), Some("fresh-token"));
    assert_eq!(client.get_refresh_token().as_deref(), Some("refresh-next"));

    let persisted: SessionTokens =
        serde_json::from_str(&std::fs::read_to_string(&token_path).unwrap()).unwrap();
    assert_eq!(persisted.access_token, "fresh-token");
    assert_eq!(persisted.refresh_token.as_deref(), Some("refresh-next"));

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn authenticated_success_does_not_call_refresh() {
    let calls = Arc::new(AtomicUsize::new(0));
    let base_url = start_mock(mock_app_no_refresh_needed(calls.clone())).await;
    let client = ApiClient::new(&base_url).unwrap();
    client.set_session(SessionTokens::new(
        "valid-token".into(),
        Some("refresh-ok".into()),
    ));

    let ent = client.get_entitlements().await.unwrap();

    assert_eq!(ent.user_id, "alice");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(client.get_token().as_deref(), Some("valid-token"));
}

#[tokio::test]
async fn concurrent_401s_share_one_refresh_request() {
    let calls = Arc::new(AtomicUsize::new(0));
    let base_url = start_mock(mock_app_counted_refresh(calls.clone())).await;
    let client = ApiClient::new(&base_url).unwrap();
    let dir = std::env::temp_dir().join(format!("canopy-api-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    client.set_session_store_path(dir.join("token"));
    client.set_session(SessionTokens::new(
        "expired-token".into(),
        Some("refresh-ok".into()),
    ));

    let (first, second) = tokio::join!(client.get_entitlements(), client.get_entitlements());

    assert!(first.is_ok(), "first request failed: {first:?}");
    assert!(second.is_ok(), "second request failed: {second:?}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(client.get_token().as_deref(), Some("fresh-token"));

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn authenticated_retry_still_401_returns_token_expired_without_looping() {
    let base_url = start_mock(mock_app_refresh_then_unauthorized()).await;
    let client = ApiClient::new(&base_url).unwrap();
    client.set_session(SessionTokens::new(
        "expired-token".into(),
        Some("refresh-ok".into()),
    ));

    let err = client.get_entitlements().await.unwrap_err();

    assert!(matches!(err, ApiClientError::TokenExpired));
    assert_eq!(client.get_token().as_deref(), Some("fresh-token"));
}

#[tokio::test]
async fn refresh_401_returns_token_expired() {
    let base_url = start_mock(mock_app_refresh_401()).await;
    let client = ApiClient::new(&base_url).unwrap();
    client.set_session(SessionTokens::new(
        "expired-token".into(),
        Some("refresh-revoked".into()),
    ));

    let err = client.get_entitlements().await.unwrap_err();

    assert!(matches!(err, ApiClientError::TokenExpired));
    assert_eq!(client.get_token().as_deref(), Some("expired-token"));
}

#[tokio::test]
async fn initial_transport_error_propagates_without_token_expired() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let client = ApiClient::new(&format!("http://{addr}")).unwrap();
    client.set_session(SessionTokens::new(
        "expired-token".into(),
        Some("refresh-ok".into()),
    ));

    let err = client.get_entitlements().await.unwrap_err();

    assert!(
        matches!(err, ApiClientError::Transport(_)),
        "connection failure must remain transport error, got {err:?}"
    );
}

#[tokio::test]
async fn refresh_requires_existing_refresh_token() {
    let base_url = start_mock(mock_app_refresh()).await;
    let client = ApiClient::new(&base_url).unwrap();
    client.set_session(SessionTokens::new("expired-token".into(), None));

    let err = client.get_entitlements().await.unwrap_err();

    assert!(matches!(err, ApiClientError::TokenExpired));
    assert_eq!(client.get_token().as_deref(), Some("expired-token"));
}

#[tokio::test]
async fn logout_during_refresh_does_not_restore_session() {
    let calls = Arc::new(AtomicUsize::new(0));
    let base_url = start_mock(mock_app_counted_refresh(calls.clone())).await;
    let client = ApiClient::new(&base_url).unwrap();
    let dir = std::env::temp_dir().join(format!("canopy-api-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let token_path = dir.join("token");
    client.set_session_store_path(token_path.clone());
    client.set_session(SessionTokens::new(
        "expired-token".into(),
        Some("refresh-ok".into()),
    ));

    let pending = {
        let client = client.clone();
        tokio::spawn(async move { client.get_entitlements().await })
    };
    for _ in 0..20 {
        if calls.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    client.clear_token();
    let err = pending.await.unwrap().unwrap_err();

    assert!(matches!(err, ApiClientError::TokenExpired));
    assert!(!client.has_token());
    assert!(
        !token_path.exists(),
        "refresh must not persist a token after logout"
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn refresh_5xx_remains_api_error_not_token_expired() {
    let base_url = start_mock(mock_app_refresh_500()).await;
    let client = ApiClient::new(&base_url).unwrap();
    client.set_session(SessionTokens::new(
        "expired-token".into(),
        Some("refresh-ok".into()),
    ));

    let err = client.get_entitlements().await.unwrap_err();

    assert!(
        matches!(err, ApiClientError::Api { status: 500, .. }),
        "expected refresh 5xx to remain API error, got {err:?}"
    );
}

#[tokio::test]
async fn refresh_persist_failure_does_not_activate_rotated_token() {
    let base_url = start_mock(mock_app_refresh()).await;
    let client = ApiClient::new(&base_url).unwrap();
    let dir = std::env::temp_dir().join(format!("canopy-api-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    // Point the session store path at a directory so the atomic file write
    // fails after the refresh endpoint has returned rotated credentials.
    client.set_session_store_path(dir.clone());
    client.set_session(SessionTokens::new(
        "expired-token".into(),
        Some("refresh-ok".into()),
    ));

    let err = client.get_entitlements().await.unwrap_err();

    assert!(matches!(err, ApiClientError::SessionStore { .. }));
    assert_eq!(client.get_token().as_deref(), Some("expired-token"));

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn apply_token_response_preserves_existing_refresh_when_omitted() {
    let base_url = start_mock(mock_app()).await;
    let client = ApiClient::new(&base_url).unwrap();
    client.set_session(SessionTokens::new(
        "old-access".into(),
        Some("refresh-keep".into()),
    ));

    let session = client.apply_token_response(shared::dto::auth::TokenResponse {
        access_token: "new-access".into(),
        token_type: "Bearer".into(),
        expires_in: 3600,
        refresh_token: None,
    });

    assert_eq!(session.access_token, "new-access");
    assert_eq!(session.refresh_token.as_deref(), Some("refresh-keep"));
    assert_eq!(client.get_refresh_token().as_deref(), Some("refresh-keep"));
}

#[tokio::test]
async fn apply_token_response_uses_server_refresh_when_provided() {
    let base_url = start_mock(mock_app()).await;
    let client = ApiClient::new(&base_url).unwrap();
    client.set_session(SessionTokens::new(
        "old-access".into(),
        Some("refresh-old".into()),
    ));

    let session = client.apply_token_response(shared::dto::auth::TokenResponse {
        access_token: "new-access".into(),
        token_type: "Bearer".into(),
        expires_in: 3600,
        refresh_token: Some("refresh-new".into()),
    });

    assert_eq!(session.access_token, "new-access");
    assert_eq!(session.refresh_token.as_deref(), Some("refresh-new"));
    assert_eq!(client.get_token().as_deref(), Some("new-access"));
    assert_eq!(client.get_refresh_token().as_deref(), Some("refresh-new"));
}

#[tokio::test]
async fn set_token_replaces_session_and_clears_refresh_token() {
    let base_url = start_mock(mock_app()).await;
    let client = ApiClient::new(&base_url).unwrap();
    client.set_session(SessionTokens::new(
        "old-access".into(),
        Some("refresh-old".into()),
    ));

    client.set_token("raw-access".into());

    assert_eq!(client.get_token().as_deref(), Some("raw-access"));
    assert_eq!(client.get_refresh_token(), None);
}

#[tokio::test]
async fn device_code_flow_returns_token_response_with_refresh() {
    let base_url = start_mock(mock_app_device_code_with_refresh()).await;
    let client = ApiClient::new(&base_url).unwrap();

    let flow = DeviceCodeFlow::start(&client).await.unwrap();
    let token = flow.poll_until_complete(&client).await.unwrap();

    assert_eq!(token.access_token, "device-access");
    assert_eq!(token.refresh_token.as_deref(), Some("device-refresh"));
}

#[tokio::test]
async fn device_code_flow_accepts_missing_refresh_token() {
    let base_url = start_mock(mock_app_device_code_without_refresh()).await;
    let client = ApiClient::new(&base_url).unwrap();

    let flow = DeviceCodeFlow::start(&client).await.unwrap();
    let token = flow.poll_until_complete(&client).await.unwrap();

    assert_eq!(token.access_token, "device-access");
    assert_eq!(token.refresh_token, None);
}

#[tokio::test]
async fn authenticated_403_is_not_token_expired() {
    let base_url = start_mock(mock_app_ec2_forbidden()).await;
    let client = ApiClient::new(&base_url).unwrap();
    client.set_token("test-token".into());

    let err = client
        .list_ec2(&shared::dto::ec2::Ec2ListRequest {
            account_id: None,
            region: None,
            name_filter: None,
            state_filter: None,
            tag_filters: None,
            next_token: None,
            page_size: 50,
        })
        .await
        .unwrap_err();

    match err {
        ApiClientError::Api {
            status,
            code,
            message,
        } => {
            assert_eq!(status, 403);
            assert_eq!(code, "FORBIDDEN");
            assert!(message.contains("not authorized"));
        }
        other => panic!("expected normal API error, got {other:?}"),
    }
}

#[tokio::test]
async fn list_log_groups_success() {
    let base_url = start_mock(mock_app()).await;
    let client = ApiClient::new(&base_url).unwrap();
    client.set_token("test-token".into());

    let resp = client
        .list_log_groups(&shared::dto::cloudwatch::LogGroupsRequest {
            account_id: "111".into(),
            region: "us-east-1".into(),
            prefix: None,
        })
        .await
        .unwrap();

    assert_eq!(resp.log_groups.len(), 1);
    assert_eq!(resp.log_groups[0].name, "/aws/ecs/my-service");
}

#[tokio::test]
async fn clear_token_revokes_access() {
    let base_url = start_mock(mock_app()).await;
    let client = ApiClient::new(&base_url).unwrap();

    client.set_token("my-token".into());
    assert!(client.has_token());

    // Entitlements works with token
    let _ent = client.get_entitlements().await.unwrap();

    // Clear token
    client.clear_token();
    assert!(!client.has_token());

    // Now entitlements should fail
    let err = client.get_entitlements().await.unwrap_err();
    assert!(matches!(err, ApiClientError::TokenExpired));
}

#[tokio::test]
async fn base_url_trailing_slash_handled() {
    let base_url = start_mock(mock_app()).await;
    let client = ApiClient::new(&format!("{}/", base_url)).unwrap();
    let resp = client.dev_login("test").await.unwrap();
    assert_eq!(resp.access_token, "tok-test");
}
