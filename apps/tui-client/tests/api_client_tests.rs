//! Integration tests for `ApiClient` against a mock HTTP server.
//!
//! Each test starts a local Axum server on an ephemeral port and exercises
//! the real `reqwest`-based ApiClient, covering the full HTTP round-trip.

use axum::{
    extract::Json,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use tokio::net::TcpListener;

use tui_client::api_client::{ApiClient, ApiClientError};

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

fn mock_app() -> Router {
    Router::new()
        .route("/auth/dev-login", post(dev_login_handler))
        .route("/api/ec2/list", post(list_ec2_handler))
        .route("/api/entitlements", get(entitlements_handler))
        .route("/api/cloudwatch/log-groups", post(log_groups_handler))
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
    let mut client = ApiClient::new(&base_url).unwrap();

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
    let mut client = ApiClient::new(&base_url).unwrap();

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
async fn authenticated_403_is_not_token_expired() {
    let base_url = start_mock(mock_app_ec2_forbidden()).await;
    let mut client = ApiClient::new(&base_url).unwrap();
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
    let mut client = ApiClient::new(&base_url).unwrap();
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
    let mut client = ApiClient::new(&base_url).unwrap();

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
