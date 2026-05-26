use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use crate::services::auth::{AuthService, Claims};
use crate::services::AppState;
use shared::errors::ApiError;

/// Extract and validate JWT from Authorization header.
/// Stores Claims in request extensions for downstream handlers.
pub async fn require_auth(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok());

    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiError::unauthorized(
                    "Missing or invalid Authorization header",
                )),
            )
                .into_response();
        }
    };

    let auth_service = AuthService::new(state.config.clone());
    match auth_service.validate_token(token) {
        Ok(claims) => {
            request.extensions_mut().insert(claims);
            next.run(request).await
        }
        Err(e) => {
            tracing::warn!(error = %e, "Token validation failed");
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiError::unauthorized("Invalid or expired token")),
            )
                .into_response()
        }
    }
}

/// Extract Claims from request extensions (use after require_auth middleware)
pub fn extract_claims(request: &Request) -> Option<&Claims> {
    request.extensions().get::<Claims>()
}

/// Helper to get claims in a handler that's behind the auth middleware
#[derive(Clone)]
pub struct AuthenticatedUser(pub Claims);

#[axum::async_trait]
impl<S> axum::extract::FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<ApiError>);

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Claims>()
            .cloned()
            .map(AuthenticatedUser)
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ApiError::unauthorized("Not authenticated")),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, AwsConfig, JwtConfig, OidcConfig};
    use crate::services::audit::AuditService;
    use crate::services::oidc::OidcClient;
    use axum::{body::Body, middleware as axum_mw, routing::get, Router};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn test_config() -> AppConfig {
        AppConfig {
            bind_address: "127.0.0.1:8443".into(),
            oidc: OidcConfig {
                issuer_url: "https://example.com".into(),
                client_id: "test".into(),
                client_secret: None,
                scopes: vec!["openid".into()],
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
            jwt: JwtConfig {
                secret: "test-secret-at-least-32-chars-long!!".into(),
                expiry_seconds: 3600,
            },
            aws: AwsConfig {
                default_region: Some("us-east-1".into()),
                session_duration_seconds: Some(3600),
                sts_external_id: Some("canopy".into()),
            },
            dev_mode: true,
            mock_aws_data: None,
            entitlements_file: None,
            entitlements_database_url: None,
            audit_log: None,
            cors_allowed_origins: vec![],
        }
    }

    fn build_test_state() -> Arc<AppState> {
        let config = test_config();
        let store = crate::models::entitlements::EntitlementStore::dev_defaults();
        let base_aws_config = aws_config::SdkConfig::builder()
            .region(aws_types::region::Region::new("us-east-1"))
            .build();

        Arc::new(AppState {
            config,
            entitlement_store: Arc::new(tokio::sync::RwLock::new(store)),
            audit_service: AuditService::new(),
            oidc_client: OidcClient::new(test_config().oidc),
            base_aws_config,
            ready: std::sync::atomic::AtomicBool::new(true),
        })
    }

    /// A trivial handler behind the auth middleware that echoes the sub claim.
    async fn echo_sub(AuthenticatedUser(claims): AuthenticatedUser) -> String {
        claims.sub
    }

    fn protected_app(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/protected", get(echo_sub))
            .route_layer(axum_mw::from_fn_with_state(state.clone(), require_auth))
            .with_state(state)
    }

    fn issue_token(secret: &str) -> String {
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = Claims {
            sub: "alice".into(),
            email: "alice@test.com".into(),
            name: "Alice".into(),
            groups: vec!["eng".into()],
            exp: now + 3600,
            iat: now,
            email_verified: true,
        };
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn missing_auth_header_returns_401() {
        let state = build_test_state();
        let app = protected_app(state);

        let resp = app
            .oneshot(
                axum::http::Request::get("/protected")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "Missing or invalid Authorization header");
    }

    #[tokio::test]
    async fn malformed_auth_header_returns_401() {
        let state = build_test_state();
        let app = protected_app(state);

        // "Basic" scheme instead of "Bearer"
        let resp = app
            .oneshot(
                axum::http::Request::get("/protected")
                    .header("Authorization", "Basic dXNlcjpwYXNz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_jwt_returns_401() {
        let state = build_test_state();
        let app = protected_app(state);

        let resp = app
            .oneshot(
                axum::http::Request::get("/protected")
                    .header("Authorization", "Bearer not.a.valid.jwt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "Invalid or expired token");
    }

    #[tokio::test]
    async fn wrong_secret_returns_401() {
        let state = build_test_state();
        let app = protected_app(state);

        let token = issue_token("completely-wrong-secret-value!!");
        let resp = app
            .oneshot(
                axum::http::Request::get("/protected")
                    .header("Authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn expired_token_returns_401() {
        let state = build_test_state();
        let app = protected_app(state);

        let claims = Claims {
            sub: "alice".into(),
            email: "alice@test.com".into(),
            name: "Alice".into(),
            groups: vec![],
            exp: 0, // epoch — expired
            iat: 0,
            email_verified: false,
        };
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(b"test-secret-at-least-32-chars-long!!"),
        )
        .unwrap();

        let resp = app
            .oneshot(
                axum::http::Request::get("/protected")
                    .header("Authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn empty_bearer_token_returns_401() {
        let state = build_test_state();
        let app = protected_app(state);

        let resp = app
            .oneshot(
                axum::http::Request::get("/protected")
                    .header("Authorization", "Bearer ")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bearer_lowercase_rejected() {
        let state = build_test_state();
        let app = protected_app(state);

        let token = issue_token("test-secret-at-least-32-chars-long!!");
        let resp = app
            .oneshot(
                axum::http::Request::get("/protected")
                    .header("Authorization", format!("bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // "bearer" (lowercase) doesn't match "Bearer" prefix check
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn authenticated_user_extractor_without_middleware_returns_401() {
        // Route using AuthenticatedUser but WITHOUT the auth middleware layer
        let state = build_test_state();
        let app = Router::new()
            .route("/no-middleware", get(echo_sub))
            .with_state(state);

        let resp = app
            .oneshot(
                axum::http::Request::get("/no-middleware")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "Not authenticated");
    }

    #[tokio::test]
    async fn valid_token_passes_claims_to_handler() {
        let state = build_test_state();
        let app = protected_app(state);

        let token = issue_token("test-secret-at-least-32-chars-long!!");
        let resp = app
            .oneshot(
                axum::http::Request::get("/protected")
                    .header("Authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "alice");
    }
}
