use axum::{extract::State, routing::{get, post}, Json, Router};
use std::sync::Arc;

use crate::services::{auth::AuthService, AppState};
use shared::dto::audit::{AuditAction, AuditOutcome};
use shared::dto::auth::*;
use shared::errors::ApiError;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/health", get(health))
        .route("/auth/dev-login", post(dev_login))
        .route("/auth/pkce/start", post(pkce_start))
        .route("/auth/pkce/exchange", post(pkce_exchange))
        .route("/auth/device-code/start", post(device_code_start))
        .route("/auth/device-code/poll", post(device_code_poll))
        .route("/auth/refresh", post(refresh_token))
}

async fn health(
    State(state): State<Arc<AppState>>,
) -> axum::http::StatusCode {
    if state.audit_service.is_healthy() && state.is_ready() {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn dev_login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DevLoginRequest>,
) -> Result<Json<DevLoginResponse>, (axum::http::StatusCode, Json<ApiError>)> {
    if !state.config.dev_mode {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("Dev login disabled in production")),
        ));
    }

    // Fail-closed: block login if durable audit sink is broken
    if !state.audit_service.is_healthy() {
        return Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal("Audit logging unavailable")),
        ));
    }

    let auth_service = AuthService::new(state.config.clone());
    match auth_service.dev_login(&req) {
        Ok(resp) => {
            state.audit_service.log_event(
                &req.username,
                AuditAction::Login,
                AuditOutcome::Success,
                None,
                None,
                None,
                None,
            ).map_err(|_| (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::internal("Audit logging failed — login blocked")),
            ))?;
            Ok(Json(resp))
        }
        Err(e) => {
            let _ = state.audit_service.log_event(
                &req.username,
                AuditAction::Login,
                AuditOutcome::Failure,
                None,
                None,
                None,
                Some(&e.to_string()),
            );
            Err((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::internal(e.to_string())),
            ))
        }
    }
}

async fn pkce_start(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PkceAuthRequest>,
) -> Result<Json<PkceAuthResponse>, (axum::http::StatusCode, Json<ApiError>)> {
    let auth_service = AuthService::new(state.config.clone());

    // Discover/resolve OIDC endpoints
    let endpoints = state.oidc_client.endpoints().await.map_err(|e| {
        tracing::error!(error = %e, "OIDC endpoint discovery failed");
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal(format!("OIDC discovery failed: {}", e))),
        )
    })?;

    Ok(Json(auth_service.build_pkce_auth_url(&req, endpoints)))
}

async fn pkce_exchange(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TokenExchangeRequest>,
) -> Result<Json<TokenResponse>, (axum::http::StatusCode, Json<ApiError>)> {
    if !state.audit_service.is_healthy() {
        return Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal("Audit logging unavailable")),
        ));
    }
    if state.config.dev_mode {
        // Dev mode: skip OIDC exchange, issue a token directly
        let auth_service = AuthService::new(state.config.clone());
        let identity = UserIdentity {
            user_id: "pkce-user".into(),
            email: "pkce-user@dev.local".into(),
            display_name: "PKCE Dev User".into(),
            groups: vec!["platform-engineering".into()],
            email_verified: true,
        };
        return auth_service.issue_token(&identity).map(Json).map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::internal(e.to_string())),
            )
        });
    }

    let auth_service = AuthService::new(state.config.clone());

    // Validate PKCE state to prevent CSRF
    if !auth_service.verify_pkce_state(&req.state) {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request("Invalid or tampered PKCE state parameter")),
        ));
    }

    let store = state.entitlement_store.read().await;

    let token = auth_service
        .exchange_oidc_code(
            &state.oidc_client,
            &req.code,
            &req.code_verifier,
            &req.redirect_uri,
            &store,
        )
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "PKCE code exchange failed");
            let _ = state.audit_service.log_event(
                "unknown",
                AuditAction::Login,
                AuditOutcome::Failure,
                None,
                None,
                None,
                Some(&e.to_string()),
            );
            (
                axum::http::StatusCode::BAD_REQUEST,
                Json(ApiError::bad_request(format!(
                    "Code exchange failed: {}",
                    e
                ))),
            )
        })?;

    // Audit the successful login — fail-closed if audit write fails
    if let Ok(claims) = auth_service.validate_token(&token.access_token) {
        state.audit_service.log_event(
            &claims.sub,
            AuditAction::Login,
            AuditOutcome::Success,
            None,
            None,
            None,
            Some("pkce"),
        ).map_err(|_| (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal("Audit logging failed — login blocked")),
        ))?;
    }

    Ok(Json(token))
}

async fn device_code_start(
    State(state): State<Arc<AppState>>,
    Json(_req): Json<DeviceCodeRequest>,
) -> Result<Json<DeviceCodeResponse>, (axum::http::StatusCode, Json<ApiError>)> {
    if state.config.dev_mode {
        // Dev mode: return mock device code that auto-approves
        return Ok(Json(DeviceCodeResponse {
            device_code: uuid::Uuid::new_v4().to_string(),
            user_code: "DEV-1234".into(),
            verification_uri: "http://localhost:8443/device".into(),
            verification_uri_complete: Some(
                "http://localhost:8443/device?user_code=DEV-1234".into(),
            ),
            expires_in: 600,
            interval: 5,
        }));
    }

    let oidc_resp = state.oidc_client.device_authorize().await.map_err(|e| {
        tracing::error!(error = %e, "Device authorization failed");
        (
            axum::http::StatusCode::BAD_GATEWAY,
            Json(ApiError::internal(format!(
                "Device authorization failed: {}",
                e
            ))),
        )
    })?;

    Ok(Json(DeviceCodeResponse {
        device_code: oidc_resp.device_code,
        user_code: oidc_resp.user_code,
        verification_uri: oidc_resp.verification_uri,
        verification_uri_complete: oidc_resp.verification_uri_complete,
        expires_in: oidc_resp.expires_in,
        interval: oidc_resp.interval,
    }))
}

async fn device_code_poll(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DeviceCodePollRequest>,
) -> Result<Json<DeviceCodePollResponse>, (axum::http::StatusCode, Json<ApiError>)> {
    if !state.audit_service.is_healthy() {
        return Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal("Audit logging unavailable")),
        ));
    }
    if state.config.dev_mode {
        // Dev mode: auto-approve on first poll
        let auth_service = AuthService::new(state.config.clone());
        let identity = UserIdentity {
            user_id: "device-user".into(),
            email: "device-user@dev.local".into(),
            display_name: "Device Dev User".into(),
            groups: vec!["platform-engineering".into()],
            email_verified: true,
        };
        return match auth_service.issue_token(&identity) {
            Ok(token) => Ok(Json(DeviceCodePollResponse::Complete {
                access_token: token.access_token,
                expires_in: token.expires_in,
            })),
            Err(_) => Ok(Json(DeviceCodePollResponse::Pending)),
        };
    }

    use crate::services::oidc::DevicePollResult;

    let result = state
        .oidc_client
        .device_poll(&req.device_code)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("expired") {
                (
                    axum::http::StatusCode::GONE,
                    Json(ApiError::new("EXPIRED", msg)),
                )
            } else if msg.contains("denied") {
                (
                    axum::http::StatusCode::FORBIDDEN,
                    Json(ApiError::forbidden(msg)),
                )
            } else {
                (
                    axum::http::StatusCode::BAD_GATEWAY,
                    Json(ApiError::internal(msg)),
                )
            }
        })?;

    match result {
        DevicePollResult::Pending => Ok(Json(DeviceCodePollResponse::Pending)),
        DevicePollResult::SlowDown => Ok(Json(DeviceCodePollResponse::SlowDown)),
        DevicePollResult::Complete(oidc_tokens) => {
            // Got tokens — extract identity and issue internal JWT
            let auth_service = AuthService::new(state.config.clone());
            let store = state.entitlement_store.read().await;

            if let Some(ref id_token) = oidc_tokens.id_token {
                let oidc_claims =
                    state.oidc_client.decode_and_validate_id_token(id_token).await
                        .map_err(|e| {
                            (
                                axum::http::StatusCode::BAD_GATEWAY,
                                Json(ApiError::internal(format!(
                                    "Failed to decode id_token: {}",
                                    e
                                ))),
                            )
                        })?;

                let email = oidc_claims
                    .email
                    .clone()
                    .unwrap_or_else(|| format!("{}@unknown", oidc_claims.sub));
                let name = oidc_claims
                    .name
                    .clone()
                    .unwrap_or_else(|| oidc_claims.sub.clone());
                let email_verified = oidc_claims.email_verified.unwrap_or(false);
                let ent = store.evaluate(&oidc_claims.sub, &email, &name, email_verified);
                let identity = AuthService::identity_from_oidc_claims(&oidc_claims, ent.groups);

                let token = auth_service.issue_token(&identity).map_err(|e| {
                    (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ApiError::internal(e.to_string())),
                    )
                })?;

                state.audit_service.log_event(
                    &oidc_claims.sub,
                    AuditAction::Login,
                    AuditOutcome::Success,
                    None,
                    None,
                    None,
                    Some("device_code"),
                ).map_err(|_| (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    Json(ApiError::internal("Audit logging failed — login blocked")),
                ))?;

                Ok(Json(DeviceCodePollResponse::Complete {
                    access_token: token.access_token,
                    expires_in: token.expires_in,
                }))
            } else {
                // No id_token — we cannot issue a valid internal JWT without
                // identity claims. Returning the IdP's raw access_token would
                // fail at validate_token on every subsequent API call.
                tracing::error!(
                    "OIDC device-code response missing id_token — \
                     ensure the provider is configured to return id_token \
                     for the device_code grant (scope must include 'openid')"
                );
                Err((
                    axum::http::StatusCode::BAD_GATEWAY,
                    Json(ApiError::internal(
                        "OIDC provider did not return an id_token in device-code response. \
                         Ensure 'openid' scope is requested.",
                    )),
                ))
            }
        }
    }
}

async fn refresh_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshTokenRequest>,
) -> Result<Json<TokenResponse>, (axum::http::StatusCode, Json<ApiError>)> {
    if !state.audit_service.is_healthy() {
        return Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal("Audit logging unavailable")),
        ));
    }
    if state.config.dev_mode {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request(
                "Token refresh not supported in dev mode",
            )),
        ));
    }

    let oidc_tokens = state
        .oidc_client
        .refresh_token(&req.refresh_token)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Token refresh failed");
            (
                axum::http::StatusCode::BAD_REQUEST,
                Json(ApiError::bad_request(format!(
                    "Token refresh failed: {}",
                    e
                ))),
            )
        })?;

    // Re-derive identity from the refreshed id_token
    let auth_service = AuthService::new(state.config.clone());

    if let Some(ref id_token) = oidc_tokens.id_token {
        let oidc_claims = state.oidc_client.decode_and_validate_id_token(id_token).await
            .map_err(|e| {
            (
                axum::http::StatusCode::BAD_GATEWAY,
                Json(ApiError::internal(format!(
                    "Failed to decode refreshed id_token: {}",
                    e
                ))),
            )
        })?;

        let store = state.entitlement_store.read().await;
        let email = oidc_claims
            .email
            .clone()
            .unwrap_or_else(|| format!("{}@unknown", oidc_claims.sub));
        let name = oidc_claims
            .name
            .clone()
            .unwrap_or_else(|| oidc_claims.sub.clone());
        let email_verified = oidc_claims.email_verified.unwrap_or(false);
        let ent = store.evaluate(&oidc_claims.sub, &email, &name, email_verified);
        let identity = AuthService::identity_from_oidc_claims(&oidc_claims, ent.groups);

        // Keep the caller's refresh token if the IdP didn't rotate it
        let effective_refresh = oidc_tokens
            .refresh_token
            .or(Some(req.refresh_token.clone()));

        let token = auth_service
            .issue_token_with_refresh(&identity, effective_refresh)
            .map_err(|e| {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiError::internal(e.to_string())),
                )
            })?;

        // Audit the refresh — fail-closed
        state.audit_service.log_event(
            &oidc_claims.sub,
            AuditAction::Login,
            AuditOutcome::Success,
            None,
            None,
            None,
            Some("refresh"),
        ).map_err(|_| (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal("Audit logging failed — refresh blocked")),
        ))?;

        Ok(Json(token))
    } else {
        Err((
            axum::http::StatusCode::BAD_GATEWAY,
            Json(ApiError::internal(
                "OIDC provider did not return an id_token on refresh. \
                 Ensure the provider returns id_token for the refresh_token \
                 grant (scope must include 'openid').",
            )),
        ))
    }
}
