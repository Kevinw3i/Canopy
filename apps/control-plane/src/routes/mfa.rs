use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use std::sync::Arc;

use crate::middleware::auth::AuthenticatedUser;
use crate::services::AppState;
use shared::dto::auth::MfaStatusResponse;
use shared::errors::ApiError;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/auth/mfa/status", get(status))
}

async fn status(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
) -> Result<Json<MfaStatusResponse>, (StatusCode, Json<ApiError>)> {
    let provider_step_up_configured = provider_step_up_controls_configured(&state.config);
    let factors = state
        .mfa_store
        .factor_statuses(&claims.sub)
        .map_err(|err| {
            tracing::error!(error = %err, "Failed to load MFA factor status");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::internal("MFA status unavailable")),
            )
        })?;
    let local_step_up_available = factors
        .iter()
        .any(|factor| factor.available && factor.enrolled);
    let message = if state.mfa_store.is_enabled() {
        "Local MFA factor store is configured. TOTP/WebAuthn enrollment and step-up enforcement are not enabled yet."
    } else if provider_step_up_configured {
        "OIDC provider MFA/re-auth controls are configured. Local TOTP/WebAuthn enrollment is not configured yet."
    } else {
        "No OIDC provider MFA/re-auth controls are configured. Local TOTP/WebAuthn enrollment is not configured yet."
    };

    Ok(Json(MfaStatusResponse {
        user_id: claims.sub,
        provider_step_up_configured,
        local_step_up_available,
        step_up_required: false,
        factors,
        message: message.into(),
    }))
}

fn provider_step_up_controls_configured(config: &crate::config::AppConfig) -> bool {
    !config.oidc.acr_values.is_empty()
        || config.oidc.prompt.as_deref().is_some_and(|prompt| {
            prompt
                .split_ascii_whitespace()
                .any(|part| matches!(part.to_ascii_lowercase().as_str(), "login"))
        })
        || config.oidc.max_age_seconds.is_some()
        || !config.oidc.required_acr_values.is_empty()
        || !config.oidc.required_amr_values.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, AwsConfig, JwtConfig, OidcConfig};

    fn test_config() -> AppConfig {
        AppConfig {
            bind_address: "127.0.0.1:8443".into(),
            oidc: OidcConfig {
                issuer_url: "https://example.com".into(),
                client_id: "test-client".into(),
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
            mfa_database_url: None,
            audit_log: None,
            audit_export: Default::default(),
            cors_allowed_origins: vec![],
        }
    }

    #[test]
    fn provider_step_up_controls_detect_claim_requirements() {
        let mut config = test_config();
        assert!(!provider_step_up_controls_configured(&config));

        config.oidc.required_amr_values = vec!["mfa".into()];
        assert!(provider_step_up_controls_configured(&config));
    }

    #[test]
    fn provider_step_up_controls_detect_auth_request_controls() {
        let mut config = test_config();
        config.oidc.acr_values = vec!["urn:mfa".into()];
        assert!(provider_step_up_controls_configured(&config));

        config.oidc.acr_values.clear();
        config.oidc.max_age_seconds = Some(300);
        assert!(provider_step_up_controls_configured(&config));
    }

    #[test]
    fn provider_step_up_controls_prompt_requires_login() {
        let mut config = test_config();
        config.oidc.prompt = Some("select_account consent".into());
        assert!(!provider_step_up_controls_configured(&config));

        config.oidc.prompt = Some("login select_account".into());
        assert!(provider_step_up_controls_configured(&config));
    }
}
