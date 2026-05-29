use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;

use crate::middleware::auth::AuthenticatedUser;
use crate::models::mfa::MfaStoreError;
use crate::services::step_up::{
    claims_step_up_key, local_step_up_required, step_up_expires_at, step_up_required_error,
};
use crate::services::AppState;
use shared::dto::audit::{AuditAction, AuditOutcome};
use shared::dto::auth::{
    MfaStatusResponse, RecoveryCodeVerifyRequest, RecoveryCodeVerifyResponse,
    RecoveryCodesGenerateResponse, TotpEnrollConfirmRequest, TotpEnrollConfirmResponse,
    TotpEnrollStartRequest, TotpEnrollStartResponse, TotpVerifyRequest, TotpVerifyResponse,
    WebAuthnRegisterFinishRequest, WebAuthnRegisterFinishResponse, WebAuthnRegisterStartRequest,
    WebAuthnRegisterStartResponse, WebAuthnVerifyFinishRequest, WebAuthnVerifyResponse,
    WebAuthnVerifyStartRequest, WebAuthnVerifyStartResponse,
};
use shared::errors::ApiError;

type RouteResult<T> = Result<Json<T>, (StatusCode, Json<ApiError>)>;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/auth/mfa/status", get(status))
        .route("/api/auth/mfa/totp/start", post(totp_start))
        .route("/api/auth/mfa/totp/confirm", post(totp_confirm))
        .route("/api/auth/mfa/totp/verify", post(totp_verify))
        .route(
            "/api/auth/mfa/recovery-codes/generate",
            post(recovery_codes_generate),
        )
        .route(
            "/api/auth/mfa/recovery-codes/verify",
            post(recovery_code_verify),
        )
        .route(
            "/api/auth/mfa/webauthn/register/start",
            post(webauthn_register_start),
        )
        .route(
            "/api/auth/mfa/webauthn/register/finish",
            post(webauthn_register_finish),
        )
        .route(
            "/api/auth/mfa/webauthn/verify/start",
            post(webauthn_verify_start),
        )
        .route(
            "/api/auth/mfa/webauthn/verify/finish",
            post(webauthn_verify_finish),
        )
}

async fn status(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
) -> RouteResult<MfaStatusResponse> {
    mfa_status_response(&state, &claims.sub).map(Json)
}

async fn totp_start(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    Json(req): Json<TotpEnrollStartRequest>,
) -> RouteResult<TotpEnrollStartResponse> {
    require_audit_healthy(&state)?;

    let result =
        state
            .mfa_store
            .start_totp_enrollment(&claims.sub, &claims.email, req.label.as_deref());

    match result {
        Ok(resp) => {
            state
                .audit_service
                .event(
                    &claims.sub,
                    AuditAction::MfaTotpEnroll,
                    AuditOutcome::Success,
                )
                .optional_metadata(Some(serde_json::json!({
                    "stage": "start",
                    "factor_id": &resp.factor_id,
                    "kind": "totp",
                })))
                .commit_or_fail()
                .map_err(|_| audit_failed_response("TOTP enrollment audit failed"))?;
            Ok(Json(resp))
        }
        Err(err) => {
            audit_totp_enroll_failure(&state, &claims.sub, "start", None, &err);
            Err(mfa_store_error_response(err))
        }
    }
}

async fn totp_confirm(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    Json(req): Json<TotpEnrollConfirmRequest>,
) -> RouteResult<TotpEnrollConfirmResponse> {
    require_audit_healthy(&state)?;

    let result = state
        .mfa_store
        .confirm_totp_enrollment(&claims.sub, &req.factor_id, &req.code);

    match result {
        Ok(()) => {
            state
                .audit_service
                .event(
                    &claims.sub,
                    AuditAction::MfaTotpEnroll,
                    AuditOutcome::Success,
                )
                .optional_metadata(Some(serde_json::json!({
                    "stage": "confirm",
                    "factor_id": &req.factor_id,
                    "kind": "totp",
                })))
                .commit_or_fail()
                .map_err(|_| audit_failed_response("TOTP enrollment audit failed"))?;
            let status = mfa_status_response(&state, &claims.sub)?;
            Ok(Json(TotpEnrollConfirmResponse {
                factor_id: req.factor_id,
                enrolled: true,
                status,
            }))
        }
        Err(err) => {
            audit_totp_enroll_failure(
                &state,
                &claims.sub,
                "confirm",
                Some(req.factor_id.as_str()),
                &err,
            );
            Err(mfa_store_error_response(err))
        }
    }
}

async fn webauthn_register_start(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    Json(req): Json<WebAuthnRegisterStartRequest>,
) -> RouteResult<WebAuthnRegisterStartResponse> {
    require_audit_healthy(&state)?;

    if local_step_up_required(&state, &claims.sub, &claims_step_up_key(&claims))
        .map_err(mfa_step_up_unavailable_response)?
    {
        audit_webauthn_enroll_denied(&state, &claims.sub, "start", None);
        return Err((StatusCode::FORBIDDEN, Json(step_up_required_error())));
    }

    let result = state.mfa_store.start_webauthn_registration_with_precommit(
        &claims.sub,
        &req.origin,
        req.label.as_deref(),
        |started| {
            state
                .audit_service
                .event(
                    &claims.sub,
                    AuditAction::MfaWebAuthnEnroll,
                    AuditOutcome::Success,
                )
                .optional_metadata(Some(serde_json::json!({
                    "stage": "start",
                    "factor_id": &started.factor_id,
                    "kind": "web_authn",
                    "origin": &req.origin,
                })))
                .commit_or_fail()
                .is_ok()
        },
    );
    match result {
        Ok(Some(started)) => Ok(Json(WebAuthnRegisterStartResponse {
            factor_id: started.factor_id,
            public_key: started.public_key,
            expires_at: (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
        })),
        Ok(None) => Err(audit_failed_response("WebAuthn enrollment audit failed")),
        Err(err) => {
            audit_webauthn_enroll_failure(&state, &claims.sub, "start", None, &err);
            Err(mfa_store_error_response(err))
        }
    }
}

async fn webauthn_register_finish(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    Json(req): Json<WebAuthnRegisterFinishRequest>,
) -> RouteResult<WebAuthnRegisterFinishResponse> {
    require_audit_healthy(&state)?;

    if local_step_up_required(&state, &claims.sub, &claims_step_up_key(&claims))
        .map_err(mfa_step_up_unavailable_response)?
    {
        audit_webauthn_enroll_denied(&state, &claims.sub, "finish", Some(req.factor_id.as_str()));
        return Err((StatusCode::FORBIDDEN, Json(step_up_required_error())));
    }

    let credential =
        match serde_json::from_value::<passkey_auth::RegistrationResponse>(req.credential) {
            Ok(credential) => credential,
            Err(_) => {
                let err = MfaStoreError::InvalidWebAuthnRegistration;
                audit_webauthn_enroll_failure(
                    &state,
                    &claims.sub,
                    "finish",
                    Some(req.factor_id.as_str()),
                    &err,
                );
                return Err(mfa_store_error_response(err));
            }
        };
    let result = state.mfa_store.finish_webauthn_registration_with_precommit(
        &claims.sub,
        &req.factor_id,
        &credential,
        |finished| {
            state
                .audit_service
                .event(
                    &claims.sub,
                    AuditAction::MfaWebAuthnEnroll,
                    AuditOutcome::Success,
                )
                .optional_metadata(Some(serde_json::json!({
                    "stage": "finish",
                    "factor_id": &finished.factor_id,
                    "kind": "web_authn",
                })))
                .commit_or_fail()
                .is_ok()
        },
    );
    match result {
        Ok(Some(finished)) => {
            let status = mfa_status_response(&state, &claims.sub)?;
            Ok(Json(WebAuthnRegisterFinishResponse {
                factor_id: finished.factor_id,
                credential_id: finished.credential_id,
                enrolled: true,
                status,
            }))
        }
        Ok(None) => Err(audit_failed_response("WebAuthn enrollment audit failed")),
        Err(err) => {
            audit_webauthn_enroll_failure(
                &state,
                &claims.sub,
                "finish",
                Some(req.factor_id.as_str()),
                &err,
            );
            Err(mfa_store_error_response(err))
        }
    }
}

async fn webauthn_verify_start(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    Json(req): Json<WebAuthnVerifyStartRequest>,
) -> RouteResult<WebAuthnVerifyStartResponse> {
    require_audit_healthy(&state)?;

    let result = state
        .mfa_store
        .start_webauthn_authentication_with_precommit(&claims.sub, &req.origin, |started| {
            state
                .audit_service
                .event(
                    &claims.sub,
                    AuditAction::MfaWebAuthnVerify,
                    AuditOutcome::Success,
                )
                .optional_metadata(Some(serde_json::json!({
                    "stage": "start",
                    "challenge_id": &started.challenge_id,
                    "kind": "web_authn",
                    "origin": &req.origin,
                })))
                .commit_or_fail()
                .is_ok()
        });
    match result {
        Ok(Some(started)) => Ok(Json(WebAuthnVerifyStartResponse {
            challenge_id: started.challenge_id,
            public_key: started.public_key,
            expires_at: (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
        })),
        Ok(None) => Err(audit_failed_response("WebAuthn verification audit failed")),
        Err(err) => {
            audit_webauthn_verify_failure(&state, &claims.sub, "start", None, &err);
            Err(mfa_store_error_response(err))
        }
    }
}

async fn webauthn_verify_finish(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    Json(req): Json<WebAuthnVerifyFinishRequest>,
) -> RouteResult<WebAuthnVerifyResponse> {
    require_audit_healthy(&state)?;

    let credential =
        match serde_json::from_value::<passkey_auth::AuthenticationResponse>(req.credential) {
            Ok(credential) => credential,
            Err(_) => {
                let err = MfaStoreError::InvalidWebAuthnAuthentication;
                audit_webauthn_verify_failure(
                    &state,
                    &claims.sub,
                    "finish",
                    Some(req.challenge_id.as_str()),
                    &err,
                );
                return Err(mfa_store_error_response(err));
            }
        };
    let result = state
        .mfa_store
        .finish_webauthn_authentication_with_precommit(
            &claims.sub,
            &req.challenge_id,
            &credential,
            |verified| {
                state
                    .audit_service
                    .event(
                        &claims.sub,
                        AuditAction::MfaWebAuthnVerify,
                        AuditOutcome::Success,
                    )
                    .optional_metadata(Some(serde_json::json!({
                        "stage": "finish",
                        "factor_id": &verified.factor_id,
                        "kind": "web_authn",
                    })))
                    .commit_or_fail()
                    .is_ok()
            },
        );
    match result {
        Ok(Some(verified)) => {
            let status = mfa_status_response(&state, &claims.sub)?;
            let verified_at = chrono::Utc::now();
            let step_up_expires_at = step_up_expires_at(verified_at);
            state
                .step_up_sessions
                .mark_verified_until(&claims_step_up_key(&claims), step_up_expires_at);
            Ok(Json(WebAuthnVerifyResponse {
                factor_id: verified.factor_id,
                credential_id: verified.credential_id,
                verified: true,
                verified_at: verified_at.to_rfc3339(),
                step_up_expires_at: step_up_expires_at.to_rfc3339(),
                status,
            }))
        }
        Ok(None) => Err(audit_failed_response("WebAuthn verification audit failed")),
        Err(err) => {
            audit_webauthn_verify_failure(
                &state,
                &claims.sub,
                "finish",
                Some(req.challenge_id.as_str()),
                &err,
            );
            Err(mfa_store_error_response(err))
        }
    }
}

async fn totp_verify(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    Json(req): Json<TotpVerifyRequest>,
) -> RouteResult<TotpVerifyResponse> {
    require_audit_healthy(&state)?;

    let result = state.mfa_store.verify_totp(&claims.sub, &req.code);

    match result {
        Ok(verified) => {
            state
                .audit_service
                .event(
                    &claims.sub,
                    AuditAction::MfaTotpVerify,
                    AuditOutcome::Success,
                )
                .optional_metadata(Some(serde_json::json!({
                    "factor_id": &verified.factor_id,
                    "kind": "totp",
                })))
                .commit_or_fail()
                .map_err(|_| audit_failed_response("TOTP verification audit failed"))?;
            let status = mfa_status_response(&state, &claims.sub)?;
            let verified_at = chrono::Utc::now();
            let step_up_expires_at = step_up_expires_at(verified_at);
            state
                .step_up_sessions
                .mark_verified_until(&claims_step_up_key(&claims), step_up_expires_at);
            Ok(Json(TotpVerifyResponse {
                factor_id: verified.factor_id,
                verified: true,
                verified_at: verified_at.to_rfc3339(),
                step_up_expires_at: step_up_expires_at.to_rfc3339(),
                status,
            }))
        }
        Err(err) => {
            audit_totp_verify_failure(&state, &claims.sub, &err);
            Err(mfa_store_error_response(err))
        }
    }
}

async fn recovery_codes_generate(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
) -> RouteResult<RecoveryCodesGenerateResponse> {
    require_audit_healthy(&state)?;

    if local_step_up_required(&state, &claims.sub, &claims_step_up_key(&claims))
        .map_err(mfa_step_up_unavailable_response)?
    {
        state
            .audit_service
            .event(
                &claims.sub,
                AuditAction::MfaRecoveryCodesGenerate,
                AuditOutcome::Denied,
            )
            .error(Some("step_up_required"))
            .commit_best_effort();
        return Err((StatusCode::FORBIDDEN, Json(step_up_required_error())));
    }

    let result = state
        .mfa_store
        .generate_recovery_codes_with_precommit(&claims.sub, |codes| {
            state
                .audit_service
                .event(
                    &claims.sub,
                    AuditAction::MfaRecoveryCodesGenerate,
                    AuditOutcome::Success,
                )
                .optional_metadata(Some(serde_json::json!({
                    "count": codes.len(),
                })))
                .commit_or_fail()
                .is_ok()
        });
    match result {
        Ok(Some(generated)) => {
            let status = mfa_status_response(&state, &claims.sub)?;
            Ok(Json(RecoveryCodesGenerateResponse {
                codes: generated.codes,
                generated_at: chrono::Utc::now().to_rfc3339(),
                remaining_codes: generated.remaining_codes,
                status,
            }))
        }
        Ok(None) => Err(audit_failed_response(
            "Recovery code generation audit failed",
        )),
        Err(err) => {
            audit_recovery_codes_generate_failure(&state, &claims.sub, &err);
            Err(mfa_store_error_response(err))
        }
    }
}

async fn recovery_code_verify(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    Json(req): Json<RecoveryCodeVerifyRequest>,
) -> RouteResult<RecoveryCodeVerifyResponse> {
    require_audit_healthy(&state)?;

    let result =
        state
            .mfa_store
            .verify_recovery_code_with_precommit(&claims.sub, &req.code, |remaining| {
                state
                    .audit_service
                    .event(
                        &claims.sub,
                        AuditAction::MfaRecoveryCodeVerify,
                        AuditOutcome::Success,
                    )
                    .optional_metadata(Some(serde_json::json!({
                        "remaining_codes": remaining,
                    })))
                    .commit_or_fail()
                    .is_ok()
            });
    match result {
        Ok(Some(verified)) => {
            let status = mfa_status_response(&state, &claims.sub)?;
            let verified_at = chrono::Utc::now();
            let step_up_expires_at = step_up_expires_at(verified_at);
            state
                .step_up_sessions
                .mark_verified_until(&claims_step_up_key(&claims), step_up_expires_at);
            Ok(Json(RecoveryCodeVerifyResponse {
                verified: true,
                verified_at: verified_at.to_rfc3339(),
                step_up_expires_at: step_up_expires_at.to_rfc3339(),
                remaining_codes: verified.remaining_codes,
                status,
            }))
        }
        Ok(None) => Err(audit_failed_response(
            "Recovery code verification audit failed",
        )),
        Err(err) => {
            audit_recovery_code_verify_failure(&state, &claims.sub, &err);
            Err(mfa_store_error_response(err))
        }
    }
}

fn mfa_step_up_unavailable_response(err: impl std::fmt::Display) -> (StatusCode, Json<ApiError>) {
    tracing::error!(error = %err, "Failed to evaluate MFA step-up status");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ApiError::internal("MFA step-up status unavailable")),
    )
}

fn mfa_status_response(
    state: &AppState,
    user_id: &str,
) -> Result<MfaStatusResponse, (StatusCode, Json<ApiError>)> {
    let provider_step_up_configured = provider_step_up_controls_configured(&state.config);
    let factors = state.mfa_store.factor_statuses(user_id).map_err(|err| {
        tracing::error!(error = %err, "Failed to load MFA factor status");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError::internal("MFA status unavailable")),
        )
    })?;
    let local_step_up_available = factors
        .iter()
        .any(|factor| factor.available && factor.enrolled);
    let recovery_codes_remaining =
        state
            .mfa_store
            .recovery_codes_remaining(user_id)
            .map_err(|err| {
                tracing::error!(error = %err, "Failed to load MFA recovery code status");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiError::internal("MFA status unavailable")),
                )
            })?;
    let message = if state.mfa_store.totp_enrollment_available() {
        "Local MFA factor store, TOTP enrollment, and passkey enrollment are configured. Step-up enforcement protects sensitive local actions."
    } else if state.mfa_store.is_enabled() {
        "Local MFA factor store and passkey enrollment are configured, but TOTP enrollment requires mfa_secret_key."
    } else if provider_step_up_configured {
        "OIDC provider MFA/re-auth controls are configured. Local TOTP/WebAuthn enrollment is not configured yet."
    } else {
        "No OIDC provider MFA/re-auth controls are configured. Local TOTP/WebAuthn enrollment is not configured yet."
    };

    Ok(MfaStatusResponse {
        user_id: user_id.into(),
        provider_step_up_configured,
        local_step_up_available,
        step_up_required: false,
        factors,
        recovery_codes_remaining,
        message: message.into(),
    })
}

fn require_audit_healthy(state: &AppState) -> Result<(), (StatusCode, Json<ApiError>)> {
    if state.audit_service.is_healthy() {
        Ok(())
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal("Audit logging unavailable")),
        ))
    }
}

fn audit_failed_response(message: &'static str) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ApiError::internal(message)),
    )
}

fn audit_totp_enroll_failure(
    state: &AppState,
    actor: &str,
    stage: &str,
    factor_id: Option<&str>,
    err: &MfaStoreError,
) {
    state
        .audit_service
        .event(actor, AuditAction::MfaTotpEnroll, AuditOutcome::Failure)
        .error(Some(&err.to_string()))
        .optional_metadata(Some(serde_json::json!({
            "stage": stage,
            "factor_id": factor_id,
            "kind": "totp",
        })))
        .commit_best_effort();
}

fn audit_totp_verify_failure(state: &AppState, actor: &str, err: &MfaStoreError) {
    state
        .audit_service
        .event(actor, AuditAction::MfaTotpVerify, AuditOutcome::Failure)
        .error(Some(&err.to_string()))
        .optional_metadata(Some(serde_json::json!({
            "kind": "totp",
        })))
        .commit_best_effort();
}

fn audit_webauthn_enroll_failure(
    state: &AppState,
    actor: &str,
    stage: &str,
    factor_id: Option<&str>,
    err: &MfaStoreError,
) {
    state
        .audit_service
        .event(actor, AuditAction::MfaWebAuthnEnroll, AuditOutcome::Failure)
        .error(Some(&err.to_string()))
        .optional_metadata(Some(serde_json::json!({
            "stage": stage,
            "factor_id": factor_id,
            "kind": "web_authn",
        })))
        .commit_best_effort();
}

fn audit_webauthn_enroll_denied(
    state: &AppState,
    actor: &str,
    stage: &str,
    factor_id: Option<&str>,
) {
    state
        .audit_service
        .event(actor, AuditAction::MfaWebAuthnEnroll, AuditOutcome::Denied)
        .error(Some("step_up_required"))
        .optional_metadata(Some(serde_json::json!({
            "stage": stage,
            "factor_id": factor_id,
            "kind": "web_authn",
        })))
        .commit_best_effort();
}

fn audit_webauthn_verify_failure(
    state: &AppState,
    actor: &str,
    stage: &str,
    challenge_id: Option<&str>,
    err: &MfaStoreError,
) {
    state
        .audit_service
        .event(actor, AuditAction::MfaWebAuthnVerify, AuditOutcome::Failure)
        .error(Some(&err.to_string()))
        .optional_metadata(Some(serde_json::json!({
            "stage": stage,
            "challenge_id": challenge_id,
            "kind": "web_authn",
        })))
        .commit_best_effort();
}

fn audit_recovery_codes_generate_failure(state: &AppState, actor: &str, err: &MfaStoreError) {
    state
        .audit_service
        .event(
            actor,
            AuditAction::MfaRecoveryCodesGenerate,
            AuditOutcome::Failure,
        )
        .error(Some(&err.to_string()))
        .commit_best_effort();
}

fn audit_recovery_code_verify_failure(state: &AppState, actor: &str, err: &MfaStoreError) {
    state
        .audit_service
        .event(
            actor,
            AuditAction::MfaRecoveryCodeVerify,
            AuditOutcome::Failure,
        )
        .error(Some(&err.to_string()))
        .commit_best_effort();
}

fn mfa_store_error_response(err: MfaStoreError) -> (StatusCode, Json<ApiError>) {
    match err {
        MfaStoreError::StoreUnavailable | MfaStoreError::TotpSecretKeyUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal(err.to_string())),
        ),
        MfaStoreError::NoActiveTotpFactor | MfaStoreError::NoActiveWebAuthnFactor => (
            StatusCode::CONFLICT,
            Json(ApiError::new("CONFLICT", err.to_string())),
        ),
        MfaStoreError::TotpAlreadyEnrolled => (
            StatusCode::CONFLICT,
            Json(ApiError::new("CONFLICT", err.to_string())),
        ),
        MfaStoreError::TotpEnrollmentNotFound => (
            StatusCode::GONE,
            Json(ApiError::new("EXPIRED", err.to_string())),
        ),
        MfaStoreError::InvalidTotpCode => (
            StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request(err.to_string())),
        ),
        MfaStoreError::TotpCodeReplayed => (
            StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request(err.to_string())),
        ),
        MfaStoreError::InvalidRecoveryCode => (
            StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request(err.to_string())),
        ),
        MfaStoreError::InvalidWebAuthnOrigin
        | MfaStoreError::InvalidWebAuthnRegistration
        | MfaStoreError::InvalidWebAuthnAuthentication => (
            StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request(err.to_string())),
        ),
        MfaStoreError::WebAuthnRegistrationNotFound
        | MfaStoreError::WebAuthnAuthenticationNotFound => (
            StatusCode::GONE,
            Json(ApiError::new("EXPIRED", err.to_string())),
        ),
        MfaStoreError::RecoveryCodesRequireTotp => (
            StatusCode::CONFLICT,
            Json(ApiError::new("CONFLICT", err.to_string())),
        ),
        other => {
            tracing::error!(error = %other, "MFA store operation failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::internal("MFA operation failed")),
            )
        }
    }
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
    use crate::config::{AppConfig, AwsConfig, JwtConfig, McpConfig, OidcConfig};

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
            database_connections: std::collections::HashMap::new(),
            dev_mode: true,
            mock_aws_data: None,
            entitlements_file: None,
            entitlements_database_url: None,
            mfa_database_url: None,
            mfa_secret_key: None,
            audit_log: None,
            audit_export: Default::default(),
            mcp: McpConfig::default(),
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
