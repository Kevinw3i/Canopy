use axum::{extract::State, http::HeaderMap, routing::get, Json, Router};
use std::sync::Arc;

use crate::middleware::auth::AuthenticatedUser;
use crate::services::audit::AuditRequestContext;
use crate::services::entitlements::EntitlementService;
use crate::services::AppState;
use shared::dto::audit::{AuditAction, AuditOutcome};
use shared::dto::entitlements::UserEntitlements;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/entitlements", get(get_entitlements))
}

async fn get_entitlements(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    headers: HeaderMap,
) -> Result<Json<UserEntitlements>, (axum::http::StatusCode, Json<shared::errors::ApiError>)> {
    // Fail-closed: block if durable audit sink is broken
    if !state.audit_service.is_healthy() {
        return Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(shared::errors::ApiError::internal(
                "Audit logging unavailable",
            )),
        ));
    }

    let ent_service = EntitlementService::new(state.entitlement_store.clone());
    let entitlements = ent_service.evaluate(&claims).await;
    let audit_ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);

    state
        .audit_service
        .event(
            &claims.sub,
            AuditAction::EntitlementsView,
            AuditOutcome::Success,
        )
        .optional_metadata(Some(audit_ctx.metadata(serde_json::json!({}))))
        .commit_or_fail()
        .map_err(|_| {
            (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(shared::errors::ApiError::internal(
                    "Audit logging failed — refusing to return data",
                )),
            )
        })?;

    Ok(Json(entitlements))
}
