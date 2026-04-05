use axum::{extract::State, routing::get, Json, Router};
use std::sync::Arc;

use crate::middleware::auth::AuthenticatedUser;
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

    state
        .audit_service
        .log_event(
            &claims.sub,
            AuditAction::EntitlementsView,
            AuditOutcome::Success,
            None,
            None,
            None,
            None,
        )
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
