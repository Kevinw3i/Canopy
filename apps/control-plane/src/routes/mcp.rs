use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shared::dto::audit::{AuditAction, AuditOutcome};
use shared::dto::cloudwatch::LogGroup;
use shared::dto::database::{
    ListDatabaseScopesRequest, ListDatabaseScopesResponse, QueryDatabaseRequest,
    QueryDatabaseResponse,
};
use shared::dto::mcp::{
    lookup_mcp_guidance, McpGuardrails, McpGuidanceSyncRequest, McpGuidanceSyncResponse,
    McpListAllowedLogGroupsRequest, McpListAllowedLogGroupsResponse, McpRegisterSessionRequest,
    McpRegisterSessionResponse, MCP_DATABASE_GUIDANCE_KEY, MCP_PRIVACY_AND_AUDIT_NOTICE_KEY,
    MCP_PROTOCOL_VERSION, MCP_SECURITY_BOUNDARIES_KEY,
};
use shared::errors::ApiError;
use std::collections::BTreeSet;
use std::sync::Arc;
use uuid::Uuid;

use crate::middleware::auth::AuthenticatedUser;
use crate::services::audit::AuditRequestContext;
use crate::services::auth::Claims;
use crate::services::cloudwatch::mock_log_groups;
use crate::services::database::{
    build_database_response, scope_summary, validate_select_sql_for_connection,
    ConnectionQueueFull, DatabaseConnectionUnavailable, DatabaseError, TableType, TableTypeQuery,
    ViewCheckedQueryOutcome,
};
use crate::services::entitlements::EntitlementService;
use crate::services::{AppState, McpSessionRecord};

type ApiResult<T> = Result<Json<T>, (StatusCode, Json<ApiError>)>;

const DATABASE_SCOPE_LIST_REQUIRED_GUIDANCE: &[&str] =
    &[MCP_SECURITY_BOUNDARIES_KEY, MCP_DATABASE_GUIDANCE_KEY];
const DATABASE_QUERY_REQUIRED_GUIDANCE: &[&str] = &[
    MCP_SECURITY_BOUNDARIES_KEY,
    MCP_DATABASE_GUIDANCE_KEY,
    MCP_PRIVACY_AND_AUDIT_NOTICE_KEY,
];
const CLOUDWATCH_DISCOVERY_REQUIRED_GUIDANCE: &[&str] = &[MCP_SECURITY_BOUNDARIES_KEY];
const CLOUDWATCH_DISCOVERY_TOOL: &str = "canopy_list_allowed_log_groups";
const CLOUDWATCH_DISCOVERY_CURSOR_AAD: &[u8] = b"canopy:mcp:cloudwatch:discovery:v1";

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/mcp/session/register", post(register_session))
        .route("/api/mcp/guidance/delivered", post(sync_guidance))
        .route(
            "/api/mcp/cloudwatch/log-groups",
            post(list_allowed_log_groups),
        )
        .route("/api/mcp/database/scopes", post(list_database_scopes))
        .route("/api/mcp/database/query", post(query_database))
}

async fn register_session(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    headers: HeaderMap,
    Json(req): Json<McpRegisterSessionRequest>,
) -> ApiResult<McpRegisterSessionResponse> {
    if !state.audit_service.is_healthy() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal("Audit logging unavailable")),
        ));
    }

    let audit_ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);
    let entitlement_service = EntitlementService::new(state.entitlement_store.clone());
    let entitlements = entitlement_service.evaluate(&claims).await;

    if !entitlements.features.can_use_mcp {
        state
            .audit_service
            .event(
                &claims.sub,
                AuditAction::McpSessionRegister,
                AuditOutcome::Denied,
            )
            .metadata(audit_ctx.metadata(serde_json::json!({
                "client_type": "mcp",
                "surface": "mcp",
                "mcp_event_kind": "mcp_session_register_failed",
                "mcp_outcome_kind": "denied",
                "aws_execution_attempted": false,
                "reason": "can_use_mcp entitlement disabled"
            })))
            .commit_best_effort();
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("MCP is not enabled for this user")),
        ));
    }

    if req.protocol_version != MCP_PROTOCOL_VERSION {
        state
            .audit_service
            .event(
                &claims.sub,
                AuditAction::McpSessionRegister,
                AuditOutcome::Failure,
            )
            .metadata(audit_ctx.metadata(serde_json::json!({
                "client_type": "mcp",
                "surface": "mcp",
                "mcp_event_kind": "mcp_session_register_failed",
                "mcp_outcome_kind": "bad_request",
                "aws_execution_attempted": false,
                "requested_protocol_version": req.protocol_version,
                "supported_protocol_version": MCP_PROTOCOL_VERSION
            })))
            .commit_best_effort();
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request("Unsupported MCP protocol version")),
        ));
    }

    // Sweep expired sessions opportunistically so a long-running process
    // does not accumulate `McpSessionRecord` instances indefinitely.
    // the previous unbounded growth could accumulate stale sessions.
    let now = Utc::now();
    state
        .mcp_sessions
        .retain(|_, record| record.expires_at >= now);

    let expires_at = now + Duration::hours(8);
    let canopy_mcp_session_id = format!("mcp_{}", Uuid::new_v4().as_simple());
    let forwarding_key = random_secret();

    // Commit the audit FIRST. If the audit sink is unhealthy we return 503
    // without leaving a session record behind. This avoids stranding
    // unaudited entries in `mcp_sessions` on audit failure.
    state
        .audit_service
        .event(
            &claims.sub,
            AuditAction::McpSessionRegister,
            AuditOutcome::Success,
        )
        .target(Some(&canopy_mcp_session_id))
        .metadata(audit_ctx.metadata(serde_json::json!({
            "client_type": "mcp",
            "surface": "mcp",
            "mcp_event_kind": "mcp_session_register",
            "mcp_outcome_kind": "mcp_session_registered",
            "aws_execution_attempted": false,
            "canopy_mcp_session_id": canopy_mcp_session_id.as_str(),
            "local_secret_generation": req.local_secret_generation.as_str(),
            "protocol_version": MCP_PROTOCOL_VERSION,
            "client_name": req.client_name.as_str(),
            "client_version": req.client_version.as_str(),
            "product_phase": req.product_phase.as_str()
        })))
        .commit_or_fail()
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::internal(
                    "Audit logging failed — refusing to register MCP session",
                )),
            )
        })?;

    // Audit is durable. Now record the session.
    state.mcp_sessions.insert(
        canopy_mcp_session_id.clone(),
        McpSessionRecord {
            actor: claims.sub.clone(),
            actor_email: claims.email.clone(),
            local_secret_generation: req.local_secret_generation.clone(),
            forwarding_key: forwarding_key.clone(),
            protocol_version: req.protocol_version.clone(),
            client_name: req.client_name.clone(),
            client_version: req.client_version.clone(),
            product_phase: req.product_phase.clone(),
            guidance_delivered: BTreeSet::new(),
            expires_at,
            created_at: now,
            updated_at: now,
        },
    );

    Ok(Json(McpRegisterSessionResponse {
        canopy_mcp_session_id,
        forwarding_key,
        expires_at,
    }))
}

async fn sync_guidance(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    headers: HeaderMap,
    Json(req): Json<McpGuidanceSyncRequest>,
) -> ApiResult<McpGuidanceSyncResponse> {
    if !state.audit_service.is_healthy() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal("Audit logging unavailable")),
        ));
    }

    let audit_ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);
    let Some(session) = state.mcp_sessions.get(&req.canopy_mcp_session_id) else {
        state
            .audit_service
            .event(
                &claims.sub,
                AuditAction::McpGuidanceSync,
                AuditOutcome::Denied,
            )
            .target(Some(&req.canopy_mcp_session_id))
            .metadata(audit_ctx.metadata(serde_json::json!({
                "client_type": "mcp",
                "surface": "mcp",
                "mcp_event_kind": "guidance_sync",
                "mcp_outcome_kind": "mcp_session_not_found",
                "guidance_id": req.guidance_id,
                "guidance_version": req.guidance_version,
                "canopy_mcp_session_id": req.canopy_mcp_session_id,
            })))
            .commit_best_effort();
        return Err((
            StatusCode::NOT_FOUND,
            Json(ApiError::not_found("MCP session not found")),
        ));
    };

    if session.actor != claims.sub
        || session.local_secret_generation != req.local_secret_generation
        || session.expires_at < Utc::now()
    {
        state
            .audit_service
            .event(
                &claims.sub,
                AuditAction::McpGuidanceSync,
                AuditOutcome::Denied,
            )
            .target(Some(&req.canopy_mcp_session_id))
            .metadata(audit_ctx.metadata(serde_json::json!({
                "client_type": "mcp",
                "surface": "mcp",
                "mcp_event_kind": "guidance_sync",
                "mcp_outcome_kind": "denied",
                "aws_execution_attempted": false,
                "guidance_id": req.guidance_id,
                "guidance_version": req.guidance_version,
                "canopy_mcp_session_id": req.canopy_mcp_session_id,
                "local_secret_generation": req.local_secret_generation
            })))
            .commit_best_effort();
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError::forbidden(
                "MCP session is not valid for this user",
            )),
        ));
    }

    // The control-plane — not the client — is the authority on which guidance
    // documents exist AND on what their content is. Looking the entry up
    // server-side here means delivery is always backed by an actual response
    // payload: a client cannot mark "delivered" by simply guessing the
    // `(id, version)` pair, because the audit record is paired with the
    // server-issued content that was returned to satisfy the call.
    let Some(entry) = lookup_mcp_guidance(&req.guidance_id, &req.guidance_version) else {
        state
            .audit_service
            .event(
                &claims.sub,
                AuditAction::McpGuidanceSync,
                AuditOutcome::Denied,
            )
            .target(Some(&req.canopy_mcp_session_id))
            .metadata(audit_ctx.metadata(serde_json::json!({
                "client_type": "mcp",
                "surface": "mcp",
                "mcp_event_kind": "guidance_sync",
                "mcp_outcome_kind": "unknown_guidance",
                "aws_execution_attempted": false,
                "guidance_id": req.guidance_id,
                "guidance_version": req.guidance_version,
                "canopy_mcp_session_id": req.canopy_mcp_session_id,
            })))
            .commit_best_effort();
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request(
                "Unknown MCP guidance id/version. The control-plane only issues guidance \
                 enumerated in the server-side registry.",
            )),
        ));
    };

    let guidance_key = format!("{}@{}", req.guidance_id, req.guidance_version);

    // Drop the DashMap write guard before doing any audit I/O. We re-acquire
    // it only after the audit is durably committed, so a failed audit cannot
    // leave the session in a "guidance delivered" state.
    drop(session);

    state
        .audit_service
        .event(
            &claims.sub,
            AuditAction::McpGuidanceSync,
            AuditOutcome::Success,
        )
        .target(Some(&req.canopy_mcp_session_id))
        .metadata(audit_ctx.metadata(serde_json::json!({
            "client_type": "mcp",
            "surface": "mcp",
            "mcp_event_kind": "guidance_sync",
            "mcp_outcome_kind": "guidance_issued",
            "aws_execution_attempted": false,
            "guidance_id": req.guidance_id,
            "guidance_version": req.guidance_version,
            "guidance_key": guidance_key,
            "canopy_mcp_session_id": req.canopy_mcp_session_id,
            "local_secret_generation": req.local_secret_generation
        })))
        .commit_or_fail()
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::internal(
                    "Audit logging failed — refusing to mark guidance delivered",
                )),
            )
        })?;

    // Audit landed durably — now record the delivery. If the session was
    // garbage-collected in the meantime (TTL hit), we report success without
    // mutation because the audit already proves the issuance.
    if let Some(mut session) = state.mcp_sessions.get_mut(&req.canopy_mcp_session_id) {
        session.guidance_delivered.insert(guidance_key.clone());
        session.updated_at = Utc::now();
    }

    Ok(Json(McpGuidanceSyncResponse {
        guidance_issued: true,
        guidance_delivered_for_gating: true,
        guidance_id: entry.id.to_string(),
        guidance_version: entry.version.to_string(),
        title: entry.title.to_string(),
        content_type: "text/markdown".to_string(),
        content: entry.content.to_string(),
    }))
}

fn random_secret() -> String {
    format!(
        "{}{}",
        Uuid::new_v4().as_simple(),
        Uuid::new_v4().as_simple()
    )
}

async fn list_allowed_log_groups(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    headers: HeaderMap,
    Json(req): Json<McpListAllowedLogGroupsRequest>,
) -> ApiResult<McpListAllowedLogGroupsResponse> {
    if !state.audit_service.is_healthy() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal("Audit logging unavailable")),
        ));
    }

    let audit_ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);
    let ent_service = EntitlementService::new(state.entitlement_store.clone());
    let entitlements = ent_service.evaluate(&claims).await;
    let guardrails = McpGuardrails::default();

    if !entitlements.features.can_use_mcp_cloudwatch {
        audit_cloudwatch_discovery_denied(
            &state,
            &claims.sub,
            &audit_ctx,
            &req,
            "can_use_mcp_cloudwatch entitlement disabled",
            "entitlement_disabled",
        )?;
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError::forbidden(
                "MCP CloudWatch discovery is not enabled for this user",
            )),
        ));
    }

    if let Err(reason) = require_mcp_guidance(
        &state,
        &claims,
        req.canopy_mcp_session_id.as_deref(),
        req.local_secret_generation.as_deref(),
        CLOUDWATCH_DISCOVERY_REQUIRED_GUIDANCE,
    ) {
        audit_cloudwatch_discovery_denied(
            &state,
            &claims.sub,
            &audit_ctx,
            &req,
            "Required MCP CloudWatch guidance has not been completed",
            reason,
        )?;
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError::forbidden(
                "Required MCP CloudWatch guidance has not been completed",
            )),
        ));
    }

    let cursor = match req.discovery_cursor.as_deref() {
        Some(raw) => match decode_discovery_cursor(&state, raw) {
            Ok(cursor) => Some(cursor),
            Err(reason) => {
                audit_cloudwatch_discovery_denied(
                    &state,
                    &claims.sub,
                    &audit_ctx,
                    &req,
                    "Invalid MCP CloudWatch discovery cursor",
                    reason,
                )?;
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiError::bad_request(
                        "Invalid MCP CloudWatch discovery cursor",
                    )),
                ));
            }
        },
        None => None,
    };

    if let Some(cursor) = cursor.as_ref() {
        if let Err(reason) = validate_discovery_cursor_scope(cursor, &claims.sub, &req, &guardrails)
        {
            audit_cloudwatch_discovery_denied(
                &state,
                &claims.sub,
                &audit_ctx,
                &req,
                "MCP CloudWatch discovery cursor is not valid for this request",
                reason,
            )?;
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ApiError::bad_request(
                    "MCP CloudWatch discovery cursor is not valid for this request",
                )),
            ));
        }
    }

    let account_id = match cursor
        .as_ref()
        .map(|c| c.account_id.clone())
        .or_else(|| req.account_id.clone())
    {
        Some(account_id) if !account_id.trim().is_empty() => account_id,
        _ => {
            audit_cloudwatch_discovery_denied(
                &state,
                &claims.sub,
                &audit_ctx,
                &req,
                "account_id is required for initial MCP CloudWatch discovery",
                "bad_request",
            )?;
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ApiError::bad_request(
                    "account_id is required for initial MCP CloudWatch discovery",
                )),
            ));
        }
    };
    let region = match cursor
        .as_ref()
        .map(|c| c.region.clone())
        .or_else(|| req.region.clone())
    {
        Some(region) if !region.trim().is_empty() => region,
        _ => {
            audit_cloudwatch_discovery_denied(
                &state,
                &claims.sub,
                &audit_ctx,
                &req,
                "region is required for initial MCP CloudWatch discovery",
                "bad_request",
            )?;
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ApiError::bad_request(
                    "region is required for initial MCP CloudWatch discovery",
                )),
            ));
        }
    };
    let prefix = cursor
        .as_ref()
        .and_then(|c| c.prefix.clone())
        .or_else(|| req.prefix.clone());

    if !ent_service
        .has_feature_for_scope(&claims, &account_id, Some(&region), None, None, |f| {
            f.can_use_mcp && f.can_use_mcp_cloudwatch
        })
        .await
    {
        audit_cloudwatch_discovery_denied(
            &state,
            &claims.sub,
            &audit_ctx,
            &req,
            "MCP CloudWatch discovery not authorized for this scope",
            "scope_not_authorized",
        )?;
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError::forbidden(
                "MCP CloudWatch discovery not authorized for this scope",
            )),
        ));
    }

    let scoped_log_arns = ent_service
        .allowed_log_group_arns_for_scope(&claims, &account_id, &region, |f| {
            f.can_use_mcp && f.can_use_mcp_cloudwatch
        })
        .await;
    let entitlement_hash = entitlement_snapshot_hash(&scoped_log_arns);

    if let Some(cursor) = cursor.as_ref() {
        if let Err(reason) =
            validate_discovery_cursor_entitlement_snapshot(cursor, &entitlement_hash)
        {
            audit_cloudwatch_discovery_denied(
                &state,
                &claims.sub,
                &audit_ctx,
                &req,
                "MCP CloudWatch discovery cursor entitlements no longer match",
                reason,
            )?;
            return Err((
                StatusCode::FORBIDDEN,
                Json(ApiError::forbidden(
                    "MCP CloudWatch discovery cursor is no longer valid for current entitlements",
                )),
            ));
        }
    }

    let mut result = if state.config.use_mock_aws() {
        discover_mock_log_groups(
            &account_id,
            &region,
            prefix.as_deref(),
            &scoped_log_arns,
            &guardrails,
        )
    } else {
        discover_aws_log_groups(
            &state,
            &claims,
            &entitlements,
            &account_id,
            &region,
            prefix.as_deref(),
            &scoped_log_arns,
            cursor.as_ref().and_then(|c| c.aws_next_token.clone()),
            cursor.as_ref().map(|c| c.pages_scanned).unwrap_or(0),
            cursor.as_ref().map(|c| c.results_scanned).unwrap_or(0),
            &guardrails,
            &audit_ctx,
            &req,
        )
        .await?
    };

    let discovery_cursor = if result.truncated && !result.budget_exhausted {
        match result.aws_next_token.take() {
            Some(aws_next_token) => {
                let cursor_payload = DiscoveryCursorPayload {
                    version: 1,
                    actor: claims.sub.clone(),
                    canopy_mcp_session_id: req.canopy_mcp_session_id.clone().unwrap_or_default(),
                    local_secret_generation: req
                        .local_secret_generation
                        .clone()
                        .unwrap_or_default(),
                    tool: CLOUDWATCH_DISCOVERY_TOOL.into(),
                    account_id: account_id.clone(),
                    region: region.clone(),
                    prefix: prefix.clone(),
                    aws_next_token: Some(aws_next_token),
                    pages_scanned: result.pages_scanned,
                    results_scanned: result.scanned_count,
                    max_results_returned: guardrails.max_log_group_list_results,
                    max_results_scanned: guardrails.max_discovery_results_scanned,
                    max_pages: guardrails.max_describe_log_groups_pages,
                    guardrail_policy_id: discovery_guardrail_policy_id(&guardrails),
                    entitlement_snapshot_hash: entitlement_hash.clone(),
                    expires_at: Utc::now()
                        + Duration::seconds(guardrails.discovery_cursor_ttl_seconds as i64),
                };
                Some(
                    encode_discovery_cursor(&state, &cursor_payload).map_err(|_| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ApiError::internal("Failed to seal MCP discovery cursor")),
                        )
                    })?,
                )
            }
            None => None,
        }
    } else {
        None
    };

    let next_action_hint = if result.truncated && discovery_cursor.is_none() {
        Some("Narrow the prefix and retry; the discovery scan budget was exhausted.".to_string())
    } else if result.truncated {
        Some("Use discovery_cursor to continue this exact discovery scope.".to_string())
    } else {
        None
    };

    state
        .audit_service
        .event(
            &claims.sub,
            AuditAction::McpCloudwatchDiscovery,
            AuditOutcome::Success,
        )
        .account(Some(&account_id))
        .region(Some(&region))
        .metadata(audit_ctx.metadata(serde_json::json!({
            "client_type": "mcp",
            "surface": "mcp",
            "mcp_event_kind": "cloudwatch_discovery",
            "mcp_outcome_kind": "success",
            "tool_name": CLOUDWATCH_DISCOVERY_TOOL,
            "canopy_mcp_session_id": req.canopy_mcp_session_id.as_deref(),
            "local_secret_generation": req.local_secret_generation.as_deref(),
            "prefix": prefix.as_deref(),
            "aws_execution_attempted": !state.config.use_mock_aws(),
            "returned_count": result.log_groups.len(),
            "scanned_count": result.scanned_count,
            "truncated": result.truncated,
            "cursor_issued": discovery_cursor.is_some(),
        })))
        .commit_or_fail()
        .map_err(|_| cloudwatch_discovery_audit_failure_response())?;

    Ok(Json(McpListAllowedLogGroupsResponse {
        account_id,
        region,
        prefix,
        returned_count: result.log_groups.len(),
        scanned_count: result.scanned_count,
        log_groups: result.log_groups,
        truncated: result.truncated,
        discovery_cursor,
        next_action_hint,
    }))
}

async fn list_database_scopes(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    headers: HeaderMap,
    Json(req): Json<ListDatabaseScopesRequest>,
) -> ApiResult<ListDatabaseScopesResponse> {
    if !state.audit_service.is_healthy() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal("Audit logging unavailable")),
        ));
    }
    // Codex round 27 (HIGH): readiness is not just an LB signal — it
    // includes the `wait_timeout` invariant `permit_hold_after_acquire_failure`
    // is sized for. Refuse database routes until preflight has cleared
    // them, so an authenticated request during LB deregistration lag
    // or via direct/internal traffic cannot bypass the limiter's
    // correctness contract. Codex round 28 (MED): use
    // `service_unavailable` (not `internal`) so clients can tell
    // startup-not-ready (retryable) from a server bug.
    if !state.is_ready() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::service_unavailable(
                "database routes not ready: startup preflight has not passed (see GET /health)",
            )),
        ));
    }

    let audit_ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);
    let store = state.entitlement_store.read().await;
    let scopes = store.database_scopes_for_user(&claims.sub, &claims.email, claims.email_verified);
    let has_database_feature = !scopes.is_empty();

    if !has_database_feature {
        state
            .audit_service
            .event(
                &claims.sub,
                AuditAction::McpDatabaseScopeList,
                AuditOutcome::Denied,
            )
            .metadata(audit_ctx.metadata(serde_json::json!({
                "client_type": "mcp",
                "surface": "mcp",
                "mcp_event_kind": "database_scope_list",
                "mcp_outcome_kind": "denied",
                "aws_execution_attempted": false,
                "db_execution_attempted": false,
                "reason": "can_use_mcp_database entitlement disabled"
            })))
            .commit_or_fail()
            .map_err(|_| database_audit_failure_response())?;
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError::forbidden(
                "MCP database is not enabled for this user",
            )),
        ));
    }

    if let Err(reason) = require_mcp_guidance(
        &state,
        &claims,
        req.canopy_mcp_session_id.as_deref(),
        req.local_secret_generation.as_deref(),
        DATABASE_SCOPE_LIST_REQUIRED_GUIDANCE,
    ) {
        audit_database_scope_list_denied(&state, &claims.sub, &audit_ctx, &req, reason)?;
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError::forbidden(
                "Required MCP database guidance has not been completed",
            )),
        ));
    }

    state
        .audit_service
        .event(
            &claims.sub,
            AuditAction::McpDatabaseScopeList,
            AuditOutcome::Success,
        )
        .metadata(audit_ctx.metadata(serde_json::json!({
            "client_type": "mcp",
            "surface": "mcp",
            "mcp_event_kind": "database_scope_list",
            "mcp_outcome_kind": "success",
            "aws_execution_attempted": false,
            "db_execution_attempted": false,
            "scope_count": scopes.len()
        })))
        .commit_or_fail()
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::internal(
                    "Audit logging failed — refusing to list database scopes",
                )),
            )
        })?;

    Ok(Json(ListDatabaseScopesResponse {
        scopes: scopes.iter().map(scope_summary).collect(),
    }))
}

async fn query_database(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    headers: HeaderMap,
    Json(req): Json<QueryDatabaseRequest>,
) -> ApiResult<QueryDatabaseResponse> {
    if !state.audit_service.is_healthy() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal("Audit logging unavailable")),
        ));
    }
    // Codex round 27 + 28 + 30 (HIGH/MED): readiness gate. Global
    // readiness (`state.is_ready()`) covers OIDC + STS — its failure
    // indicates the whole service is unusable, so all auth-protected
    // routes already 503 via `/health` deregistration. The
    // **per-connection** check below is the database-specific
    // half: only fail the connection whose wait_timeout invariant
    // was not provable, leaving healthy scopes serving traffic. The
    // per-connection check fires AFTER scope resolution because we
    // need `scope.connection` to look up the right entry. Pre-scope
    // global readiness is still asserted here so an entirely unbooted
    // process cannot accept database calls.
    if !state.is_ready() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::service_unavailable(
                "database routes not ready: startup preflight has not passed (see GET /health)",
            )),
        ));
    }

    let audit_ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);

    // Check guidance BEFORE scope match. A user without delivered guidance
    // cannot probe the scope namespace via different rejection reasons, and
    // we never inspect raw SQL until guidance is confirmed (and the
    // `audit_database_denied` helper redacts SQL in every denial path
    // regardless, but ordering keeps the audit story consistent).
    if let Err(reason) = require_mcp_guidance(
        &state,
        &claims,
        req.canopy_mcp_session_id.as_deref(),
        req.local_secret_generation.as_deref(),
        DATABASE_QUERY_REQUIRED_GUIDANCE,
    ) {
        audit_database_denied(&state, &claims.sub, &audit_ctx, &req, reason, None)?;
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError::forbidden(
                "Required MCP database guidance has not been completed",
            )),
        ));
    }

    let store = state.entitlement_store.read().await;
    let Some(scope) = store.matching_database_scope(
        &claims.sub,
        &claims.email,
        claims.email_verified,
        &req.scope,
        req.connection.as_deref(),
        req.environment.as_deref(),
    ) else {
        audit_database_denied(
            &state,
            &claims.sub,
            &audit_ctx,
            &req,
            "scope_not_allowed",
            None,
        )?;
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("Database scope is not allowed")),
        ));
    };
    drop(store);

    let Some(connection) = state.config.database_connections.get(&scope.connection) else {
        audit_database_denied(
            &state,
            &claims.sub,
            &audit_ctx,
            &req,
            "connection_not_configured",
            Some(&scope),
        )?;
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request(
                "Database connection is not configured",
            )),
        ));
    };
    // Codex round 30 (HIGH): per-connection readiness. Only this
    // scope's underlying connection has to be preflight-OK. A
    // different misconfigured upstream still serves its own healthy
    // scopes, and other Canopy surfaces (EC2, CloudWatch) are never
    // affected.
    if !state.db_connection_is_ready(&scope.connection) {
        audit_database_denied(
            &state,
            &claims.sub,
            &audit_ctx,
            &req,
            "database_connection_not_ready",
            Some(&scope),
        )?;
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::service_unavailable(format!(
                "database connection '{}' is not ready: its @@session/@@global.wait_timeout \
                 preflight has not passed (see GET /health and docs/OPERATOR-SETUP.md)",
                scope.connection
            ))),
        ));
    }
    if !connection.readonly {
        audit_database_denied(
            &state,
            &claims.sub,
            &audit_ctx,
            &req,
            "connection_not_readonly",
            Some(&scope),
        )?;
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request("Database connection is not readonly")),
        ));
    }

    let validated = match validate_select_sql_for_connection(&req.sql, &scope, &connection.database)
    {
        Ok(validated) => validated,
        Err(err) => {
            audit_database_error(
                &state,
                &claims.sub,
                &audit_ctx,
                &req,
                Some(&scope),
                &err,
                DatabaseAuditStage {
                    views_allowed: scope.allow_views,
                    view_check_required: !scope.allow_views,
                    ..DatabaseAuditStage::default()
                },
                None,
            )?;
            return Err(database_error_response(err));
        }
    };

    // Commit a durable attempt audit BEFORE touching Secrets Manager or
    // MySQL. a previous implementation allowed EXPLAIN was reaching the database
    // before the attempt event was durable: in that window a failed audit
    // sink would refuse the request, but credentials had been used and SQL
    // already executed (EXPLAIN counts) against the production database.
    state
        .audit_service
        .event(
            &claims.sub,
            AuditAction::McpDatabaseQuery,
            AuditOutcome::Success,
        )
        .target(Some(&scope.name))
        .metadata(audit_ctx.metadata(serde_json::json!({
            "client_type": "mcp",
            "surface": "mcp",
            "mcp_event_kind": "database_query",
            "mcp_outcome_kind": "attempt",
            "tool_name": "canopy_query_database",
            "database_scope": scope.name,
            "connection": scope.connection,
            "environment": scope.environment,
            "canopy_mcp_session_id": req.canopy_mcp_session_id.as_deref(),
            "local_secret_generation": req.local_secret_generation.as_deref(),
            "sql_raw": req.sql,
            "tables": validated.tables,
            // this audit event is committed BEFORE
            // any database round-trip — Secrets Manager has not been
            // queried, EXPLAIN has not run, no MySQL connection has
            // been acquired. The `*_attempted` fields therefore have
            // to read as `false` here; the terminal events that follow
            // (success / Overloaded / EXPLAIN-rejected / etc.) own the
            // truth about what actually ran. The `*_planned` fields
            // preserve the original intent signal so SIEM / dashboards
            // grouping by "user submitted a query against this scope"
            // are unaffected.
            "db_execution_attempted": false,
            "explain_attempted": false,
            "db_execution_planned": true,
            "explain_planned": true,
            // `views_allowed` and `view_check_required` document the SCOPE's
            // policy at request time, regardless of whether the view check
            // ultimately ran. Reviewers grepping `views_allowed: true` in
            // audit logs see every query that landed on a view-opt-in scope.
            "views_allowed": scope.allow_views,
            "view_check_required": !scope.allow_views,
        })))
        .commit_or_fail()
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::internal(
                    "Audit logging failed — refusing to touch the database",
                )),
            )
        })?;

    let secret = match state
        .database_secret_provider
        .load_secret(&connection.secret_arn)
        .await
    {
        Ok(secret) => secret,
        Err(err) => {
            tracing::error!(
                error = %err,
                database_scope = %scope.name,
                connection = %scope.connection,
                "failed to load MCP database secret"
            );
            let db_err = DatabaseError::Internal {
                message: "database credential load failed".into(),
                reason: "credential_load_failed",
            };
            audit_database_error(
                &state,
                &claims.sub,
                &audit_ctx,
                &req,
                Some(&scope),
                &db_err,
                DatabaseAuditStage {
                    views_allowed: scope.allow_views,
                    view_check_required: !scope.allow_views,
                    ..DatabaseAuditStage::default()
                },
                Some(&validated.tables),
            )?;
            return Err(database_error_response(db_err));
        }
    };

    // View guard. When the scope has not opted into VIEW reads, every table
    // touched by the validated SELECT must resolve to `BASE TABLE` in
    // `information_schema.tables`. This closes a bypass where the
    // EXPLAIN-based unqualified-leaf heuristic can be bypassed by views
    // whose base tables are inside the scope's `allowed_schemas` — without
    // this check, a query like `SELECT * FROM scope_view` (where
    // `scope_view` is a VIEW joining tables the scope does NOT grant) would
    // pass every other validator. We run this BEFORE EXPLAIN so a denial
    // never causes the DB to plan / count rows against a view we are about
    // to refuse anyway. Cache lives in the executor; see
    // `TABLE_TYPE_CACHE_TTL`.
    let mut view_check_passed = false;
    if !scope.allow_views {
        let queries: Vec<TableTypeQuery> = validated
            .tables
            .iter()
            .map(|raw| {
                let (schema, table) = split_qualified_table(raw, &connection.database);
                TableTypeQuery { schema, table }
            })
            .collect();
        let types_map = match state
            .database_executor
            .fetch_table_types(connection, &secret, &queries, connection.explain_timeout_ms)
            .await
        {
            Ok(map) => map,
            Err(err) => {
                tracing::error!(
                    error = %err,
                    database_scope = %scope.name,
                    connection = %scope.connection,
                    "information_schema lookup for view check failed"
                );
                // Layer A can also hit either kind of
                // upstream saturation (local semaphore queue full OR
                // MySQL/RDS Proxy capacity exhaustion). Translate to a
                // typed 503 so the saturation signal is consistent
                // regardless of which executor method first failed.
                let db_err = classify_executor_overload(&err).unwrap_or(DatabaseError::Internal {
                    message: "view type check failed".into(),
                    reason: "view_check_failed",
                });
                audit_database_error(
                    &state,
                    &claims.sub,
                    &audit_ctx,
                    &req,
                    Some(&scope),
                    &db_err,
                    DatabaseAuditStage {
                        views_allowed: scope.allow_views,
                        view_check_required: true,
                        ..DatabaseAuditStage::default()
                    },
                    Some(&validated.tables),
                )?;
                return Err(database_error_response(db_err));
            }
        };

        for raw in &validated.tables {
            let (schema, table) = split_qualified_table(raw, &connection.database);
            let key = (schema.to_ascii_lowercase(), table.to_ascii_lowercase());
            let reason = match types_map.get(&key) {
                Some(TableType::BaseTable) => continue,
                Some(TableType::View) => "view_not_allowed_by_scope",
                Some(TableType::Other) => "non_base_table_not_allowed_by_scope",
                None => "table_type_unknown",
            };
            let db_err = DatabaseError::QueryPlanRejected {
                message: format!(
                    "Query rejected before execution: table '{raw}' is not a BASE TABLE \
                     and scope '{}' has allow_views = false. Ask an operator to either \
                     query the base tables directly or flip allow_views = true on the \
                     scope after reviewing the view's DEFINER and base-table reads.",
                    scope.name
                ),
                table: Some(raw.clone()),
                access_type: None,
                estimated_rows: None,
                reason,
            };
            audit_database_error(
                &state,
                &claims.sub,
                &audit_ctx,
                &req,
                Some(&scope),
                &db_err,
                DatabaseAuditStage {
                    views_allowed: scope.allow_views,
                    view_check_required: true,
                    ..DatabaseAuditStage::default()
                },
                Some(&validated.tables),
            )?;
            return Err(database_error_response(db_err));
        }
        view_check_passed = true;
    }

    // ALL scopes now run through the MDL-protected pipeline. The legacy
    // `if scope.allow_views { explain + query }` branch ran EXPLAIN and
    // SELECT on separate connections, with no MDL across them — reopening
    // the same cross-connection DDL race the protected path was built to
    // close. `query_with_view_check` now
    // accepts the scope and only enforces the BASE-TABLE check when
    // `allow_views = false`; view-opt-in scopes still get the MDL umbrella
    // across EXPLAIN + SELECT.
    let statement_timeout_ms = scope
        .statement_timeout_ms
        .min(connection.statement_timeout_ms);
    let (explain, query) = {
        let view_targets: Vec<TableTypeQuery> = validated
            .tables
            .iter()
            .map(|raw| {
                let (schema, table) = split_qualified_table(raw, &connection.database);
                TableTypeQuery { schema, table }
            })
            .collect();
        let outcome = state
            .database_executor
            .query_with_view_check(
                connection,
                &secret,
                &scope,
                &view_targets,
                &validated.normalized_sql,
                connection.explain_timeout_ms,
                statement_timeout_ms,
            )
            .await;
        match outcome {
            Ok(ViewCheckedQueryOutcome::Ok { explain, rows, .. }) => (explain, rows),
            Ok(ViewCheckedQueryOutcome::ViewSwapDetected { offender, .. }) => {
                // Concurrent DDL flipped a table to a view between Layer A
                // and Layer B. Audit with a distinct reason so reviewers
                // can tell a "stable view" denial from a "DDL race"
                // denial.
                let (off_schema, off_table, off_kind) = offender;
                tracing::warn!(
                    database_scope = %scope.name,
                    schema = %off_schema,
                    table = %off_table,
                    ?off_kind,
                    "view swap detected between Layer A and Layer B view checks"
                );
                let db_err = DatabaseError::QueryPlanRejected {
                    message: format!(
                        "Query rejected before execution: table '{off_schema}.{off_table}' \
                         changed type between the Layer-A view check and the MDL-protected \
                         re-check. The most likely cause is a concurrent DDL migration; \
                         retry the query once it completes."
                    ),
                    table: Some(format!("{off_schema}.{off_table}")),
                    access_type: None,
                    estimated_rows: None,
                    reason: "view_swap_detected_between_checks",
                };
                audit_database_error(
                    &state,
                    &claims.sub,
                    &audit_ctx,
                    &req,
                    Some(&scope),
                    &db_err,
                    DatabaseAuditStage {
                        // EXPLAIN was attempted under MDL but ROLLBACK
                        // happened before it ran (we bailed on the type
                        // mismatch). Mark `explain_attempted = false` so
                        // the audit reflects the actual state.
                        explain_attempted: false,
                        db_execution_attempted: false,
                        views_allowed: scope.allow_views,
                        view_check_required: true,
                        view_check_passed: false,
                    },
                    Some(&validated.tables),
                )?;
                return Err(database_error_response(db_err));
            }
            Ok(ViewCheckedQueryOutcome::ExplainRejected { error, .. }) => {
                // EXPLAIN ran inside the MDL-protected transaction and
                // evaluate_explain rejected the plan. Surface the
                // existing structured `DatabaseError` to the audit + the
                // response so the rejection reason matches the
                // allow_views=true path.
                audit_database_error(
                    &state,
                    &claims.sub,
                    &audit_ctx,
                    &req,
                    Some(&scope),
                    &error,
                    DatabaseAuditStage {
                        explain_attempted: true,
                        db_execution_attempted: false,
                        views_allowed: scope.allow_views,
                        view_check_required: true,
                        view_check_passed: true,
                    },
                    Some(&validated.tables),
                )?;
                return Err(database_error_response(error));
            }
            Err(err) => {
                tracing::error!(
                    error = %err,
                    database_scope = %scope.name,
                    connection = %scope.connection,
                    "MDL-protected database query failed"
                );
                // Every upstream saturation signal — local semaphore
                // queue full or MySQL/RDS Proxy capacity exhaustion
                // (Conn::new timeout, error 1040, error 1203) — gets
                // translated to a typed 503 overload via
                // `classify_executor_overload`. Other errors fall
                // through as `database_execution_failed` (500).
                let db_err = classify_executor_overload(&err).unwrap_or(DatabaseError::Internal {
                    message: "database query failed".into(),
                    reason: "database_execution_failed",
                });
                let db_execution_attempted = !matches!(db_err, DatabaseError::Overloaded { .. });
                audit_database_error(
                    &state,
                    &claims.sub,
                    &audit_ctx,
                    &req,
                    Some(&scope),
                    &db_err,
                    DatabaseAuditStage {
                        // For the queue-full case, EXPLAIN never even
                        // started — we never got a slot. Reflect that
                        // honestly in audit.
                        explain_attempted: !matches!(db_err, DatabaseError::Overloaded { .. }),
                        db_execution_attempted,
                        views_allowed: scope.allow_views,
                        view_check_required: true,
                        view_check_passed,
                    },
                    Some(&validated.tables),
                )?;
                return Err(database_error_response(db_err));
            }
        }
    };

    // Completion event recording the actual row_count. The query has already
    // executed and the durable `attempt` audit above documents intent, so we
    // do not need to fail-closed here: a missing completion event still
    // leaves a clear audit trail of "user X tried to run Y SQL".
    state
        .audit_service
        .event(
            &claims.sub,
            AuditAction::McpDatabaseQuery,
            AuditOutcome::Success,
        )
        .target(Some(&scope.name))
        .metadata(audit_ctx.metadata(serde_json::json!({
            "client_type": "mcp",
            "surface": "mcp",
            "mcp_event_kind": "database_query",
            "mcp_outcome_kind": "success",
            "tool_name": "canopy_query_database",
            "database_scope": scope.name,
            "connection": scope.connection,
            "environment": scope.environment,
            "canopy_mcp_session_id": req.canopy_mcp_session_id.as_deref(),
            "local_secret_generation": req.local_secret_generation.as_deref(),
            "sql_raw": req.sql,
            "tables": validated.tables,
            "db_execution_attempted": true,
            "explain_attempted": true,
            "explain_passed": true,
            "views_allowed": scope.allow_views,
            "view_check_required": !scope.allow_views,
            "view_check_passed": view_check_passed,
            "access_type": explain.access_type,
            "key_used": explain.key_used,
            "estimated_rows": explain.estimated_rows,
            "row_count": query.rows.len()
        })))
        .commit_best_effort();

    Ok(Json(build_database_response(&scope, explain, query)))
}

/// Translate an `anyhow::Error` from the executor into a typed
/// `DatabaseError::Overloaded` when it carries one of the upstream
/// saturation markers (`ConnectionQueueFull` local semaphore queue full,
/// `DatabaseConnectionUnavailable` MySQL/RDS Proxy capacity exhaustion).
/// Used by both Layer-A and Layer-B Err arms so the route emits a
/// consistent 503 + `connection_queue_full` / `database_connection_unavailable`
/// reason regardless of which executor method first failed.
fn classify_executor_overload(err: &anyhow::Error) -> Option<DatabaseError> {
    if err.chain().any(|cause| cause.is::<ConnectionQueueFull>()) {
        return Some(DatabaseError::Overloaded {
            message: "Database connection queue is full; retry after the in-flight \
                      requests complete."
                .into(),
            reason: "connection_queue_full",
        });
    }
    if err
        .chain()
        .any(|cause| cause.is::<DatabaseConnectionUnavailable>())
    {
        return Some(DatabaseError::Overloaded {
            message: "Database is at capacity (connection acquisition timed out or \
                      server reported too many connections); retry after the load \
                      subsides."
                .into(),
            reason: "database_connection_unavailable",
        });
    }
    None
}

fn database_error_response(err: DatabaseError) -> (StatusCode, Json<ApiError>) {
    match err {
        DatabaseError::BadRequest(message) => (
            StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request(message)),
        ),
        DatabaseError::Denied(message) => {
            (StatusCode::FORBIDDEN, Json(ApiError::forbidden(message)))
        }
        DatabaseError::QueryPlanRejected { message, .. } => (
            StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request(message)),
        ),
        DatabaseError::Internal { message, .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError::internal(message)),
        ),
        // queue saturation is a transient overload, not
        // a server bug — clients should back off and retry, not page
        // on-call. 503 (with the standard "retry later" semantics) is
        // the right HTTP-level signal.
        DatabaseError::Overloaded { message, .. } => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::service_unavailable(message)),
        ),
    }
}

fn database_audit_failure_response() -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ApiError::internal(
            "Audit logging failed — refusing to process database MCP request",
        )),
    )
}

fn cloudwatch_discovery_audit_failure_response() -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ApiError::internal(
            "Audit logging failed — refusing to process CloudWatch MCP discovery request",
        )),
    )
}

#[derive(Debug)]
struct DiscoveryResult {
    log_groups: Vec<LogGroup>,
    scanned_count: u64,
    pages_scanned: u64,
    truncated: bool,
    budget_exhausted: bool,
    aws_next_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DiscoveryCursorPayload {
    version: u8,
    actor: String,
    canopy_mcp_session_id: String,
    local_secret_generation: String,
    tool: String,
    account_id: String,
    region: String,
    prefix: Option<String>,
    aws_next_token: Option<String>,
    pages_scanned: u64,
    results_scanned: u64,
    max_results_returned: u64,
    max_results_scanned: u64,
    max_pages: u64,
    guardrail_policy_id: String,
    entitlement_snapshot_hash: String,
    expires_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DiscoveryCursorEnvelope {
    version: u8,
    alg: String,
    key_id: String,
    nonce: String,
    ciphertext: String,
}

fn discover_mock_log_groups(
    account_id: &str,
    region: &str,
    prefix: Option<&str>,
    scoped_log_arns: &[String],
    guardrails: &McpGuardrails,
) -> DiscoveryResult {
    let scope_prefix = format!("arn:aws:logs:{region}:{account_id}:log-group:");
    let mut scanned_count = 0_u64;
    let mut log_groups = Vec::new();
    for group in mock_log_groups()
        .into_iter()
        .filter(|group| group.arn.starts_with(&scope_prefix))
        .filter(|group| prefix.map(|p| group.name.starts_with(p)).unwrap_or(true))
    {
        scanned_count += 1;
        if scoped_log_arns.is_empty()
            || scoped_log_arns.iter().any(|pattern| {
                crate::services::entitlements::arn_matches_pattern(pattern, &group.arn)
            })
        {
            log_groups.push(group);
        }
    }

    let max_returned = guardrails.max_log_group_list_results as usize;
    let truncated = log_groups.len() > max_returned;
    if truncated {
        log_groups.truncate(max_returned);
    }

    DiscoveryResult {
        log_groups,
        scanned_count,
        pages_scanned: 1,
        truncated,
        budget_exhausted: truncated,
        aws_next_token: None,
    }
}

#[allow(clippy::too_many_arguments)]
async fn discover_aws_log_groups(
    state: &AppState,
    claims: &Claims,
    entitlements: &shared::dto::entitlements::UserEntitlements,
    account_id: &str,
    region: &str,
    prefix: Option<&str>,
    scoped_log_arns: &[String],
    mut next_token: Option<String>,
    mut pages_scanned: u64,
    mut scanned_count: u64,
    guardrails: &McpGuardrails,
    audit_ctx: &AuditRequestContext,
    req: &McpListAllowedLogGroupsRequest,
) -> Result<DiscoveryResult, (StatusCode, Json<ApiError>)> {
    let client = crate::routes::cloudwatch::get_cwl_client_for_account(
        state,
        entitlements,
        account_id,
        region,
        &claims.sub,
    )
    .await?;

    let max_returned = guardrails.max_log_group_list_results as usize;
    let mut log_groups = Vec::new();
    let mut budget_exhausted = false;
    let mut returned_cap_overflow = false;

    loop {
        if pages_scanned >= guardrails.max_describe_log_groups_pages
            || scanned_count >= guardrails.max_discovery_results_scanned
        {
            budget_exhausted = true;
            break;
        }

        let mut describe = client.describe_log_groups().limit(50);
        if let Some(prefix) = prefix {
            describe = describe.log_group_name_prefix(prefix);
        }
        if let Some(token) = next_token.take() {
            describe = describe.next_token(token);
        }

        let resp = describe.send().await.map_err(|e| {
            tracing::error!("mcp DescribeLogGroups failed: {e}");
            let _ = audit_cloudwatch_discovery_error(
                state,
                &claims.sub,
                audit_ctx,
                req,
                account_id,
                region,
                "AWS DescribeLogGroups failed",
                "aws_describe_log_groups_failed",
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ApiError::internal(format!(
                    "AWS DescribeLogGroups failed: {e}"
                ))),
            )
        })?;

        pages_scanned += 1;
        for group in resp.log_groups() {
            if scanned_count >= guardrails.max_discovery_results_scanned {
                budget_exhausted = true;
                break;
            }
            scanned_count += 1;
            let name = group.log_group_name().unwrap_or_default().to_string();
            let arn = group.arn().unwrap_or_default().to_string();
            if scoped_log_arns.is_empty()
                || scoped_log_arns.iter().any(|pattern| {
                    crate::services::entitlements::arn_matches_pattern(pattern, &arn)
                })
            {
                if log_groups.len() < max_returned {
                    log_groups.push(LogGroup {
                        name,
                        arn,
                        stored_bytes: group.stored_bytes(),
                        retention_days: group.retention_in_days(),
                    });
                } else {
                    returned_cap_overflow = true;
                }
            }
        }

        next_token = resp.next_token().map(|s| s.to_string());
        if returned_cap_overflow {
            budget_exhausted = true;
            next_token = None;
        }
        if next_token.is_none() || log_groups.len() >= max_returned || budget_exhausted {
            break;
        }
    }

    let truncated = next_token.is_some() || budget_exhausted;
    Ok(DiscoveryResult {
        log_groups,
        scanned_count,
        pages_scanned,
        truncated,
        budget_exhausted,
        aws_next_token: if budget_exhausted { None } else { next_token },
    })
}

fn discovery_guardrail_policy_id(guardrails: &McpGuardrails) -> String {
    format!(
        "mcp-cloudwatch-discovery:v1:max_returned={}:max_scanned={}:max_pages={}:ttl={}",
        guardrails.max_log_group_list_results,
        guardrails.max_discovery_results_scanned,
        guardrails.max_describe_log_groups_pages,
        guardrails.discovery_cursor_ttl_seconds
    )
}

fn entitlement_snapshot_hash(scoped_log_arns: &[String]) -> String {
    let mut patterns = scoped_log_arns.to_vec();
    patterns.sort();
    let mut hasher = Sha256::new();
    for pattern in patterns {
        hasher.update(pattern.as_bytes());
        hasher.update([0]);
    }
    hex::encode(hasher.finalize())
}

fn discovery_cursor_cipher(state: &AppState) -> Result<Aes256Gcm, ()> {
    let digest = Sha256::digest(state.config.jwt.secret.as_bytes());
    Aes256Gcm::new_from_slice(&digest).map_err(|_| ())
}

fn encode_discovery_cursor(
    state: &AppState,
    payload: &DiscoveryCursorPayload,
) -> Result<String, ()> {
    let cipher = discovery_cursor_cipher(state)?;
    let mut nonce_bytes = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = serde_json::to_vec(payload).map_err(|_| ())?;
    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext.as_slice(),
                aad: CLOUDWATCH_DISCOVERY_CURSOR_AAD,
            },
        )
        .map_err(|_| ())?;
    let envelope = DiscoveryCursorEnvelope {
        version: 1,
        alg: "AES-256-GCM".into(),
        key_id: "jwt-secret-sha256:v1".into(),
        nonce: URL_SAFE_NO_PAD.encode(nonce_bytes),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    };
    let envelope_json = serde_json::to_vec(&envelope).map_err(|_| ())?;
    Ok(URL_SAFE_NO_PAD.encode(envelope_json))
}

fn decode_discovery_cursor(
    state: &AppState,
    raw: &str,
) -> Result<DiscoveryCursorPayload, &'static str> {
    let envelope_bytes = URL_SAFE_NO_PAD
        .decode(raw.as_bytes())
        .map_err(|_| "discovery_cursor_decode_failed")?;
    let envelope: DiscoveryCursorEnvelope =
        serde_json::from_slice(&envelope_bytes).map_err(|_| "discovery_cursor_decode_failed")?;
    if envelope.version != 1
        || envelope.alg != "AES-256-GCM"
        || envelope.key_id != "jwt-secret-sha256:v1"
    {
        return Err("discovery_cursor_unsupported_version");
    }
    let nonce_bytes = URL_SAFE_NO_PAD
        .decode(envelope.nonce.as_bytes())
        .map_err(|_| "discovery_cursor_decode_failed")?;
    if nonce_bytes.len() != 12 {
        return Err("discovery_cursor_decode_failed");
    }
    let ciphertext = URL_SAFE_NO_PAD
        .decode(envelope.ciphertext.as_bytes())
        .map_err(|_| "discovery_cursor_decode_failed")?;
    let cipher = discovery_cursor_cipher(state).map_err(|_| "discovery_cursor_key_unavailable")?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            aes_gcm::aead::Payload {
                msg: ciphertext.as_slice(),
                aad: CLOUDWATCH_DISCOVERY_CURSOR_AAD,
            },
        )
        .map_err(|_| "discovery_cursor_auth_failed")?;
    serde_json::from_slice(&plaintext).map_err(|_| "discovery_cursor_decode_failed")
}

fn validate_discovery_cursor_scope(
    cursor: &DiscoveryCursorPayload,
    actor: &str,
    req: &McpListAllowedLogGroupsRequest,
    guardrails: &McpGuardrails,
) -> Result<(), &'static str> {
    if cursor.version != 1 || cursor.tool != CLOUDWATCH_DISCOVERY_TOOL {
        return Err("discovery_cursor_unsupported_version");
    }
    if cursor.aws_next_token.is_none() {
        return Err("discovery_cursor_unsupported_version");
    }
    if cursor.actor != actor {
        return Err("discovery_cursor_actor_mismatch");
    }
    if req
        .canopy_mcp_session_id
        .as_deref()
        .is_some_and(|sid| sid != cursor.canopy_mcp_session_id)
    {
        return Err("discovery_cursor_session_mismatch");
    }
    if req
        .local_secret_generation
        .as_deref()
        .is_some_and(|lsg| lsg != cursor.local_secret_generation)
    {
        return Err("discovery_cursor_generation_mismatch");
    }
    if req
        .account_id
        .as_deref()
        .is_some_and(|account_id| account_id != cursor.account_id)
    {
        return Err("discovery_cursor_scope_mismatch");
    }
    if req
        .region
        .as_deref()
        .is_some_and(|region| region != cursor.region)
    {
        return Err("discovery_cursor_scope_mismatch");
    }
    if req.prefix.as_deref() != cursor.prefix.as_deref() && req.prefix.is_some() {
        return Err("discovery_cursor_scope_mismatch");
    }
    if cursor.expires_at < Utc::now() {
        return Err("discovery_cursor_expired");
    }
    if cursor.pages_scanned >= guardrails.max_describe_log_groups_pages
        || cursor.results_scanned >= guardrails.max_discovery_results_scanned
        || cursor.max_results_returned != guardrails.max_log_group_list_results
        || cursor.max_results_scanned != guardrails.max_discovery_results_scanned
        || cursor.max_pages != guardrails.max_describe_log_groups_pages
        || cursor.guardrail_policy_id != discovery_guardrail_policy_id(guardrails)
    {
        return Err("discovery_cursor_exhausted_or_policy_changed");
    }
    Ok(())
}

fn validate_discovery_cursor_entitlement_snapshot(
    cursor: &DiscoveryCursorPayload,
    current_entitlement_hash: &str,
) -> Result<(), &'static str> {
    if cursor.entitlement_snapshot_hash != current_entitlement_hash {
        return Err("discovery_cursor_entitlement_changed");
    }
    Ok(())
}

#[cfg(test)]
mod cloudwatch_discovery_tests {
    use super::*;

    fn matching_scope_hash() -> String {
        entitlement_snapshot_hash(&[
            "arn:aws:logs:*:111111111111:log-group:/app/*".to_string(),
            "arn:aws:logs:*:111111111111:log-group:/worker/*".to_string(),
        ])
    }

    fn cursor_payload(guardrails: &McpGuardrails) -> DiscoveryCursorPayload {
        DiscoveryCursorPayload {
            version: 1,
            actor: "dev-admin".into(),
            canopy_mcp_session_id: "session-1".into(),
            local_secret_generation: "generation-1".into(),
            tool: CLOUDWATCH_DISCOVERY_TOOL.into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            prefix: Some("/app".into()),
            aws_next_token: Some("aws-token-1".into()),
            pages_scanned: 1,
            results_scanned: 25,
            max_results_returned: guardrails.max_log_group_list_results,
            max_results_scanned: guardrails.max_discovery_results_scanned,
            max_pages: guardrails.max_describe_log_groups_pages,
            guardrail_policy_id: discovery_guardrail_policy_id(guardrails),
            entitlement_snapshot_hash: matching_scope_hash(),
            expires_at: Utc::now() + Duration::minutes(5),
        }
    }

    fn matching_request() -> McpListAllowedLogGroupsRequest {
        McpListAllowedLogGroupsRequest {
            canopy_mcp_session_id: Some("session-1".into()),
            local_secret_generation: Some("generation-1".into()),
            account_id: Some("111111111111".into()),
            region: Some("us-east-1".into()),
            prefix: Some("/app".into()),
            discovery_cursor: Some("opaque".into()),
        }
    }

    #[test]
    fn discovery_cursor_validation_accepts_matching_scope_and_entitlements() {
        let guardrails = McpGuardrails::default();
        let cursor = cursor_payload(&guardrails);

        assert_eq!(
            validate_discovery_cursor_scope(&cursor, "dev-admin", &matching_request(), &guardrails),
            Ok(())
        );
        assert_eq!(
            validate_discovery_cursor_entitlement_snapshot(&cursor, &matching_scope_hash()),
            Ok(())
        );
    }

    #[test]
    fn discovery_cursor_validation_rejects_scope_mismatch() {
        let guardrails = McpGuardrails::default();
        let cursor = cursor_payload(&guardrails);
        let mut req = matching_request();
        req.region = Some("us-west-2".into());

        assert_eq!(
            validate_discovery_cursor_scope(&cursor, "dev-admin", &req, &guardrails),
            Err("discovery_cursor_scope_mismatch")
        );
    }

    #[test]
    fn discovery_cursor_validation_rejects_exhausted_policy_or_entitlement_changes() {
        let guardrails = McpGuardrails::default();
        let mut cursor = cursor_payload(&guardrails);
        cursor.pages_scanned = guardrails.max_describe_log_groups_pages;
        assert_eq!(
            validate_discovery_cursor_scope(&cursor, "dev-admin", &matching_request(), &guardrails),
            Err("discovery_cursor_exhausted_or_policy_changed")
        );

        let cursor = cursor_payload(&guardrails);
        let changed_hash =
            entitlement_snapshot_hash(&["arn:aws:logs:*:111111111111:log-group:/other/*".into()]);
        assert_eq!(
            validate_discovery_cursor_entitlement_snapshot(&cursor, &changed_hash),
            Err("discovery_cursor_entitlement_changed")
        );
    }
}

fn audit_cloudwatch_discovery_denied(
    state: &AppState,
    actor: &str,
    audit_ctx: &AuditRequestContext,
    req: &McpListAllowedLogGroupsRequest,
    message: &str,
    reason: &str,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    state
        .audit_service
        .event(
            actor,
            AuditAction::McpCloudwatchDiscovery,
            AuditOutcome::Denied,
        )
        .account(req.account_id.as_deref())
        .region(req.region.as_deref())
        .error(Some(message))
        .metadata(audit_ctx.metadata(serde_json::json!({
            "client_type": "mcp",
            "surface": "mcp",
            "mcp_event_kind": "cloudwatch_discovery",
            "mcp_outcome_kind": reason,
            "tool_name": CLOUDWATCH_DISCOVERY_TOOL,
            "canopy_mcp_session_id": req.canopy_mcp_session_id.as_deref(),
            "local_secret_generation": req.local_secret_generation.as_deref(),
            "prefix": req.prefix.as_deref(),
            "has_discovery_cursor": req.discovery_cursor.is_some(),
            "aws_execution_attempted": false,
            "rejection_reason": reason
        })))
        .commit_or_fail()
        .map_err(|_| cloudwatch_discovery_audit_failure_response())
}

fn audit_cloudwatch_discovery_error(
    state: &AppState,
    actor: &str,
    audit_ctx: &AuditRequestContext,
    req: &McpListAllowedLogGroupsRequest,
    account_id: &str,
    region: &str,
    message: &str,
    reason: &str,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    state
        .audit_service
        .event(
            actor,
            AuditAction::McpCloudwatchDiscovery,
            AuditOutcome::Failure,
        )
        .account(Some(account_id))
        .region(Some(region))
        .error(Some(message))
        .metadata(audit_ctx.metadata(serde_json::json!({
            "client_type": "mcp",
            "surface": "mcp",
            "mcp_event_kind": "cloudwatch_discovery",
            "mcp_outcome_kind": reason,
            "tool_name": CLOUDWATCH_DISCOVERY_TOOL,
            "canopy_mcp_session_id": req.canopy_mcp_session_id.as_deref(),
            "local_secret_generation": req.local_secret_generation.as_deref(),
            "prefix": req.prefix.as_deref(),
            "has_discovery_cursor": req.discovery_cursor.is_some(),
            "aws_execution_attempted": true,
            "rejection_reason": reason
        })))
        .commit_or_fail()
        .map_err(|_| cloudwatch_discovery_audit_failure_response())
}

fn require_mcp_guidance(
    state: &AppState,
    claims: &Claims,
    session_id: Option<&str>,
    local_secret_generation: Option<&str>,
    required_guidance: &[&str],
) -> Result<(), &'static str> {
    let Some(session_id) = session_id else {
        return Err("mcp_session_required");
    };
    let Some(local_secret_generation) = local_secret_generation else {
        return Err("mcp_session_required");
    };
    let Some(session) = state.mcp_sessions.get(session_id) else {
        return Err("mcp_session_not_found");
    };

    if session.actor != claims.sub {
        return Err("mcp_session_actor_mismatch");
    }
    if session.local_secret_generation != local_secret_generation {
        return Err("mcp_session_generation_mismatch");
    }
    if session.expires_at < Utc::now() {
        return Err("mcp_session_expired");
    }
    if !required_guidance
        .iter()
        .all(|guidance| session.guidance_delivered.contains(*guidance))
    {
        return Err("guidance_required");
    }

    Ok(())
}

fn audit_database_scope_list_denied(
    state: &AppState,
    actor: &str,
    audit_ctx: &AuditRequestContext,
    req: &ListDatabaseScopesRequest,
    reason: &str,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    state
        .audit_service
        .event(
            actor,
            AuditAction::McpDatabaseScopeList,
            AuditOutcome::Denied,
        )
        .metadata(audit_ctx.metadata(serde_json::json!({
            "client_type": "mcp",
            "surface": "mcp",
            "mcp_event_kind": "database_scope_list",
            "mcp_outcome_kind": reason,
            "aws_execution_attempted": false,
            "db_execution_attempted": false,
            "canopy_mcp_session_id": req.canopy_mcp_session_id.as_deref(),
            "local_secret_generation": req.local_secret_generation.as_deref(),
            "reason": reason
        })))
        .commit_or_fail()
        .map_err(|_| database_audit_failure_response())
}

fn audit_database_denied(
    state: &AppState,
    actor: &str,
    audit_ctx: &AuditRequestContext,
    req: &QueryDatabaseRequest,
    reason: &str,
    scope: Option<&shared::dto::entitlements::DatabaseScope>,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    // Denial-path audit ALWAYS redacts raw SQL. The privacy notice
    // (`privacy_and_audit_notice` guidance) promises that raw SQL is
    // recorded only AFTER the user has been shown the audit warning, which
    // happens during the guidance issuance flow. The literal SQL is
    // captured in the `attempt` audit event, which fires only after all
    // pre-execution gates (including guidance) have passed. Anything that
    // reaches `audit_database_denied` is by definition before that point,
    // so we cannot prove the user has seen the warning yet.
    let sql_field = serde_json::Value::String(
        "[redacted: denial path; raw SQL is captured by the \
                                    `attempt` audit event only after guidance is delivered]"
            .into(),
    );
    let redact_sql = true;
    state
        .audit_service
        .event(actor, AuditAction::McpDatabaseQuery, AuditOutcome::Denied)
        .target(Some(&req.scope))
        .metadata(audit_ctx.metadata(serde_json::json!({
            "client_type": "mcp",
            "surface": "mcp",
            "mcp_event_kind": "database_query",
            "mcp_outcome_kind": "denied",
            "tool_name": "canopy_query_database",
            "database_scope": req.scope,
            "connection": scope.map(|s| s.connection.as_str()),
            "environment": scope.map(|s| s.environment.as_str()),
            "canopy_mcp_session_id": req.canopy_mcp_session_id.as_deref(),
            "local_secret_generation": req.local_secret_generation.as_deref(),
            "sql_raw": sql_field,
            "sql_redacted_pre_guidance": redact_sql,
            "db_execution_attempted": false,
            "explain_attempted": false,
            "explain_passed": false,
            "rejection_reason": reason
        })))
        .commit_or_fail()
        .map_err(|_| database_audit_failure_response())
}

#[allow(clippy::too_many_arguments)]
/// Split a `validated.tables` entry into `(schema, table)`. The collector
/// inserts either `"orders"` (unqualified — resolves against the
/// connection's default database) or `"other_schema.orders"` (an explicit
/// qualifier that survived `enforce_tables`). The view guard needs the
/// pair so it can query `information_schema.tables` deterministically;
/// downstream comparison is always lowercase to match the validator's
/// case-insensitive invariant. We only split on the first `.` to avoid
/// being thrown off by table names that contain a `.` (MySQL allows them
/// in backquotes; the lowercase-only validator already rejects names with
/// non-`[a-z0-9_]` characters, but the helper stays defensive).
fn split_qualified_table(raw: &str, default_schema: &str) -> (String, String) {
    match raw.split_once('.') {
        Some((schema, table)) => (schema.to_string(), table.to_string()),
        None => (default_schema.to_string(), raw.to_string()),
    }
}

/// Bundle of "did we reach stage X before failing" flags + view-guard
/// outcome for `audit_database_error`. Avoids growing the function
/// signature with one new bool per defense layer.
#[derive(Debug, Clone, Copy, Default)]
struct DatabaseAuditStage {
    explain_attempted: bool,
    db_execution_attempted: bool,
    /// `scope.allow_views` snapshot. Recorded so audit reviewers can spot
    /// which scopes have flipped the view opt-in on.
    views_allowed: bool,
    /// True iff the route was going to call `fetch_table_types` because
    /// `allow_views = false`. False when `allow_views = true` (the policy
    /// makes the runtime check unnecessary).
    view_check_required: bool,
    /// True only when the view check ran and every referenced table
    /// resolved to `BASE TABLE`. Stays false on any other path (skipped,
    /// rejected, or information_schema lookup failure).
    view_check_passed: bool,
}

#[allow(clippy::too_many_arguments)]
fn audit_database_error(
    state: &AppState,
    actor: &str,
    audit_ctx: &AuditRequestContext,
    req: &QueryDatabaseRequest,
    scope: Option<&shared::dto::entitlements::DatabaseScope>,
    err: &DatabaseError,
    stage: DatabaseAuditStage,
    tables: Option<&[String]>,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    let (outcome, kind, message, table, access_type, estimated_rows) = match err {
        DatabaseError::BadRequest(message) => (
            AuditOutcome::Failure,
            "bad_request",
            message.as_str(),
            None,
            None,
            None,
        ),
        DatabaseError::Denied(message) => (
            AuditOutcome::Denied,
            "denied",
            message.as_str(),
            None,
            None,
            None,
        ),
        DatabaseError::QueryPlanRejected {
            message,
            table,
            access_type,
            estimated_rows,
            reason,
        } => (
            AuditOutcome::Denied,
            *reason,
            message.as_str(),
            table.as_deref(),
            access_type.as_deref(),
            *estimated_rows,
        ),
        DatabaseError::Overloaded { message, reason } => (
            // Treat overload as Failure for audit so existing dashboards
            // grouping by outcome don't suddenly see a new bucket. The
            // distinct rejection reason (`reason` field) is what
            // operators pivot on for queue-saturation alerts.
            AuditOutcome::Failure,
            *reason,
            message.as_str(),
            None,
            None,
            None,
        ),
        DatabaseError::Internal { message, reason } => (
            AuditOutcome::Failure,
            *reason,
            message.as_str(),
            None,
            None,
            None,
        ),
    };

    // Validation / EXPLAIN denials (DatabaseError::Denied,
    // QueryPlanRejected) must NOT record the literal SQL: those decisions
    // happen before the durable `attempt` audit event, so we can't prove
    // the user has been shown the raw-SQL warning. Failures (genuine I/O
    // errors after the attempt event) can keep the raw SQL because we know
    // the user passed the guidance check by that point.
    let redact_sql = matches!(outcome, AuditOutcome::Denied);
    let sql_field = if redact_sql {
        serde_json::Value::String(
            "[redacted: denial path; raw SQL is captured only by the post-guidance \
             `attempt` event]"
                .into(),
        )
    } else {
        serde_json::Value::String(req.sql.clone())
    };
    state
        .audit_service
        .event(actor, AuditAction::McpDatabaseQuery, outcome)
        .target(Some(&req.scope))
        .error(Some(message))
        .metadata(audit_ctx.metadata(serde_json::json!({
            "client_type": "mcp",
            "surface": "mcp",
            "mcp_event_kind": "database_query",
            "mcp_outcome_kind": kind,
            "tool_name": "canopy_query_database",
            "database_scope": req.scope,
            "connection": scope.map(|s| s.connection.as_str()),
            "environment": scope.map(|s| s.environment.as_str()),
            "canopy_mcp_session_id": req.canopy_mcp_session_id.as_deref(),
            "local_secret_generation": req.local_secret_generation.as_deref(),
            "sql_raw": sql_field,
            "sql_redacted_pre_attempt_event": redact_sql,
            "tables": tables.unwrap_or(&[]),
            "db_execution_attempted": stage.db_execution_attempted,
            "explain_attempted": stage.explain_attempted,
            "explain_passed": false,
            "views_allowed": stage.views_allowed,
            "view_check_required": stage.view_check_required,
            "view_check_passed": stage.view_check_passed,
            "rejection_reason": kind,
            "table": table,
            "access_type": access_type,
            "estimated_rows": estimated_rows
        })))
        .commit_or_fail()
        .map_err(|_| database_audit_failure_response())
}
