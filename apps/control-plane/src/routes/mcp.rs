use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shared::dto::audit::{AuditAction, AuditOutcome};
use shared::dto::cloudwatch::{LogEvent, LogGroup, QueryResultField, QueryStatistics, QueryStatus};
use shared::dto::database::{
    ListDatabaseScopesRequest, ListDatabaseScopesResponse, QueryDatabaseRequest,
    QueryDatabaseResponse,
};
use shared::dto::entitlements::{
    AllowedAccount, McpEc2DiagnosticScope, McpEc2DnsRecordType as EntitlementDnsRecordType,
    McpEc2HttpQueryPolicy, McpEc2LogPathScope,
};
use shared::dto::mcp::{
    lookup_mcp_guidance, McpCloudwatchPreflightRequest, McpCloudwatchPreflightResponse,
    McpEc2DiagnosticCommand, McpEc2DiagnosticCommandStatus, McpEc2DiagnosticCommandType,
    McpEc2DnsRecordType as McpCommandDnsRecordType, McpGetEc2DiagnosticResultResponse,
    McpGuardrails, McpGuidanceSyncRequest, McpGuidanceSyncResponse, McpListAllowedLogGroupsRequest,
    McpListAllowedLogGroupsResponse, McpRegisterSessionRequest, McpRegisterSessionResponse,
    McpRunEc2DiagnosticCommandRequest, McpRunEc2DiagnosticCommandResponse,
    McpRunInsightsQueryRequest, McpRunInsightsQueryResponse, McpSearchLogsRequest,
    McpSearchLogsResponse, MCP_CLOUDWATCH_INSIGHTS_GUIDANCE_KEY,
    MCP_CLOUDWATCH_SEARCH_GUIDANCE_KEY, MCP_DATABASE_GUIDANCE_KEY,
    MCP_EC2_DIAGNOSTICS_GUIDANCE_KEY, MCP_PRIVACY_AND_AUDIT_NOTICE_KEY, MCP_PROTOCOL_VERSION,
    MCP_SECURITY_BOUNDARIES_KEY,
};
use shared::errors::ApiError;
use std::collections::BTreeSet;
use std::sync::Arc;
use uuid::Uuid;

use crate::aws::credentials::SessionContext;
use crate::middleware::auth::AuthenticatedUser;
use crate::services::audit::AuditRequestContext;
use crate::services::auth::Claims;
use crate::services::cloudwatch::{mock_log_events, mock_log_groups};
use crate::services::database::{
    build_database_response, scope_summary, validate_select_sql_for_connection,
    ConnectionQueueFull, DatabaseConnectionUnavailable, DatabaseError, TableType, TableTypeQuery,
    ViewCheckedQueryOutcome,
};
use crate::services::entitlements::{
    arn_matches_pattern, EntitlementService, McpEc2DiagnosticScopeGrant,
};
use crate::services::mcp_ec2_diagnostics::{
    build_mcp_ec2_diagnostic_ssm_dispatch_request, build_mcp_ec2_diagnostic_ssm_send_command_input,
    format_mcp_ec2_diagnostic_output, prepare_mcp_ec2_diagnostic_command_spec_ref_for_dispatch,
    McpEc2DiagnosticCommandSpecRefPayload, MCP_EC2_COMMAND_SPEC_HELPER_VERSION,
    MCP_EC2_COMMAND_SPEC_REF_MAX_TTL_SECONDS,
};
use crate::services::{
    AppState, McpEc2DiagnosticCommandCompletion, McpEc2DiagnosticCommandRecord,
    McpEc2DiagnosticSsmInvocation, McpEc2DiagnosticSsmInvocationStatus,
    McpEc2DiagnosticSsmTargetConfig, McpSessionRecord,
};

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
const CLOUDWATCH_PREFLIGHT_TOOL: &str = "canopy_preflight_request";
const CLOUDWATCH_SEARCH_TOOL: &str = "canopy_search_logs";
const CLOUDWATCH_INSIGHTS_TOOL: &str = "canopy_run_insights_query";
const CLOUDWATCH_SEARCH_REQUIRED_GUIDANCE: &[&str] = &[
    MCP_SECURITY_BOUNDARIES_KEY,
    MCP_CLOUDWATCH_SEARCH_GUIDANCE_KEY,
    MCP_PRIVACY_AND_AUDIT_NOTICE_KEY,
];
const CLOUDWATCH_INSIGHTS_REQUIRED_GUIDANCE: &[&str] = &[
    MCP_SECURITY_BOUNDARIES_KEY,
    MCP_CLOUDWATCH_INSIGHTS_GUIDANCE_KEY,
    MCP_PRIVACY_AND_AUDIT_NOTICE_KEY,
];
const EC2_DIAGNOSTICS_REQUIRED_GUIDANCE: &[&str] = &[
    MCP_SECURITY_BOUNDARIES_KEY,
    MCP_EC2_DIAGNOSTICS_GUIDANCE_KEY,
    MCP_PRIVACY_AND_AUDIT_NOTICE_KEY,
];
const CLOUDWATCH_PREFLIGHT_TOKEN_AAD: &[u8] = b"canopy:mcp:cloudwatch:preflight:v1";
const CLOUDWATCH_SEARCH_CURSOR_AAD: &[u8] = b"canopy:mcp:cloudwatch:search-cursor:v1";
const CLOUDWATCH_INSIGHTS_QUERY_TOKEN_AAD: &[u8] = b"canopy:mcp:cloudwatch:insights-query-token:v1";
const CLOUDWATCH_RAW_AUDIT_AAD: &[u8] = b"canopy:mcp:cloudwatch:raw-audit:v1";
const MCP_EC2_DIAGNOSTIC_RESULT_MAX_BYTES: u64 = 64 * 1024;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/mcp/session/register", post(register_session))
        .route("/api/mcp/guidance/delivered", post(sync_guidance))
        .route(
            "/api/mcp/cloudwatch/log-groups",
            post(list_allowed_log_groups),
        )
        .route(
            "/api/mcp/cloudwatch/preflight",
            post(preflight_cloudwatch_data),
        )
        .route("/api/mcp/cloudwatch/search", post(search_logs))
        .route("/api/mcp/cloudwatch/insights", post(run_insights_query))
        .route("/api/mcp/database/scopes", post(list_database_scopes))
        .route("/api/mcp/database/query", post(query_database))
        .route(
            "/api/mcp/ec2/diagnostics/run",
            post(run_ec2_diagnostic_command),
        )
        .route(
            "/api/mcp/ec2/diagnostics/:command_id",
            get(get_ec2_diagnostic_result),
        )
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

    // Reject empty client-supplied fields up front. The DynamoDB store
    // persists these as string attributes and refuses to decode empty
    // strings on read, so an empty value here would brick the session on the
    // DynamoDB backend: the write succeeds (DynamoDB accepts empty non-key
    // strings) but every later read fails to decode and returns 503. Fail
    // loud with a 400 so behavior is identical across both store backends.
    let empty_field = if req.local_secret_generation.is_empty() {
        Some("local_secret_generation")
    } else if req.client_name.is_empty() {
        Some("client_name")
    } else if req.client_version.is_empty() {
        Some("client_version")
    } else if req.product_phase.is_empty() {
        Some("product_phase")
    } else {
        None
    };
    if let Some(field) = empty_field {
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
                "missing_field": field
            })))
            .commit_best_effort();
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request(
                "MCP session registration requires non-empty client fields",
            )),
        ));
    }

    // Sweep expired sessions opportunistically so a long-running process
    // does not accumulate `McpSessionRecord` instances indefinitely.
    // the previous unbounded growth could accumulate stale sessions.
    let now = Utc::now();
    state.mcp_sessions.sweep_expired(now).await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::service_unavailable(
                "MCP session store unavailable",
            )),
        )
    })?;

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
    state
        .mcp_sessions
        .create_session(
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
        )
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::service_unavailable(
                    "MCP session store unavailable",
                )),
            )
        })?;

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
    let session = state
        .mcp_sessions
        .get_session(&req.canopy_mcp_session_id)
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::service_unavailable(
                    "MCP session store unavailable",
                )),
            )
        })?;
    let Some(session) = session else {
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

    let invalid_reason = if session.actor != claims.sub {
        Some(McpGuidanceDenial::ActorMismatch)
    } else if session.local_secret_generation != req.local_secret_generation {
        Some(McpGuidanceDenial::GenerationMismatch)
    } else if session.is_expired_at(Utc::now()) {
        Some(McpGuidanceDenial::SessionExpired)
    } else {
        None
    };
    if let Some(denial) = invalid_reason {
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
                "mcp_outcome_kind": denial.audit_outcome_kind(),
                "aws_execution_attempted": false,
                "guidance_id": req.guidance_id,
                "guidance_version": req.guidance_version,
                "canopy_mcp_session_id": req.canopy_mcp_session_id,
                "local_secret_generation": req.local_secret_generation
            })))
            .commit_best_effort();
        return Err(denial.http_response("MCP session is not valid for this user"));
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
    // concurrently removed or no longer matches this actor/generation, fail
    // closed so clients cannot receive a "delivered for gating" response that
    // later cannot authorize protected tools.
    let persisted = state
        .mcp_sessions
        .mark_guidance_delivered(
            &req.canopy_mcp_session_id,
            &claims.sub,
            &req.local_secret_generation,
            &guidance_key,
            Utc::now(),
        )
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::service_unavailable(
                    "MCP session store unavailable",
                )),
            )
        })?;
    if !persisted {
        return Err((
            StatusCode::CONFLICT,
            Json(ApiError::new(
                "MCP_SESSION_STATE_CONFLICT",
                "MCP session changed before guidance delivery could be persisted",
            )),
        ));
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

    if let Err(denial) = require_mcp_guidance(
        &state,
        &claims,
        req.canopy_mcp_session_id.as_deref(),
        req.local_secret_generation.as_deref(),
        CLOUDWATCH_DISCOVERY_REQUIRED_GUIDANCE,
    )
    .await
    {
        let message = "Required MCP CloudWatch guidance has not been completed";
        if !denial.is_store_unavailable() {
            audit_cloudwatch_discovery_denied(
                &state,
                &claims.sub,
                &audit_ctx,
                &req,
                message,
                denial.audit_outcome_kind(),
            )?;
        }
        return Err(denial.http_response(message));
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

async fn preflight_cloudwatch_data(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    headers: HeaderMap,
    Json(req): Json<McpCloudwatchPreflightRequest>,
) -> ApiResult<McpCloudwatchPreflightResponse> {
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

    let Some(required_guidance) = cloudwatch_required_guidance_for_tool(&req.tool_name) else {
        audit_cloudwatch_preflight_denied(
            &state,
            &claims.sub,
            &audit_ctx,
            &req,
            "unknown_tool",
            "Unknown MCP CloudWatch data tool",
        )?;
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request("Unknown MCP CloudWatch data tool")),
        ));
    };

    if !entitlements.features.can_use_mcp_cloudwatch {
        audit_cloudwatch_preflight_denied(
            &state,
            &claims.sub,
            &audit_ctx,
            &req,
            "entitlement_disabled",
            "can_use_mcp_cloudwatch entitlement disabled",
        )?;
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("MCP CloudWatch is not enabled")),
        ));
    }

    if let Err(denial) = require_mcp_guidance(
        &state,
        &claims,
        req.canopy_mcp_session_id.as_deref(),
        req.local_secret_generation.as_deref(),
        required_guidance,
    )
    .await
    {
        let message = "Required MCP CloudWatch data guidance has not been completed";
        if !denial.is_store_unavailable() {
            audit_cloudwatch_preflight_denied(
                &state,
                &claims.sub,
                &audit_ctx,
                &req,
                denial.audit_outcome_kind(),
                message,
            )?;
        }
        return Err(denial.http_response(message));
    }

    let log_group_names = match validate_cloudwatch_preflight_shape(&req, &guardrails) {
        Ok(names) => names,
        Err(reason) => {
            audit_cloudwatch_preflight_denied(
                &state,
                &claims.sub,
                &audit_ctx,
                &req,
                reason,
                "MCP CloudWatch preflight request failed guardrails",
            )?;
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ApiError::bad_request(format!(
                    "MCP CloudWatch preflight request failed guardrails: {reason}"
                ))),
            ));
        }
    };

    let scoped_log_arns = match authorize_mcp_cloudwatch_scope(
        &ent_service,
        &claims,
        &req.account_id,
        &req.region,
        &log_group_names,
    )
    .await
    {
        Ok(scoped_log_arns) => scoped_log_arns,
        Err(reason) => {
            audit_cloudwatch_preflight_denied(
                &state,
                &claims.sub,
                &audit_ctx,
                &req,
                reason,
                "MCP CloudWatch preflight is not authorized for this scope",
            )?;
            return Err((
                StatusCode::FORBIDDEN,
                Json(ApiError::forbidden(
                    "MCP CloudWatch preflight is not authorized for this scope",
                )),
            ));
        }
    };
    let raw_plaintext_allowed = ent_service
        .mcp_cloudwatch_raw_audit_plaintext_allowed(
            &claims,
            &req.account_id,
            &req.region,
            &log_group_names,
        )
        .await;
    let filter_pattern_raw_encrypted = encrypted_cloudwatch_raw_audit_value(
        &state,
        &claims.sub,
        req.canopy_mcp_session_id.as_deref(),
        req.local_secret_generation.as_deref(),
        req.tool_name.as_str(),
        &req.account_id,
        &req.region,
        &log_group_names,
        "filter_pattern",
        req.filter_pattern.as_deref(),
    )?;
    let query_string_raw_encrypted = encrypted_cloudwatch_raw_audit_value(
        &state,
        &claims.sub,
        req.canopy_mcp_session_id.as_deref(),
        req.local_secret_generation.as_deref(),
        req.tool_name.as_str(),
        &req.account_id,
        &req.region,
        &log_group_names,
        "query_string",
        req.query_string.as_deref(),
    )?;

    let expires_at = Utc::now() + Duration::seconds(guardrails.preflight_token_ttl_seconds as i64);
    let payload = CloudwatchPreflightTokenPayload {
        version: 1,
        actor: claims.sub.clone(),
        canopy_mcp_session_id: req.canopy_mcp_session_id.clone().unwrap_or_default(),
        local_secret_generation: req.local_secret_generation.clone().unwrap_or_default(),
        tool: req.tool_name.clone(),
        account_id: req.account_id.clone(),
        region: req.region.clone(),
        log_group_names: log_group_names.clone(),
        filter_pattern: req.filter_pattern.clone(),
        query_string: req.query_string.clone(),
        start_time: req.start_time,
        end_time: req.end_time,
        limit: req.limit,
        max_events: guardrails.max_search_events,
        guardrail_policy_id: cloudwatch_data_guardrail_policy_id(&guardrails),
        entitlement_snapshot_hash: entitlement_snapshot_hash(&scoped_log_arns),
        expires_at,
    };
    let preflight_token = encode_cloudwatch_token(&state, &payload, CLOUDWATCH_PREFLIGHT_TOKEN_AAD)
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::internal(
                    "Failed to seal MCP CloudWatch preflight token",
                )),
            )
        })?;

    state
        .audit_service
        .event(
            &claims.sub,
            AuditAction::McpCloudwatchPreflight,
            AuditOutcome::Success,
        )
        .account(Some(&req.account_id))
        .region(Some(&req.region))
        .target(Some(&log_group_names.join(",")))
        .metadata(audit_ctx.metadata(serde_json::json!({
            "client_type": "mcp",
            "surface": "mcp",
            "mcp_event_kind": "cloudwatch_preflight",
            "mcp_outcome_kind": "success",
            "tool_name": req.tool_name,
            "canopy_mcp_session_id": req.canopy_mcp_session_id.as_deref(),
            "local_secret_generation": req.local_secret_generation.as_deref(),
            "log_group_names": log_group_names,
            "start_time": req.start_time,
            "end_time": req.end_time,
            "limit": req.limit,
            "raw_audit_storage": if raw_plaintext_allowed { "plaintext_restricted" } else { "encrypted_default" },
            "raw_plaintext_allowed": raw_plaintext_allowed,
            "filter_pattern_raw": cloudwatch_raw_plaintext_value(req.filter_pattern.as_deref(), raw_plaintext_allowed),
            "filter_pattern_raw_encrypted": filter_pattern_raw_encrypted,
            "query_string_raw": cloudwatch_raw_plaintext_value(req.query_string.as_deref(), raw_plaintext_allowed),
            "query_string_raw_encrypted": query_string_raw_encrypted,
            "aws_execution_attempted": false,
            "preflight_token_issued": true,
        })))
        .commit_or_fail()
        .map_err(|_| cloudwatch_data_audit_failure_response())?;

    Ok(Json(McpCloudwatchPreflightResponse {
        tool_name: req.tool_name,
        account_id: req.account_id,
        region: req.region,
        log_group_names,
        preflight_token,
        expires_at,
        guardrails,
    }))
}

async fn search_logs(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    headers: HeaderMap,
    Json(req): Json<McpSearchLogsRequest>,
) -> ApiResult<McpSearchLogsResponse> {
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

    if let Err(denial) = require_mcp_guidance(
        &state,
        &claims,
        req.canopy_mcp_session_id.as_deref(),
        req.local_secret_generation.as_deref(),
        CLOUDWATCH_SEARCH_REQUIRED_GUIDANCE,
    )
    .await
    {
        let message = "Required MCP CloudWatch search guidance has not been completed";
        if !denial.is_store_unavailable() {
            audit_cloudwatch_search_denied(
                &state,
                &claims.sub,
                &audit_ctx,
                &req,
                None,
                denial.audit_outcome_kind(),
                message,
            )?;
        }
        return Err(denial.http_response(message));
    }

    let context = match cloudwatch_search_context_from_request(&state, &claims, &req, &guardrails) {
        Ok(context) => context,
        Err(reason) => {
            audit_cloudwatch_search_denied(
                &state,
                &claims.sub,
                &audit_ctx,
                &req,
                None,
                reason,
                "Invalid MCP CloudWatch search token mode",
            )?;
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ApiError::bad_request(format!(
                    "Invalid MCP CloudWatch search token mode: {reason}"
                ))),
            ));
        }
    };

    let scoped_log_arns = match authorize_mcp_cloudwatch_scope(
        &ent_service,
        &claims,
        &context.account_id,
        &context.region,
        std::slice::from_ref(&context.log_group_name),
    )
    .await
    {
        Ok(scoped_log_arns) => scoped_log_arns,
        Err(reason) => {
            audit_cloudwatch_search_denied(
                &state,
                &claims.sub,
                &audit_ctx,
                &req,
                Some(&context),
                reason,
                "MCP CloudWatch search is not authorized for this scope",
            )?;
            return Err((
                StatusCode::FORBIDDEN,
                Json(ApiError::forbidden(
                    "MCP CloudWatch search is not authorized for this scope",
                )),
            ));
        }
    };

    if context.entitlement_snapshot_hash != entitlement_snapshot_hash(&scoped_log_arns) {
        audit_cloudwatch_search_denied(
            &state,
            &claims.sub,
            &audit_ctx,
            &req,
            Some(&context),
            "search_token_entitlement_changed",
            "MCP CloudWatch search token entitlements no longer match",
        )?;
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError::forbidden(
                "MCP CloudWatch search token is no longer valid for current entitlements",
            )),
        ));
    }

    let search_log_group_names = vec![context.log_group_name.clone()];
    let raw_plaintext_allowed = ent_service
        .mcp_cloudwatch_raw_audit_plaintext_allowed(
            &claims,
            &context.account_id,
            &context.region,
            &search_log_group_names,
        )
        .await;

    audit_cloudwatch_search_attempt(
        &state,
        &claims.sub,
        &audit_ctx,
        &req,
        &context,
        raw_plaintext_allowed,
    )?;

    let search_result = if state.config.use_mock_aws() {
        execute_mock_search(&context, &guardrails)
    } else {
        execute_aws_search(&state, &claims, &entitlements, &context)
            .await
            .inspect_err(|_| {
                let _ = audit_cloudwatch_search_failure(
                    &state,
                    &claims.sub,
                    &audit_ctx,
                    &req,
                    &context,
                    raw_plaintext_allowed,
                    "aws_filter_log_events_failed",
                    "AWS FilterLogEvents failed",
                );
            })?
    };

    let search_cursor = if search_result.truncated {
        search_result
            .next_context
            .map(|next_context| {
                let next_context = attach_search_cursor_identity(next_context, &claims, &req);
                encode_cloudwatch_token(&state, &next_context, CLOUDWATCH_SEARCH_CURSOR_AAD)
                    .map_err(|_| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ApiError::internal(
                                "Failed to seal MCP CloudWatch search cursor",
                            )),
                        )
                    })
            })
            .transpose()?
    } else {
        None
    };
    let filter_pattern_raw_encrypted = encrypted_cloudwatch_raw_audit_value(
        &state,
        &claims.sub,
        req.canopy_mcp_session_id.as_deref(),
        req.local_secret_generation.as_deref(),
        CLOUDWATCH_SEARCH_TOOL,
        &context.account_id,
        &context.region,
        &search_log_group_names,
        "filter_pattern",
        context.filter_pattern.as_deref(),
    )?;

    state
        .audit_service
        .event(
            &claims.sub,
            AuditAction::McpCloudwatchSearch,
            AuditOutcome::Success,
        )
        .account(Some(&context.account_id))
        .region(Some(&context.region))
        .target(Some(&context.log_group_name))
        .metadata(audit_ctx.metadata(serde_json::json!({
            "client_type": "mcp",
            "surface": "mcp",
            "mcp_event_kind": "cloudwatch_search",
            "mcp_outcome_kind": "success",
            "tool_name": CLOUDWATCH_SEARCH_TOOL,
            "canopy_mcp_session_id": req.canopy_mcp_session_id.as_deref(),
            "local_secret_generation": req.local_secret_generation.as_deref(),
            "log_group_name": context.log_group_name,
            "start_time": context.start_time,
            "end_time": context.end_time,
            "limit": context.limit,
            "raw_audit_storage": if raw_plaintext_allowed { "plaintext_restricted" } else { "encrypted_default" },
            "raw_plaintext_allowed": raw_plaintext_allowed,
            "filter_pattern_raw": cloudwatch_raw_plaintext_value(context.filter_pattern.as_deref(), raw_plaintext_allowed),
            "filter_pattern_raw_encrypted": filter_pattern_raw_encrypted,
            "aws_execution_attempted": !state.config.use_mock_aws(),
            "returned_count": search_result.events.len(),
            "truncated": search_result.truncated,
            "cursor_issued": search_cursor.is_some(),
        })))
        .commit_or_fail()
        .map_err(|_| cloudwatch_data_audit_failure_response())?;

    let next_action_hint = if search_result.truncated && search_cursor.is_some() {
        Some("Use search_cursor to continue this exact CloudWatch search.".to_string())
    } else if search_result.truncated {
        Some(
            "Narrow the time range or filter; the MCP search result budget was exhausted."
                .to_string(),
        )
    } else {
        None
    };

    Ok(Json(McpSearchLogsResponse {
        account_id: context.account_id,
        region: context.region,
        log_group_name: context.log_group_name,
        returned_count: search_result.events.len(),
        events: search_result.events,
        truncated: search_result.truncated,
        search_cursor,
        next_action_hint,
    }))
}

async fn run_insights_query(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    headers: HeaderMap,
    Json(req): Json<McpRunInsightsQueryRequest>,
) -> ApiResult<McpRunInsightsQueryResponse> {
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

    if let Err(denial) = require_mcp_guidance(
        &state,
        &claims,
        req.canopy_mcp_session_id.as_deref(),
        req.local_secret_generation.as_deref(),
        CLOUDWATCH_INSIGHTS_REQUIRED_GUIDANCE,
    )
    .await
    {
        let message = "Required MCP CloudWatch Insights guidance has not been completed";
        if !denial.is_store_unavailable() {
            audit_cloudwatch_insights_denied(
                &state,
                &claims.sub,
                &audit_ctx,
                &req,
                None,
                denial.audit_outcome_kind(),
                message,
            )?;
        }
        return Err(denial.http_response(message));
    }

    match (req.preflight_token.as_deref(), req.query_token.as_deref()) {
        (Some(preflight_token), None) => {
            start_mcp_insights_query(
                &state,
                &claims,
                &audit_ctx,
                &ent_service,
                &entitlements,
                &req,
                preflight_token,
                &guardrails,
            )
            .await
        }
        (None, Some(query_token)) => {
            poll_mcp_insights_query(
                &state,
                &claims,
                &audit_ctx,
                &ent_service,
                &entitlements,
                &req,
                query_token,
                &guardrails,
            )
            .await
        }
        _ => {
            audit_cloudwatch_insights_denied(
                &state,
                &claims.sub,
                &audit_ctx,
                &req,
                None,
                "invalid_token_mode",
                "MCP Insights calls require exactly one of preflight_token or query_token",
            )?;
            Err((
                StatusCode::BAD_REQUEST,
                Json(ApiError::bad_request(
                    "MCP Insights calls require exactly one of preflight_token or query_token",
                )),
            ))
        }
    }
}

async fn run_ec2_diagnostic_command(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    headers: HeaderMap,
    Json(req): Json<McpRunEc2DiagnosticCommandRequest>,
) -> ApiResult<McpRunEc2DiagnosticCommandResponse> {
    if !state.audit_service.is_healthy() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal("Audit logging unavailable")),
        ));
    }

    let audit_ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);
    let ent_service = EntitlementService::new(state.entitlement_store.clone());
    let entitlements = ent_service.evaluate(&claims).await;

    if !entitlements.features.can_use_mcp_ec2 {
        audit_mcp_ec2_diagnostics(
            &state,
            &claims.sub,
            &audit_ctx,
            McpEc2DiagnosticAudit::Run {
                req: &req,
                command_type: Some(mcp_ec2_command_type(&req.command)),
                command_id: None,
            },
            AuditOutcome::Denied,
            "entitlement_disabled",
            None,
            false,
        )?;
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError::forbidden(
                "MCP EC2 diagnostics is not enabled for this user",
            )),
        ));
    }

    if let Err(denial) = require_mcp_guidance(
        &state,
        &claims,
        req.canopy_mcp_session_id.as_deref(),
        req.local_secret_generation.as_deref(),
        EC2_DIAGNOSTICS_REQUIRED_GUIDANCE,
    )
    .await
    {
        if !denial.is_store_unavailable() {
            audit_mcp_ec2_diagnostics(
                &state,
                &claims.sub,
                &audit_ctx,
                McpEc2DiagnosticAudit::Run {
                    req: &req,
                    command_type: Some(mcp_ec2_command_type(&req.command)),
                    command_id: None,
                },
                AuditOutcome::Denied,
                denial.audit_outcome_kind(),
                None,
                false,
            )?;
        }
        return Err(
            denial.http_response("Required MCP EC2 diagnostics guidance has not been delivered")
        );
    }

    let authorization =
        match authorize_mcp_ec2_diagnostic_command(&ent_service, &claims, &req).await {
            Ok(authorization) => authorization,
            Err(reason) => {
                audit_mcp_ec2_diagnostics(
                    &state,
                    &claims.sub,
                    &audit_ctx,
                    McpEc2DiagnosticAudit::Run {
                        req: &req,
                        command_type: Some(mcp_ec2_command_type(&req.command)),
                        command_id: None,
                    },
                    AuditOutcome::Denied,
                    reason,
                    None,
                    false,
                )?;
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ApiError::forbidden(
                        "EC2 diagnostic command is outside the authorized MCP scope",
                    )),
                ));
            }
        };

    if authorization.requires_instance_metadata {
        audit_mcp_ec2_diagnostics(
            &state,
            &claims.sub,
            &audit_ctx,
            McpEc2DiagnosticAudit::Run {
                req: &req,
                command_type: Some(authorization.command_type.clone()),
                command_id: None,
            },
            AuditOutcome::Failure,
            "target_metadata_resolution_not_implemented",
            Some(&authorization),
            false,
        )?;
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::service_unavailable(
                "EC2 target metadata resolution is not available yet",
            )),
        ));
    }

    if !state
        .mcp_ec2_diagnostic_ssm_dispatchers
        .uses_live_aws_backend()
    {
        audit_mcp_ec2_diagnostics(
            &state,
            &claims.sub,
            &audit_ctx,
            McpEc2DiagnosticAudit::Run {
                req: &req,
                command_type: Some(authorization.command_type.clone()),
                command_id: None,
            },
            AuditOutcome::Failure,
            "dispatch_backend_unavailable",
            Some(&authorization),
            false,
        )?;
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::service_unavailable(
                "MCP EC2 diagnostics dispatch backend is not available yet",
            )),
        ));
    }

    let Some(account) = authorization.account.as_ref() else {
        audit_mcp_ec2_diagnostics(
            &state,
            &claims.sub,
            &audit_ctx,
            McpEc2DiagnosticAudit::Run {
                req: &req,
                command_type: Some(authorization.command_type.clone()),
                command_id: None,
            },
            AuditOutcome::Failure,
            "authorized_account_missing",
            Some(&authorization),
            false,
        )?;
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::service_unavailable(
                "MCP EC2 diagnostics target account is unavailable",
            )),
        ));
    };

    let Some(session_id) = req.canopy_mcp_session_id.as_deref() else {
        audit_mcp_ec2_diagnostics(
            &state,
            &claims.sub,
            &audit_ctx,
            McpEc2DiagnosticAudit::Run {
                req: &req,
                command_type: Some(authorization.command_type.clone()),
                command_id: None,
            },
            AuditOutcome::Failure,
            "mcp_session_required",
            Some(&authorization),
            false,
        )?;
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::service_unavailable(
                "MCP EC2 diagnostics session is unavailable",
            )),
        ));
    };
    let Some(local_secret_generation) = req.local_secret_generation.as_deref() else {
        audit_mcp_ec2_diagnostics(
            &state,
            &claims.sub,
            &audit_ctx,
            McpEc2DiagnosticAudit::Run {
                req: &req,
                command_type: Some(authorization.command_type.clone()),
                command_id: None,
            },
            AuditOutcome::Failure,
            "local_secret_generation_required",
            Some(&authorization),
            false,
        )?;
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::service_unavailable(
                "MCP EC2 diagnostics session generation is unavailable",
            )),
        ));
    };

    let Some(command_spec_key) = state
        .config
        .mcp
        .ec2_diagnostic_command_spec_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        audit_mcp_ec2_diagnostics(
            &state,
            &claims.sub,
            &audit_ctx,
            McpEc2DiagnosticAudit::Run {
                req: &req,
                command_type: Some(authorization.command_type.clone()),
                command_id: None,
            },
            AuditOutcome::Failure,
            "dispatch_config_unavailable",
            Some(&authorization),
            false,
        )?;
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::service_unavailable(
                "MCP EC2 diagnostics dispatch configuration is unavailable",
            )),
        ));
    };

    let now = Utc::now();
    let command_id = format!("mcp-ec2-{}", Uuid::new_v4());
    let submitted_at = now;
    let expires_at = now + Duration::minutes(10);
    let spec_ref_ttl_seconds = MCP_EC2_COMMAND_SPEC_REF_MAX_TTL_SECONDS.min(300);
    let helper_version = state
        .config
        .mcp
        .ec2_diagnostic_helper_version
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(MCP_EC2_COMMAND_SPEC_HELPER_VERSION)
        .to_string();
    let command_type = authorization.command_type.clone();
    let command_spec_payload = McpEc2DiagnosticCommandSpecRefPayload {
        version: 1,
        helper_version,
        mcp_ec2_command_id: command_id.clone(),
        actor: claims.sub.clone(),
        mcp_session_id: session_id.to_string(),
        local_secret_generation: local_secret_generation.to_string(),
        instance_id: req.instance_id.clone(),
        account_id: req.account_id.clone(),
        region: req.region.clone(),
        command_type: command_type.clone(),
        command: authorization.command.clone(),
        one_time_command_store_claim_required: true,
        allowlist_rule_id: authorization.allowlist_rule_id.clone(),
        command_scope_id: authorization.command_scope_id.clone(),
        issued_at: now,
        expires_at: now + Duration::seconds(spec_ref_ttl_seconds),
    };
    let prepared_ref = match prepare_mcp_ec2_diagnostic_command_spec_ref_for_dispatch(
        command_spec_key,
        &command_spec_payload,
        now,
    ) {
        Ok(prepared_ref) => prepared_ref,
        Err(_) => {
            audit_mcp_ec2_diagnostics(
                &state,
                &claims.sub,
                &audit_ctx,
                McpEc2DiagnosticAudit::Run {
                    req: &req,
                    command_type: Some(command_type.clone()),
                    command_id: None,
                },
                AuditOutcome::Failure,
                "command_spec_ref_failed",
                Some(&authorization),
                false,
            )?;
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::service_unavailable(
                    "MCP EC2 diagnostics command spec reference could not be prepared",
                )),
            ));
        }
    };
    let dispatch_request = match build_mcp_ec2_diagnostic_ssm_dispatch_request(
        &state.config.mcp,
        &command_id,
        &req.instance_id,
        &prepared_ref,
    ) {
        Ok(request) => request,
        Err(_) => {
            audit_mcp_ec2_diagnostics(
                &state,
                &claims.sub,
                &audit_ctx,
                McpEc2DiagnosticAudit::Run {
                    req: &req,
                    command_type: Some(command_type.clone()),
                    command_id: Some(&command_id),
                },
                AuditOutcome::Failure,
                "dispatch_config_unavailable",
                Some(&authorization),
                false,
            )?;
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::service_unavailable(
                    "MCP EC2 diagnostics dispatch configuration is unavailable",
                )),
            ));
        }
    };
    let ssm_command_input = match build_mcp_ec2_diagnostic_ssm_send_command_input(&dispatch_request)
    {
        Ok(input) => input,
        Err(_) => {
            audit_mcp_ec2_diagnostics(
                &state,
                &claims.sub,
                &audit_ctx,
                McpEc2DiagnosticAudit::Run {
                    req: &req,
                    command_type: Some(command_type.clone()),
                    command_id: Some(&command_id),
                },
                AuditOutcome::Failure,
                "dispatch_request_invalid",
                Some(&authorization),
                false,
            )?;
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::service_unavailable(
                    "MCP EC2 diagnostics dispatch request is invalid",
                )),
            ));
        }
    };

    audit_mcp_ec2_diagnostics(
        &state,
        &claims.sub,
        &audit_ctx,
        McpEc2DiagnosticAudit::Run {
            req: &req,
            command_type: Some(command_type.clone()),
            command_id: Some(&command_id),
        },
        AuditOutcome::Success,
        "attempt",
        Some(&authorization),
        false,
    )?;

    let command_record = McpEc2DiagnosticCommandRecord {
        actor: claims.sub.clone(),
        actor_email: claims.email.clone(),
        mcp_session_id: session_id.to_string(),
        local_secret_generation: local_secret_generation.to_string(),
        instance_id: req.instance_id.clone(),
        account_id: req.account_id.clone(),
        region: req.region.clone(),
        command_type: command_type.clone(),
        allowlist_rule_id: authorization.allowlist_rule_id.clone(),
        command_scope_id: authorization.command_scope_id.clone(),
        authorization_fingerprint: Some(authorization.authorization_fingerprint.clone()),
        status: McpEc2DiagnosticCommandStatus::Queued,
        aws_ssm_command_id: None,
        submitted_at,
        completed_at: None,
        output_byte_count: 0,
        dropped_byte_count: 0,
        output_sequence_start: 0,
        output_sequence_end: 0,
        exit_status: None,
        truncated: false,
        expires_at,
        created_at: now,
        updated_at: now,
    };
    if state
        .mcp_ec2_diagnostic_commands
        .create_command(command_id.clone(), command_record)
        .await
        .is_err()
    {
        audit_mcp_ec2_diagnostics(
            &state,
            &claims.sub,
            &audit_ctx,
            McpEc2DiagnosticAudit::Run {
                req: &req,
                command_type: Some(command_type.clone()),
                command_id: Some(&command_id),
            },
            AuditOutcome::Failure,
            "command_store_unavailable",
            Some(&authorization),
            false,
        )?;
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::service_unavailable(
                "MCP EC2 diagnostics command store is unavailable",
            )),
        ));
    }

    let session_context = SessionContext {
        user_id: claims.sub.clone(),
        team: claims
            .groups
            .first()
            .cloned()
            .unwrap_or_else(|| "unknown".to_string()),
        environment: if state.config.dev_mode {
            "dev".to_string()
        } else {
            "production".to_string()
        },
        session_duration_seconds: state.config.aws.session_duration_seconds,
        sts_external_id: state.config.aws.sts_external_id.clone(),
    };
    let resolved_aws_config = match state
        .mcp_ec2_diagnostic_aws_config_resolver
        .resolve_config(
            &state.base_aws_config,
            account,
            &req.region,
            &session_context,
        )
        .await
    {
        Ok(config) => config,
        Err(_) => {
            audit_mcp_ec2_diagnostics(
                &state,
                &claims.sub,
                &audit_ctx,
                McpEc2DiagnosticAudit::Run {
                    req: &req,
                    command_type: Some(command_type.clone()),
                    command_id: Some(&command_id),
                },
                AuditOutcome::Failure,
                "dispatch_credentials_unavailable",
                Some(&authorization),
                true,
            )?;
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::service_unavailable(
                    "MCP EC2 diagnostics AWS credentials are unavailable",
                )),
            ));
        }
    };
    let target_config = match McpEc2DiagnosticSsmTargetConfig::new(
        &req.account_id,
        &req.region,
        resolved_aws_config.resolved_account_id(),
        resolved_aws_config.resolved_region(),
        resolved_aws_config.aws_config(),
    ) {
        Ok(target_config) => target_config,
        Err(_) => {
            audit_mcp_ec2_diagnostics(
                &state,
                &claims.sub,
                &audit_ctx,
                McpEc2DiagnosticAudit::Run {
                    req: &req,
                    command_type: Some(command_type.clone()),
                    command_id: Some(&command_id),
                },
                AuditOutcome::Failure,
                "dispatch_target_config_invalid",
                Some(&authorization),
                true,
            )?;
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::service_unavailable(
                    "MCP EC2 diagnostics target configuration is invalid",
                )),
            ));
        }
    };
    let dispatcher = state
        .mcp_ec2_diagnostic_ssm_dispatchers
        .dispatcher_for_target_config(&target_config);
    let aws_ssm_command_id = match dispatcher.dispatch(&ssm_command_input).await {
        Ok(command_id) => command_id,
        Err(_) => {
            audit_mcp_ec2_diagnostics(
                &state,
                &claims.sub,
                &audit_ctx,
                McpEc2DiagnosticAudit::Run {
                    req: &req,
                    command_type: Some(command_type.clone()),
                    command_id: Some(&command_id),
                },
                AuditOutcome::Failure,
                "dispatch_backend_unavailable",
                Some(&authorization),
                true,
            )?;
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::service_unavailable(
                    "MCP EC2 diagnostics dispatch backend is unavailable",
                )),
            ));
        }
    };
    let claim = state
        .mcp_ec2_diagnostic_commands
        .mark_dispatched(
            &command_id,
            &claims.sub,
            session_id,
            local_secret_generation,
            &aws_ssm_command_id,
            Utc::now(),
        )
        .await;
    match claim {
        Ok(Some(_)) => {}
        Ok(None) | Err(_) => {
            let cancel_succeeded = dispatcher.cancel(&aws_ssm_command_id).await.is_ok();
            audit_mcp_ec2_diagnostics_with_details(
                &state,
                &claims.sub,
                &audit_ctx,
                McpEc2DiagnosticAudit::Run {
                    req: &req,
                    command_type: Some(command_type.clone()),
                    command_id: Some(&command_id),
                },
                AuditOutcome::Failure,
                "command_store_claim_failed",
                Some(&authorization),
                true,
                McpEc2DiagnosticAuditDetails {
                    aws_ssm_command_id: Some(&aws_ssm_command_id),
                    aws_cancel_attempted: Some(true),
                    aws_cancel_succeeded: Some(cancel_succeeded),
                    ..McpEc2DiagnosticAuditDetails::default()
                },
            )?;
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::service_unavailable(
                    "MCP EC2 diagnostics command store claim failed",
                )),
            ));
        }
    }

    audit_mcp_ec2_diagnostics(
        &state,
        &claims.sub,
        &audit_ctx,
        McpEc2DiagnosticAudit::Run {
            req: &req,
            command_type: Some(command_type.clone()),
            command_id: Some(&command_id),
        },
        AuditOutcome::Success,
        "dispatch_submitted",
        Some(&authorization),
        true,
    )?;

    Ok(Json(McpRunEc2DiagnosticCommandResponse {
        mcp_ec2_command_id: command_id,
        status: McpEc2DiagnosticCommandStatus::Running,
        instance_id: req.instance_id,
        account_id: req.account_id,
        region: req.region,
        command_type,
        submitted_at,
        expires_at,
    }))
}

#[derive(Debug, Deserialize)]
struct McpGetEc2DiagnosticResultQuery {
    canopy_mcp_session_id: Option<String>,
    local_secret_generation: Option<String>,
    max_bytes: u64,
}

async fn get_ec2_diagnostic_result(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    headers: HeaderMap,
    Path(command_id): Path<String>,
    Query(query): Query<McpGetEc2DiagnosticResultQuery>,
) -> ApiResult<McpGetEc2DiagnosticResultResponse> {
    if !state.audit_service.is_healthy() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal("Audit logging unavailable")),
        ));
    }

    let audit_ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);
    if let Err(denial) = require_mcp_guidance(
        &state,
        &claims,
        query.canopy_mcp_session_id.as_deref(),
        query.local_secret_generation.as_deref(),
        EC2_DIAGNOSTICS_REQUIRED_GUIDANCE,
    )
    .await
    {
        if !denial.is_store_unavailable() {
            audit_mcp_ec2_diagnostics(
                &state,
                &claims.sub,
                &audit_ctx,
                McpEc2DiagnosticAudit::Result {
                    command_id: &command_id,
                    session_id: query.canopy_mcp_session_id.as_deref(),
                    local_secret_generation: query.local_secret_generation.as_deref(),
                    max_bytes: query.max_bytes,
                },
                AuditOutcome::Denied,
                denial.audit_outcome_kind(),
                None,
                false,
            )?;
        }
        return Err(
            denial.http_response("Required MCP EC2 diagnostics guidance has not been delivered")
        );
    }

    let Some(session_id) = query.canopy_mcp_session_id.as_deref() else {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("MCP session is required")),
        ));
    };
    let Some(local_secret_generation) = query.local_secret_generation.as_deref() else {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("MCP session is required")),
        ));
    };
    let result_byte_budget = match mcp_ec2_result_byte_budget(query.max_bytes) {
        Some(budget) => budget,
        None => {
            audit_mcp_ec2_diagnostics(
                &state,
                &claims.sub,
                &audit_ctx,
                McpEc2DiagnosticAudit::Result {
                    command_id: &command_id,
                    session_id: Some(session_id),
                    local_secret_generation: Some(local_secret_generation),
                    max_bytes: query.max_bytes,
                },
                AuditOutcome::Failure,
                "invalid_max_bytes",
                None,
                false,
            )?;
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ApiError::bad_request("max_bytes must be greater than zero")),
            ));
        }
    };

    let record = state
        .mcp_ec2_diagnostic_commands
        .get_owned_command(
            &command_id,
            &claims.sub,
            session_id,
            local_secret_generation,
            Utc::now(),
        )
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::service_unavailable(
                    "MCP EC2 diagnostic command store unavailable",
                )),
            )
        })?;

    let Some(record) = record else {
        audit_mcp_ec2_diagnostics(
            &state,
            &claims.sub,
            &audit_ctx,
            McpEc2DiagnosticAudit::Result {
                command_id: &command_id,
                session_id: Some(session_id),
                local_secret_generation: Some(local_secret_generation),
                max_bytes: query.max_bytes,
            },
            AuditOutcome::Denied,
            "command_not_found_or_not_owned",
            None,
            false,
        )?;
        return Err((
            StatusCode::NOT_FOUND,
            Json(ApiError::not_found("EC2 diagnostic command not found")),
        ));
    };

    let authorization = AuthorizedMcpEc2DiagnosticCommand {
        entitlement_rule_id: String::new(),
        account: None,
        allowlist_rule_id: record.allowlist_rule_id.clone(),
        command_scope_id: record.command_scope_id.clone(),
        authorization_fingerprint: String::new(),
        command_type: record.command_type.clone(),
        command: mcp_ec2_placeholder_command_for_type(&record.command_type),
        requires_instance_metadata: false,
    };
    if !state
        .mcp_ec2_diagnostic_ssm_dispatchers
        .uses_live_aws_backend()
    {
        audit_mcp_ec2_diagnostics(
            &state,
            &claims.sub,
            &audit_ctx,
            McpEc2DiagnosticAudit::Result {
                command_id: &command_id,
                session_id: Some(session_id),
                local_secret_generation: Some(local_secret_generation),
                max_bytes: query.max_bytes,
            },
            AuditOutcome::Failure,
            "result_backend_unavailable",
            Some(&authorization),
            false,
        )?;
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::service_unavailable(
                "MCP EC2 diagnostics result backend is not available yet",
            )),
        ));
    }

    if record.status == McpEc2DiagnosticCommandStatus::Queued {
        audit_mcp_ec2_diagnostics(
            &state,
            &claims.sub,
            &audit_ctx,
            McpEc2DiagnosticAudit::Result {
                command_id: &command_id,
                session_id: Some(session_id),
                local_secret_generation: Some(local_secret_generation),
                max_bytes: query.max_bytes,
            },
            AuditOutcome::Success,
            "result_poll_queued",
            Some(&authorization),
            false,
        )?;
        return Ok(Json(McpGetEc2DiagnosticResultResponse {
            mcp_ec2_command_id: command_id,
            status: McpEc2DiagnosticCommandStatus::Queued,
            sequence_start: record.output_sequence_start,
            sequence_end: record.output_sequence_end,
            output_text: None,
            untrusted_remote_output: false,
            output_bytes: 0,
            dropped_bytes: 0,
            exit_code: None,
            error: None,
        }));
    }

    let Some(aws_ssm_command_id) = record.aws_ssm_command_id.as_deref() else {
        audit_mcp_ec2_diagnostics(
            &state,
            &claims.sub,
            &audit_ctx,
            McpEc2DiagnosticAudit::Result {
                command_id: &command_id,
                session_id: Some(session_id),
                local_secret_generation: Some(local_secret_generation),
                max_bytes: query.max_bytes,
            },
            AuditOutcome::Failure,
            "result_command_record_invalid",
            Some(&authorization),
            false,
        )?;
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::service_unavailable(
                "MCP EC2 diagnostic command record is invalid",
            )),
        ));
    };

    let ent_service = EntitlementService::new(state.entitlement_store.clone());
    let authorization =
        match authorize_mcp_ec2_diagnostic_result_record(&ent_service, &claims, &record).await {
            Ok(authorization) => authorization,
            Err(reason) => {
                audit_mcp_ec2_diagnostics(
                    &state,
                    &claims.sub,
                    &audit_ctx,
                    McpEc2DiagnosticAudit::Result {
                        command_id: &command_id,
                        session_id: Some(session_id),
                        local_secret_generation: Some(local_secret_generation),
                        max_bytes: query.max_bytes,
                    },
                    AuditOutcome::Denied,
                    reason,
                    Some(&authorization),
                    false,
                )?;
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ApiError::forbidden(
                        "MCP EC2 diagnostic command is not authorized",
                    )),
                ));
            }
        };
    let Some(account) = authorization.account.as_ref() else {
        audit_mcp_ec2_diagnostics(
            &state,
            &claims.sub,
            &audit_ctx,
            McpEc2DiagnosticAudit::Result {
                command_id: &command_id,
                session_id: Some(session_id),
                local_secret_generation: Some(local_secret_generation),
                max_bytes: query.max_bytes,
            },
            AuditOutcome::Failure,
            "authorized_account_missing",
            Some(&authorization),
            false,
        )?;
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::service_unavailable(
                "MCP EC2 diagnostics target account is unavailable",
            )),
        ));
    };
    if authorization.requires_instance_metadata {
        audit_mcp_ec2_diagnostics(
            &state,
            &claims.sub,
            &audit_ctx,
            McpEc2DiagnosticAudit::Result {
                command_id: &command_id,
                session_id: Some(session_id),
                local_secret_generation: Some(local_secret_generation),
                max_bytes: query.max_bytes,
            },
            AuditOutcome::Failure,
            "target_metadata_resolution_not_implemented",
            Some(&authorization),
            false,
        )?;
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::service_unavailable(
                "EC2 target metadata resolution is not available yet",
            )),
        ));
    }

    let session_context = mcp_ec2_session_context(&state, &claims);
    let resolved_aws_config = match state
        .mcp_ec2_diagnostic_aws_config_resolver
        .resolve_config(
            &state.base_aws_config,
            account,
            &record.region,
            &session_context,
        )
        .await
    {
        Ok(config) => config,
        Err(_) => {
            audit_mcp_ec2_diagnostics(
                &state,
                &claims.sub,
                &audit_ctx,
                McpEc2DiagnosticAudit::Result {
                    command_id: &command_id,
                    session_id: Some(session_id),
                    local_secret_generation: Some(local_secret_generation),
                    max_bytes: query.max_bytes,
                },
                AuditOutcome::Failure,
                "result_credentials_unavailable",
                Some(&authorization),
                true,
            )?;
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::service_unavailable(
                    "MCP EC2 diagnostics AWS credentials are unavailable",
                )),
            ));
        }
    };
    let target_config = match McpEc2DiagnosticSsmTargetConfig::new(
        &record.account_id,
        &record.region,
        resolved_aws_config.resolved_account_id(),
        resolved_aws_config.resolved_region(),
        resolved_aws_config.aws_config(),
    ) {
        Ok(target_config) => target_config,
        Err(_) => {
            audit_mcp_ec2_diagnostics(
                &state,
                &claims.sub,
                &audit_ctx,
                McpEc2DiagnosticAudit::Result {
                    command_id: &command_id,
                    session_id: Some(session_id),
                    local_secret_generation: Some(local_secret_generation),
                    max_bytes: query.max_bytes,
                },
                AuditOutcome::Failure,
                "result_target_config_invalid",
                Some(&authorization),
                true,
            )?;
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::service_unavailable(
                    "MCP EC2 diagnostics target configuration is invalid",
                )),
            ));
        }
    };
    let dispatcher = state
        .mcp_ec2_diagnostic_ssm_dispatchers
        .dispatcher_for_target_config(&target_config);
    let invocation = match dispatcher
        .get_invocation(aws_ssm_command_id, &record.instance_id)
        .await
    {
        Ok(invocation) => invocation,
        Err(_) => {
            audit_mcp_ec2_diagnostics_with_details(
                &state,
                &claims.sub,
                &audit_ctx,
                McpEc2DiagnosticAudit::Result {
                    command_id: &command_id,
                    session_id: Some(session_id),
                    local_secret_generation: Some(local_secret_generation),
                    max_bytes: query.max_bytes,
                },
                AuditOutcome::Failure,
                "result_backend_unavailable",
                Some(&authorization),
                true,
                McpEc2DiagnosticAuditDetails {
                    aws_ssm_command_id: Some(aws_ssm_command_id),
                    ssm_invocation_status: None,
                    ..McpEc2DiagnosticAuditDetails::default()
                },
            )?;
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::service_unavailable(
                    "MCP EC2 diagnostics result backend is unavailable",
                )),
            ));
        }
    };

    if !invocation.status().is_terminal() {
        if record.status != McpEc2DiagnosticCommandStatus::Running {
            audit_mcp_ec2_diagnostics_with_details(
                &state,
                &claims.sub,
                &audit_ctx,
                McpEc2DiagnosticAudit::Result {
                    command_id: &command_id,
                    session_id: Some(session_id),
                    local_secret_generation: Some(local_secret_generation),
                    max_bytes: query.max_bytes,
                },
                AuditOutcome::Failure,
                "result_command_record_invalid",
                Some(&authorization),
                true,
                McpEc2DiagnosticAuditDetails {
                    aws_ssm_command_id: Some(aws_ssm_command_id),
                    ssm_invocation_status: Some(mcp_ec2_invocation_status_wire(
                        invocation.status(),
                    )),
                    ..McpEc2DiagnosticAuditDetails::default()
                },
            )?;
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::service_unavailable(
                    "MCP EC2 diagnostic command record is invalid",
                )),
            ));
        }

        audit_mcp_ec2_diagnostics_with_details(
            &state,
            &claims.sub,
            &audit_ctx,
            McpEc2DiagnosticAudit::Result {
                command_id: &command_id,
                session_id: Some(session_id),
                local_secret_generation: Some(local_secret_generation),
                max_bytes: query.max_bytes,
            },
            AuditOutcome::Success,
            "result_poll_running",
            Some(&authorization),
            true,
            McpEc2DiagnosticAuditDetails {
                aws_ssm_command_id: Some(aws_ssm_command_id),
                ssm_invocation_status: Some(mcp_ec2_invocation_status_wire(invocation.status())),
                ..McpEc2DiagnosticAuditDetails::default()
            },
        )?;
        return Ok(Json(McpGetEc2DiagnosticResultResponse {
            mcp_ec2_command_id: command_id,
            status: McpEc2DiagnosticCommandStatus::Running,
            sequence_start: record.output_sequence_start,
            sequence_end: record.output_sequence_end,
            output_text: None,
            untrusted_remote_output: false,
            output_bytes: 0,
            dropped_bytes: 0,
            exit_code: None,
            error: None,
        }));
    }

    let completed_status = mcp_ec2_terminal_status_for_invocation(&invocation);
    let response_status = if record.status == McpEc2DiagnosticCommandStatus::Running {
        completed_status.clone()
    } else {
        record.status.clone()
    };
    let formatted_output = format_mcp_ec2_diagnostic_output(
        &mcp_ec2_invocation_output_text(&invocation),
        result_byte_budget,
    );
    let output_sequence_start = 0;
    let output_sequence_end = formatted_output.output_bytes;
    let completion = McpEc2DiagnosticCommandCompletion {
        status: completed_status.clone(),
        completed_at: Utc::now(),
        output_byte_count: formatted_output.output_bytes,
        dropped_byte_count: formatted_output.dropped_bytes,
        output_sequence_start,
        output_sequence_end,
        exit_status: invocation.response_code(),
        truncated: formatted_output.truncated,
    };
    if record.status == McpEc2DiagnosticCommandStatus::Running {
        audit_mcp_ec2_diagnostics_with_details(
            &state,
            &claims.sub,
            &audit_ctx,
            McpEc2DiagnosticAudit::Result {
                command_id: &command_id,
                session_id: Some(session_id),
                local_secret_generation: Some(local_secret_generation),
                max_bytes: query.max_bytes,
            },
            AuditOutcome::Success,
            "result_completion_observed",
            Some(&authorization),
            true,
            McpEc2DiagnosticAuditDetails {
                aws_ssm_command_id: Some(aws_ssm_command_id),
                output_byte_count: Some(formatted_output.output_bytes),
                dropped_byte_count: Some(formatted_output.dropped_bytes),
                output_sequence_start: Some(output_sequence_start),
                output_sequence_end: Some(output_sequence_end),
                exit_status: invocation.response_code(),
                truncated: Some(formatted_output.truncated),
                ssm_invocation_status: Some(mcp_ec2_invocation_status_wire(invocation.status())),
                ..McpEc2DiagnosticAuditDetails::default()
            },
        )?;
        if !state
            .mcp_ec2_diagnostic_commands
            .mark_terminal(
                &command_id,
                &claims.sub,
                session_id,
                local_secret_generation,
                completion,
                Utc::now(),
            )
            .await
            .unwrap_or(false)
        {
            audit_mcp_ec2_diagnostics_with_details(
                &state,
                &claims.sub,
                &audit_ctx,
                McpEc2DiagnosticAudit::Result {
                    command_id: &command_id,
                    session_id: Some(session_id),
                    local_secret_generation: Some(local_secret_generation),
                    max_bytes: query.max_bytes,
                },
                AuditOutcome::Failure,
                "command_store_completion_failed",
                Some(&authorization),
                true,
                McpEc2DiagnosticAuditDetails {
                    aws_ssm_command_id: Some(aws_ssm_command_id),
                    output_byte_count: Some(formatted_output.output_bytes),
                    dropped_byte_count: Some(formatted_output.dropped_bytes),
                    output_sequence_start: Some(output_sequence_start),
                    output_sequence_end: Some(output_sequence_end),
                    exit_status: invocation.response_code(),
                    truncated: Some(formatted_output.truncated),
                    ssm_invocation_status: Some(mcp_ec2_invocation_status_wire(
                        invocation.status(),
                    )),
                    ..McpEc2DiagnosticAuditDetails::default()
                },
            )?;
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::service_unavailable(
                    "MCP EC2 diagnostic command completion could not be recorded",
                )),
            ));
        }
    }

    audit_mcp_ec2_diagnostics_with_details(
        &state,
        &claims.sub,
        &audit_ctx,
        McpEc2DiagnosticAudit::Result {
            command_id: &command_id,
            session_id: Some(session_id),
            local_secret_generation: Some(local_secret_generation),
            max_bytes: query.max_bytes,
        },
        AuditOutcome::Success,
        "result_completed",
        Some(&authorization),
        true,
        McpEc2DiagnosticAuditDetails {
            aws_ssm_command_id: Some(aws_ssm_command_id),
            output_byte_count: Some(formatted_output.output_bytes),
            dropped_byte_count: Some(formatted_output.dropped_bytes),
            output_sequence_start: Some(output_sequence_start),
            output_sequence_end: Some(output_sequence_end),
            exit_status: invocation.response_code(),
            truncated: Some(formatted_output.truncated),
            ssm_invocation_status: Some(mcp_ec2_invocation_status_wire(invocation.status())),
            ..McpEc2DiagnosticAuditDetails::default()
        },
    )?;

    Ok(Json(McpGetEc2DiagnosticResultResponse {
        mcp_ec2_command_id: command_id,
        status: response_status.clone(),
        sequence_start: output_sequence_start,
        sequence_end: output_sequence_end,
        output_text: Some(formatted_output.output_text),
        untrusted_remote_output: true,
        output_bytes: formatted_output.output_bytes,
        dropped_bytes: formatted_output.dropped_bytes,
        exit_code: invocation.response_code(),
        error: mcp_ec2_terminal_error(&response_status),
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
    let scopes = store.database_scopes_for_groups(&claims.groups);
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

    if let Err(denial) = require_mcp_guidance(
        &state,
        &claims,
        req.canopy_mcp_session_id.as_deref(),
        req.local_secret_generation.as_deref(),
        DATABASE_SCOPE_LIST_REQUIRED_GUIDANCE,
    )
    .await
    {
        if !denial.is_store_unavailable() {
            audit_database_scope_list_denied(
                &state,
                &claims.sub,
                &audit_ctx,
                &req,
                denial.audit_outcome_kind(),
            )?;
        }
        return Err(denial.http_response("Required MCP database guidance has not been completed"));
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
    if let Err(denial) = require_mcp_guidance(
        &state,
        &claims,
        req.canopy_mcp_session_id.as_deref(),
        req.local_secret_generation.as_deref(),
        DATABASE_QUERY_REQUIRED_GUIDANCE,
    )
    .await
    {
        if !denial.is_store_unavailable() {
            audit_database_denied(
                &state,
                &claims.sub,
                &audit_ctx,
                &req,
                denial.audit_outcome_kind(),
                None,
            )?;
        }
        return Err(denial.http_response("Required MCP database guidance has not been completed"));
    }

    let store = state.entitlement_store.read().await;
    let Some(scope) = store.matching_database_scope_for_groups(
        &claims.groups,
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
                 preflight has not passed (see GET /health and docs/zh-TW/OPERATOR-SETUP.md)",
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

fn cloudwatch_data_audit_failure_response() -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ApiError::internal(
            "Audit logging failed — refusing to process CloudWatch MCP data request",
        )),
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CloudwatchPreflightTokenPayload {
    version: u8,
    actor: String,
    canopy_mcp_session_id: String,
    local_secret_generation: String,
    tool: String,
    account_id: String,
    region: String,
    log_group_names: Vec<String>,
    filter_pattern: Option<String>,
    query_string: Option<String>,
    start_time: i64,
    end_time: i64,
    limit: Option<i32>,
    max_events: u64,
    guardrail_policy_id: String,
    entitlement_snapshot_hash: String,
    expires_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SearchCursorPayload {
    version: u8,
    actor: String,
    canopy_mcp_session_id: String,
    local_secret_generation: String,
    account_id: String,
    region: String,
    log_group_name: String,
    filter_pattern: Option<String>,
    start_time: i64,
    end_time: i64,
    limit: i32,
    aws_next_token: Option<String>,
    mock_offset: Option<usize>,
    returned_count: u64,
    max_events: u64,
    guardrail_policy_id: String,
    entitlement_snapshot_hash: String,
    expires_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct CloudwatchSearchContext {
    account_id: String,
    region: String,
    log_group_name: String,
    filter_pattern: Option<String>,
    start_time: i64,
    end_time: i64,
    limit: i32,
    aws_next_token: Option<String>,
    mock_offset: Option<usize>,
    returned_count: u64,
    entitlement_snapshot_hash: String,
}

#[derive(Debug)]
struct SearchExecutionResult {
    events: Vec<LogEvent>,
    truncated: bool,
    next_context: Option<SearchCursorPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InsightsQueryTokenPayload {
    version: u8,
    actor: String,
    canopy_mcp_session_id: String,
    local_secret_generation: String,
    account_id: String,
    region: String,
    log_group_names: Vec<String>,
    query_string: String,
    start_time: i64,
    end_time: i64,
    aws_query_id: String,
    guardrail_policy_id: String,
    entitlement_snapshot_hash: String,
    expires_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct CloudwatchRawAuditPayload<'a> {
    version: u8,
    actor: &'a str,
    canopy_mcp_session_id: Option<&'a str>,
    local_secret_generation: Option<&'a str>,
    tool_name: &'a str,
    account_id: &'a str,
    region: &'a str,
    log_group_names: &'a [String],
    field: &'a str,
    value: &'a str,
    created_at: chrono::DateTime<Utc>,
}

trait CloudwatchInsightsAuditPayload {
    fn audit_account_id(&self) -> &str;
    fn audit_region(&self) -> &str;
    fn audit_log_group_names(&self) -> &[String];
    fn audit_query_string(&self) -> Option<&str>;
}

impl CloudwatchInsightsAuditPayload for CloudwatchPreflightTokenPayload {
    fn audit_account_id(&self) -> &str {
        &self.account_id
    }

    fn audit_region(&self) -> &str {
        &self.region
    }

    fn audit_log_group_names(&self) -> &[String] {
        &self.log_group_names
    }

    fn audit_query_string(&self) -> Option<&str> {
        self.query_string.as_deref()
    }
}

impl CloudwatchInsightsAuditPayload for InsightsQueryTokenPayload {
    fn audit_account_id(&self) -> &str {
        &self.account_id
    }

    fn audit_region(&self) -> &str {
        &self.region
    }

    fn audit_log_group_names(&self) -> &[String] {
        &self.log_group_names
    }

    fn audit_query_string(&self) -> Option<&str> {
        Some(self.query_string.as_str())
    }
}

fn cloudwatch_required_guidance_for_tool(tool_name: &str) -> Option<&'static [&'static str]> {
    match tool_name {
        CLOUDWATCH_SEARCH_TOOL => Some(CLOUDWATCH_SEARCH_REQUIRED_GUIDANCE),
        CLOUDWATCH_INSIGHTS_TOOL => Some(CLOUDWATCH_INSIGHTS_REQUIRED_GUIDANCE),
        _ => None,
    }
}

fn cloudwatch_data_guardrail_policy_id(guardrails: &McpGuardrails) -> String {
    format!(
        "mcp-cloudwatch-data:v1:max_window={}:max_events={}:max_response_bytes={}:max_event_bytes={}:preflight_ttl={}:search_cursor_ttl={}:insights_token_ttl={}:insights_timeout={}",
        guardrails.max_search_window_seconds,
        guardrails.max_search_events,
        guardrails.max_response_bytes,
        guardrails.max_event_message_bytes,
        guardrails.preflight_token_ttl_seconds,
        guardrails.search_cursor_ttl_seconds,
        guardrails.insights_query_token_ttl_seconds,
        guardrails.default_insights_timeout_seconds,
    )
}

fn validate_cloudwatch_preflight_shape(
    req: &McpCloudwatchPreflightRequest,
    guardrails: &McpGuardrails,
) -> Result<Vec<String>, &'static str> {
    if req.end_time <= req.start_time {
        return Err("invalid_time_window");
    }
    if (req.end_time - req.start_time) as u64 > guardrails.max_search_window_seconds {
        return Err("time_window_exceeds_guardrail");
    }
    let raw_len = req.filter_pattern.as_deref().unwrap_or_default().len()
        + req.query_string.as_deref().unwrap_or_default().len();
    if raw_len as u64 > guardrails.max_request_body_bytes {
        return Err("raw_input_too_large");
    }

    match req.tool_name.as_str() {
        CLOUDWATCH_SEARCH_TOOL => {
            if req.query_string.is_some() {
                return Err("query_string_not_allowed_for_search");
            }
            if !req.log_group_names.is_empty() {
                return Err("log_group_names_not_allowed_for_search");
            }
            let Some(name) = req
                .log_group_name
                .as_ref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
            else {
                return Err("log_group_name_required");
            };
            if let Some(limit) = req.limit {
                if limit <= 0 || limit as u64 > guardrails.max_search_events {
                    return Err("limit_exceeds_guardrail");
                }
            }
            Ok(vec![name.to_string()])
        }
        CLOUDWATCH_INSIGHTS_TOOL => {
            if req.filter_pattern.is_some() {
                return Err("filter_pattern_not_allowed_for_insights");
            }
            let names: Vec<String> = if !req.log_group_names.is_empty() {
                req.log_group_names
                    .iter()
                    .map(|name| name.trim())
                    .filter(|name| !name.is_empty())
                    .map(str::to_string)
                    .collect()
            } else {
                req.log_group_name
                    .as_ref()
                    .map(|name| vec![name.trim().to_string()])
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|name| !name.is_empty())
                    .collect()
            };
            if names.is_empty() {
                return Err("log_group_names_required");
            }
            if req
                .query_string
                .as_ref()
                .map(|query| query.trim().is_empty())
                .unwrap_or(true)
            {
                return Err("query_string_required");
            }
            Ok(names)
        }
        _ => Err("unknown_tool"),
    }
}

fn mcp_log_group_arn_variants(region: &str, account_id: &str, log_group_name: &str) -> Vec<String> {
    let base = format!("arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}");
    vec![base.clone(), format!("{base}:*")]
}

fn mcp_log_group_matches_patterns(patterns: &[String], arn_variants: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        arn_variants
            .iter()
            .any(|arn| crate::services::entitlements::arn_matches_pattern(pattern, arn))
    })
}

async fn authorize_mcp_cloudwatch_scope(
    ent_service: &EntitlementService,
    claims: &Claims,
    account_id: &str,
    region: &str,
    log_group_names: &[String],
) -> Result<Vec<String>, &'static str> {
    if !ent_service
        .has_feature_for_scope(claims, account_id, Some(region), None, None, |f| {
            f.can_use_mcp && f.can_use_mcp_cloudwatch
        })
        .await
    {
        return Err("scope_not_authorized");
    }

    let scoped_log_arns = ent_service
        .allowed_log_group_arns_for_scope(claims, account_id, region, |f| {
            f.can_use_mcp && f.can_use_mcp_cloudwatch
        })
        .await;
    if !scoped_log_arns.is_empty() {
        for name in log_group_names {
            let variants = mcp_log_group_arn_variants(region, account_id, name);
            if !mcp_log_group_matches_patterns(&scoped_log_arns, &variants) {
                return Err("log_group_not_authorized");
            }
        }
    }
    Ok(scoped_log_arns)
}

fn encode_cloudwatch_token<T: Serialize>(
    state: &AppState,
    payload: &T,
    aad: &[u8],
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
                aad,
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

fn decode_cloudwatch_token<T: DeserializeOwned>(
    state: &AppState,
    raw: &str,
    aad: &[u8],
) -> Result<T, &'static str> {
    let envelope_bytes = URL_SAFE_NO_PAD
        .decode(raw.as_bytes())
        .map_err(|_| "cloudwatch_token_decode_failed")?;
    let envelope: DiscoveryCursorEnvelope =
        serde_json::from_slice(&envelope_bytes).map_err(|_| "cloudwatch_token_decode_failed")?;
    if envelope.version != 1
        || envelope.alg != "AES-256-GCM"
        || envelope.key_id != "jwt-secret-sha256:v1"
    {
        return Err("cloudwatch_token_unsupported_version");
    }
    let nonce_bytes = URL_SAFE_NO_PAD
        .decode(envelope.nonce.as_bytes())
        .map_err(|_| "cloudwatch_token_decode_failed")?;
    if nonce_bytes.len() != 12 {
        return Err("cloudwatch_token_decode_failed");
    }
    let ciphertext = URL_SAFE_NO_PAD
        .decode(envelope.ciphertext.as_bytes())
        .map_err(|_| "cloudwatch_token_decode_failed")?;
    let cipher = discovery_cursor_cipher(state).map_err(|_| "cloudwatch_token_key_unavailable")?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            aes_gcm::aead::Payload {
                msg: ciphertext.as_slice(),
                aad,
            },
        )
        .map_err(|_| "cloudwatch_token_auth_failed")?;
    serde_json::from_slice(&plaintext).map_err(|_| "cloudwatch_token_decode_failed")
}

#[allow(clippy::too_many_arguments)]
fn encrypted_cloudwatch_raw_audit_value(
    state: &AppState,
    actor: &str,
    session_id: Option<&str>,
    local_secret_generation: Option<&str>,
    tool_name: &str,
    account_id: &str,
    region: &str,
    log_group_names: &[String],
    field: &str,
    raw: Option<&str>,
) -> Result<serde_json::Value, (StatusCode, Json<ApiError>)> {
    let Some(value) = raw else {
        return Ok(serde_json::Value::Null);
    };
    let payload = CloudwatchRawAuditPayload {
        version: 1,
        actor,
        canopy_mcp_session_id: session_id,
        local_secret_generation,
        tool_name,
        account_id,
        region,
        log_group_names,
        field,
        value,
        created_at: Utc::now(),
    };
    encode_cloudwatch_token(state, &payload, CLOUDWATCH_RAW_AUDIT_AAD)
        .map(serde_json::Value::String)
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::internal(
                    "Failed to encrypt MCP CloudWatch raw audit value",
                )),
            )
        })
}

fn cloudwatch_raw_plaintext_value(raw: Option<&str>, plaintext_allowed: bool) -> serde_json::Value {
    match (raw, plaintext_allowed) {
        (Some(value), true) => serde_json::Value::String(value.to_string()),
        (Some(_), false) => serde_json::Value::String("[encrypted: see *_raw_encrypted]".into()),
        (None, _) => serde_json::Value::Null,
    }
}

fn validate_preflight_payload(
    payload: &CloudwatchPreflightTokenPayload,
    claims: &Claims,
    session_id: Option<&str>,
    local_secret_generation: Option<&str>,
    expected_tool: &str,
    guardrails: &McpGuardrails,
) -> Result<(), &'static str> {
    if payload.version != 1 || payload.tool != expected_tool {
        return Err("preflight_token_tool_mismatch");
    }
    if payload.actor != claims.sub {
        return Err("preflight_token_actor_mismatch");
    }
    if session_id != Some(payload.canopy_mcp_session_id.as_str()) {
        return Err("preflight_token_session_mismatch");
    }
    if local_secret_generation != Some(payload.local_secret_generation.as_str()) {
        return Err("preflight_token_generation_mismatch");
    }
    if payload.expires_at < Utc::now() {
        return Err("preflight_token_expired");
    }
    if payload.max_events != guardrails.max_search_events
        || payload.guardrail_policy_id != cloudwatch_data_guardrail_policy_id(guardrails)
    {
        return Err("preflight_token_policy_changed");
    }
    Ok(())
}

fn validate_search_cursor_payload(
    payload: &SearchCursorPayload,
    claims: &Claims,
    session_id: Option<&str>,
    local_secret_generation: Option<&str>,
    guardrails: &McpGuardrails,
) -> Result<(), &'static str> {
    if payload.version != 1 {
        return Err("search_cursor_unsupported_version");
    }
    if payload.actor != claims.sub {
        return Err("search_cursor_actor_mismatch");
    }
    if session_id != Some(payload.canopy_mcp_session_id.as_str()) {
        return Err("search_cursor_session_mismatch");
    }
    if local_secret_generation != Some(payload.local_secret_generation.as_str()) {
        return Err("search_cursor_generation_mismatch");
    }
    if payload.expires_at < Utc::now() {
        return Err("search_cursor_expired");
    }
    if payload.returned_count >= guardrails.max_search_events
        || payload.max_events != guardrails.max_search_events
        || payload.guardrail_policy_id != cloudwatch_data_guardrail_policy_id(guardrails)
    {
        return Err("search_cursor_exhausted_or_policy_changed");
    }
    Ok(())
}

fn cloudwatch_search_context_from_request(
    state: &AppState,
    claims: &Claims,
    req: &McpSearchLogsRequest,
    guardrails: &McpGuardrails,
) -> Result<CloudwatchSearchContext, &'static str> {
    match (req.preflight_token.as_deref(), req.search_cursor.as_deref()) {
        (Some(preflight), None) => {
            let payload: CloudwatchPreflightTokenPayload =
                decode_cloudwatch_token(state, preflight, CLOUDWATCH_PREFLIGHT_TOKEN_AAD)?;
            validate_preflight_payload(
                &payload,
                claims,
                req.canopy_mcp_session_id.as_deref(),
                req.local_secret_generation.as_deref(),
                CLOUDWATCH_SEARCH_TOOL,
                guardrails,
            )?;
            if payload.log_group_names.len() != 1 {
                return Err("preflight_token_scope_mismatch");
            }
            Ok(CloudwatchSearchContext {
                account_id: payload.account_id,
                region: payload.region,
                log_group_name: payload.log_group_names[0].clone(),
                filter_pattern: payload.filter_pattern,
                start_time: payload.start_time,
                end_time: payload.end_time,
                limit: payload
                    .limit
                    .unwrap_or(guardrails.max_search_events as i32)
                    .min(guardrails.max_search_events as i32),
                aws_next_token: None,
                mock_offset: None,
                returned_count: 0,
                entitlement_snapshot_hash: payload.entitlement_snapshot_hash,
            })
        }
        (None, Some(cursor)) => {
            let payload: SearchCursorPayload =
                decode_cloudwatch_token(state, cursor, CLOUDWATCH_SEARCH_CURSOR_AAD)?;
            validate_search_cursor_payload(
                &payload,
                claims,
                req.canopy_mcp_session_id.as_deref(),
                req.local_secret_generation.as_deref(),
                guardrails,
            )?;
            Ok(CloudwatchSearchContext {
                account_id: payload.account_id,
                region: payload.region,
                log_group_name: payload.log_group_name,
                filter_pattern: payload.filter_pattern,
                start_time: payload.start_time,
                end_time: payload.end_time,
                limit: payload.limit,
                aws_next_token: payload.aws_next_token,
                mock_offset: payload.mock_offset,
                returned_count: payload.returned_count,
                entitlement_snapshot_hash: payload.entitlement_snapshot_hash,
            })
        }
        _ => Err("invalid_token_mode"),
    }
}

fn truncate_utf8(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    input[..end].to_string()
}

fn bounded_log_event(mut event: LogEvent, guardrails: &McpGuardrails) -> LogEvent {
    event.message = truncate_utf8(&event.message, guardrails.max_event_message_bytes as usize);
    event
}

fn max_events_per_response(guardrails: &McpGuardrails) -> u64 {
    let per_event_budget = guardrails.max_event_message_bytes.saturating_add(1024);
    let by_bytes = guardrails
        .max_response_bytes
        .checked_div(per_event_budget.max(1))
        .unwrap_or(1)
        .max(1);
    by_bytes.min(guardrails.max_search_events).max(1)
}

fn truncate_insights_results_by_budget(
    rows: Vec<Vec<QueryResultField>>,
    guardrails: &McpGuardrails,
) -> (Vec<Vec<QueryResultField>>, bool) {
    let max_bytes = guardrails.max_response_bytes as usize;
    let mut used = 2_usize; // JSON array brackets.
    let mut out = Vec::new();

    for row in rows {
        let bounded_row = row
            .into_iter()
            .map(|mut field| {
                field.value =
                    truncate_utf8(&field.value, guardrails.max_event_message_bytes as usize);
                field
            })
            .collect::<Vec<_>>();
        let row_bytes = serde_json::to_vec(&bounded_row)
            .map(|bytes| bytes.len())
            .unwrap_or(max_bytes.saturating_add(1));
        let comma = usize::from(!out.is_empty());
        if used.saturating_add(comma).saturating_add(row_bytes) > max_bytes {
            return (out, true);
        }
        used = used.saturating_add(comma).saturating_add(row_bytes);
        out.push(bounded_row);
    }

    (out, false)
}

fn search_cursor_payload_from_context(
    context: &CloudwatchSearchContext,
    aws_next_token: Option<String>,
    mock_offset: Option<usize>,
    returned_count: u64,
    guardrails: &McpGuardrails,
) -> SearchCursorPayload {
    SearchCursorPayload {
        version: 1,
        actor: String::new(),
        canopy_mcp_session_id: String::new(),
        local_secret_generation: String::new(),
        account_id: context.account_id.clone(),
        region: context.region.clone(),
        log_group_name: context.log_group_name.clone(),
        filter_pattern: context.filter_pattern.clone(),
        start_time: context.start_time,
        end_time: context.end_time,
        limit: context.limit,
        aws_next_token,
        mock_offset,
        returned_count,
        max_events: guardrails.max_search_events,
        guardrail_policy_id: cloudwatch_data_guardrail_policy_id(guardrails),
        entitlement_snapshot_hash: context.entitlement_snapshot_hash.clone(),
        expires_at: Utc::now() + Duration::seconds(guardrails.search_cursor_ttl_seconds as i64),
    }
}

fn execute_mock_search(
    context: &CloudwatchSearchContext,
    guardrails: &McpGuardrails,
) -> SearchExecutionResult {
    let offset = context.mock_offset.unwrap_or(0);
    let remaining_budget = guardrails
        .max_search_events
        .saturating_sub(context.returned_count);
    let limit = (context.limit as u64)
        .min(remaining_budget)
        .min(max_events_per_response(guardrails)) as usize;
    let all = mock_log_events();
    let mut events = all
        .iter()
        .skip(offset)
        .take(limit)
        .cloned()
        .map(|event| bounded_log_event(event, guardrails))
        .collect::<Vec<_>>();
    let next_offset = offset + events.len();
    let new_returned = context.returned_count + events.len() as u64;
    let truncated = next_offset < all.len();
    let next_context = if next_offset < all.len() && new_returned < guardrails.max_search_events {
        let mut cursor = search_cursor_payload_from_context(
            context,
            None,
            Some(next_offset),
            new_returned,
            guardrails,
        );
        cursor.actor = String::new();
        Some(cursor)
    } else {
        None
    };
    events.shrink_to_fit();
    SearchExecutionResult {
        events,
        truncated,
        next_context,
    }
}

async fn execute_aws_search(
    state: &AppState,
    claims: &Claims,
    entitlements: &shared::dto::entitlements::UserEntitlements,
    context: &CloudwatchSearchContext,
) -> Result<SearchExecutionResult, (StatusCode, Json<ApiError>)> {
    let guardrails = McpGuardrails::default();
    let client = crate::routes::cloudwatch::get_cwl_client_for_account(
        state,
        entitlements,
        &context.account_id,
        &context.region,
        &claims.sub,
    )
    .await?;
    let remaining_budget = guardrails
        .max_search_events
        .saturating_sub(context.returned_count);
    let limit = (context.limit as u64)
        .min(remaining_budget)
        .min(max_events_per_response(&guardrails))
        .min(i32::MAX as u64) as i32;
    let mut filter = client
        .filter_log_events()
        .log_group_name(&context.log_group_name)
        .start_time(context.start_time)
        .end_time(context.end_time)
        .limit(limit);
    if let Some(pattern) = context.filter_pattern.as_ref() {
        filter = filter.filter_pattern(pattern);
    }
    if let Some(token) = context.aws_next_token.as_ref() {
        filter = filter.next_token(token);
    }
    let resp = filter.send().await.map_err(|e| {
        let service_error = e.as_service_error();
        let is_invalid_parameter = service_error
            .map(|err| err.is_invalid_parameter_exception())
            .unwrap_or(false);
        if is_invalid_parameter {
            (
                StatusCode::BAD_REQUEST,
                Json(ApiError::bad_request("Invalid CloudWatch filter pattern")),
            )
        } else {
            (
                StatusCode::BAD_GATEWAY,
                Json(ApiError::internal(format!(
                    "AWS FilterLogEvents failed: {e}"
                ))),
            )
        }
    })?;
    let events = resp
        .events()
        .iter()
        .map(|event| {
            bounded_log_event(
                LogEvent {
                    timestamp: event.timestamp().unwrap_or(0),
                    message: event.message().unwrap_or_default().to_string(),
                    log_stream_name: event.log_stream_name().map(str::to_string),
                    ingestion_time: event.ingestion_time(),
                    event_id: event.event_id().map(str::to_string),
                },
                &guardrails,
            )
        })
        .collect::<Vec<_>>();
    let new_returned = context.returned_count + events.len() as u64;
    let next_token = resp.next_token().map(str::to_string);
    let budget_exhausted = new_returned >= guardrails.max_search_events;
    let truncated = next_token.is_some() || budget_exhausted;
    let next_context = next_token.filter(|_| !budget_exhausted).map(|next_token| {
        search_cursor_payload_from_context(
            context,
            Some(next_token),
            None,
            new_returned,
            &guardrails,
        )
    });
    Ok(SearchExecutionResult {
        events,
        truncated,
        next_context,
    })
}

fn attach_search_cursor_identity(
    mut cursor: SearchCursorPayload,
    claims: &Claims,
    req: &McpSearchLogsRequest,
) -> SearchCursorPayload {
    cursor.actor = claims.sub.clone();
    cursor.canopy_mcp_session_id = req.canopy_mcp_session_id.clone().unwrap_or_default();
    cursor.local_secret_generation = req.local_secret_generation.clone().unwrap_or_default();
    cursor
}

fn validate_insights_query_token_payload(
    payload: &InsightsQueryTokenPayload,
    claims: &Claims,
    session_id: Option<&str>,
    local_secret_generation: Option<&str>,
    guardrails: &McpGuardrails,
) -> Result<(), &'static str> {
    if payload.version != 1 {
        return Err("query_token_unsupported_version");
    }
    if payload.actor != claims.sub {
        return Err("query_token_actor_mismatch");
    }
    if session_id != Some(payload.canopy_mcp_session_id.as_str()) {
        return Err("query_token_session_mismatch");
    }
    if local_secret_generation != Some(payload.local_secret_generation.as_str()) {
        return Err("query_token_generation_mismatch");
    }
    if payload.expires_at < Utc::now() {
        return Err("query_token_expired");
    }
    if payload.guardrail_policy_id != cloudwatch_data_guardrail_policy_id(guardrails) {
        return Err("query_token_policy_changed");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn start_mcp_insights_query(
    state: &AppState,
    claims: &Claims,
    audit_ctx: &AuditRequestContext,
    ent_service: &EntitlementService,
    entitlements: &shared::dto::entitlements::UserEntitlements,
    req: &McpRunInsightsQueryRequest,
    preflight_token: &str,
    guardrails: &McpGuardrails,
) -> ApiResult<McpRunInsightsQueryResponse> {
    let payload: CloudwatchPreflightTokenPayload =
        match decode_cloudwatch_token(state, preflight_token, CLOUDWATCH_PREFLIGHT_TOKEN_AAD) {
            Ok(payload) => payload,
            Err(reason) => {
                audit_cloudwatch_insights_denied(
                    state,
                    &claims.sub,
                    audit_ctx,
                    req,
                    None,
                    reason,
                    "Invalid MCP Insights preflight token",
                )?;
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiError::bad_request(
                        "Invalid MCP Insights preflight token",
                    )),
                ));
            }
        };
    if let Err(reason) = validate_preflight_payload(
        &payload,
        claims,
        req.canopy_mcp_session_id.as_deref(),
        req.local_secret_generation.as_deref(),
        CLOUDWATCH_INSIGHTS_TOOL,
        guardrails,
    ) {
        audit_cloudwatch_insights_denied(
            state,
            &claims.sub,
            audit_ctx,
            req,
            Some(&payload),
            reason,
            "MCP Insights preflight token is not valid for this request",
        )?;
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request(
                "MCP Insights preflight token is not valid for this request",
            )),
        ));
    }

    let scoped_log_arns = match authorize_mcp_cloudwatch_scope(
        ent_service,
        claims,
        &payload.account_id,
        &payload.region,
        &payload.log_group_names,
    )
    .await
    {
        Ok(scoped_log_arns) => scoped_log_arns,
        Err(reason) => {
            audit_cloudwatch_insights_denied(
                state,
                &claims.sub,
                audit_ctx,
                req,
                Some(&payload),
                reason,
                "MCP Insights query is not authorized for this scope",
            )?;
            return Err((
                StatusCode::FORBIDDEN,
                Json(ApiError::forbidden(
                    "MCP Insights query is not authorized for this scope",
                )),
            ));
        }
    };
    if payload.entitlement_snapshot_hash != entitlement_snapshot_hash(&scoped_log_arns) {
        audit_cloudwatch_insights_denied(
            state,
            &claims.sub,
            audit_ctx,
            req,
            Some(&payload),
            "preflight_token_entitlement_changed",
            "MCP Insights preflight token entitlements no longer match",
        )?;
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError::forbidden(
                "MCP Insights preflight token is no longer valid for current entitlements",
            )),
        ));
    }

    let raw_plaintext_allowed = ent_service
        .mcp_cloudwatch_raw_audit_plaintext_allowed(
            claims,
            &payload.account_id,
            &payload.region,
            &payload.log_group_names,
        )
        .await;

    audit_cloudwatch_insights_attempt(
        state,
        &claims.sub,
        audit_ctx,
        req,
        &payload,
        raw_plaintext_allowed,
        "start",
    )?;

    let query_string = payload.query_string.clone().unwrap_or_default();
    let aws_query_id = if state.config.use_mock_aws() {
        Uuid::new_v4().to_string()
    } else {
        let client = crate::routes::cloudwatch::get_cwl_client_for_account(
            state,
            entitlements,
            &payload.account_id,
            &payload.region,
            &claims.sub,
        )
        .await?;
        let mut start = client
            .start_query()
            .query_string(&query_string)
            .start_time(payload.start_time)
            .end_time(payload.end_time);
        for log_group_name in &payload.log_group_names {
            start = start.log_group_names(log_group_name);
        }
        start
            .send()
            .await
            .map_err(|e| {
                let _ = audit_cloudwatch_insights_failure(
                    state,
                    &claims.sub,
                    audit_ctx,
                    req,
                    Some(&payload),
                    raw_plaintext_allowed,
                    "aws_start_query_failed",
                    "AWS StartQuery failed",
                );
                (
                    StatusCode::BAD_GATEWAY,
                    Json(ApiError::internal(format!("AWS StartQuery failed: {e}"))),
                )
            })?
            .query_id()
            .ok_or_else(|| {
                let _ = audit_cloudwatch_insights_failure(
                    state,
                    &claims.sub,
                    audit_ctx,
                    req,
                    Some(&payload),
                    raw_plaintext_allowed,
                    "aws_start_query_missing_query_id",
                    "AWS StartQuery returned no query_id",
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiError::internal("AWS StartQuery returned no query_id")),
                )
            })?
            .to_string()
    };

    let query_payload = InsightsQueryTokenPayload {
        version: 1,
        actor: claims.sub.clone(),
        canopy_mcp_session_id: req.canopy_mcp_session_id.clone().unwrap_or_default(),
        local_secret_generation: req.local_secret_generation.clone().unwrap_or_default(),
        account_id: payload.account_id.clone(),
        region: payload.region.clone(),
        log_group_names: payload.log_group_names.clone(),
        query_string,
        start_time: payload.start_time,
        end_time: payload.end_time,
        aws_query_id,
        guardrail_policy_id: cloudwatch_data_guardrail_policy_id(guardrails),
        entitlement_snapshot_hash: payload.entitlement_snapshot_hash.clone(),
        expires_at: Utc::now()
            + Duration::seconds(guardrails.insights_query_token_ttl_seconds as i64),
    };
    let query_token =
        encode_cloudwatch_token(state, &query_payload, CLOUDWATCH_INSIGHTS_QUERY_TOKEN_AAD)
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiError::internal(
                        "Failed to seal MCP CloudWatch Insights query token",
                    )),
                )
            })?;

    audit_cloudwatch_insights_success(
        state,
        &claims.sub,
        audit_ctx,
        req,
        &query_payload,
        "started",
        QueryStatus::Running,
        0,
        false,
        !state.config.use_mock_aws(),
        raw_plaintext_allowed,
    )?;

    Ok(Json(McpRunInsightsQueryResponse {
        account_id: query_payload.account_id,
        region: query_payload.region,
        log_group_names: query_payload.log_group_names,
        query_token: Some(query_token),
        status: QueryStatus::Running,
        results: Vec::new(),
        statistics: None,
        terminal: false,
        next_action_hint: Some("Use query_token to poll this exact Insights query.".into()),
    }))
}

#[allow(clippy::too_many_arguments)]
async fn poll_mcp_insights_query(
    state: &AppState,
    claims: &Claims,
    audit_ctx: &AuditRequestContext,
    ent_service: &EntitlementService,
    entitlements: &shared::dto::entitlements::UserEntitlements,
    req: &McpRunInsightsQueryRequest,
    query_token: &str,
    guardrails: &McpGuardrails,
) -> ApiResult<McpRunInsightsQueryResponse> {
    let payload: InsightsQueryTokenPayload =
        match decode_cloudwatch_token(state, query_token, CLOUDWATCH_INSIGHTS_QUERY_TOKEN_AAD) {
            Ok(payload) => payload,
            Err(reason) => {
                audit_cloudwatch_insights_denied(
                    state,
                    &claims.sub,
                    audit_ctx,
                    req,
                    None,
                    reason,
                    "Invalid MCP Insights query token",
                )?;
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiError::bad_request("Invalid MCP Insights query token")),
                ));
            }
        };
    if let Err(reason) = validate_insights_query_token_payload(
        &payload,
        claims,
        req.canopy_mcp_session_id.as_deref(),
        req.local_secret_generation.as_deref(),
        guardrails,
    ) {
        audit_cloudwatch_insights_denied(
            state,
            &claims.sub,
            audit_ctx,
            req,
            None,
            reason,
            "MCP Insights query token is not valid for this request",
        )?;
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request(
                "MCP Insights query token is not valid for this request",
            )),
        ));
    }

    let scoped_log_arns = match authorize_mcp_cloudwatch_scope(
        ent_service,
        claims,
        &payload.account_id,
        &payload.region,
        &payload.log_group_names,
    )
    .await
    {
        Ok(scoped_log_arns) => scoped_log_arns,
        Err(reason) => {
            audit_cloudwatch_insights_denied(
                state,
                &claims.sub,
                audit_ctx,
                req,
                None,
                reason,
                "MCP Insights query is not authorized for this scope",
            )?;
            return Err((
                StatusCode::FORBIDDEN,
                Json(ApiError::forbidden(
                    "MCP Insights query is not authorized for this scope",
                )),
            ));
        }
    };
    if payload.entitlement_snapshot_hash != entitlement_snapshot_hash(&scoped_log_arns) {
        audit_cloudwatch_insights_denied(
            state,
            &claims.sub,
            audit_ctx,
            req,
            None,
            "query_token_entitlement_changed",
            "MCP Insights query token entitlements no longer match",
        )?;
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError::forbidden(
                "MCP Insights query token is no longer valid for current entitlements",
            )),
        ));
    }

    let raw_plaintext_allowed = ent_service
        .mcp_cloudwatch_raw_audit_plaintext_allowed(
            claims,
            &payload.account_id,
            &payload.region,
            &payload.log_group_names,
        )
        .await;

    audit_cloudwatch_insights_attempt(
        state,
        &claims.sub,
        audit_ctx,
        req,
        &payload,
        raw_plaintext_allowed,
        "poll",
    )?;

    let (status, raw_results, statistics) = if state.config.use_mock_aws() {
        (
            QueryStatus::Complete,
            mock_insights_results(),
            Some(QueryStatistics {
                records_matched: 2.0,
                records_scanned: 1000.0,
                bytes_scanned: 524288.0,
            }),
        )
    } else {
        let client = crate::routes::cloudwatch::get_cwl_client_for_account(
            state,
            entitlements,
            &payload.account_id,
            &payload.region,
            &claims.sub,
        )
        .await?;
        let resp = client
            .get_query_results()
            .query_id(&payload.aws_query_id)
            .send()
            .await
            .map_err(|e| {
                let _ = audit_cloudwatch_insights_failure(
                    state,
                    &claims.sub,
                    audit_ctx,
                    req,
                    None,
                    false,
                    "aws_get_query_results_failed",
                    "AWS GetQueryResults failed",
                );
                (
                    StatusCode::BAD_GATEWAY,
                    Json(ApiError::internal(format!(
                        "AWS GetQueryResults failed: {e}"
                    ))),
                )
            })?;
        let status = map_aws_query_status(resp.status());
        let results = resp
            .results()
            .iter()
            .map(|row| {
                row.iter()
                    .map(|field| QueryResultField {
                        field: field.field().unwrap_or_default().to_string(),
                        value: truncate_utf8(
                            field.value().unwrap_or_default(),
                            guardrails.max_event_message_bytes as usize,
                        ),
                    })
                    .collect()
            })
            .collect();
        let statistics = resp.statistics().map(|s| QueryStatistics {
            records_matched: s.records_matched(),
            records_scanned: s.records_scanned(),
            bytes_scanned: s.bytes_scanned(),
        });
        (status, results, statistics)
    };
    let (results, results_truncated) = truncate_insights_results_by_budget(raw_results, guardrails);

    let terminal = status.is_terminal();
    audit_cloudwatch_insights_success(
        state,
        &claims.sub,
        audit_ctx,
        req,
        &payload,
        if terminal { "complete" } else { "poll" },
        status.clone(),
        results.len(),
        results_truncated,
        !state.config.use_mock_aws(),
        raw_plaintext_allowed,
    )?;

    let next_action_hint = if !terminal {
        Some("Use query_token to continue polling this exact Insights query.".to_string())
    } else if results_truncated {
        Some(
            "Narrow the query or time range; the MCP Insights response budget was exhausted."
                .to_string(),
        )
    } else {
        None
    };

    Ok(Json(McpRunInsightsQueryResponse {
        account_id: payload.account_id,
        region: payload.region,
        log_group_names: payload.log_group_names,
        query_token: (!terminal).then(|| query_token.to_string()),
        status: status.clone(),
        results,
        statistics,
        terminal,
        next_action_hint,
    }))
}

fn map_aws_query_status(
    status: Option<&aws_sdk_cloudwatchlogs::types::QueryStatus>,
) -> QueryStatus {
    match status {
        Some(aws_sdk_cloudwatchlogs::types::QueryStatus::Scheduled) => QueryStatus::Scheduled,
        Some(aws_sdk_cloudwatchlogs::types::QueryStatus::Running) => QueryStatus::Running,
        Some(aws_sdk_cloudwatchlogs::types::QueryStatus::Complete) => QueryStatus::Complete,
        Some(aws_sdk_cloudwatchlogs::types::QueryStatus::Failed) => QueryStatus::Failed,
        Some(aws_sdk_cloudwatchlogs::types::QueryStatus::Cancelled) => QueryStatus::Cancelled,
        Some(aws_sdk_cloudwatchlogs::types::QueryStatus::Timeout) => QueryStatus::Timeout,
        _ => QueryStatus::Unknown,
    }
}

fn mock_insights_results() -> Vec<Vec<QueryResultField>> {
    vec![
        vec![
            QueryResultField {
                field: "@timestamp".into(),
                value: "2025-03-15 10:30:00".into(),
            },
            QueryResultField {
                field: "@message".into(),
                value: "Request processed successfully".into(),
            },
        ],
        vec![
            QueryResultField {
                field: "@timestamp".into(),
                value: "2025-03-15 10:30:01".into(),
            },
            QueryResultField {
                field: "@message".into(),
                value: "Database query completed in 45ms".into(),
            },
        ],
    ]
}

fn audit_cloudwatch_preflight_denied(
    state: &AppState,
    actor: &str,
    audit_ctx: &AuditRequestContext,
    req: &McpCloudwatchPreflightRequest,
    reason: &str,
    message: &str,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    state
        .audit_service
        .event(
            actor,
            AuditAction::McpCloudwatchPreflight,
            AuditOutcome::Denied,
        )
        .account(Some(&req.account_id))
        .region(Some(&req.region))
        .target(req.log_group_name.as_deref())
        .error(Some(message))
        .metadata(audit_ctx.metadata(serde_json::json!({
            "client_type": "mcp",
            "surface": "mcp",
            "mcp_event_kind": "cloudwatch_preflight",
            "mcp_outcome_kind": reason,
            "tool_name": req.tool_name.as_str(),
            "canopy_mcp_session_id": req.canopy_mcp_session_id.as_deref(),
            "local_secret_generation": req.local_secret_generation.as_deref(),
            "log_group_name": req.log_group_name.as_deref(),
            "log_group_names": req.log_group_names,
            "start_time": req.start_time,
            "end_time": req.end_time,
            "limit": req.limit,
            "filter_pattern_raw": "[redacted: denial path]",
            "query_string_raw": "[redacted: denial path]",
            "raw_inputs_redacted": true,
            "aws_execution_attempted": false,
            "rejection_reason": reason,
        })))
        .commit_or_fail()
        .map_err(|_| cloudwatch_data_audit_failure_response())
}

fn audit_cloudwatch_search_denied(
    state: &AppState,
    actor: &str,
    audit_ctx: &AuditRequestContext,
    req: &McpSearchLogsRequest,
    context: Option<&CloudwatchSearchContext>,
    reason: &str,
    message: &str,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    state
        .audit_service
        .event(
            actor,
            AuditAction::McpCloudwatchSearch,
            AuditOutcome::Denied,
        )
        .account(context.map(|c| c.account_id.as_str()))
        .region(context.map(|c| c.region.as_str()))
        .target(context.map(|c| c.log_group_name.as_str()))
        .error(Some(message))
        .metadata(audit_ctx.metadata(serde_json::json!({
            "client_type": "mcp",
            "surface": "mcp",
            "mcp_event_kind": "cloudwatch_search",
            "mcp_outcome_kind": reason,
            "tool_name": CLOUDWATCH_SEARCH_TOOL,
            "canopy_mcp_session_id": req.canopy_mcp_session_id.as_deref(),
            "local_secret_generation": req.local_secret_generation.as_deref(),
            "has_preflight_token": req.preflight_token.is_some(),
            "has_search_cursor": req.search_cursor.is_some(),
            "account_id": context.map(|c| c.account_id.as_str()),
            "region": context.map(|c| c.region.as_str()),
            "log_group_name": context.map(|c| c.log_group_name.as_str()),
            "filter_pattern_raw": "[redacted: denial path]",
            "raw_inputs_redacted": true,
            "aws_execution_attempted": false,
            "rejection_reason": reason,
        })))
        .commit_or_fail()
        .map_err(|_| cloudwatch_data_audit_failure_response())
}

fn audit_cloudwatch_search_attempt(
    state: &AppState,
    actor: &str,
    audit_ctx: &AuditRequestContext,
    req: &McpSearchLogsRequest,
    context: &CloudwatchSearchContext,
    raw_plaintext_allowed: bool,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    let log_group_names = vec![context.log_group_name.clone()];
    let filter_pattern_raw_encrypted = encrypted_cloudwatch_raw_audit_value(
        state,
        actor,
        req.canopy_mcp_session_id.as_deref(),
        req.local_secret_generation.as_deref(),
        CLOUDWATCH_SEARCH_TOOL,
        &context.account_id,
        &context.region,
        &log_group_names,
        "filter_pattern",
        context.filter_pattern.as_deref(),
    )?;
    state
        .audit_service
        .event(
            actor,
            AuditAction::McpCloudwatchSearch,
            AuditOutcome::Success,
        )
        .account(Some(&context.account_id))
        .region(Some(&context.region))
        .target(Some(&context.log_group_name))
        .metadata(audit_ctx.metadata(serde_json::json!({
            "client_type": "mcp",
            "surface": "mcp",
            "mcp_event_kind": "cloudwatch_search",
            "mcp_outcome_kind": "attempt",
            "tool_name": CLOUDWATCH_SEARCH_TOOL,
            "canopy_mcp_session_id": req.canopy_mcp_session_id.as_deref(),
            "local_secret_generation": req.local_secret_generation.as_deref(),
            "log_group_name": context.log_group_name.as_str(),
            "start_time": context.start_time,
            "end_time": context.end_time,
            "limit": context.limit,
            "raw_audit_storage": if raw_plaintext_allowed { "plaintext_restricted" } else { "encrypted_default" },
            "raw_plaintext_allowed": raw_plaintext_allowed,
            "filter_pattern_raw": cloudwatch_raw_plaintext_value(context.filter_pattern.as_deref(), raw_plaintext_allowed),
            "filter_pattern_raw_encrypted": filter_pattern_raw_encrypted,
            "aws_execution_attempted": false,
            "aws_execution_planned": true,
        })))
        .commit_or_fail()
        .map_err(|_| cloudwatch_data_audit_failure_response())
}

#[allow(clippy::too_many_arguments)]
fn audit_cloudwatch_search_failure(
    state: &AppState,
    actor: &str,
    audit_ctx: &AuditRequestContext,
    req: &McpSearchLogsRequest,
    context: &CloudwatchSearchContext,
    raw_plaintext_allowed: bool,
    reason: &str,
    message: &str,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    let log_group_names = vec![context.log_group_name.clone()];
    let filter_pattern_raw_encrypted = encrypted_cloudwatch_raw_audit_value(
        state,
        actor,
        req.canopy_mcp_session_id.as_deref(),
        req.local_secret_generation.as_deref(),
        CLOUDWATCH_SEARCH_TOOL,
        &context.account_id,
        &context.region,
        &log_group_names,
        "filter_pattern",
        context.filter_pattern.as_deref(),
    )?;
    state
        .audit_service
        .event(
            actor,
            AuditAction::McpCloudwatchSearch,
            AuditOutcome::Failure,
        )
        .account(Some(&context.account_id))
        .region(Some(&context.region))
        .target(Some(&context.log_group_name))
        .error(Some(message))
        .metadata(audit_ctx.metadata(serde_json::json!({
            "client_type": "mcp",
            "surface": "mcp",
            "mcp_event_kind": "cloudwatch_search",
            "mcp_outcome_kind": reason,
            "tool_name": CLOUDWATCH_SEARCH_TOOL,
            "canopy_mcp_session_id": req.canopy_mcp_session_id.as_deref(),
            "local_secret_generation": req.local_secret_generation.as_deref(),
            "log_group_name": context.log_group_name.as_str(),
            "raw_audit_storage": if raw_plaintext_allowed { "plaintext_restricted" } else { "encrypted_default" },
            "raw_plaintext_allowed": raw_plaintext_allowed,
            "filter_pattern_raw": cloudwatch_raw_plaintext_value(context.filter_pattern.as_deref(), raw_plaintext_allowed),
            "filter_pattern_raw_encrypted": filter_pattern_raw_encrypted,
            "aws_execution_attempted": true,
            "rejection_reason": reason,
        })))
        .commit_or_fail()
        .map_err(|_| cloudwatch_data_audit_failure_response())
}

fn audit_cloudwatch_insights_denied(
    state: &AppState,
    actor: &str,
    audit_ctx: &AuditRequestContext,
    req: &McpRunInsightsQueryRequest,
    preflight: Option<&CloudwatchPreflightTokenPayload>,
    reason: &str,
    message: &str,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    state
        .audit_service
        .event(
            actor,
            AuditAction::McpCloudwatchInsights,
            AuditOutcome::Denied,
        )
        .account(preflight.map(|p| p.account_id.as_str()))
        .region(preflight.map(|p| p.region.as_str()))
        .target(preflight.map(|p| p.log_group_names.join(",")).as_deref())
        .error(Some(message))
        .metadata(audit_ctx.metadata(serde_json::json!({
            "client_type": "mcp",
            "surface": "mcp",
            "mcp_event_kind": "cloudwatch_insights",
            "mcp_outcome_kind": reason,
            "tool_name": CLOUDWATCH_INSIGHTS_TOOL,
            "canopy_mcp_session_id": req.canopy_mcp_session_id.as_deref(),
            "local_secret_generation": req.local_secret_generation.as_deref(),
            "has_preflight_token": req.preflight_token.is_some(),
            "has_query_token": req.query_token.is_some(),
            "account_id": preflight.map(|p| p.account_id.as_str()),
            "region": preflight.map(|p| p.region.as_str()),
            "log_group_names": preflight.map(|p| p.log_group_names.as_slice()),
            "query_string_raw": "[redacted: denial path]",
            "raw_inputs_redacted": true,
            "aws_execution_attempted": false,
            "rejection_reason": reason,
        })))
        .commit_or_fail()
        .map_err(|_| cloudwatch_data_audit_failure_response())
}

fn audit_cloudwatch_insights_attempt<T: CloudwatchInsightsAuditPayload>(
    state: &AppState,
    actor: &str,
    audit_ctx: &AuditRequestContext,
    req: &McpRunInsightsQueryRequest,
    payload: &T,
    raw_plaintext_allowed: bool,
    phase: &str,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    let target = payload.audit_log_group_names().join(",");
    let query_string_raw_encrypted = encrypted_cloudwatch_raw_audit_value(
        state,
        actor,
        req.canopy_mcp_session_id.as_deref(),
        req.local_secret_generation.as_deref(),
        CLOUDWATCH_INSIGHTS_TOOL,
        payload.audit_account_id(),
        payload.audit_region(),
        payload.audit_log_group_names(),
        "query_string",
        payload.audit_query_string(),
    )?;
    state
        .audit_service
        .event(
            actor,
            AuditAction::McpCloudwatchInsights,
            AuditOutcome::Success,
        )
        .account(Some(payload.audit_account_id()))
        .region(Some(payload.audit_region()))
        .target(Some(&target))
        .metadata(audit_ctx.metadata(serde_json::json!({
            "client_type": "mcp",
            "surface": "mcp",
            "mcp_event_kind": "cloudwatch_insights",
            "mcp_outcome_kind": "attempt",
            "tool_name": CLOUDWATCH_INSIGHTS_TOOL,
            "canopy_mcp_session_id": req.canopy_mcp_session_id.as_deref(),
            "local_secret_generation": req.local_secret_generation.as_deref(),
            "phase": phase,
            "account_id": payload.audit_account_id(),
            "region": payload.audit_region(),
            "log_group_names": payload.audit_log_group_names(),
            "raw_audit_storage": if raw_plaintext_allowed { "plaintext_restricted" } else { "encrypted_default" },
            "raw_plaintext_allowed": raw_plaintext_allowed,
            "query_string_raw": cloudwatch_raw_plaintext_value(payload.audit_query_string(), raw_plaintext_allowed),
            "query_string_raw_encrypted": query_string_raw_encrypted,
            "aws_execution_attempted": false,
            "aws_execution_planned": true,
        })))
        .commit_or_fail()
        .map_err(|_| cloudwatch_data_audit_failure_response())
}

#[allow(clippy::too_many_arguments)]
fn audit_cloudwatch_insights_failure(
    state: &AppState,
    actor: &str,
    audit_ctx: &AuditRequestContext,
    req: &McpRunInsightsQueryRequest,
    preflight: Option<&CloudwatchPreflightTokenPayload>,
    raw_plaintext_allowed: bool,
    reason: &str,
    message: &str,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    let log_group_names = preflight
        .map(|p| p.log_group_names.as_slice())
        .unwrap_or(&[]);
    let query_string = preflight.and_then(|p| p.query_string.as_deref());
    let query_string_raw_encrypted = if let Some(preflight) = preflight {
        encrypted_cloudwatch_raw_audit_value(
            state,
            actor,
            req.canopy_mcp_session_id.as_deref(),
            req.local_secret_generation.as_deref(),
            CLOUDWATCH_INSIGHTS_TOOL,
            &preflight.account_id,
            &preflight.region,
            &preflight.log_group_names,
            "query_string",
            query_string,
        )?
    } else {
        serde_json::Value::Null
    };
    state
        .audit_service
        .event(
            actor,
            AuditAction::McpCloudwatchInsights,
            AuditOutcome::Failure,
        )
        .account(preflight.map(|p| p.account_id.as_str()))
        .region(preflight.map(|p| p.region.as_str()))
        .error(Some(message))
        .metadata(audit_ctx.metadata(serde_json::json!({
            "client_type": "mcp",
            "surface": "mcp",
            "mcp_event_kind": "cloudwatch_insights",
            "mcp_outcome_kind": reason,
            "tool_name": CLOUDWATCH_INSIGHTS_TOOL,
            "canopy_mcp_session_id": req.canopy_mcp_session_id.as_deref(),
            "local_secret_generation": req.local_secret_generation.as_deref(),
            "account_id": preflight.map(|p| p.account_id.as_str()),
            "region": preflight.map(|p| p.region.as_str()),
            "log_group_names": log_group_names,
            "raw_audit_storage": if raw_plaintext_allowed { "plaintext_restricted" } else { "encrypted_default" },
            "raw_plaintext_allowed": raw_plaintext_allowed,
            "query_string_raw": cloudwatch_raw_plaintext_value(query_string, raw_plaintext_allowed),
            "query_string_raw_encrypted": query_string_raw_encrypted,
            "aws_execution_attempted": true,
            "rejection_reason": reason,
        })))
        .commit_or_fail()
        .map_err(|_| cloudwatch_data_audit_failure_response())
}

#[allow(clippy::too_many_arguments)]
fn audit_cloudwatch_insights_success(
    state: &AppState,
    actor: &str,
    audit_ctx: &AuditRequestContext,
    req: &McpRunInsightsQueryRequest,
    payload: &InsightsQueryTokenPayload,
    outcome_kind: &str,
    status: QueryStatus,
    row_count: usize,
    results_truncated: bool,
    aws_execution_attempted: bool,
    raw_plaintext_allowed: bool,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    let query_string_raw_encrypted = encrypted_cloudwatch_raw_audit_value(
        state,
        actor,
        req.canopy_mcp_session_id.as_deref(),
        req.local_secret_generation.as_deref(),
        CLOUDWATCH_INSIGHTS_TOOL,
        &payload.account_id,
        &payload.region,
        &payload.log_group_names,
        "query_string",
        Some(payload.query_string.as_str()),
    )?;
    state
        .audit_service
        .event(
            actor,
            AuditAction::McpCloudwatchInsights,
            AuditOutcome::Success,
        )
        .account(Some(&payload.account_id))
        .region(Some(&payload.region))
        .target(Some(&payload.log_group_names.join(",")))
        .metadata(audit_ctx.metadata(serde_json::json!({
            "client_type": "mcp",
            "surface": "mcp",
            "mcp_event_kind": "cloudwatch_insights",
            "mcp_outcome_kind": outcome_kind,
            "tool_name": CLOUDWATCH_INSIGHTS_TOOL,
            "canopy_mcp_session_id": req.canopy_mcp_session_id.as_deref(),
            "local_secret_generation": req.local_secret_generation.as_deref(),
            "log_group_names": payload.log_group_names,
            "raw_audit_storage": if raw_plaintext_allowed { "plaintext_restricted" } else { "encrypted_default" },
            "raw_plaintext_allowed": raw_plaintext_allowed,
            "query_string_raw": cloudwatch_raw_plaintext_value(Some(payload.query_string.as_str()), raw_plaintext_allowed),
            "query_string_raw_encrypted": query_string_raw_encrypted,
            "status": status,
            "row_count": row_count,
            "results_truncated": results_truncated,
            "aws_execution_attempted": aws_execution_attempted,
        })))
        .commit_or_fail()
        .map_err(|_| cloudwatch_data_audit_failure_response())
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

    #[test]
    fn response_event_cap_respects_byte_budget() {
        let guardrails = McpGuardrails {
            max_response_bytes: 64 * 1024,
            max_event_message_bytes: 16 * 1024,
            ..McpGuardrails::default()
        };

        let cap = max_events_per_response(&guardrails);

        assert!(
            cap < guardrails.max_search_events,
            "byte budget should reduce the per-response page size"
        );
        assert!(cap >= 1);
    }

    #[test]
    fn insights_results_truncate_at_response_budget() {
        let guardrails = McpGuardrails {
            max_response_bytes: 120,
            max_event_message_bytes: 80,
            ..McpGuardrails::default()
        };
        let rows = vec![
            vec![QueryResultField {
                field: "@message".into(),
                value: "first row fits".into(),
            }],
            vec![QueryResultField {
                field: "@message".into(),
                value: "second row should exceed the tiny response budget".into(),
            }],
        ];

        let (truncated_rows, truncated) = truncate_insights_results_by_budget(rows, &guardrails);

        assert!(truncated);
        assert_eq!(truncated_rows.len(), 1);
        assert_eq!(truncated_rows[0][0].value, "first row fits");
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

#[allow(clippy::too_many_arguments)]
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

/// Why `require_mcp_guidance` (or `sync_guidance`'s session-validity check)
/// rejected a request. Modeling these reasons as a type keeps the HTTP status
/// and the audit `mcp_outcome_kind` in lockstep and lets the compiler enforce
/// that every reason is handled — previously they were bare `&'static str`s
/// shared untyped across the status mapping, the audit metadata, and the route
/// tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum McpGuidanceDenial {
    SessionRequired,
    StoreUnavailable,
    SessionNotFound,
    SessionExpired,
    ActorMismatch,
    GenerationMismatch,
    GuidanceRequired,
}

impl McpGuidanceDenial {
    /// Stable `mcp_outcome_kind` audit value. These strings are a wire contract
    /// — audit consumers and route tests key on them — so they must not change.
    fn audit_outcome_kind(self) -> &'static str {
        match self {
            Self::SessionRequired => "mcp_session_required",
            Self::StoreUnavailable => "mcp_session_store_unavailable",
            Self::SessionNotFound => "mcp_session_not_found",
            Self::SessionExpired => "mcp_session_expired",
            Self::ActorMismatch => "mcp_session_actor_mismatch",
            Self::GenerationMismatch => "mcp_session_generation_mismatch",
            Self::GuidanceRequired => "guidance_required",
        }
    }

    /// Store/backend unavailability is an infrastructure failure, not an
    /// authorization decision: callers must surface it as 503 without writing a
    /// `Denied` audit event (that would pollute the security trail and can trip
    /// denial-based alerting). This mirrors how `sync_guidance` treats a
    /// `get_session` error.
    fn is_store_unavailable(self) -> bool {
        matches!(self, Self::StoreUnavailable)
    }

    /// HTTP response for this denial. `guidance_required_message` is the
    /// endpoint-specific text used only for `GuidanceRequired`; every other
    /// reason carries a fixed message.
    fn http_response(
        self,
        guidance_required_message: &'static str,
    ) -> (StatusCode, Json<ApiError>) {
        match self {
            Self::StoreUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::service_unavailable(
                    "MCP session store unavailable",
                )),
            ),
            Self::SessionRequired => (
                StatusCode::FORBIDDEN,
                Json(ApiError::forbidden("MCP session is required")),
            ),
            Self::SessionNotFound => (
                StatusCode::NOT_FOUND,
                Json(ApiError::not_found("MCP session not found")),
            ),
            Self::SessionExpired => (
                StatusCode::FORBIDDEN,
                Json(ApiError::forbidden("MCP session expired")),
            ),
            Self::ActorMismatch | Self::GenerationMismatch => (
                StatusCode::FORBIDDEN,
                Json(ApiError::forbidden(
                    "MCP session is not valid for this user",
                )),
            ),
            Self::GuidanceRequired => (
                StatusCode::FORBIDDEN,
                Json(ApiError::forbidden(guidance_required_message)),
            ),
        }
    }
}

async fn require_mcp_guidance(
    state: &AppState,
    claims: &Claims,
    session_id: Option<&str>,
    local_secret_generation: Option<&str>,
    required_guidance: &[&str],
) -> Result<(), McpGuidanceDenial> {
    let Some(session_id) = session_id else {
        return Err(McpGuidanceDenial::SessionRequired);
    };
    let Some(local_secret_generation) = local_secret_generation else {
        return Err(McpGuidanceDenial::SessionRequired);
    };
    let session = state
        .mcp_sessions
        .get_session(session_id)
        .await
        .map_err(|_| McpGuidanceDenial::StoreUnavailable)?;
    let Some(session) = session else {
        return Err(McpGuidanceDenial::SessionNotFound);
    };

    if session.actor != claims.sub {
        return Err(McpGuidanceDenial::ActorMismatch);
    }
    if session.local_secret_generation != local_secret_generation {
        return Err(McpGuidanceDenial::GenerationMismatch);
    }
    if session.is_expired_at(Utc::now()) {
        return Err(McpGuidanceDenial::SessionExpired);
    }
    if !required_guidance
        .iter()
        .all(|guidance| session.guidance_delivered.contains(*guidance))
    {
        return Err(McpGuidanceDenial::GuidanceRequired);
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct AuthorizedMcpEc2DiagnosticCommand {
    entitlement_rule_id: String,
    account: Option<AllowedAccount>,
    allowlist_rule_id: String,
    command_scope_id: String,
    authorization_fingerprint: String,
    command_type: McpEc2DiagnosticCommandType,
    command: McpEc2DiagnosticCommand,
    requires_instance_metadata: bool,
}

fn mcp_ec2_command_type(command: &McpEc2DiagnosticCommand) -> McpEc2DiagnosticCommandType {
    match command {
        McpEc2DiagnosticCommand::TailLog { .. } => McpEc2DiagnosticCommandType::TailLog,
        McpEc2DiagnosticCommand::GrepLog { .. } => McpEc2DiagnosticCommandType::GrepLog,
        McpEc2DiagnosticCommand::JournalctlUnit { .. } => {
            McpEc2DiagnosticCommandType::JournalctlUnit
        }
        McpEc2DiagnosticCommand::HttpHead { .. } => McpEc2DiagnosticCommandType::HttpHead,
        McpEc2DiagnosticCommand::TcpProbe { .. } => McpEc2DiagnosticCommandType::TcpProbe,
        McpEc2DiagnosticCommand::DnsLookup { .. } => McpEc2DiagnosticCommandType::DnsLookup,
    }
}

fn mcp_ec2_command_type_wire(command_type: &McpEc2DiagnosticCommandType) -> &'static str {
    match command_type {
        McpEc2DiagnosticCommandType::TailLog => "tail_log",
        McpEc2DiagnosticCommandType::GrepLog => "grep_log",
        McpEc2DiagnosticCommandType::JournalctlUnit => "journalctl_unit",
        McpEc2DiagnosticCommandType::HttpHead => "http_head",
        McpEc2DiagnosticCommandType::TcpProbe => "tcp_probe",
        McpEc2DiagnosticCommandType::DnsLookup => "dns_lookup",
    }
}

fn mcp_ec2_placeholder_command_for_type(
    command_type: &McpEc2DiagnosticCommandType,
) -> McpEc2DiagnosticCommand {
    match command_type {
        McpEc2DiagnosticCommandType::TailLog => McpEc2DiagnosticCommand::TailLog {
            path: String::new(),
            lines: 1,
        },
        McpEc2DiagnosticCommandType::GrepLog => McpEc2DiagnosticCommand::GrepLog {
            path: String::new(),
            literal_pattern: String::new(),
            case_insensitive: false,
            max_matches: 1,
        },
        McpEc2DiagnosticCommandType::JournalctlUnit => McpEc2DiagnosticCommand::JournalctlUnit {
            unit: String::new(),
            since: String::new(),
            lines: 1,
        },
        McpEc2DiagnosticCommandType::HttpHead => McpEc2DiagnosticCommand::HttpHead {
            url: String::new(),
            max_time_seconds: 1,
        },
        McpEc2DiagnosticCommandType::TcpProbe => McpEc2DiagnosticCommand::TcpProbe {
            host: String::new(),
            port: 1,
            timeout_seconds: 1,
        },
        McpEc2DiagnosticCommandType::DnsLookup => McpEc2DiagnosticCommand::DnsLookup {
            host: String::new(),
            record_type: McpCommandDnsRecordType::A,
        },
    }
}

fn mcp_ec2_result_byte_budget(max_bytes: u64) -> Option<usize> {
    if max_bytes == 0 {
        return None;
    }
    MCP_EC2_DIAGNOSTIC_RESULT_MAX_BYTES
        .min(max_bytes)
        .try_into()
        .ok()
}

fn mcp_ec2_session_context(state: &AppState, claims: &Claims) -> SessionContext {
    SessionContext {
        user_id: claims.sub.clone(),
        team: claims
            .groups
            .first()
            .cloned()
            .unwrap_or_else(|| "unknown".to_string()),
        environment: if state.config.dev_mode {
            "dev".to_string()
        } else {
            "production".to_string()
        },
        session_duration_seconds: state.config.aws.session_duration_seconds,
        sts_external_id: state.config.aws.sts_external_id.clone(),
    }
}

fn mcp_ec2_invocation_output_text(invocation: &McpEc2DiagnosticSsmInvocation) -> String {
    match (
        invocation.stdout().is_empty(),
        invocation.stderr().is_empty(),
    ) {
        (true, true) => String::new(),
        (false, true) => invocation.stdout().to_string(),
        (true, false) => format!("[stderr]\n{}", invocation.stderr()),
        (false, false) => format!("{}\n[stderr]\n{}", invocation.stdout(), invocation.stderr()),
    }
}

fn mcp_ec2_terminal_status_for_invocation(
    invocation: &McpEc2DiagnosticSsmInvocation,
) -> McpEc2DiagnosticCommandStatus {
    match invocation.status() {
        McpEc2DiagnosticSsmInvocationStatus::Succeeded => McpEc2DiagnosticCommandStatus::Succeeded,
        McpEc2DiagnosticSsmInvocationStatus::Failed => McpEc2DiagnosticCommandStatus::Failed,
        McpEc2DiagnosticSsmInvocationStatus::Running => McpEc2DiagnosticCommandStatus::Running,
    }
}

fn mcp_ec2_terminal_error(status: &McpEc2DiagnosticCommandStatus) -> Option<String> {
    match status {
        McpEc2DiagnosticCommandStatus::Failed => {
            Some("MCP EC2 diagnostic command failed".to_string())
        }
        _ => None,
    }
}

fn mcp_ec2_invocation_status_wire(status: &McpEc2DiagnosticSsmInvocationStatus) -> &'static str {
    match status {
        McpEc2DiagnosticSsmInvocationStatus::Running => "running",
        McpEc2DiagnosticSsmInvocationStatus::Succeeded => "succeeded",
        McpEc2DiagnosticSsmInvocationStatus::Failed => "failed",
    }
}

fn mcp_ec2_authorization_fingerprint(grant: &McpEc2DiagnosticScopeGrant) -> String {
    let payload = serde_json::json!({
        "version": 1,
        "entitlement_rule_id": grant.entitlement_rule_id.as_str(),
        "account": &grant.account,
        "scope": &grant.scope,
        "requires_instance_metadata": grant.requires_instance_metadata,
    });
    let encoded = serde_json::to_vec(&payload).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(Sha256::digest(encoded))
}

async fn authorize_mcp_ec2_diagnostic_command(
    ent_service: &EntitlementService,
    claims: &Claims,
    req: &McpRunEc2DiagnosticCommandRequest,
) -> Result<AuthorizedMcpEc2DiagnosticCommand, &'static str> {
    if req.instance_id.trim().is_empty()
        || req.account_id.trim().is_empty()
        || req.region.trim().is_empty()
    {
        return Err("invalid_target");
    }

    let grants = ent_service
        .mcp_ec2_diagnostic_scope_grants_for_target(&claims, &req.account_id, &req.region)
        .await;
    if grants.is_empty() {
        return Err("no_matching_rule_scope");
    }
    if mcp_ec2_grants_have_ambiguous_account_identity(&grants) {
        return Err("ambiguous_target_account");
    }

    let mut metadata_required_candidate = None;
    for grant in grants {
        if let Some(authorization) = authorize_mcp_ec2_command_for_grant(&grant, &req.command) {
            if authorization.requires_instance_metadata {
                metadata_required_candidate = Some(authorization);
                continue;
            }
            return Ok(authorization);
        }
    }

    metadata_required_candidate.ok_or("command_scope_denied")
}

async fn authorize_mcp_ec2_diagnostic_result_record(
    ent_service: &EntitlementService,
    claims: &Claims,
    record: &McpEc2DiagnosticCommandRecord,
) -> Result<AuthorizedMcpEc2DiagnosticCommand, &'static str> {
    let matching_grants = ent_service
        .mcp_ec2_diagnostic_scope_grants_for_target(&claims, &record.account_id, &record.region)
        .await
        .into_iter()
        .filter(|grant| {
            grant.scope.id == record.command_scope_id
                && grant.scope.allowlist_rule_id == record.allowlist_rule_id
        })
        .collect::<Vec<_>>();
    if matching_grants.is_empty() {
        return Err("result_scope_not_authorized");
    }
    if mcp_ec2_grants_have_ambiguous_account_identity(&matching_grants) {
        return Err("ambiguous_target_account");
    }
    if let Some(grant) = matching_grants
        .iter()
        .find(|grant| grant.requires_instance_metadata)
        .cloned()
    {
        let authorization_fingerprint = mcp_ec2_authorization_fingerprint(&grant);
        return Ok(AuthorizedMcpEc2DiagnosticCommand {
            entitlement_rule_id: grant.entitlement_rule_id,
            account: Some(grant.account),
            allowlist_rule_id: record.allowlist_rule_id.clone(),
            command_scope_id: record.command_scope_id.clone(),
            authorization_fingerprint,
            command_type: record.command_type.clone(),
            command: mcp_ec2_placeholder_command_for_type(&record.command_type),
            requires_instance_metadata: grant.requires_instance_metadata,
        });
    }
    let Some(expected_fingerprint) = record.authorization_fingerprint.as_deref() else {
        return Err("result_scope_fingerprint_missing");
    };
    let grant = matching_grants
        .into_iter()
        .find(|grant| mcp_ec2_authorization_fingerprint(grant) == expected_fingerprint)
        .ok_or("result_scope_changed")?;
    let authorization_fingerprint = mcp_ec2_authorization_fingerprint(&grant);
    Ok(AuthorizedMcpEc2DiagnosticCommand {
        entitlement_rule_id: grant.entitlement_rule_id,
        account: Some(grant.account),
        allowlist_rule_id: record.allowlist_rule_id.clone(),
        command_scope_id: record.command_scope_id.clone(),
        authorization_fingerprint,
        command_type: record.command_type.clone(),
        command: mcp_ec2_placeholder_command_for_type(&record.command_type),
        requires_instance_metadata: grant.requires_instance_metadata,
    })
}

fn mcp_ec2_grants_have_ambiguous_account_identity(grants: &[McpEc2DiagnosticScopeGrant]) -> bool {
    let Some(first) = grants.first() else {
        return false;
    };
    grants.iter().any(|grant| {
        grant.account.account_id != first.account.account_id
            || grant.account.account_name != first.account.account_name
            || grant.account.role_arn != first.account.role_arn
    })
}

fn authorize_mcp_ec2_command_for_grant(
    grant: &McpEc2DiagnosticScopeGrant,
    command: &McpEc2DiagnosticCommand,
) -> Option<AuthorizedMcpEc2DiagnosticCommand> {
    let authorized_command = mcp_ec2_authorized_command_for_scope(&grant.scope, command)?;
    Some(AuthorizedMcpEc2DiagnosticCommand {
        entitlement_rule_id: grant.entitlement_rule_id.clone(),
        account: Some(grant.account.clone()),
        allowlist_rule_id: grant.scope.allowlist_rule_id.clone(),
        command_scope_id: grant.scope.id.clone(),
        authorization_fingerprint: mcp_ec2_authorization_fingerprint(grant),
        command_type: mcp_ec2_command_type(&authorized_command),
        command: authorized_command,
        requires_instance_metadata: grant.requires_instance_metadata,
    })
}

fn mcp_ec2_authorized_command_for_scope(
    scope: &McpEc2DiagnosticScope,
    command: &McpEc2DiagnosticCommand,
) -> Option<McpEc2DiagnosticCommand> {
    match command {
        McpEc2DiagnosticCommand::TailLog { path, lines } => {
            if *lines == 0 || *lines > scope.max_lines {
                return None;
            }
            let path = mcp_ec2_authorized_log_path(scope, path)?;
            Some(McpEc2DiagnosticCommand::TailLog {
                path,
                lines: *lines,
            })
        }
        McpEc2DiagnosticCommand::GrepLog {
            path,
            literal_pattern,
            case_insensitive,
            max_matches,
        } => {
            let pattern = literal_pattern.trim();
            if *max_matches == 0
                || *max_matches > scope.max_matches
                || pattern.len() < 3
                || pattern == "."
            {
                return None;
            }
            let path = mcp_ec2_authorized_log_path(scope, path)?;
            Some(McpEc2DiagnosticCommand::GrepLog {
                path,
                literal_pattern: literal_pattern.clone(),
                case_insensitive: *case_insensitive,
                max_matches: *max_matches,
            })
        }
        McpEc2DiagnosticCommand::JournalctlUnit { unit, since, lines } => {
            if *lines > 0
                && *lines <= scope.max_lines
                && scope
                    .allowed_journal_units
                    .iter()
                    .any(|allowed| allowed.safe_for_mcp_output && allowed.unit == *unit)
            {
                let since =
                    normalize_mcp_ec2_journal_since(since, scope.max_since_seconds, Utc::now())?;
                Some(McpEc2DiagnosticCommand::JournalctlUnit {
                    unit: unit.clone(),
                    since,
                    lines: *lines,
                })
            } else {
                None
            }
        }
        McpEc2DiagnosticCommand::HttpHead {
            url,
            max_time_seconds,
        } => {
            if *max_time_seconds > 0
                && *max_time_seconds <= scope.max_timeout_seconds
                && scope.allowed_http_urls.iter().any(|allowed| {
                    allowed.safe_for_mcp_output
                        && allowed.normalized_url == *url
                        && match allowed.query_policy {
                            McpEc2HttpQueryPolicy::NoQuery => !url.contains('?'),
                            McpEc2HttpQueryPolicy::ExactOnly => true,
                        }
                })
            {
                Some(command.clone())
            } else {
                None
            }
        }
        McpEc2DiagnosticCommand::TcpProbe {
            host,
            port,
            timeout_seconds,
        } => {
            if *timeout_seconds > 0
                && *timeout_seconds <= scope.max_timeout_seconds
                && scope
                    .allowed_tcp_targets
                    .iter()
                    .any(|allowed| allowed.host == *host && allowed.port == *port)
            {
                Some(command.clone())
            } else {
                None
            }
        }
        McpEc2DiagnosticCommand::DnsLookup { host, record_type } => {
            if scope.allowed_dns_targets.iter().any(|allowed| {
                allowed.safe_for_mcp_output
                    && allowed.host == *host
                    && allowed.record_types.iter().any(|allowed_type| {
                        mcp_ec2_dns_record_type_matches(allowed_type, record_type)
                    })
            }) {
                Some(command.clone())
            } else {
                None
            }
        }
    }
}

fn mcp_ec2_authorized_log_path(scope: &McpEc2DiagnosticScope, path: &str) -> Option<String> {
    let normalized_path = normalize_mcp_ec2_absolute_log_path(path)?;
    scope
        .allowed_log_paths
        .iter()
        .find_map(|allowed| mcp_ec2_log_path_matches_allowed(allowed, &normalized_path))
}

fn mcp_ec2_log_path_matches_allowed(
    allowed: &McpEc2LogPathScope,
    normalized_path: &str,
) -> Option<String> {
    if !allowed.safe_for_mcp_output || !arn_matches_pattern(&allowed.path_pattern, normalized_path)
    {
        return None;
    }
    let normalized_prefix = normalize_mcp_ec2_absolute_log_path(&allowed.canonical_safe_prefix)?;
    let under_prefix = if normalized_prefix == "/" {
        normalized_path.starts_with('/')
    } else {
        normalized_path == normalized_prefix
            || normalized_path
                .strip_prefix(&normalized_prefix)
                .is_some_and(|suffix| suffix.starts_with('/'))
    };
    under_prefix.then(|| normalized_path.to_string())
}

fn normalize_mcp_ec2_absolute_log_path(path: &str) -> Option<String> {
    if path.is_empty() || !path.starts_with('/') || path.contains('\0') {
        return None;
    }
    let mut segments = Vec::new();
    for segment in path.split('/').skip(1) {
        match segment {
            "" | "." => {}
            ".." => return None,
            value => segments.push(value),
        }
    }
    if segments.is_empty() {
        return None;
    }
    Some(format!("/{}", segments.join("/")))
}

fn normalize_mcp_ec2_journal_since(
    since: &str,
    max_since_seconds: u64,
    now: DateTime<Utc>,
) -> Option<String> {
    let trimmed = since.trim();
    if trimmed.is_empty() || trimmed.contains('\0') || trimmed.len() > 64 {
        return None;
    }
    let seconds = parse_mcp_ec2_journal_since_duration_seconds(trimmed)
        .or_else(|| parse_mcp_ec2_journal_since_rfc3339_seconds(trimmed, now))?;
    if seconds == 0 || seconds > max_since_seconds {
        return None;
    }
    Some(format!("{seconds}s"))
}

fn parse_mcp_ec2_journal_since_rfc3339_seconds(since: &str, now: DateTime<Utc>) -> Option<u64> {
    let requested = DateTime::parse_from_rfc3339(since)
        .ok()?
        .with_timezone(&Utc);
    if requested > now {
        return None;
    }
    now.signed_duration_since(requested)
        .num_seconds()
        .try_into()
        .ok()
}

fn parse_mcp_ec2_journal_since_duration_seconds(since: &str) -> Option<u64> {
    let compact = since
        .trim()
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    if compact.is_empty() {
        return None;
    }
    let digit_count = compact
        .as_bytes()
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digit_count == 0 {
        return None;
    }
    let value = compact[..digit_count].parse::<u64>().ok()?;
    let unit = &compact[digit_count..];
    let multiplier = match unit {
        "" | "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3600,
        _ => return None,
    };
    value.checked_mul(multiplier)
}

fn mcp_ec2_dns_record_type_matches(
    allowed: &EntitlementDnsRecordType,
    requested: &McpCommandDnsRecordType,
) -> bool {
    matches!(
        (allowed, requested),
        (EntitlementDnsRecordType::A, McpCommandDnsRecordType::A)
            | (
                EntitlementDnsRecordType::Aaaa,
                McpCommandDnsRecordType::Aaaa
            )
            | (
                EntitlementDnsRecordType::Cname,
                McpCommandDnsRecordType::Cname
            )
    )
}

enum McpEc2DiagnosticAudit<'a> {
    Run {
        req: &'a McpRunEc2DiagnosticCommandRequest,
        command_type: Option<McpEc2DiagnosticCommandType>,
        command_id: Option<&'a str>,
    },
    Result {
        command_id: &'a str,
        session_id: Option<&'a str>,
        local_secret_generation: Option<&'a str>,
        max_bytes: u64,
    },
}

#[derive(Default)]
struct McpEc2DiagnosticAuditDetails<'a> {
    aws_ssm_command_id: Option<&'a str>,
    aws_cancel_attempted: Option<bool>,
    aws_cancel_succeeded: Option<bool>,
    output_byte_count: Option<u64>,
    dropped_byte_count: Option<u64>,
    output_sequence_start: Option<u64>,
    output_sequence_end: Option<u64>,
    exit_status: Option<i32>,
    truncated: Option<bool>,
    ssm_invocation_status: Option<&'a str>,
}

#[allow(clippy::too_many_arguments)]
fn audit_mcp_ec2_diagnostics(
    state: &AppState,
    actor: &str,
    audit_ctx: &AuditRequestContext,
    event: McpEc2DiagnosticAudit<'_>,
    outcome: AuditOutcome,
    outcome_kind: &str,
    authorization: Option<&AuthorizedMcpEc2DiagnosticCommand>,
    aws_execution_attempted: bool,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    audit_mcp_ec2_diagnostics_with_details(
        state,
        actor,
        audit_ctx,
        event,
        outcome,
        outcome_kind,
        authorization,
        aws_execution_attempted,
        McpEc2DiagnosticAuditDetails::default(),
    )
}

#[allow(clippy::too_many_arguments)]
fn audit_mcp_ec2_diagnostics_with_details(
    state: &AppState,
    actor: &str,
    audit_ctx: &AuditRequestContext,
    event: McpEc2DiagnosticAudit<'_>,
    outcome: AuditOutcome,
    outcome_kind: &str,
    authorization: Option<&AuthorizedMcpEc2DiagnosticCommand>,
    aws_execution_attempted: bool,
    details: McpEc2DiagnosticAuditDetails<'_>,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    let mut metadata = serde_json::json!({
        "client_type": "mcp",
        "surface": "mcp",
        "mcp_outcome_kind": outcome_kind,
        "aws_execution_attempted": aws_execution_attempted,
        "raw_command_recorded": false,
        "remote_output_recorded": false,
    });
    match event {
        McpEc2DiagnosticAudit::Run {
            req,
            command_type,
            command_id,
        } => {
            metadata["mcp_event_kind"] = serde_json::json!("ec2_diagnostic_run");
            metadata["tool_name"] = serde_json::json!("canopy_run_ec2_diagnostic_command");
            metadata["canopy_mcp_session_id"] =
                serde_json::json!(req.canopy_mcp_session_id.as_deref());
            metadata["local_secret_generation"] =
                serde_json::json!(req.local_secret_generation.as_deref());
            metadata["account_id"] = serde_json::json!(req.account_id.as_str());
            metadata["region"] = serde_json::json!(req.region.as_str());
            metadata["instance_id"] = serde_json::json!(req.instance_id.as_str());
            metadata["command_type"] =
                serde_json::json!(command_type.as_ref().map(mcp_ec2_command_type_wire));
            metadata["mcp_ec2_command_id"] = serde_json::json!(command_id);
        }
        McpEc2DiagnosticAudit::Result {
            command_id,
            session_id,
            local_secret_generation,
            max_bytes,
        } => {
            metadata["mcp_event_kind"] = serde_json::json!("ec2_diagnostic_result");
            metadata["tool_name"] = serde_json::json!("canopy_get_ec2_diagnostic_result");
            metadata["canopy_mcp_session_id"] = serde_json::json!(session_id);
            metadata["local_secret_generation"] = serde_json::json!(local_secret_generation);
            metadata["mcp_ec2_command_id"] = serde_json::json!(command_id);
            metadata["max_bytes"] = serde_json::json!(max_bytes);
        }
    }
    if let Some(authorization) = authorization {
        metadata["entitlement_rule_id"] =
            serde_json::json!(authorization.entitlement_rule_id.as_str());
        if let Some(account) = authorization.account.as_ref() {
            metadata["authorized_account_id"] = serde_json::json!(account.account_id.as_str());
            metadata["authorized_account_name"] = serde_json::json!(account.account_name.as_str());
            metadata["authorized_credential_mode"] =
                serde_json::json!(mcp_ec2_credential_mode(account));
        }
        metadata["allowlist_rule_id"] = serde_json::json!(authorization.allowlist_rule_id.as_str());
        metadata["command_scope_id"] = serde_json::json!(authorization.command_scope_id.as_str());
        metadata["authorized_command_type"] =
            serde_json::json!(mcp_ec2_command_type_wire(&authorization.command_type));
        metadata["requires_instance_metadata"] =
            serde_json::json!(authorization.requires_instance_metadata);
    }
    if let Some(aws_ssm_command_id) = details.aws_ssm_command_id {
        metadata["aws_ssm_command_id"] = serde_json::json!(aws_ssm_command_id);
    }
    if let Some(aws_cancel_attempted) = details.aws_cancel_attempted {
        metadata["aws_cancel_attempted"] = serde_json::json!(aws_cancel_attempted);
    }
    if let Some(aws_cancel_succeeded) = details.aws_cancel_succeeded {
        metadata["aws_cancel_succeeded"] = serde_json::json!(aws_cancel_succeeded);
    }
    if let Some(output_byte_count) = details.output_byte_count {
        metadata["output_byte_count"] = serde_json::json!(output_byte_count);
    }
    if let Some(dropped_byte_count) = details.dropped_byte_count {
        metadata["dropped_byte_count"] = serde_json::json!(dropped_byte_count);
    }
    if let Some(output_sequence_start) = details.output_sequence_start {
        metadata["output_sequence_start"] = serde_json::json!(output_sequence_start);
    }
    if let Some(output_sequence_end) = details.output_sequence_end {
        metadata["output_sequence_end"] = serde_json::json!(output_sequence_end);
    }
    if let Some(exit_status) = details.exit_status {
        metadata["exit_status"] = serde_json::json!(exit_status);
    }
    if let Some(truncated) = details.truncated {
        metadata["truncated"] = serde_json::json!(truncated);
    }
    if let Some(ssm_invocation_status) = details.ssm_invocation_status {
        metadata["ssm_invocation_status"] = serde_json::json!(ssm_invocation_status);
    }

    state
        .audit_service
        .event(actor, AuditAction::McpEc2Diagnostics, outcome)
        .metadata(audit_ctx.metadata(metadata))
        .commit_or_fail()
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::internal(
                    "Audit logging failed — refusing MCP EC2 diagnostics request",
                )),
            )
        })
}

fn mcp_ec2_credential_mode(account: &AllowedAccount) -> &'static str {
    if account.role_arn == "direct" {
        "direct"
    } else if account.role_arn.starts_with("profile:") {
        "profile"
    } else {
        "assume_role"
    }
}

#[cfg(test)]
mod mcp_ec2_diagnostic_tests {
    use super::*;

    fn account_with_role(role_arn: &str) -> AllowedAccount {
        AllowedAccount {
            account_id: "111111111111".into(),
            account_name: "test".into(),
            role_arn: role_arn.into(),
        }
    }

    #[test]
    fn mcp_ec2_credential_mode_classifies_without_exposing_role_arn() {
        assert_eq!(
            mcp_ec2_credential_mode(&account_with_role("direct")),
            "direct"
        );
        assert_eq!(
            mcp_ec2_credential_mode(&account_with_role("profile:ops")),
            "profile"
        );
        assert_eq!(
            mcp_ec2_credential_mode(&account_with_role(concat!(
                "arn:aws:iam::111111111111",
                ":role/CanopyMcpEc2Diagnostics"
            ),)),
            "assume_role"
        );
    }

    #[test]
    fn mcp_ec2_log_path_normalization_rejects_traversal() {
        assert_eq!(
            normalize_mcp_ec2_absolute_log_path("/var/log/nginx/./error.log").as_deref(),
            Some("/var/log/nginx/error.log")
        );
        assert!(normalize_mcp_ec2_absolute_log_path("/var/log/nginx/../../etc/shadow").is_none());
        assert!(normalize_mcp_ec2_absolute_log_path("var/log/nginx/error.log").is_none());
    }

    #[test]
    fn mcp_ec2_journal_since_normalizes_and_enforces_scope_window() {
        let now = DateTime::parse_from_rfc3339("2026-06-04T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            normalize_mcp_ec2_journal_since("10m", 1800, now).as_deref(),
            Some("600s")
        );
        assert_eq!(
            normalize_mcp_ec2_journal_since("600 seconds", 1800, now).as_deref(),
            Some("600s")
        );
        assert_eq!(
            normalize_mcp_ec2_journal_since("2026-06-04T11:50:00Z", 1800, now).as_deref(),
            Some("600s")
        );
        assert!(normalize_mcp_ec2_journal_since("3600s", 1800, now).is_none());
        assert!(normalize_mcp_ec2_journal_since("2026-06-04T12:01:00Z", 1800, now).is_none());
        assert!(normalize_mcp_ec2_journal_since("yesterday", 1800, now).is_none());
    }
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
