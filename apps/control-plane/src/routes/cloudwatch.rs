use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
use std::sync::Arc;

use crate::aws::clients::AwsClients;
use crate::aws::credentials::SessionContext;
use crate::middleware::auth::AuthenticatedUser;
use crate::services::audit::AuditRequestContext;
use crate::services::cloudwatch::{mock_log_events, mock_log_groups};
use crate::services::entitlements::EntitlementService;
use crate::services::AppState;
use shared::dto::audit::{AuditAction, AuditOutcome};
use shared::dto::cloudwatch::*;
use shared::dto::entitlements::AllowedAccount;
use shared::errors::ApiError;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/cloudwatch/log-groups", post(list_log_groups))
        .route("/api/cloudwatch/filter-events", post(filter_log_events))
        .route("/api/cloudwatch/insights/start", post(start_insights_query))
        .route("/api/cloudwatch/insights/results", post(get_query_results))
}

/// Try each matching AllowedAccount entry for the given account_id until
/// AssumeRole succeeds. Returns all successfully-assumed CWL clients so
/// callers can retry operations across candidate roles when the first
/// role lacks the specific CloudWatch permission.
async fn get_cwl_clients_for_account(
    state: &AppState,
    entitlements: &shared::dto::entitlements::UserEntitlements,
    account_id: &str,
    region: &str,
    user_id: &str,
) -> Result<Vec<aws_sdk_cloudwatchlogs::Client>, (axum::http::StatusCode, Json<ApiError>)> {
    let matching: Vec<_> = entitlements
        .allowed_accounts
        .iter()
        .filter(|a| a.account_id == account_id)
        .collect();

    if matching.is_empty() {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("Account not authorized")),
        ));
    }

    let mut clients = Vec::new();
    for account in matching {
        match get_cwl_client(state, account, region, user_id).await {
            Ok(client) => clients.push(client),
            Err(e) => {
                tracing::debug!(
                    role = %account.role_arn,
                    error = ?e,
                    "CWL client creation failed, trying next role"
                );
            }
        }
    }

    if clients.is_empty() {
        return Err((
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError::internal(
                "Failed to get AWS credentials for any authorized role",
            )),
        ));
    }

    Ok(clients)
}

/// Returns all assumable clients for the account. Callers should iterate
/// and retry on permission errors to handle multi-role accounts.
pub(crate) async fn get_cwl_client_for_account(
    state: &AppState,
    entitlements: &shared::dto::entitlements::UserEntitlements,
    account_id: &str,
    region: &str,
    user_id: &str,
) -> Result<aws_sdk_cloudwatchlogs::Client, (axum::http::StatusCode, Json<ApiError>)> {
    let mut clients =
        get_cwl_clients_for_account(state, entitlements, account_id, region, user_id).await?;
    // Return the first; callers that need retry should use get_cwl_clients_for_account directly.
    Ok(clients.remove(0))
}

/// Obtain a CloudWatch Logs SDK client for the given account and region.
async fn get_cwl_client(
    state: &AppState,
    account: &AllowedAccount,
    region: &str,
    user_id: &str,
) -> Result<aws_sdk_cloudwatchlogs::Client, (axum::http::StatusCode, Json<ApiError>)> {
    let base_config = state.base_aws_config.clone();
    let session_ctx = SessionContext {
        user_id: user_id.to_string(),
        team: "canopy".to_string(),
        environment: if state.config.dev_mode {
            "dev".to_string()
        } else {
            "production".to_string()
        },
        session_duration_seconds: state.config.aws.session_duration_seconds,
        sts_external_id: state.config.aws.sts_external_id.clone(),
    };

    let effective_config =
        crate::aws::credentials::resolve_aws_config(&base_config, account, region, &session_ctx)
            .await
            .map_err(|e| {
                tracing::error!("AWS config resolution failed for {}: {e}", account.role_arn);
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiError::internal(format!(
                        "Failed to get AWS credentials for account {}: {e}",
                        account.account_id
                    ))),
                )
            })?;

    Ok(AwsClients::cloudwatch_logs(&effective_config))
}

/// Fail-closed when the durable audit sink is broken.
fn require_audit_healthy(state: &AppState) -> Result<(), (axum::http::StatusCode, Json<ApiError>)> {
    if !state.audit_service.is_healthy() {
        Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal("Audit logging unavailable")),
        ))
    } else {
        Ok(())
    }
}

fn log_group_arn_variants(region: &str, account_id: &str, log_group_name: &str) -> Vec<String> {
    let base = format!("arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}");
    vec![base.clone(), format!("{base}:*")]
}

fn log_group_matches_patterns(patterns: &[String], arn_variants: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        arn_variants
            .iter()
            .any(|arn| crate::services::entitlements::arn_matches_pattern(pattern, arn))
    })
}

fn log_groups_metadata(ctx: &AuditRequestContext, req: &LogGroupsRequest) -> serde_json::Value {
    ctx.metadata(serde_json::json!({
        "prefix": req.prefix.as_deref(),
    }))
}

fn filter_events_metadata(
    ctx: &AuditRequestContext,
    req: &FilterLogEventsRequest,
) -> serde_json::Value {
    // Filter/query text is intentionally logged in full for auditability.
    // Treat audit logs as sensitive.
    ctx.metadata(serde_json::json!({
        "filter_pattern": req.filter_pattern.as_deref(),
        "start_time": req.start_time,
        "end_time": req.end_time,
        "limit": req.limit,
        "has_next_token": req.next_token.is_some(),
    }))
}

fn insights_query_metadata(
    ctx: &AuditRequestContext,
    req: &StartInsightsQueryRequest,
) -> serde_json::Value {
    // Filter/query text is intentionally logged in full for auditability.
    // Treat audit logs as sensitive.
    ctx.metadata(serde_json::json!({
        "query_string": &req.query_string,
        "start_time": req.start_time,
        "end_time": req.end_time,
        "log_group_names": &req.log_group_names,
    }))
}

fn query_results_metadata(
    ctx: &AuditRequestContext,
    req: &GetQueryResultsRequest,
) -> serde_json::Value {
    ctx.metadata(serde_json::json!({
        "query_id": &req.query_id,
    }))
}

async fn list_log_groups(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    headers: HeaderMap,
    Json(req): Json<LogGroupsRequest>,
) -> Result<Json<LogGroupsResponse>, (axum::http::StatusCode, Json<ApiError>)> {
    require_audit_healthy(&state)?;
    let audit_ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);
    let ent_service = EntitlementService::new(state.entitlement_store.clone());
    let entitlements = ent_service.evaluate(&claims).await;

    // Scope-aware check: verify that at least one rule grants CloudWatch
    // search AND access to the requested account+region (prevents cross-group escalation)
    if !ent_service
        .has_feature_for_scope(
            &claims,
            &req.account_id,
            Some(&req.region),
            None,
            None,
            |f| f.can_use_cloudwatch_search,
        )
        .await
    {
        state
            .audit_service
            .event(&claims.sub, AuditAction::LogGroupList, AuditOutcome::Denied)
            .account(Some(&req.account_id))
            .region(Some(&req.region))
            .error(Some("CloudWatch search not authorized"))
            .optional_metadata(Some(log_groups_metadata(&audit_ctx, &req)))
            .commit_best_effort();
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("CloudWatch search not authorized")),
        ));
    }

    // Verify account access
    if !entitlements
        .allowed_accounts
        .iter()
        .any(|a| a.account_id == req.account_id)
    {
        state
            .audit_service
            .event(&claims.sub, AuditAction::LogGroupList, AuditOutcome::Denied)
            .account(Some(&req.account_id))
            .region(Some(&req.region))
            .error(Some("Account not authorized"))
            .optional_metadata(Some(log_groups_metadata(&audit_ctx, &req)))
            .commit_best_effort();
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("Account not authorized")),
        ));
    }

    // Enforce region entitlement
    if !entitlements.allowed_regions.contains(&req.region) {
        state
            .audit_service
            .event(&claims.sub, AuditAction::LogGroupList, AuditOutcome::Denied)
            .account(Some(&req.account_id))
            .region(Some(&req.region))
            .error(Some("Region not authorized"))
            .optional_metadata(Some(log_groups_metadata(&audit_ctx, &req)))
            .commit_best_effort();
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("Region not authorized")),
        ));
    }

    // Use scope-aware log-group ARN patterns: only patterns from rules that
    // also grant CloudWatch search + this account (prevents cross-group leak).
    let scoped_log_arns = ent_service
        .allowed_log_group_arns_for_scope(&claims, &req.account_id, &req.region, |f| {
            f.can_use_cloudwatch_search
        })
        .await;

    let filtered: Vec<LogGroup> = if state.config.use_mock_aws() {
        // Dev mode: filter mock data to the requested scope
        let all_groups = mock_log_groups();
        let scope_prefix = format!("arn:aws:logs:{}:{}:log-group:", req.region, req.account_id);
        all_groups
            .into_iter()
            .filter(|g| g.arn.starts_with(&scope_prefix))
            .filter(|g| {
                scoped_log_arns.is_empty()
                    || scoped_log_arns.iter().any(|pattern| {
                        crate::services::entitlements::arn_matches_pattern(pattern, &g.arn)
                    })
            })
            .filter(|g| {
                req.prefix
                    .as_ref()
                    .map(|p| g.name.starts_with(p))
                    .unwrap_or(true)
            })
            .collect()
    } else {
        // Production: fetch log groups from AWS via SDK
        let client = get_cwl_client_for_account(
            &state,
            &entitlements,
            &req.account_id,
            &req.region,
            &claims.sub,
        )
        .await?;

        let mut all_groups: Vec<LogGroup> = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut describe = client.describe_log_groups();

            if let Some(ref prefix) = req.prefix {
                describe = describe.log_group_name_prefix(prefix);
            }
            if let Some(ref token) = next_token {
                describe = describe.next_token(token);
            }

            let resp = describe.send().await.map_err(|e| {
                tracing::error!("describe_log_groups failed: {e}");
                state
                    .audit_service
                    .event(
                        &claims.sub,
                        AuditAction::LogGroupList,
                        AuditOutcome::Failure,
                    )
                    .account(Some(&req.account_id))
                    .region(Some(&req.region))
                    .error(Some("AWS DescribeLogGroups failed"))
                    .optional_metadata(Some(log_groups_metadata(&audit_ctx, &req)))
                    .commit_best_effort();
                (
                    axum::http::StatusCode::BAD_GATEWAY,
                    Json(ApiError::internal(format!(
                        "AWS DescribeLogGroups failed: {e}"
                    ))),
                )
            })?;

            for g in resp.log_groups() {
                let name = g.log_group_name().unwrap_or_default().to_string();
                let arn = g.arn().unwrap_or_default().to_string();
                all_groups.push(LogGroup {
                    name,
                    arn,
                    stored_bytes: g.stored_bytes(),
                    retention_days: g.retention_in_days(),
                });
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        // Enforce entitlement ARN pattern filtering on the real results
        all_groups
            .into_iter()
            .filter(|g| {
                scoped_log_arns.is_empty()
                    || scoped_log_arns.iter().any(|pattern| {
                        crate::services::entitlements::arn_matches_pattern(pattern, &g.arn)
                    })
            })
            .collect()
    };

    // Audit after all checks pass and data is ready — fail-closed on write failure
    state
        .audit_service
        .event(
            &claims.sub,
            AuditAction::LogGroupList,
            AuditOutcome::Success,
        )
        .account(Some(&req.account_id))
        .region(Some(&req.region))
        .optional_metadata(Some(log_groups_metadata(&audit_ctx, &req)))
        .commit_or_fail()
        .map_err(|_| {
            (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::internal(
                    "Audit logging failed — refusing to return data",
                )),
            )
        })?;

    Ok(Json(LogGroupsResponse {
        log_groups: filtered,
    }))
}

async fn filter_log_events(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    headers: HeaderMap,
    Json(req): Json<FilterLogEventsRequest>,
) -> Result<Json<FilterLogEventsResponse>, (axum::http::StatusCode, Json<ApiError>)> {
    require_audit_healthy(&state)?;
    let audit_ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);
    let ent_service = EntitlementService::new(state.entitlement_store.clone());
    let entitlements = ent_service.evaluate(&claims).await;

    let filter_lg_arns = log_group_arn_variants(&req.region, &req.account_id, &req.log_group_name);
    let mut filter_scope_allowed = false;
    for arn in &filter_lg_arns {
        if ent_service
            .has_feature_for_scope(
                &claims,
                &req.account_id,
                Some(&req.region),
                Some(arn),
                None,
                |f| f.can_use_cloudwatch_search,
            )
            .await
        {
            filter_scope_allowed = true;
            break;
        }
    }
    if !filter_scope_allowed {
        state
            .audit_service
            .event(
                &claims.sub,
                AuditAction::CloudwatchSearch,
                AuditOutcome::Denied,
            )
            .account(Some(&req.account_id))
            .region(Some(&req.region))
            .target(Some(&req.log_group_name))
            .error(Some("CloudWatch search not authorized for this scope"))
            .optional_metadata(Some(filter_events_metadata(&audit_ctx, &req)))
            .commit_best_effort();
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("CloudWatch search not authorized")),
        ));
    }

    if !entitlements
        .allowed_accounts
        .iter()
        .any(|a| a.account_id == req.account_id)
    {
        state
            .audit_service
            .event(
                &claims.sub,
                AuditAction::CloudwatchSearch,
                AuditOutcome::Denied,
            )
            .account(Some(&req.account_id))
            .region(Some(&req.region))
            .target(Some(&req.log_group_name))
            .error(Some("Account not authorized"))
            .optional_metadata(Some(filter_events_metadata(&audit_ctx, &req)))
            .commit_best_effort();
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("Account not authorized")),
        ));
    }

    // Enforce region entitlement
    if !entitlements.allowed_regions.contains(&req.region) {
        state
            .audit_service
            .event(
                &claims.sub,
                AuditAction::CloudwatchSearch,
                AuditOutcome::Denied,
            )
            .account(Some(&req.account_id))
            .region(Some(&req.region))
            .target(Some(&req.log_group_name))
            .error(Some("Region not authorized"))
            .optional_metadata(Some(filter_events_metadata(&audit_ctx, &req)))
            .commit_best_effort();
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("Region not authorized")),
        ));
    }

    // Enforce log-group ARN entitlement using scope-aware patterns
    let scoped_log_arns = ent_service
        .allowed_log_group_arns_for_scope(&claims, &req.account_id, &req.region, |f| {
            f.can_use_cloudwatch_search
        })
        .await;
    if !scoped_log_arns.is_empty() && !log_group_matches_patterns(&scoped_log_arns, &filter_lg_arns)
    {
        state
            .audit_service
            .event(
                &claims.sub,
                AuditAction::CloudwatchSearch,
                AuditOutcome::Denied,
            )
            .account(Some(&req.account_id))
            .region(Some(&req.region))
            .target(Some(&req.log_group_name))
            .error(Some("Log group not authorized"))
            .optional_metadata(Some(filter_events_metadata(&audit_ctx, &req)))
            .commit_best_effort();
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("Log group not authorized")),
        ));
    }

    let (events, resp_next_token) = if state.config.use_mock_aws() {
        (mock_log_events(), None)
    } else {
        // Production: call FilterLogEvents via AWS SDK
        let client = get_cwl_client_for_account(
            &state,
            &entitlements,
            &req.account_id,
            &req.region,
            &claims.sub,
        )
        .await?;

        let mut filter = client
            .filter_log_events()
            .log_group_name(&req.log_group_name)
            .start_time(req.start_time)
            .end_time(req.end_time)
            .limit(req.limit);

        if let Some(ref pattern) = req.filter_pattern {
            filter = filter.filter_pattern(pattern);
        }
        if let Some(ref token) = req.next_token {
            filter = filter.next_token(token);
        }

        let resp = filter.send().await.map_err(|e| {
            let service_error = e.as_service_error();
            let is_invalid_parameter = service_error
                .map(|err| err.is_invalid_parameter_exception())
                .unwrap_or(false);
            let invalid_parameter_message = service_error
                .and_then(|err| err.meta().message())
                .unwrap_or("invalid filter pattern");
            tracing::error!("filter_log_events failed: {e}");
            if is_invalid_parameter {
                state
                    .audit_service
                    .event(
                        &claims.sub,
                        AuditAction::CloudwatchSearch,
                        AuditOutcome::Failure,
                    )
                    .account(Some(&req.account_id))
                    .region(Some(&req.region))
                    .target(Some(&req.log_group_name))
                    .error(Some("Invalid CloudWatch filter pattern"))
                    .optional_metadata(Some(filter_events_metadata(&audit_ctx, &req)))
                    .commit_best_effort();
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(ApiError::bad_request(format!(
                        "Invalid CloudWatch filter pattern: {invalid_parameter_message}"
                    ))),
                )
            } else {
                state
                    .audit_service
                    .event(
                        &claims.sub,
                        AuditAction::CloudwatchSearch,
                        AuditOutcome::Failure,
                    )
                    .account(Some(&req.account_id))
                    .region(Some(&req.region))
                    .target(Some(&req.log_group_name))
                    .error(Some("AWS FilterLogEvents failed"))
                    .optional_metadata(Some(filter_events_metadata(&audit_ctx, &req)))
                    .commit_best_effort();
                (
                    axum::http::StatusCode::BAD_GATEWAY,
                    Json(ApiError::internal(format!(
                        "AWS FilterLogEvents failed: {e}"
                    ))),
                )
            }
        })?;

        let events: Vec<LogEvent> = resp
            .events()
            .iter()
            .map(|e| LogEvent {
                timestamp: e.timestamp().unwrap_or(0),
                message: e.message().unwrap_or_default().to_string(),
                log_stream_name: e.log_stream_name().map(|s| s.to_string()),
                ingestion_time: e.ingestion_time(),
                event_id: e.event_id().map(|s| s.to_string()),
            })
            .collect();

        let token = resp.next_token().map(|s| s.to_string());
        (events, token)
    };

    // Audit after the operation succeeds — fail-closed on write failure
    state
        .audit_service
        .event(
            &claims.sub,
            AuditAction::CloudwatchSearch,
            AuditOutcome::Success,
        )
        .account(Some(&req.account_id))
        .region(Some(&req.region))
        .target(Some(&req.log_group_name))
        .optional_metadata(Some(filter_events_metadata(&audit_ctx, &req)))
        .commit_or_fail()
        .map_err(|_| {
            (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::internal(
                    "Audit logging failed — refusing to return data",
                )),
            )
        })?;

    Ok(Json(FilterLogEventsResponse {
        events,
        next_token: resp_next_token,
    }))
}

async fn start_insights_query(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    headers: HeaderMap,
    Json(req): Json<StartInsightsQueryRequest>,
) -> Result<Json<StartInsightsQueryResponse>, (axum::http::StatusCode, Json<ApiError>)> {
    require_audit_healthy(&state)?;
    let audit_ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);
    let ent_service = EntitlementService::new(state.entitlement_store.clone());
    let entitlements = ent_service.evaluate(&claims).await;

    if !ent_service
        .has_feature_for_scope(
            &claims,
            &req.account_id,
            Some(&req.region),
            None,
            None,
            |f| f.can_use_cloudwatch_search,
        )
        .await
    {
        state
            .audit_service
            .event(
                &claims.sub,
                AuditAction::CloudwatchInsightsQuery,
                AuditOutcome::Denied,
            )
            .account(Some(&req.account_id))
            .region(Some(&req.region))
            .error(Some("CloudWatch search not authorized"))
            .optional_metadata(Some(insights_query_metadata(&audit_ctx, &req)))
            .commit_best_effort();
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("CloudWatch search not authorized")),
        ));
    }

    // Enforce account entitlement
    if !entitlements
        .allowed_accounts
        .iter()
        .any(|a| a.account_id == req.account_id)
    {
        state
            .audit_service
            .event(
                &claims.sub,
                AuditAction::CloudwatchInsightsQuery,
                AuditOutcome::Denied,
            )
            .account(Some(&req.account_id))
            .region(Some(&req.region))
            .error(Some("Account not authorized"))
            .optional_metadata(Some(insights_query_metadata(&audit_ctx, &req)))
            .commit_best_effort();
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("Account not authorized")),
        ));
    }

    // Enforce region entitlement
    if !entitlements.allowed_regions.contains(&req.region) {
        state
            .audit_service
            .event(
                &claims.sub,
                AuditAction::CloudwatchInsightsQuery,
                AuditOutcome::Denied,
            )
            .account(Some(&req.account_id))
            .region(Some(&req.region))
            .error(Some("Region not authorized"))
            .optional_metadata(Some(insights_query_metadata(&audit_ctx, &req)))
            .commit_best_effort();
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("Region not authorized")),
        ));
    }

    // Enforce log-group ARN entitlements using scope-aware patterns
    // Reject empty log_group_names to prevent bypass via SOURCE in query_string
    if req.log_group_names.is_empty() {
        state
            .audit_service
            .event(
                &claims.sub,
                AuditAction::CloudwatchInsightsQuery,
                AuditOutcome::Failure,
            )
            .account(Some(&req.account_id))
            .region(Some(&req.region))
            .error(Some("log_group_names must not be empty"))
            .optional_metadata(Some(insights_query_metadata(&audit_ctx, &req)))
            .commit_best_effort();
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request(
                "log_group_names must not be empty — specify at least one log group",
            )),
        ));
    }

    let scoped_log_arns = ent_service
        .allowed_log_group_arns_for_scope(&claims, &req.account_id, &req.region, |f| {
            f.can_use_cloudwatch_search
        })
        .await;
    if !scoped_log_arns.is_empty() {
        for lg_name in &req.log_group_names {
            let lg_arns = log_group_arn_variants(&req.region, &req.account_id, lg_name);
            if !log_group_matches_patterns(&scoped_log_arns, &lg_arns) {
                state
                    .audit_service
                    .event(
                        &claims.sub,
                        AuditAction::CloudwatchInsightsQuery,
                        AuditOutcome::Denied,
                    )
                    .account(Some(&req.account_id))
                    .region(Some(&req.region))
                    .target(Some(lg_name))
                    .error(Some("Log group not authorized"))
                    .optional_metadata(Some(insights_query_metadata(&audit_ctx, &req)))
                    .commit_best_effort();
                return Err((
                    axum::http::StatusCode::FORBIDDEN,
                    Json(ApiError::forbidden(format!(
                        "Log group '{}' not authorized",
                        lg_name
                    ))),
                ));
            }
        }
    }

    // Write audit BEFORE launching StartQuery to prevent orphaned unaudited queries
    state
        .audit_service
        .event(
            &claims.sub,
            AuditAction::CloudwatchInsightsQuery,
            AuditOutcome::Success,
        )
        .account(Some(&req.account_id))
        .region(Some(&req.region))
        .target(Some(&req.log_group_names.join(",")))
        .optional_metadata(Some(insights_query_metadata(&audit_ctx, &req)))
        .commit_or_fail()
        .map_err(|_| {
            (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::internal(
                    "Audit logging failed — refusing to start query",
                )),
            )
        })?;

    let query_id = if state.config.use_mock_aws() {
        uuid::Uuid::new_v4().to_string()
    } else {
        // Production: call StartQuery via AWS SDK
        let client = get_cwl_client_for_account(
            &state,
            &entitlements,
            &req.account_id,
            &req.region,
            &claims.sub,
        )
        .await?;

        let mut start = client
            .start_query()
            .query_string(&req.query_string)
            .start_time(req.start_time)
            .end_time(req.end_time);

        for lg_name in &req.log_group_names {
            start = start.log_group_names(lg_name);
        }

        let resp = start.send().await.map_err(|e| {
            let service_error = e.as_service_error();
            let is_invalid_parameter = service_error
                .map(|err| err.is_invalid_parameter_exception())
                .unwrap_or(false);
            let aws_message = service_error
                .and_then(|err| err.meta().message())
                .unwrap_or("service error");
            tracing::error!("start_query failed: {e}");
            state
                .audit_service
                .event(
                    &claims.sub,
                    AuditAction::CloudwatchInsightsQuery,
                    AuditOutcome::Failure,
                )
                .account(Some(&req.account_id))
                .region(Some(&req.region))
                .target(Some(&req.log_group_names.join(",")))
                .error(Some(if is_invalid_parameter {
                    "Invalid CloudWatch Insights query"
                } else {
                    "AWS StartQuery failed"
                }))
                .optional_metadata(Some(insights_query_metadata(&audit_ctx, &req)))
                .commit_best_effort();
            if is_invalid_parameter {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(ApiError::bad_request(format!(
                        "Invalid CloudWatch Insights query: {aws_message}"
                    ))),
                )
            } else {
                (
                    axum::http::StatusCode::BAD_GATEWAY,
                    Json(ApiError::internal(format!(
                        "AWS StartQuery failed: {aws_message}"
                    ))),
                )
            }
        })?;

        resp.query_id()
            .ok_or_else(|| {
                state
                    .audit_service
                    .event(
                        &claims.sub,
                        AuditAction::CloudwatchInsightsQuery,
                        AuditOutcome::Failure,
                    )
                    .account(Some(&req.account_id))
                    .region(Some(&req.region))
                    .target(Some(&req.log_group_names.join(",")))
                    .error(Some("AWS StartQuery returned no query_id"))
                    .optional_metadata(Some(insights_query_metadata(&audit_ctx, &req)))
                    .commit_best_effort();
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiError::internal("AWS StartQuery returned no query_id")),
                )
            })?
            .to_string()
    };

    // Encode authorization into a signed token so it survives restarts.
    // The client receives this as the "query_id" and sends it back on poll.
    let auth = crate::services::QueryAuthorization {
        user_id: claims.sub.clone(),
        log_group_names: req.log_group_names.clone(),
    };
    let signed_query_id =
        crate::services::sign_query_token(&query_id, &auth, &state.config.jwt.secret);

    Ok(Json(StartInsightsQueryResponse {
        query_id: signed_query_id,
    }))
}

async fn get_query_results(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    headers: HeaderMap,
    Json(req): Json<GetQueryResultsRequest>,
) -> Result<Json<GetQueryResultsResponse>, (axum::http::StatusCode, Json<ApiError>)> {
    require_audit_healthy(&state)?;
    let audit_ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);
    let ent_service = EntitlementService::new(state.entitlement_store.clone());
    let entitlements = ent_service.evaluate(&claims).await;

    if !ent_service
        .has_feature_for_scope(
            &claims,
            &req.account_id,
            Some(&req.region),
            None,
            None,
            |f| f.can_use_cloudwatch_search,
        )
        .await
    {
        state
            .audit_service
            .event(
                &claims.sub,
                AuditAction::CloudwatchInsightsQuery,
                AuditOutcome::Denied,
            )
            .account(Some(&req.account_id))
            .region(Some(&req.region))
            .target(Some(&req.query_id))
            .error(Some("CloudWatch search not authorized for this scope"))
            .optional_metadata(Some(query_results_metadata(&audit_ctx, &req)))
            .commit_best_effort();
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden(
                "CloudWatch search not authorized for this scope",
            )),
        ));
    }

    if !entitlements
        .allowed_accounts
        .iter()
        .any(|a| a.account_id == req.account_id)
    {
        state
            .audit_service
            .event(
                &claims.sub,
                AuditAction::CloudwatchInsightsQuery,
                AuditOutcome::Denied,
            )
            .account(Some(&req.account_id))
            .region(Some(&req.region))
            .target(Some(&req.query_id))
            .error(Some("Account not authorized"))
            .optional_metadata(Some(query_results_metadata(&audit_ctx, &req)))
            .commit_best_effort();
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("Account not authorized")),
        ));
    }

    if !entitlements.allowed_regions.contains(&req.region) {
        state
            .audit_service
            .event(
                &claims.sub,
                AuditAction::CloudwatchInsightsQuery,
                AuditOutcome::Denied,
            )
            .account(Some(&req.account_id))
            .region(Some(&req.region))
            .target(Some(&req.query_id))
            .error(Some("Region not authorized"))
            .optional_metadata(Some(query_results_metadata(&audit_ctx, &req)))
            .commit_best_effort();
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("Region not authorized")),
        ));
    }

    // Verify query authorization via signed token (survives restarts).
    // The query_id from the client is a signed compound token:
    // {aws_query_id}.{base64(auth)}.{hmac}
    // With mock data, the query_id is a plain UUID — skip verification.
    let real_query_id = if state.config.use_mock_aws() {
        req.query_id.clone()
    } else {
        // Try signed token first, then in-memory map as fallback
        match crate::services::verify_query_token(&req.query_id, &state.config.jwt.secret) {
            Some((aws_qid, auth)) => {
                if auth.user_id != claims.sub {
                    state
                        .audit_service
                        .event(
                            &claims.sub,
                            AuditAction::CloudwatchInsightsQuery,
                            AuditOutcome::Denied,
                        )
                        .account(Some(&req.account_id))
                        .region(Some(&req.region))
                        .target(Some(&req.query_id))
                        .error(Some("Query was started by a different user"))
                        .optional_metadata(Some(query_results_metadata(&audit_ctx, &req)))
                        .commit_best_effort();
                    return Err((
                        axum::http::StatusCode::FORBIDDEN,
                        Json(ApiError::forbidden("Query was started by a different user")),
                    ));
                }
                // Re-verify log group entitlements using scope-aware patterns
                let scoped_arns = ent_service
                    .allowed_log_group_arns_for_scope(&claims, &req.account_id, &req.region, |f| {
                        f.can_use_cloudwatch_search
                    })
                    .await;
                if !scoped_arns.is_empty() {
                    for lg_name in &auth.log_group_names {
                        let lg_arns = log_group_arn_variants(&req.region, &req.account_id, lg_name);
                        if !log_group_matches_patterns(&scoped_arns, &lg_arns) {
                            state
                                .audit_service
                                .event(
                                    &claims.sub,
                                    AuditAction::CloudwatchInsightsQuery,
                                    AuditOutcome::Denied,
                                )
                                .account(Some(&req.account_id))
                                .region(Some(&req.region))
                                .target(Some(lg_name))
                                .error(Some("Access to log group has been revoked"))
                                .optional_metadata(Some(query_results_metadata(&audit_ctx, &req)))
                                .commit_best_effort();
                            return Err((
                                axum::http::StatusCode::FORBIDDEN,
                                Json(ApiError::forbidden(format!(
                                    "Access to log group '{}' has been revoked",
                                    lg_name
                                ))),
                            ));
                        }
                    }
                }
                aws_qid
            }
            None => {
                state
                    .audit_service
                    .event(
                        &claims.sub,
                        AuditAction::CloudwatchInsightsQuery,
                        AuditOutcome::Denied,
                    )
                    .account(Some(&req.account_id))
                    .region(Some(&req.region))
                    .target(Some(&req.query_id))
                    .error(Some("Invalid or tampered query authorization token"))
                    .optional_metadata(Some(query_results_metadata(&audit_ctx, &req)))
                    .commit_best_effort();
                return Err((
                    axum::http::StatusCode::FORBIDDEN,
                    Json(ApiError::forbidden(
                        "Invalid or tampered query authorization token",
                    )),
                ));
            }
        }
    };

    if state.config.use_mock_aws() {
        // Dev mode: return hardcoded mock results
        Ok(Json(GetQueryResultsResponse {
            status: QueryStatus::Complete,
            results: vec![
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
            ],
            statistics: Some(QueryStatistics {
                records_matched: 2.0,
                records_scanned: 1000.0,
                bytes_scanned: 524288.0,
            }),
        }))
    } else {
        // Production: call GetQueryResults via AWS SDK
        let client = get_cwl_client_for_account(
            &state,
            &entitlements,
            &req.account_id,
            &req.region,
            &claims.sub,
        )
        .await?;

        let resp = client
            .get_query_results()
            .query_id(&real_query_id)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("get_query_results failed: {e}");
                state
                    .audit_service
                    .event(
                        &claims.sub,
                        AuditAction::CloudwatchInsightsQuery,
                        AuditOutcome::Failure,
                    )
                    .account(Some(&req.account_id))
                    .region(Some(&req.region))
                    .target(Some(&req.query_id))
                    .error(Some("AWS GetQueryResults failed"))
                    .optional_metadata(Some(query_results_metadata(&audit_ctx, &req)))
                    .commit_best_effort();
                (
                    axum::http::StatusCode::BAD_GATEWAY,
                    Json(ApiError::internal(format!(
                        "AWS GetQueryResults failed: {e}"
                    ))),
                )
            })?;

        let status = match resp.status() {
            Some(s) => match s {
                aws_sdk_cloudwatchlogs::types::QueryStatus::Scheduled => QueryStatus::Scheduled,
                aws_sdk_cloudwatchlogs::types::QueryStatus::Running => QueryStatus::Running,
                aws_sdk_cloudwatchlogs::types::QueryStatus::Complete => QueryStatus::Complete,
                aws_sdk_cloudwatchlogs::types::QueryStatus::Failed => QueryStatus::Failed,
                aws_sdk_cloudwatchlogs::types::QueryStatus::Cancelled => QueryStatus::Cancelled,
                aws_sdk_cloudwatchlogs::types::QueryStatus::Timeout => QueryStatus::Timeout,
                _ => QueryStatus::Unknown,
            },
            None => QueryStatus::Unknown,
        };

        let results: Vec<Vec<QueryResultField>> = resp
            .results()
            .iter()
            .map(|row| {
                row.iter()
                    .map(|field| QueryResultField {
                        field: field.field().unwrap_or_default().to_string(),
                        value: field.value().unwrap_or_default().to_string(),
                    })
                    .collect()
            })
            .collect();

        let statistics = resp.statistics().map(|s| QueryStatistics {
            records_matched: s.records_matched(),
            records_scanned: s.records_scanned(),
            bytes_scanned: s.bytes_scanned(),
        });

        Ok(Json(GetQueryResultsResponse {
            status,
            results,
            statistics,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_group_arn_variants_include_cloudwatch_describe_suffix() {
        assert_eq!(
            log_group_arn_variants("ap-northeast-1", "123456789012", "/app/web-service"),
            vec![
                "arn:aws:logs:ap-northeast-1:123456789012:log-group:/app/web-service".to_string(),
                "arn:aws:logs:ap-northeast-1:123456789012:log-group:/app/web-service:*".to_string(),
            ]
        );
    }

    #[test]
    fn log_group_patterns_match_describe_arn_suffix() {
        let patterns = vec![
            "arn:aws:logs:ap-northeast-1:123456789012:log-group:/app/web-service:*".to_string(),
        ];
        let variants = log_group_arn_variants("ap-northeast-1", "123456789012", "/app/web-service");

        assert!(log_group_matches_patterns(&patterns, &variants));
    }
}
