use aws_credential_types::provider::ProvideCredentials;
use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
use std::sync::Arc;

use crate::aws::clients::AwsClients;
use crate::aws::credentials::{
    assume_role_scoped, ecs_exec_session_policy, resolve_aws_config, SessionContext,
};
use crate::middleware::auth::AuthenticatedUser;
use crate::services::audit::AuditRequestContext;
use crate::services::ecs::{
    build_ecs_exec_command, cluster_arn, cluster_name_from_arn, convert_sdk_task,
    ecs_arn_region_account, ecs_status_is_running, filter_tasks_by_entitlements,
    matching_rule_scopes, mock_tasks, AssumedRoleCredentials,
};
use crate::services::entitlements::EntitlementService;
use crate::services::AppState;
use shared::dto::audit::{AuditAction, AuditOutcome};
use shared::dto::ecs::*;
use shared::dto::entitlements::AllowedAccount;
use shared::errors::ApiError;

pub(crate) const MAX_CLUSTERS_PER_REQUEST: usize = 10;
pub(crate) const MAX_TASKS_PER_CLUSTER: usize = 50;
pub(crate) const MAX_TASKS_PER_RESPONSE: usize = 200;
const DEFAULT_TASKS_PAGE_SIZE: usize = 50;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/ecs/tasks", post(list_tasks))
        .route("/api/ecs/exec", post(exec_task))
}

struct RequiredIamSimulation {
    action: &'static str,
    resources: Vec<String>,
}

fn iam_string_context_entry(name: &str, value: &str) -> aws_sdk_iam::types::ContextEntry {
    aws_sdk_iam::types::ContextEntry::builder()
        .context_key_name(name)
        .context_key_values(value)
        .context_key_type(aws_sdk_iam::types::ContextKeyTypeEnum::String)
        .build()
}

fn ecs_exec_simulation_context(req: &EcsExecRequest) -> Vec<aws_sdk_iam::types::ContextEntry> {
    vec![
        iam_string_context_entry("aws:RequestedRegion", &req.region),
        iam_string_context_entry("ecs:cluster", &req.cluster_arn),
        iam_string_context_entry("ecs:container-name", &req.container_name),
    ]
}

fn required_ecs_exec_simulations(req: &EcsExecRequest) -> Vec<RequiredIamSimulation> {
    vec![
        RequiredIamSimulation {
            action: "ecs:ExecuteCommand",
            resources: vec![req.task_arn.clone()],
        },
        RequiredIamSimulation {
            action: "ecs:DescribeTasks",
            resources: vec!["*".into()],
        },
        RequiredIamSimulation {
            action: "ssmmessages:CreateControlChannel",
            resources: vec!["*".into()],
        },
        RequiredIamSimulation {
            action: "ssmmessages:CreateDataChannel",
            resources: vec!["*".into()],
        },
        RequiredIamSimulation {
            action: "ssmmessages:OpenControlChannel",
            resources: vec!["*".into()],
        },
        RequiredIamSimulation {
            action: "ssmmessages:OpenDataChannel",
            resources: vec!["*".into()],
        },
    ]
}

fn ecs_task_list_metadata(
    ctx: &AuditRequestContext,
    req: &EcsTasksRequest,
    clusters_returned: Option<usize>,
    tasks_returned: Option<usize>,
    truncated: Option<bool>,
    failed_scopes: &[String],
    broad_discovery: bool,
) -> serde_json::Value {
    ctx.metadata(serde_json::json!({
        "clusters_filter": req.cluster.as_deref(),
        "page_size": req.page_size,
        "clusters_returned": clusters_returned,
        "tasks_returned": tasks_returned,
        "truncated": truncated,
        "failed_scopes": failed_scopes,
        "broad_discovery": broad_discovery,
    }))
}

fn ecs_exec_metadata(
    ctx: &AuditRequestContext,
    req: &EcsExecRequest,
    launch_type: Option<&str>,
    error_kind: Option<&str>,
) -> serde_json::Value {
    ctx.metadata(serde_json::json!({
        "cluster_name": cluster_name_from_arn(&req.cluster_arn),
        "cluster_arn": &req.cluster_arn,
        "task_arn": &req.task_arn,
        "container_name": &req.container_name,
        "launch_type": launch_type,
        "broad_discovery": false,
        "error_kind": error_kind,
    }))
}

fn requested_cluster_for_account_region(
    req: &EcsTasksRequest,
    account_id: &str,
    region: &str,
) -> Option<String> {
    req.cluster.as_ref().map(|cluster| {
        if cluster.starts_with("arn:") {
            cluster.clone()
        } else {
            cluster_arn(region, account_id, cluster)
        }
    })
}

fn requested_tasks_page_size(page_size: u32) -> usize {
    let requested = if page_size == 0 {
        DEFAULT_TASKS_PAGE_SIZE
    } else {
        page_size as usize
    };
    requested.min(MAX_TASKS_PER_RESPONSE)
}

fn authorized_cluster_refs(
    cluster_refs: Vec<String>,
    allowed_cluster_patterns: &[String],
) -> (Vec<String>, bool) {
    let mut refs = cluster_refs
        .into_iter()
        .filter(|cluster| {
            allowed_cluster_patterns
                .iter()
                .any(|pattern| crate::services::ecs::cluster_matches_pattern(pattern, cluster))
        })
        .collect::<Vec<_>>();
    let truncated = refs.len() > MAX_CLUSTERS_PER_REQUEST;
    refs.truncate(MAX_CLUSTERS_PER_REQUEST);
    (refs, truncated)
}

fn scope_applies_to_account_region(
    scope: &crate::services::ecs::EcsRuleScope,
    account_id: &str,
    region: &str,
) -> bool {
    scope
        .account_ids
        .iter()
        .any(|account| account == account_id)
        && (scope.regions.is_empty()
            || scope
                .regions
                .iter()
                .any(|scope_region| scope_region == region))
}

fn cluster_pattern_applies_to_account_region(
    pattern: &str,
    account_id: &str,
    region: &str,
) -> bool {
    ecs_arn_region_account(pattern).map_or(true, |(pattern_region, pattern_account)| {
        (pattern_region == "*" || pattern_region == region)
            && (pattern_account == "*" || pattern_account == account_id)
    })
}

fn cluster_patterns_for_account_region(
    rule_scopes: &[crate::services::ecs::EcsRuleScope],
    account_id: &str,
    region: &str,
) -> Vec<String> {
    let mut patterns = Vec::new();
    for scope in rule_scopes {
        if !scope_applies_to_account_region(scope, account_id, region) {
            continue;
        }
        for pattern in &scope.cluster_patterns {
            if !cluster_pattern_applies_to_account_region(pattern, account_id, region) {
                continue;
            }
            if !patterns.contains(pattern) {
                patterns.push(pattern.clone());
            }
        }
    }
    patterns
}

fn cluster_ref_authorized(
    rule_scopes: &[crate::services::ecs::EcsRuleScope],
    account_id: &str,
    region: &str,
    cluster_ref: &str,
) -> bool {
    cluster_patterns_for_account_region(rule_scopes, account_id, region)
        .iter()
        .any(|pattern| crate::services::ecs::cluster_matches_pattern(pattern, cluster_ref))
}

fn concrete_cluster_pattern_regions(
    rule_scopes: &[crate::services::ecs::EcsRuleScope],
    account_id: &str,
) -> Vec<String> {
    let mut regions = std::collections::BTreeSet::new();
    for scope in rule_scopes {
        if !scope.account_ids.iter().any(|id| id == account_id) {
            continue;
        }
        for pattern in &scope.cluster_patterns {
            let Some((region, account)) = ecs_arn_region_account(pattern) else {
                continue;
            };
            if region != "*" && (account == account_id || account == "*") {
                regions.insert(region.to_string());
            }
        }
    }
    regions.into_iter().collect()
}

fn cluster_request_matches_any_rule_scope(
    req: &EcsTasksRequest,
    rule_scopes: &[crate::services::ecs::EcsRuleScope],
) -> bool {
    rule_scopes.iter().any(|scope| {
        let account_ids = if let Some(account_id) = req.account_id.as_deref() {
            if !scope
                .account_ids
                .iter()
                .any(|scope_account| scope_account == account_id)
            {
                return false;
            }
            vec![account_id.to_string()]
        } else {
            scope.account_ids.clone()
        };

        let regions = if let Some(region) = req.region.as_deref() {
            if !scope.regions.is_empty()
                && !scope
                    .regions
                    .iter()
                    .any(|scope_region| scope_region == region)
            {
                return false;
            }
            vec![region.to_string()]
        } else if scope.regions.is_empty() {
            let mut concrete_regions = Vec::new();
            for account_id in &account_ids {
                for region in
                    concrete_cluster_pattern_regions(std::slice::from_ref(scope), account_id)
                {
                    if !concrete_regions.contains(&region) {
                        concrete_regions.push(region);
                    }
                }
            }
            if concrete_regions.is_empty() {
                vec!["*".to_string()]
            } else {
                concrete_regions
            }
        } else {
            scope.regions.clone()
        };

        let Some(cluster) = req.cluster.as_deref() else {
            return true;
        };

        if let Some((cluster_region, cluster_account)) = cluster
            .starts_with("arn:")
            .then(|| ecs_arn_region_account(cluster))
            .flatten()
        {
            return account_ids
                .iter()
                .any(|account_id| account_id == cluster_account)
                && regions
                    .iter()
                    .any(|region| region == "*" || region == cluster_region)
                && scope.cluster_patterns.iter().any(|pattern| {
                    crate::services::ecs::cluster_matches_pattern(pattern, cluster)
                });
        }

        for account_id in &account_ids {
            for region in &regions {
                let cluster_ref = cluster_arn(region, account_id, cluster);
                if scope.cluster_patterns.iter().any(|pattern| {
                    crate::services::ecs::cluster_matches_pattern(pattern, &cluster_ref)
                }) {
                    return true;
                }
            }
        }
        false
    })
}

fn validate_tasks_request_scope(
    req: &EcsTasksRequest,
    rule_scopes: &[crate::services::ecs::EcsRuleScope],
) -> Result<(), (axum::http::StatusCode, Json<ApiError>)> {
    if let Some(cluster) = req
        .cluster
        .as_deref()
        .filter(|cluster| cluster.starts_with("arn:"))
    {
        let Some((cluster_region, cluster_account)) = ecs_arn_region_account(cluster) else {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                Json(ApiError::bad_request("Invalid ECS cluster ARN")),
            ));
        };
        if req
            .account_id
            .as_deref()
            .is_some_and(|account| account != cluster_account)
        {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                Json(ApiError::bad_request(
                    "Cluster ARN account does not match request account",
                )),
            ));
        }
        if req
            .region
            .as_deref()
            .is_some_and(|region| region != cluster_region)
        {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                Json(ApiError::bad_request(
                    "Cluster ARN region does not match request region",
                )),
            ));
        }
    }

    if cluster_request_matches_any_rule_scope(req, rule_scopes) {
        Ok(())
    } else {
        Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("ECS task scope not authorized")),
        ))
    }
}

fn task_matches_request_filters(task: &EcsTask, req: &EcsTasksRequest) -> bool {
    if let Some(account_id) = &req.account_id {
        if task.account_id != *account_id {
            return false;
        }
    }
    if let Some(region) = &req.region {
        if task.region != *region {
            return false;
        }
    }
    if let Some(cluster) = &req.cluster {
        if cluster.starts_with("arn:") {
            if task.cluster_arn != *cluster {
                return false;
            }
        } else if task.cluster_name != *cluster {
            return false;
        }
    }
    true
}

fn is_local_credential_mode(account: &AllowedAccount) -> bool {
    account.role_arn == "direct" || account.role_arn.starts_with("profile:")
}

fn first_assumable_account(accounts: &[AllowedAccount]) -> Option<AllowedAccount> {
    accounts
        .iter()
        .find(|account| !is_local_credential_mode(account))
        .cloned()
}

fn session_context(
    state: &AppState,
    entitlements: &shared::dto::entitlements::UserEntitlements,
) -> SessionContext {
    SessionContext {
        user_id: entitlements.user_id.clone(),
        team: entitlements
            .groups
            .first()
            .cloned()
            .unwrap_or_else(|| "unknown".to_string()),
        environment: state
            .config
            .aws
            .default_region
            .clone()
            .unwrap_or_else(|| "production".to_string()),
        session_duration_seconds: state.config.aws.session_duration_seconds,
        sts_external_id: state.config.aws.sts_external_id.clone(),
    }
}

fn effective_task_fetch_regions(
    req: &EcsTasksRequest,
    rule_regions: &[String],
    cluster_pattern_regions: &[String],
    default_region: String,
) -> Vec<String> {
    if let Some(region) = req.region.as_ref() {
        vec![region.clone()]
    } else if let Some((cluster_region, _)) = req
        .cluster
        .as_deref()
        .filter(|cluster| cluster.starts_with("arn:"))
        .and_then(ecs_arn_region_account)
    {
        vec![cluster_region.to_string()]
    } else if !rule_regions.is_empty() {
        rule_regions.to_vec()
    } else if !cluster_pattern_regions.is_empty() {
        cluster_pattern_regions.to_vec()
    } else {
        vec![default_region]
    }
}

fn rule_scopes_for_account_role(
    rule_scopes: &[crate::services::ecs::EcsRuleScope],
    account: &AllowedAccount,
) -> Vec<crate::services::ecs::EcsRuleScope> {
    rule_scopes
        .iter()
        .filter(|scope| {
            scope.accounts.iter().any(|scope_account| {
                scope_account.account_id == account.account_id
                    && scope_account.role_arn == account.role_arn
            })
        })
        .cloned()
        .collect()
}

async fn fetch_tasks_from_aws(
    state: &AppState,
    entitlements: &shared::dto::entitlements::UserEntitlements,
    scoped_account_regions: &[(AllowedAccount, Vec<String>)],
    rule_scopes: &[crate::services::ecs::EcsRuleScope],
    req: &EcsTasksRequest,
) -> Result<(Vec<EcsTask>, Vec<String>, bool), (axum::http::StatusCode, Json<ApiError>)> {
    let session_ctx = session_context(state, entitlements);
    let mut handles = Vec::new();

    for (account, rule_regions) in scoped_account_regions {
        if let Some(filter_account) = req.account_id.as_deref() {
            if account.account_id != filter_account {
                continue;
            }
        }

        let scoped_rule_scopes = rule_scopes_for_account_role(rule_scopes, account);
        if scoped_rule_scopes.is_empty() {
            continue;
        }

        let default_region = state
            .config
            .aws
            .default_region
            .clone()
            .unwrap_or_else(|| "us-east-1".to_string());
        let cluster_pattern_regions =
            concrete_cluster_pattern_regions(&scoped_rule_scopes, &account.account_id);
        let effective_regions = effective_task_fetch_regions(
            req,
            rule_regions,
            &cluster_pattern_regions,
            default_region,
        );

        for region in effective_regions {
            let requested_cluster =
                requested_cluster_for_account_region(req, &account.account_id, &region);
            if let Some(cluster_ref) = requested_cluster.as_deref() {
                if !cluster_ref_authorized(
                    &scoped_rule_scopes,
                    &account.account_id,
                    &region,
                    cluster_ref,
                ) {
                    continue;
                }
            }

            let allowed_cluster_patterns = cluster_patterns_for_account_region(
                &scoped_rule_scopes,
                &account.account_id,
                &region,
            );
            if allowed_cluster_patterns.is_empty() {
                continue;
            }
            let concrete_cluster_refs = allowed_cluster_patterns
                .iter()
                .filter(|pattern| !pattern.contains('*'))
                .cloned()
                .collect::<Vec<_>>();
            let must_discover_clusters = requested_cluster.is_none()
                && concrete_cluster_refs.len() != allowed_cluster_patterns.len();

            let account = account.clone();
            let base_config = state.base_aws_config.clone();
            let session_ctx = SessionContext {
                user_id: session_ctx.user_id.clone(),
                team: session_ctx.team.clone(),
                environment: session_ctx.environment.clone(),
                session_duration_seconds: session_ctx.session_duration_seconds,
                sts_external_id: session_ctx.sts_external_id.clone(),
            };
            handles.push(tokio::spawn(async move {
                let config =
                    resolve_aws_config(&base_config, &account, &region, &session_ctx).await?;
                let ecs = AwsClients::ecs(&config);

                let (cluster_refs, clusters_truncated) = if let Some(cluster) = requested_cluster {
                    (vec![cluster], false)
                } else if !must_discover_clusters {
                    (concrete_cluster_refs, false)
                } else {
                    let resp = ecs
                        .list_clusters()
                        .max_results(MAX_CLUSTERS_PER_REQUEST as i32)
                        .send()
                        .await?;
                    let cluster_refs = resp
                        .cluster_arns()
                        .iter()
                        .take(MAX_CLUSTERS_PER_REQUEST)
                        .map(ToString::to_string)
                        .collect::<Vec<_>>();
                    (cluster_refs, resp.next_token().is_some())
                };

                let (cluster_refs, cluster_cap_truncated) =
                    authorized_cluster_refs(cluster_refs, &allowed_cluster_patterns);

                let mut tasks = Vec::new();
                let mut truncated = clusters_truncated || cluster_cap_truncated;
                for cluster in cluster_refs {
                    let list_resp = ecs
                        .list_tasks()
                        .cluster(&cluster)
                        .desired_status(aws_sdk_ecs::types::DesiredStatus::Running)
                        .max_results(MAX_TASKS_PER_CLUSTER as i32)
                        .send()
                        .await?;
                    if list_resp.next_token().is_some() {
                        truncated = true;
                    }
                    let task_arns = list_resp
                        .task_arns()
                        .iter()
                        .take(MAX_TASKS_PER_CLUSTER)
                        .map(ToString::to_string)
                        .collect::<Vec<_>>();
                    if task_arns.is_empty() {
                        continue;
                    }

                    let describe_resp = ecs
                        .describe_tasks()
                        .cluster(&cluster)
                        .set_tasks(Some(task_arns))
                        .include(aws_sdk_ecs::types::TaskField::Tags)
                        .send()
                        .await?;
                    tasks.extend(
                        describe_resp
                            .tasks()
                            .iter()
                            .map(|task| convert_sdk_task(task, &account.account_id, &region)),
                    );
                    if tasks.len() >= MAX_TASKS_PER_RESPONSE {
                        truncated = true;
                        tasks.truncate(MAX_TASKS_PER_RESPONSE);
                        break;
                    }
                }

                Ok::<_, anyhow::Error>((tasks, truncated))
            }));
        }
    }

    let mut all_tasks = Vec::new();
    let mut failed_scopes = Vec::new();
    let mut truncated = false;
    for handle in handles {
        match handle.await {
            Ok(Ok((tasks, scope_truncated))) => {
                truncated |= scope_truncated;
                all_tasks.extend(tasks);
            }
            Ok(Err(err)) => {
                tracing::error!("Failed to fetch ECS tasks: {}", err);
                failed_scopes.push(err.to_string());
            }
            Err(err) => {
                tracing::error!("Task join error fetching ECS tasks: {}", err);
                failed_scopes.push(format!("task join error: {}", err));
            }
        }
    }

    if !failed_scopes.is_empty() && all_tasks.is_empty() {
        return Err((
            axum::http::StatusCode::BAD_GATEWAY,
            Json(ApiError::internal(format!(
                "All ECS fetch scopes failed: {}",
                failed_scopes.join("; ")
            ))),
        ));
    }

    Ok((all_tasks, failed_scopes, truncated))
}

async fn list_tasks(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    headers: HeaderMap,
    Json(req): Json<EcsTasksRequest>,
) -> Result<Json<EcsTasksResponse>, (axum::http::StatusCode, Json<ApiError>)> {
    if !state.audit_service.is_healthy() {
        return Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal("Audit logging unavailable")),
        ));
    }

    let audit_ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);
    let ent_service = EntitlementService::new(state.entitlement_store.clone());
    let entitlements = ent_service.evaluate(&claims).await;
    let rule_scopes = ent_service
        .ecs_rule_scopes_for_feature(&claims, |features| features.can_view_ecs)
        .await;
    let broad_discovery = rule_scopes
        .iter()
        .any(|scope| scope.allow_broad_cluster_discovery);

    if req.cluster.as_deref() == Some("*") {
        state
            .audit_service
            .event(&claims.sub, AuditAction::EcsTaskList, AuditOutcome::Denied)
            .account(req.account_id.as_deref())
            .region(req.region.as_deref())
            .error(Some("Cluster '*' is not allowed"))
            .optional_metadata(Some(ecs_task_list_metadata(
                &audit_ctx,
                &req,
                None,
                None,
                None,
                &[],
                broad_discovery,
            )))
            .commit_best_effort();
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request("Cluster '*' is not allowed")),
        ));
    }

    if !entitlements.features.can_view_ecs {
        state
            .audit_service
            .event(&claims.sub, AuditAction::EcsTaskList, AuditOutcome::Denied)
            .account(req.account_id.as_deref())
            .region(req.region.as_deref())
            .error(Some("ECS view not authorized"))
            .optional_metadata(Some(ecs_task_list_metadata(
                &audit_ctx,
                &req,
                None,
                None,
                None,
                &[],
                broad_discovery,
            )))
            .commit_best_effort();
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("ECS view not authorized")),
        ));
    }

    if let Err(err) = validate_tasks_request_scope(&req, &rule_scopes) {
        state
            .audit_service
            .event(&claims.sub, AuditAction::EcsTaskList, AuditOutcome::Denied)
            .account(req.account_id.as_deref())
            .region(req.region.as_deref())
            .error(Some(&err.1 .0.message))
            .optional_metadata(Some(ecs_task_list_metadata(
                &audit_ctx,
                &req,
                None,
                None,
                None,
                &[],
                broad_discovery,
            )))
            .commit_best_effort();
        return Err(err);
    }

    let scoped_accounts = ent_service
        .scoped_accounts_for_feature(&claims, |features| features.can_view_ecs)
        .await;
    let (all_tasks, failed_scopes, aws_truncated) = if state.config.use_mock_aws() {
        (mock_tasks(), vec![], false)
    } else {
        match fetch_tasks_from_aws(&state, &entitlements, &scoped_accounts, &rule_scopes, &req)
            .await
        {
            Ok(result) => result,
            Err(err) => {
                state
                    .audit_service
                    .event(&claims.sub, AuditAction::EcsTaskList, AuditOutcome::Failure)
                    .account(req.account_id.as_deref())
                    .region(req.region.as_deref())
                    .error(Some(&err.1 .0.message))
                    .optional_metadata(Some(ecs_task_list_metadata(
                        &audit_ctx,
                        &req,
                        None,
                        None,
                        None,
                        &[],
                        broad_discovery,
                    )))
                    .commit_best_effort();
                return Err(err);
            }
        }
    };

    let entitled = filter_tasks_by_entitlements(all_tasks, &entitlements, &rule_scopes);
    let filtered = entitled
        .into_iter()
        .filter(|task| task_matches_request_filters(task, &req))
        .collect::<Vec<_>>();
    let total_count = filtered.len();
    let page_size = requested_tasks_page_size(req.page_size);
    let truncated = aws_truncated || total_count > page_size;
    let tasks = filtered.into_iter().take(page_size).collect::<Vec<_>>();

    state
        .audit_service
        .event(&claims.sub, AuditAction::EcsTaskList, AuditOutcome::Success)
        .account(req.account_id.as_deref())
        .region(req.region.as_deref())
        .target(req.cluster.as_deref())
        .optional_metadata(Some(ecs_task_list_metadata(
            &audit_ctx,
            &req,
            Some(
                tasks
                    .iter()
                    .map(|task| task.cluster_arn.clone())
                    .collect::<std::collections::HashSet<_>>()
                    .len(),
            ),
            Some(tasks.len()),
            Some(truncated),
            &failed_scopes,
            broad_discovery,
        )))
        .commit_or_fail()
        .map_err(|_| {
            (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::internal(
                    "Audit logging failed — refusing to return data",
                )),
            )
        })?;

    Ok(Json(EcsTasksResponse {
        tasks,
        total_count,
        truncated,
        failed_scopes,
    }))
}

fn validate_task_request_arn(
    req: &EcsExecRequest,
) -> Result<(), (axum::http::StatusCode, Json<ApiError>)> {
    match ecs_arn_region_account(&req.task_arn) {
        Some((region, account)) if region == req.region && account == req.account_id => {}
        Some((_region, _account)) => {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                Json(ApiError::bad_request(
                    "Task ARN account or region does not match request",
                )),
            ));
        }
        None => {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                Json(ApiError::bad_request("Invalid ECS task ARN")),
            ));
        }
    }

    match ecs_arn_region_account(&req.cluster_arn) {
        Some((region, account)) if region == req.region && account == req.account_id => Ok(()),
        Some((_region, _account)) => Err((
            axum::http::StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request(
                "Cluster ARN account or region does not match request",
            )),
        )),
        None => Err((
            axum::http::StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request("Invalid ECS cluster ARN")),
        )),
    }
}

fn validate_task_for_exec(
    task: &EcsTask,
    req: &EcsExecRequest,
) -> Result<(), (&'static str, axum::http::StatusCode, String)> {
    if task.task_arn != req.task_arn {
        return Err((
            "task_not_found",
            axum::http::StatusCode::NOT_FOUND,
            "Task not found".into(),
        ));
    }
    if !ecs_status_is_running(&task.last_status) {
        return Err((
            "task_not_running",
            axum::http::StatusCode::NOT_FOUND,
            "Task is not running".into(),
        ));
    }
    if !task.enable_execute_command {
        return Err((
            "execute_command_disabled",
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "ECS Exec is not enabled for this task".into(),
        ));
    }
    let Some(container) = task
        .containers
        .iter()
        .find(|container| container.name == req.container_name)
    else {
        return Err((
            "container_not_found",
            axum::http::StatusCode::NOT_FOUND,
            "Container not found in task".into(),
        ));
    };
    if !ecs_status_is_running(&container.last_status) {
        return Err((
            "container_not_running",
            axum::http::StatusCode::NOT_FOUND,
            "Container is not running".into(),
        ));
    }
    if !container.execute_command_agent_running {
        return Err((
            "execute_command_agent_not_running",
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "ECS execute-command agent is not running".into(),
        ));
    }
    Ok(())
}

fn container_eligible_rule_scopes<'a>(
    matching_scopes: &[&'a crate::services::ecs::EcsRuleScope],
    container_name: &str,
) -> Vec<&'a crate::services::ecs::EcsRuleScope> {
    matching_scopes
        .iter()
        .copied()
        .filter(|scope| {
            !scope
                .excluded_container_names
                .iter()
                .any(|excluded| excluded == container_name)
        })
        .collect()
}

async fn select_account_for_exec(
    state: &AppState,
    accounts: Vec<AllowedAccount>,
    req: &EcsExecRequest,
) -> Result<AllowedAccount, (axum::http::StatusCode, Json<ApiError>)> {
    let matching = accounts
        .into_iter()
        .filter(|account| account.account_id == req.account_id)
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("Account not authorized")),
        ));
    }

    if state.config.use_mock_aws() {
        return Ok(matching.into_iter().next().unwrap());
    }

    let Some(first_assumable) = first_assumable_account(&matching) else {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden(
                "ECS Exec requires an AssumeRole ARN, not direct/profile credentials",
            )),
        ));
    };

    let iam_client = aws_sdk_iam::Client::new(&state.base_aws_config);
    let simulation_context = ecs_exec_simulation_context(req);
    let mut all_sim_errored = true;
    for candidate in &matching {
        if is_local_credential_mode(candidate) {
            continue;
        }

        let mut allowed = true;
        let mut candidate_sim_errored = false;
        for required in required_ecs_exec_simulations(req) {
            let mut sim = iam_client
                .simulate_principal_policy()
                .policy_source_arn(&candidate.role_arn)
                .action_names(required.action);
            for resource in &required.resources {
                sim = sim.resource_arns(resource);
            }
            for context_entry in &simulation_context {
                sim = sim.context_entries(context_entry.clone());
            }
            match sim.send().await {
                Ok(sim_resp) => {
                    all_sim_errored = false;
                    let action_allowed = sim_resp.evaluation_results().iter().all(|result| {
                        matches!(
                            result.eval_decision(),
                            aws_sdk_iam::types::PolicyEvaluationDecisionType::Allowed
                        )
                    });
                    if !action_allowed {
                        allowed = false;
                        break;
                    }
                }
                Err(err) => {
                    candidate_sim_errored = true;
                    tracing::warn!(
                        role = %candidate.role_arn,
                        action = required.action,
                        error = %err,
                        "IAM simulation failed for ECS exec candidate"
                    );
                    allowed = false;
                    break;
                }
            }
        }
        if candidate_sim_errored {
            continue;
        }
        if allowed {
            return Ok(candidate.clone());
        }
    }

    if all_sim_errored {
        tracing::warn!(
            role = %first_assumable.role_arn,
            "All IAM simulations failed for ECS exec; falling back to first AssumeRole candidate"
        );
        return Ok(first_assumable);
    }

    Err((
        axum::http::StatusCode::FORBIDDEN,
        Json(ApiError::forbidden(
            "No authorized role can perform ECS Exec",
        )),
    ))
}

fn select_account_for_describe(
    state: &AppState,
    accounts: Vec<AllowedAccount>,
    req: &EcsExecRequest,
) -> Result<AllowedAccount, (axum::http::StatusCode, Json<ApiError>)> {
    let matching = accounts
        .into_iter()
        .filter(|account| account.account_id == req.account_id)
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("Account not authorized")),
        ));
    }

    if !state.config.use_mock_aws() {
        let Some(account) = first_assumable_account(&matching) else {
            return Err((
                axum::http::StatusCode::FORBIDDEN,
                Json(ApiError::forbidden(
                    "ECS Exec requires an AssumeRole ARN, not direct/profile credentials",
                )),
            ));
        };
        return Ok(account);
    }

    Ok(matching.into_iter().next().unwrap())
}

async fn exec_task(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    headers: HeaderMap,
    Json(req): Json<EcsExecRequest>,
) -> Result<Json<EcsExecResponse>, (axum::http::StatusCode, Json<ApiError>)> {
    if !state.audit_service.is_healthy() {
        return Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal(
                "Audit logging is unavailable — privileged operations are suspended",
            )),
        ));
    }
    let audit_ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);
    let audit_deny = |state: &AppState, reason: &str, error_kind: Option<&str>| {
        state
            .audit_service
            .event(&claims.sub, AuditAction::EcsExec, AuditOutcome::Denied)
            .account(Some(&req.account_id))
            .region(Some(&req.region))
            .target(Some(&req.task_arn))
            .error(Some(reason))
            .optional_metadata(Some(ecs_exec_metadata(&audit_ctx, &req, None, error_kind)))
            .commit_best_effort();
    };

    if req.container_name.trim().is_empty() {
        audit_deny(
            &state,
            "Container name is required",
            Some("missing_container"),
        );
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request("Container name is required")),
        ));
    }
    if let Err(err) = validate_task_request_arn(&req) {
        audit_deny(&state, &err.1 .0.message, Some("arn_mismatch"));
        return Err(err);
    }

    let ent_service = EntitlementService::new(state.entitlement_store.clone());
    let entitlements = ent_service.evaluate(&claims).await;
    if !entitlements.features.can_use_ecs_exec
        || !ent_service
            .ecs_has_feature_for_scope(
                &claims,
                &req.account_id,
                &req.region,
                &req.cluster_arn,
                |features| features.can_use_ecs_exec,
            )
            .await
    {
        audit_deny(&state, "ECS exec not authorized", Some("scope_denied"));
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("ECS exec not authorized")),
        ));
    }

    let rule_scopes = ent_service
        .ecs_rule_scopes_for_feature(&claims, |features| features.can_use_ecs_exec)
        .await;
    let cluster_scopes = rule_scopes
        .iter()
        .filter(|scope| {
            scope.account_ids.contains(&req.account_id)
                && (scope.regions.is_empty() || scope.regions.contains(&req.region))
                && scope.cluster_patterns.iter().any(|pattern| {
                    crate::services::ecs::cluster_matches_pattern(pattern, &req.cluster_arn)
                })
        })
        .collect::<Vec<_>>();

    let describe_accounts = cluster_scopes
        .iter()
        .flat_map(|scope| scope.accounts.iter().cloned())
        .filter(|account| account.account_id == req.account_id)
        .collect::<Vec<_>>();
    let describe_account = match select_account_for_describe(&state, describe_accounts, &req) {
        Ok(account) => account,
        Err(err) => {
            audit_deny(&state, &err.1 .0.message, Some("scope_denied"));
            return Err(err);
        }
    };

    let task = if state.config.use_mock_aws() {
        mock_tasks()
            .into_iter()
            .find(|task| task.task_arn == req.task_arn)
    } else {
        let session_ctx = session_context(&state, &entitlements);
        let config = resolve_aws_config(
            &state.base_aws_config,
            &describe_account,
            &req.region,
            &session_ctx,
        )
        .await
        .map_err(|err| {
            tracing::error!("AWS config failed for ECS exec: {}", err);
            audit_deny(
                &state,
                "Failed to get credentials for target account",
                Some("aws_config"),
            );
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::internal(
                    "Failed to get credentials for target account",
                )),
            )
        })?;
        let ecs = AwsClients::ecs(&config);
        let describe_resp = ecs
            .describe_tasks()
            .cluster(&req.cluster_arn)
            .tasks(&req.task_arn)
            .include(aws_sdk_ecs::types::TaskField::Tags)
            .send()
            .await
            .map_err(|err| {
                tracing::error!("DescribeTasks failed for ECS exec: {}", err);
                audit_deny(
                    &state,
                    "DescribeTasks failed or target not authorized",
                    Some("describe_tasks_failed"),
                );
                (
                    axum::http::StatusCode::FORBIDDEN,
                    Json(ApiError::forbidden("ECS exec not authorized")),
                )
            })?;
        describe_resp
            .tasks()
            .first()
            .map(|task| convert_sdk_task(task, &req.account_id, &req.region))
    };

    let Some(task) = task else {
        audit_deny(
            &state,
            "Task not found or not authorized",
            Some("task_not_found_or_not_authorized"),
        );
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("ECS exec not authorized")),
        ));
    };

    let matching_scopes = matching_rule_scopes(&task, &rule_scopes);
    if matching_scopes.is_empty() {
        audit_deny(
            &state,
            "Task does not match ECS entitlement scope",
            Some("scope_denied"),
        );
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("ECS exec not authorized")),
        ));
    }

    if let Err((kind, status, message)) = validate_task_for_exec(&task, &req) {
        state
            .audit_service
            .event(&claims.sub, AuditAction::EcsExec, AuditOutcome::Denied)
            .account(Some(&req.account_id))
            .region(Some(&req.region))
            .target(Some(&req.task_arn))
            .error(Some(&message))
            .optional_metadata(Some(ecs_exec_metadata(
                &audit_ctx,
                &req,
                Some(&task.launch_type),
                Some(kind),
            )))
            .commit_best_effort();
        return Err((status, Json(ApiError::new(kind, message))));
    }

    let eligible_scopes = container_eligible_rule_scopes(&matching_scopes, &req.container_name);
    if eligible_scopes.is_empty() {
        audit_deny(
            &state,
            "Container is excluded by ECS sidecar denylist",
            Some("container_in_sidecar_denylist"),
        );
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden(
                "Container is excluded by ECS sidecar denylist",
            )),
        ));
    }

    let scoped_accounts = eligible_scopes
        .iter()
        .flat_map(|scope| scope.accounts.iter().cloned())
        .filter(|account| account.account_id == req.account_id)
        .collect::<Vec<_>>();
    let selected_account = match select_account_for_exec(&state, scoped_accounts, &req).await {
        Ok(account) => account,
        Err(err) => {
            audit_deny(&state, &err.1 .0.message, Some("iam_simulation_denied"));
            return Err(err);
        }
    };

    if let Some(cap) = entitlements.max_session_seconds {
        if cap > 0 && cap < 900 && !state.config.use_mock_aws() {
            audit_deny(
                &state,
                "max_session_seconds is below STS minimum",
                Some("session_cap_too_low"),
            );
            return Err((
                axum::http::StatusCode::FORBIDDEN,
                Json(ApiError::forbidden(
                    "Session cap is below the minimum enforceable limit (900s)",
                )),
            ));
        }
    }

    let credentials = if state.config.use_mock_aws() {
        Some(AssumedRoleCredentials {
            access_key_id: "ASIADEVMOCK000000001".into(),
            secret_access_key: "dev-mock-secret-not-real".into(),
            session_token: "dev-mock-session-token".into(),
        })
    } else {
        let session_ctx = session_context(&state, &entitlements);
        let policy = ecs_exec_session_policy(&req.cluster_arn, &req.task_arn, &req.region);
        let scoped_config = assume_role_scoped(
            &state.base_aws_config,
            &selected_account,
            &req.region,
            &session_ctx,
            &policy,
            entitlements.max_session_seconds,
        )
        .await
        .map_err(|err| {
            tracing::error!("Scoped ECS AssumeRole failed: {}", err);
            audit_deny(
                &state,
                "Failed to create scoped credentials for ECS exec",
                Some("assume_role_failed"),
            );
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::internal(
                    "Failed to create scoped credentials for ECS exec",
                )),
            )
        })?;
        let provider = scoped_config.credentials_provider().ok_or_else(|| {
            audit_deny(
                &state,
                "Scoped config missing credentials",
                Some("missing_credentials"),
            );
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::internal("Scoped config missing credentials")),
            )
        })?;
        let resolved = provider.provide_credentials().await.map_err(|err| {
            tracing::error!("Failed to resolve scoped ECS credentials: {}", err);
            audit_deny(
                &state,
                "Failed to resolve scoped credentials",
                Some("credentials"),
            );
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::internal("Failed to resolve scoped credentials")),
            )
        })?;
        Some(AssumedRoleCredentials {
            access_key_id: resolved.access_key_id().to_string(),
            secret_access_key: resolved.secret_access_key().to_string(),
            session_token: resolved.session_token().unwrap_or_default().to_string(),
        })
    };

    let eligible_rule_scopes = eligible_scopes
        .into_iter()
        .cloned()
        .collect::<Vec<crate::services::ecs::EcsRuleScope>>();

    let response = build_ecs_exec_command(
        &req,
        &entitlements,
        &task,
        credentials.as_ref(),
        &eligible_rule_scopes,
    )
    .map_err(|message| {
        audit_deny(&state, &message, Some("command_denied"));
        (
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden(message)),
        )
    })?;

    state
        .audit_service
        .event(&claims.sub, AuditAction::EcsExec, AuditOutcome::Success)
        .account(Some(&req.account_id))
        .region(Some(&req.region))
        .target(Some(&req.task_arn))
        .metadata(ecs_exec_metadata(
            &audit_ctx,
            &req,
            Some(&task.launch_type),
            None,
        ))
        .commit_or_fail()
        .map_err(|err| {
            (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::internal(format!(
                    "ECS exec blocked: audit write failed ({})",
                    err
                ))),
            )
        })?;

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn non_mock_exec_state() -> AppState {
        let config = crate::config::AppConfig {
            bind_address: "127.0.0.1:8443".into(),
            oidc: crate::config::OidcConfig {
                issuer_url: "https://example.com".into(),
                client_id: "test-client".into(),
                client_secret: None,
                scopes: vec!["openid".into()],
                authorization_endpoint: None,
                token_endpoint: None,
                device_authorization_endpoint: None,
                userinfo_endpoint: None,
                jwks_uri: None,
            },
            jwt: crate::config::JwtConfig {
                secret: "test-secret-at-least-32-chars-long!!".into(),
                expiry_seconds: 3600,
            },
            aws: crate::config::AwsConfig {
                default_region: Some("us-east-1".into()),
                session_duration_seconds: Some(3600),
                sts_external_id: Some("canopy".into()),
            },
            dev_mode: true,
            mock_aws_data: Some(false),
            entitlements_file: None,
            audit_log: None,
            cors_allowed_origins: vec![],
        };
        let oidc_client = crate::services::oidc::OidcClient::new(config.oidc.clone());
        AppState {
            config,
            entitlement_store: Arc::new(tokio::sync::RwLock::new(
                crate::models::entitlements::EntitlementStore::dev_defaults(),
            )),
            audit_service: crate::services::audit::AuditService::new(),
            oidc_client,
            base_aws_config: aws_config::SdkConfig::builder()
                .region(aws_types::region::Region::new("us-east-1"))
                .build(),
            ready: std::sync::atomic::AtomicBool::new(true),
        }
    }

    fn route_scope() -> crate::services::ecs::EcsRuleScope {
        crate::services::ecs::EcsRuleScope {
            accounts: vec![AllowedAccount {
                account_id: "111111111111".into(),
                account_name: "production".into(),
                role_arn: "arn:aws:iam::111111111111:role/CanopyRole".into(),
            }],
            account_ids: vec!["111111111111".into()],
            regions: vec!["us-east-1".into()],
            cluster_patterns: vec![cluster_arn(
                "us-east-1",
                "111111111111",
                DEV_MOCK_CLUSTER_NAME,
            )],
            allow_selectors: vec![],
            deny_selectors: vec![],
            excluded_container_names: vec![],
            allow_broad_cluster_discovery: false,
        }
    }

    fn account(role_arn: &str) -> AllowedAccount {
        AllowedAccount {
            account_id: "111111111111".into(),
            account_name: "production".into(),
            role_arn: role_arn.into(),
        }
    }

    fn exec_req() -> EcsExecRequest {
        let task = mock_tasks().remove(0);
        EcsExecRequest {
            account_id: task.account_id,
            region: task.region,
            cluster_arn: task.cluster_arn,
            task_arn: task.task_arn,
            container_name: "app".into(),
        }
    }

    #[test]
    fn required_ecs_exec_simulations_include_execute_and_ssmmessages() {
        let simulations = required_ecs_exec_simulations(&exec_req());
        let actions = simulations.iter().map(|sim| sim.action).collect::<Vec<_>>();
        assert!(actions.contains(&"ecs:ExecuteCommand"));
        assert!(actions.contains(&"ecs:DescribeTasks"));
        assert!(actions.contains(&"ssmmessages:CreateDataChannel"));
        assert!(actions.contains(&"ssmmessages:OpenControlChannel"));
    }

    #[test]
    fn ecs_exec_simulation_context_includes_cluster_region_and_container() {
        let req = exec_req();
        let context = ecs_exec_simulation_context(&req);
        let by_name = context
            .iter()
            .filter_map(|entry| Some((entry.context_key_name()?, entry.context_key_values())))
            .collect::<std::collections::HashMap<_, _>>();

        assert_eq!(by_name["aws:RequestedRegion"], [req.region.as_str()]);
        assert_eq!(by_name["ecs:cluster"], [req.cluster_arn.as_str()]);
        assert_eq!(by_name["ecs:container-name"], [req.container_name.as_str()]);
    }

    #[test]
    fn validate_task_request_arn_rejects_cross_account_task() {
        let mut req = exec_req();
        req.account_id = "222222222222".into();
        let err = validate_task_request_arn(&req).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn task_matches_request_filters_accepts_short_cluster_filter() {
        let task = mock_tasks().remove(0);
        let req = EcsTasksRequest {
            account_id: Some(task.account_id.clone()),
            region: Some(task.region.clone()),
            cluster: Some(task.cluster_name.clone()),
            page_size: 50,
        };
        assert!(task_matches_request_filters(&task, &req));
    }

    #[test]
    fn task_matches_request_filters_accepts_arn_cluster_filter() {
        let task = mock_tasks().remove(0);
        let req = EcsTasksRequest {
            account_id: Some(task.account_id.clone()),
            region: Some(task.region.clone()),
            cluster: Some(task.cluster_arn.clone()),
            page_size: 50,
        };
        assert!(task_matches_request_filters(&task, &req));
    }

    #[test]
    fn cluster_request_scope_rejects_unauthorized_cluster() {
        let req = EcsTasksRequest {
            account_id: Some("111111111111".into()),
            region: Some("us-east-1".into()),
            cluster: Some("other-cluster".into()),
            page_size: 50,
        };

        let err = validate_tasks_request_scope(&req, &[route_scope()]).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn cluster_ref_authorized_requires_allowed_pattern() {
        let scope = route_scope();
        assert!(cluster_ref_authorized(
            std::slice::from_ref(&scope),
            "111111111111",
            "us-east-1",
            &cluster_arn("us-east-1", "111111111111", DEV_MOCK_CLUSTER_NAME)
        ));
        assert!(!cluster_ref_authorized(
            &[scope],
            "111111111111",
            "us-east-1",
            &cluster_arn("us-east-1", "111111111111", "other-cluster")
        ));
    }

    #[test]
    fn cluster_request_scope_rejects_cluster_arn_outside_rule_region() {
        let mut scope = route_scope();
        let cluster = cluster_arn("ap-northeast-1", "111111111111", "app");
        scope.regions = vec!["us-east-1".into()];
        scope.cluster_patterns = vec![cluster.clone()];
        let req = EcsTasksRequest {
            account_id: None,
            region: None,
            cluster: Some(cluster),
            page_size: 50,
        };

        let err = validate_tasks_request_scope(&req, &[scope]).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::FORBIDDEN);
        assert_eq!(err.1 .0.message, "ECS task scope not authorized");
    }

    #[test]
    fn cluster_request_scope_accepts_short_cluster_using_concrete_pattern_region() {
        let mut scope = route_scope();
        scope.regions.clear();
        scope.cluster_patterns = vec![cluster_arn("ap-northeast-1", "111111111111", "app")];
        let req = EcsTasksRequest {
            account_id: Some("111111111111".into()),
            region: None,
            cluster: Some("app".into()),
            page_size: 50,
        };

        assert!(validate_tasks_request_scope(&req, &[scope]).is_ok());
    }

    #[test]
    fn cluster_request_scope_rejects_short_cluster_outside_concrete_pattern_region() {
        let mut scope = route_scope();
        scope.regions.clear();
        scope.cluster_patterns = vec![cluster_arn("ap-northeast-1", "111111111111", "app")];
        let req = EcsTasksRequest {
            account_id: Some("111111111111".into()),
            region: Some("us-east-1".into()),
            cluster: Some("app".into()),
            page_size: 50,
        };

        let err = validate_tasks_request_scope(&req, &[scope]).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::FORBIDDEN);
        assert_eq!(err.1 .0.message, "ECS task scope not authorized");
    }

    #[test]
    fn cluster_patterns_for_account_region_excludes_other_concrete_regions() {
        let mut scope = route_scope();
        scope.regions.clear();
        scope.cluster_patterns = vec![
            cluster_arn("ap-northeast-1", "111111111111", "api"),
            cluster_arn("*", "111111111111", "shared"),
            cluster_arn("us-west-2", "111111111111", "worker"),
        ];

        assert_eq!(
            cluster_patterns_for_account_region(&[scope], "111111111111", "ap-northeast-1"),
            vec![
                cluster_arn("ap-northeast-1", "111111111111", "api"),
                cluster_arn("*", "111111111111", "shared")
            ]
        );
    }

    #[test]
    fn concrete_cluster_pattern_regions_extracts_authorized_arn_regions() {
        let mut scope = route_scope();
        scope.regions = vec![];
        scope.cluster_patterns = vec![
            cluster_arn("ap-northeast-1", "111111111111", "api"),
            cluster_arn("us-west-2", "111111111111", "worker-*"),
            cluster_arn("*", "111111111111", "fallback"),
            cluster_arn("eu-west-1", "222222222222", "other-account"),
        ];

        assert_eq!(
            concrete_cluster_pattern_regions(&[scope], "111111111111"),
            vec!["ap-northeast-1", "us-west-2"]
        );
    }

    #[test]
    fn effective_regions_use_requested_region_for_all_region_scope() {
        let req = EcsTasksRequest {
            account_id: Some("111111111111".into()),
            region: Some("ap-northeast-1".into()),
            cluster: None,
            page_size: 50,
        };

        assert_eq!(
            effective_task_fetch_regions(&req, &[], &[], "us-east-1".into()),
            vec!["ap-northeast-1"]
        );
    }

    #[test]
    fn effective_regions_use_cluster_arn_region_when_request_region_absent() {
        let req = EcsTasksRequest {
            account_id: Some("111111111111".into()),
            region: None,
            cluster: Some(cluster_arn("ap-northeast-1", "111111111111", "app")),
            page_size: 50,
        };

        assert_eq!(
            effective_task_fetch_regions(&req, &["us-east-1".into()], &[], "us-west-2".into()),
            vec!["ap-northeast-1"]
        );
    }

    #[test]
    fn effective_regions_use_concrete_cluster_regions_before_default_region() {
        let req = EcsTasksRequest {
            account_id: Some("111111111111".into()),
            region: None,
            cluster: None,
            page_size: 50,
        };
        let cluster_regions = vec!["ap-northeast-1".into(), "us-west-2".into()];

        assert_eq!(
            effective_task_fetch_regions(&req, &[], &cluster_regions, "us-east-1".into()),
            cluster_regions
        );
    }

    #[test]
    fn effective_regions_use_default_region_instead_of_merged_entitlement_regions() {
        let req = EcsTasksRequest {
            account_id: Some("111111111111".into()),
            region: None,
            cluster: None,
            page_size: 50,
        };

        assert_eq!(
            effective_task_fetch_regions(&req, &[], &[], "us-west-2".into()),
            vec!["us-west-2"]
        );
    }

    #[test]
    fn requested_tasks_page_size_honors_requested_size_up_to_response_cap() {
        assert_eq!(requested_tasks_page_size(0), DEFAULT_TASKS_PAGE_SIZE);
        assert_eq!(requested_tasks_page_size(1), 1);
        assert_eq!(requested_tasks_page_size(200), 200);
        assert_eq!(requested_tasks_page_size(500), MAX_TASKS_PER_RESPONSE);
    }

    #[test]
    fn authorized_cluster_refs_marks_concrete_cluster_cap_truncated() {
        let clusters = (0..(MAX_CLUSTERS_PER_REQUEST + 2))
            .map(|idx| cluster_arn("us-east-1", "111111111111", &format!("app-{idx}")))
            .collect::<Vec<_>>();

        let (refs, truncated) = authorized_cluster_refs(clusters.clone(), &clusters);

        assert_eq!(refs.len(), MAX_CLUSTERS_PER_REQUEST);
        assert!(truncated);
    }

    #[test]
    fn first_assumable_account_skips_direct_and_profile_entries() {
        let accounts = vec![
            account("direct"),
            account("profile:ops"),
            account("arn:aws:iam::111111111111:role/CanopyRole"),
        ];

        let selected = first_assumable_account(&accounts).unwrap();
        assert_eq!(
            selected.role_arn,
            "arn:aws:iam::111111111111:role/CanopyRole"
        );
    }

    #[test]
    fn first_assumable_account_returns_none_for_local_only_entries() {
        let accounts = vec![account("direct"), account("profile:ops")];
        assert!(first_assumable_account(&accounts).is_none());
    }

    #[test]
    fn select_account_for_describe_rejects_local_only_credentials() {
        let state = non_mock_exec_state();
        let err = select_account_for_describe(
            &state,
            vec![account("direct"), account("profile:ops")],
            &exec_req(),
        )
        .unwrap_err();

        assert_eq!(err.0, axum::http::StatusCode::FORBIDDEN);
        assert!(err.1 .0.message.contains("AssumeRole ARN"));
    }

    #[tokio::test]
    async fn select_account_for_exec_rejects_local_only_credentials() {
        let state = non_mock_exec_state();
        let err = select_account_for_exec(
            &state,
            vec![account("direct"), account("profile:ops")],
            &exec_req(),
        )
        .await
        .unwrap_err();

        assert_eq!(err.0, axum::http::StatusCode::FORBIDDEN);
        assert!(err.1 .0.message.contains("AssumeRole ARN"));
    }

    #[test]
    fn rule_scopes_for_account_role_keeps_cluster_scope_role_local() {
        let mut read_scope = route_scope();
        read_scope.accounts[0].role_arn = "arn:aws:iam::111111111111:role/ReadOnly".into();
        read_scope.cluster_patterns = vec![cluster_arn("us-east-1", "111111111111", "read")];
        let mut exec_scope = route_scope();
        exec_scope.accounts[0].role_arn = "arn:aws:iam::111111111111:role/EcsExec".into();
        exec_scope.cluster_patterns = vec![cluster_arn("ap-northeast-1", "111111111111", "exec")];
        let selected = account("arn:aws:iam::111111111111:role/ReadOnly");

        let scoped = rule_scopes_for_account_role(&[read_scope, exec_scope], &selected);

        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].accounts[0].role_arn, selected.role_arn);
        assert_eq!(
            concrete_cluster_pattern_regions(&scoped, "111111111111"),
            vec!["us-east-1"]
        );
    }

    #[test]
    fn container_eligible_scopes_keep_rule_local_denylist() {
        let mut denying = route_scope();
        denying.excluded_container_names = vec!["app".into()];
        denying.accounts[0].role_arn = "arn:aws:iam::111111111111:role/DenyApp".into();
        let mut allowing = route_scope();
        allowing.accounts[0].role_arn = "arn:aws:iam::111111111111:role/AllowApp".into();
        let matching = vec![&denying, &allowing];

        let eligible = container_eligible_rule_scopes(&matching, "app");

        assert_eq!(eligible.len(), 1);
        assert_eq!(
            eligible[0].accounts[0].role_arn,
            "arn:aws:iam::111111111111:role/AllowApp"
        );
    }

    #[test]
    fn container_eligible_scopes_empty_when_all_matching_rules_exclude_container() {
        let mut denying = route_scope();
        denying.excluded_container_names = vec!["app".into()];
        let matching = vec![&denying];

        assert!(container_eligible_rule_scopes(&matching, "app").is_empty());
    }

    #[test]
    fn validate_task_for_exec_normalizes_running_statuses() {
        let mut task = mock_tasks().remove(0);
        task.last_status = " running ".into();
        task.containers[0].last_status = "Running".into();
        let req = EcsExecRequest {
            account_id: task.account_id.clone(),
            region: task.region.clone(),
            cluster_arn: task.cluster_arn.clone(),
            task_arn: task.task_arn.clone(),
            container_name: "app".into(),
        };

        assert!(validate_task_for_exec(&task, &req).is_ok());
    }
}
