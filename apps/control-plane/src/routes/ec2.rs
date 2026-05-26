use aws_credential_types::provider::ProvideCredentials;
use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
use std::sync::Arc;

use crate::aws::clients::AwsClients;
use crate::aws::credentials::{assume_role_scoped, connect_session_policy, SessionContext};
use crate::aws::ec2_convert::convert_sdk_instance;
use crate::middleware::auth::AuthenticatedUser;
use crate::services::audit::AuditRequestContext;
use crate::services::ec2::{
    apply_user_filters, build_connect_command, filter_instances_by_entitlements, mock_instances,
    power_feature_enabled, requested_state_for_power_action, AssumedRoleCredentials,
};
use crate::services::entitlements::EntitlementService;
use crate::services::AppState;
use shared::dto::audit::{AuditAction, AuditOutcome};
use shared::dto::ec2::*;
use shared::dto::entitlements::AllowedAccount;
use shared::errors::ApiError;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/ec2/list", post(list_instances))
        .route("/api/ec2/connect", post(connect_instance))
        .route("/api/ec2/power", post(power_instance))
}

struct RequiredIamSimulation {
    action: &'static str,
    resources: Vec<String>,
}

fn required_connect_simulations(req: &ConnectRequest) -> Vec<RequiredIamSimulation> {
    let mut simulations = vec![RequiredIamSimulation {
        action: "ec2:DescribeInstances",
        // DescribeInstances does not support instance-level resource
        // permissions. Simulating it against an instance ARN false-denies
        // roles that correctly allow the API on "*".
        resources: vec!["*".to_string()],
    }];

    match req.method {
        ConnectMethod::Ssm => {
            let mut resources = vec![format!(
                "arn:aws:ec2:{}:{}:instance/{}",
                req.region, req.account_id, req.instance_id
            )];
            if req.os_user.is_some() {
                resources.push(format!(
                    "arn:aws:ssm:{}::document/AWS-StartSSHSession",
                    req.region
                ));
            } else {
                resources.push(format!(
                    "arn:aws:ssm:{}::document/SSM-SessionManagerRunShell",
                    req.region
                ));
            }
            simulations.push(RequiredIamSimulation {
                action: "ssm:StartSession",
                resources,
            });
        }
        ConnectMethod::Ec2InstanceConnect => {
            simulations.push(RequiredIamSimulation {
                action: "ec2-instance-connect:SendSSHPublicKey",
                resources: vec![format!(
                    "arn:aws:ec2:{}:{}:instance/{}",
                    req.region, req.account_id, req.instance_id
                )],
            });
            simulations.push(RequiredIamSimulation {
                action: "ec2-instance-connect:OpenTunnel",
                resources: vec![format!(
                    "arn:aws:ec2:{}:{}:instance-connect-endpoint/*",
                    req.region, req.account_id
                )],
            });
        }
        ConnectMethod::Ssh => {}
    }

    simulations
}

fn simulated_action_names(simulations: &[RequiredIamSimulation]) -> Vec<&'static str> {
    simulations.iter().map(|s| s.action).collect()
}

fn ec2_list_metadata(
    ctx: &AuditRequestContext,
    req: &Ec2ListRequest,
    returned_count: Option<usize>,
    total_count: Option<usize>,
    failed_scopes: &[String],
) -> serde_json::Value {
    ctx.metadata(serde_json::json!({
        "name_filter": req.name_filter.as_deref(),
        "state_filter": &req.state_filter,
        "tag_filters": &req.tag_filters,
        "has_next_token": req.next_token.is_some(),
        "page_size": req.page_size,
        "returned_count": returned_count,
        "total_count": total_count,
        "failed_scopes": failed_scopes,
    }))
}

fn ec2_connect_metadata(ctx: &AuditRequestContext, req: &ConnectRequest) -> serde_json::Value {
    ctx.metadata(serde_json::json!({
        "method": &req.method,
        "os_user": req.os_user.as_deref(),
    }))
}

fn power_action_iam_name(action: Ec2PowerAction) -> &'static str {
    match action {
        Ec2PowerAction::Start => "ec2:StartInstances",
        Ec2PowerAction::Stop => "ec2:StopInstances",
        Ec2PowerAction::Reboot => "ec2:RebootInstances",
    }
}

fn required_power_simulations(req: &Ec2PowerRequest) -> Vec<RequiredIamSimulation> {
    vec![
        RequiredIamSimulation {
            action: "ec2:DescribeInstances",
            resources: vec!["*".to_string()],
        },
        RequiredIamSimulation {
            action: power_action_iam_name(req.action),
            resources: vec![format!(
                "arn:aws:ec2:{}:{}:instance/{}",
                req.region, req.account_id, req.instance_id
            )],
        },
    ]
}

fn required_describe_instance_simulations() -> [RequiredIamSimulation; 1] {
    [RequiredIamSimulation {
        action: "ec2:DescribeInstances",
        resources: vec!["*".to_string()],
    }]
}

fn is_local_account(account: &AllowedAccount) -> bool {
    account.role_arn == "direct" || account.role_arn.starts_with("profile:")
}

async fn select_account_for_simulations(
    state: &AppState,
    candidates: &[AllowedAccount],
    required_simulations: &[RequiredIamSimulation],
) -> Option<AllowedAccount> {
    if candidates.is_empty() {
        return None;
    }
    if candidates.iter().all(is_local_account) {
        return candidates.first().cloned();
    }

    let iam_client = aws_sdk_iam::Client::new(&state.base_aws_config);
    let mut chosen = None;
    let mut local_fallback = None;
    let mut first_assumable = None;
    let mut all_sim_errored = true;

    for candidate in candidates {
        if is_local_account(candidate) {
            if local_fallback.is_none() {
                local_fallback = Some(candidate.clone());
            }
            continue;
        }
        if first_assumable.is_none() {
            first_assumable = Some(candidate.clone());
        }

        let mut candidate_allowed = true;
        let mut candidate_sim_errored = false;
        for required in required_simulations {
            let mut sim = iam_client
                .simulate_principal_policy()
                .policy_source_arn(&candidate.role_arn)
                .action_names(required.action);
            for resource in &required.resources {
                sim = sim.resource_arns(resource);
            }
            match sim.send().await {
                Ok(sim_resp) => {
                    all_sim_errored = false;
                    let allowed = sim_resp.evaluation_results().iter().all(|result| {
                        matches!(
                            result.eval_decision(),
                            aws_sdk_iam::types::PolicyEvaluationDecisionType::Allowed
                        )
                    });
                    if !allowed {
                        candidate_allowed = false;
                        break;
                    }
                }
                Err(err) => {
                    candidate_sim_errored = true;
                    tracing::warn!(
                        role = %candidate.role_arn,
                        action = required.action,
                        error = %err,
                        "IAM simulation failed, skipping candidate"
                    );
                    break;
                }
            }
        }
        if candidate_sim_errored {
            continue;
        }
        if candidate_allowed {
            chosen = Some(candidate.clone());
            break;
        }
    }

    if chosen.is_none() && all_sim_errored {
        if let Some(fallback) = first_assumable {
            tracing::warn!(
                "All IAM simulations failed — falling back to first role candidate {}",
                fallback.role_arn
            );
            chosen = Some(fallback);
        }
    }

    chosen.or(local_fallback)
}

fn ec2_power_metadata(
    ctx: &AuditRequestContext,
    req: &Ec2PowerRequest,
    previous_state: Option<&InstanceState>,
    requested_state: Option<&InstanceState>,
) -> serde_json::Value {
    ctx.metadata(serde_json::json!({
        "power_action": &req.action,
        "previous_state": previous_state,
        "requested_state": requested_state,
        "confirmation_present": !req.confirmation_instance_id.is_empty(),
    }))
}

fn sdk_state_name_to_instance_state(
    state: &aws_sdk_ec2::types::InstanceStateName,
) -> InstanceState {
    match state {
        aws_sdk_ec2::types::InstanceStateName::Pending => InstanceState::Pending,
        aws_sdk_ec2::types::InstanceStateName::Running => InstanceState::Running,
        aws_sdk_ec2::types::InstanceStateName::ShuttingDown => InstanceState::ShuttingDown,
        aws_sdk_ec2::types::InstanceStateName::Terminated => InstanceState::Terminated,
        aws_sdk_ec2::types::InstanceStateName::Stopping => InstanceState::Stopping,
        aws_sdk_ec2::types::InstanceStateName::Stopped => InstanceState::Stopped,
        _ => InstanceState::Pending,
    }
}

fn sdk_state_change_current_state(
    state_change: Option<&aws_sdk_ec2::types::InstanceStateChange>,
    fallback: InstanceState,
) -> InstanceState {
    state_change
        .and_then(|change| change.current_state())
        .and_then(|state| state.name())
        .map(sdk_state_name_to_instance_state)
        .unwrap_or(fallback)
}

fn power_success_message(req: &Ec2PowerRequest, requested_state: &InstanceState) -> String {
    format!(
        "{} requested for {} (AWS state: {})",
        req.action, req.instance_id, requested_state
    )
}

/// Fetch EC2 instances from real AWS across all allowed account+region pairs.
async fn fetch_instances_from_aws(
    state: &AppState,
    entitlements: &shared::dto::entitlements::UserEntitlements,
    scoped_account_regions: &[(shared::dto::entitlements::AllowedAccount, Vec<String>)],
    filter_account: Option<&str>,
    filter_region: Option<&str>,
) -> Result<(Vec<Ec2Instance>, Vec<String>), (axum::http::StatusCode, Json<ApiError>)> {
    let session_ctx = SessionContext {
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
    };

    // Query each (account, role, region) combination using ONLY
    // rule-scoped tuples to prevent cross-group cartesian products.
    // Each tuple is derived from a single rule that grants can_view_ec2.
    let mut tasks = Vec::new();
    for (account, rule_regions) in scoped_account_regions {
        // Skip accounts not matching the request filter
        if let Some(fa) = filter_account {
            if account.account_id != fa {
                continue;
            }
        }
        // Use only regions from the same rule. If the rule has no region
        // restriction, use the merged region list. If both are empty,
        // use the default region from config to avoid returning no instances.
        let default_region = state
            .config
            .aws
            .default_region
            .clone()
            .unwrap_or_else(|| "us-east-1".to_string());
        let effective_regions: Vec<String> = if !rule_regions.is_empty() {
            rule_regions.clone()
        } else if !entitlements.allowed_regions.is_empty() {
            entitlements.allowed_regions.clone()
        } else {
            vec![default_region]
        };
        for region in &effective_regions {
            // Skip regions not matching the request filter
            if let Some(fr) = filter_region {
                if region != fr {
                    continue;
                }
            }
            let base_config = state.base_aws_config.clone();
            let account = account.clone();
            let region = region.clone();
            let session_ctx = SessionContext {
                user_id: session_ctx.user_id.clone(),
                team: session_ctx.team.clone(),
                environment: session_ctx.environment.clone(),
                session_duration_seconds: session_ctx.session_duration_seconds,
                sts_external_id: session_ctx.sts_external_id.clone(),
            };

            tasks.push(tokio::spawn(async move {
                let effective_config = crate::aws::credentials::resolve_aws_config(
                    &base_config,
                    &account,
                    &region,
                    &session_ctx,
                )
                .await?;

                let ec2_client = AwsClients::ec2(&effective_config);

                let mut instances = Vec::new();
                let mut next_token: Option<String> = None;

                loop {
                    let mut req = ec2_client.describe_instances();
                    if let Some(token) = next_token.take() {
                        req = req.next_token(token);
                    }

                    let resp = req.send().await.map_err(|e| {
                        anyhow::anyhow!(
                            "DescribeInstances failed for account {} region {}: {}",
                            account.account_id,
                            region,
                            e
                        )
                    })?;

                    for reservation in resp.reservations() {
                        for inst in reservation.instances() {
                            instances.push(convert_sdk_instance(
                                inst,
                                &account.account_id,
                                &region,
                            ));
                        }
                    }

                    match resp.next_token() {
                        Some(t) if !t.is_empty() => {
                            next_token = Some(t.to_string());
                        }
                        _ => break,
                    }
                }

                Ok::<Vec<Ec2Instance>, anyhow::Error>(instances)
            }));
        }
    }

    let mut all_instances = Vec::new();
    let mut seen_instance_ids = std::collections::HashSet::new();
    let mut failed_scopes = Vec::new();

    for task in tasks {
        match task.await {
            Ok(Ok(instances)) => {
                for inst in instances {
                    if seen_instance_ids.insert(inst.instance_id.clone()) {
                        all_instances.push(inst);
                    }
                }
            }
            Ok(Err(e)) => {
                tracing::error!("Failed to fetch EC2 instances: {}", e);
                failed_scopes.push(e.to_string());
            }
            Err(e) => {
                tracing::error!("Task join error fetching EC2 instances: {}", e);
                failed_scopes.push(format!("task join error: {}", e));
            }
        }
    }

    // If ALL scopes failed, return an error instead of an empty 200
    if !failed_scopes.is_empty() && all_instances.is_empty() {
        return Err((
            axum::http::StatusCode::BAD_GATEWAY,
            Json(ApiError::internal(format!(
                "All EC2 fetch scopes failed: {}",
                failed_scopes.join("; ")
            ))),
        ));
    }

    Ok((all_instances, failed_scopes))
}

async fn list_instances(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    headers: HeaderMap,
    Json(req): Json<Ec2ListRequest>,
) -> Result<Json<Ec2ListResponse>, (axum::http::StatusCode, Json<ApiError>)> {
    if !state.audit_service.is_healthy() {
        return Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal("Audit logging unavailable")),
        ));
    }
    let audit_ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);
    let ent_service = EntitlementService::new(state.entitlement_store.clone());
    let entitlements = ent_service.evaluate(&claims).await;

    if !entitlements.features.can_view_ec2 {
        state
            .audit_service
            .event(&claims.sub, AuditAction::Ec2List, AuditOutcome::Denied)
            .account(req.account_id.as_deref())
            .region(req.region.as_deref())
            .error(Some("EC2 view not authorized"))
            .optional_metadata(Some(ec2_list_metadata(&audit_ctx, &req, None, None, &[])))
            .commit_best_effort();
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("EC2 view not authorized")),
        ));
    }

    // Derive per-rule (account, regions) tuples for scope-aware fan-out.
    let scoped_tuples = ent_service
        .scoped_accounts_for_feature(&claims, |f| f.can_view_ec2)
        .await;

    // Use mock data or real AWS depending on config.
    let (all_instances, failed_scopes) = if state.config.use_mock_aws() {
        (mock_instances(), vec![])
    } else {
        match fetch_instances_from_aws(
            &state,
            &entitlements,
            &scoped_tuples,
            req.account_id.as_deref(),
            req.region.as_deref(),
        )
        .await
        {
            Ok(result) => result,
            Err(err) => {
                state
                    .audit_service
                    .event(&claims.sub, AuditAction::Ec2List, AuditOutcome::Failure)
                    .account(req.account_id.as_deref())
                    .region(req.region.as_deref())
                    .error(Some(&err.1 .0.message))
                    .optional_metadata(Some(ec2_list_metadata(&audit_ctx, &req, None, None, &[])))
                    .commit_best_effort();
                return Err(err);
            }
        }
    };

    // CRITICAL: Server-side entitlement filtering before any client filters.
    // Use per-rule scopes to prevent cross-group tag-selector splicing.
    let rule_scopes = ent_service
        .rule_scopes_for_feature(&claims, |f| f.can_view_ec2)
        .await;
    let entitled_instances =
        filter_instances_by_entitlements(all_instances, &entitlements, &rule_scopes);

    // Apply user-requested filters on top of entitlement-filtered set
    let filtered = apply_user_filters(entitled_instances, &req);

    let total_count = filtered.len();

    // Pagination
    let page_size = req.page_size as usize;
    let start = req
        .next_token
        .as_ref()
        .and_then(|t| t.parse::<usize>().ok())
        .unwrap_or(0);

    // Clamp start so a stale or malicious token cannot panic on the slice.
    let start = start.min(total_count);
    let end = (start + page_size).min(total_count);
    let page = filtered[start..end].to_vec();
    let next_token = if end < total_count {
        Some(end.to_string())
    } else {
        None
    };

    state
        .audit_service
        .event(&claims.sub, AuditAction::Ec2List, AuditOutcome::Success)
        .account(req.account_id.as_deref())
        .region(req.region.as_deref())
        .optional_metadata(Some(ec2_list_metadata(
            &audit_ctx,
            &req,
            Some(page.len()),
            Some(total_count),
            &failed_scopes,
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

    Ok(Json(Ec2ListResponse {
        instances: page,
        next_token,
        total_count,
        failed_scopes,
    }))
}

async fn power_instance(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    headers: HeaderMap,
    Json(req): Json<Ec2PowerRequest>,
) -> Result<Json<Ec2PowerResponse>, (axum::http::StatusCode, Json<ApiError>)> {
    if !state.audit_service.is_healthy() {
        return Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal(
                "Audit logging is unavailable — privileged operations are suspended",
            )),
        ));
    }

    let audit_ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);
    let ent_service = EntitlementService::new(state.entitlement_store.clone());
    let entitlements = ent_service.evaluate(&claims).await;

    if req.confirmation_instance_id != req.instance_id {
        state
            .audit_service
            .event(&claims.sub, AuditAction::Ec2Power, AuditOutcome::Denied)
            .account(Some(&req.account_id))
            .region(Some(&req.region))
            .target(Some(&req.instance_id))
            .error(Some("confirmation_mismatch"))
            .metadata(ec2_power_metadata(&audit_ctx, &req, None, None))
            .commit_best_effort();
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            Json(ApiError::bad_request(
                "Confirmation must exactly match the instance id",
            )),
        ));
    }

    if !ent_service
        .has_feature_for_scope(
            &claims,
            &req.account_id,
            Some(&req.region),
            None,
            None,
            |features| power_feature_enabled(req.action, features),
        )
        .await
    {
        state
            .audit_service
            .event(&claims.sub, AuditAction::Ec2Power, AuditOutcome::Denied)
            .account(Some(&req.account_id))
            .region(Some(&req.region))
            .target(Some(&req.instance_id))
            .error(Some("EC2 power action not authorized for this scope"))
            .metadata(ec2_power_metadata(&audit_ctx, &req, None, None))
            .commit_best_effort();
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden(
                "EC2 power action not authorized for this scope",
            )),
        ));
    }

    let target_instance = if state.config.use_mock_aws() {
        let Some(instance) = mock_instances().into_iter().find(|instance| {
            instance.instance_id == req.instance_id
                && instance.account_id == req.account_id
                && instance.region == req.region
        }) else {
            state
                .audit_service
                .event(&claims.sub, AuditAction::Ec2Power, AuditOutcome::Denied)
                .account(Some(&req.account_id))
                .region(Some(&req.region))
                .target(Some(&req.instance_id))
                .error(Some("Instance not found or not authorized"))
                .metadata(ec2_power_metadata(&audit_ctx, &req, None, None))
                .commit_best_effort();
            return Err((
                axum::http::StatusCode::FORBIDDEN,
                Json(ApiError::forbidden("Power action not authorized")),
            ));
        };
        instance
    } else {
        let scoped_power_tuples = ent_service
            .scoped_accounts_for_feature(&claims, |features| {
                power_feature_enabled(req.action, features)
            })
            .await;
        let matching_accounts: Vec<_> = scoped_power_tuples
            .into_iter()
            .filter(|(account, regions)| {
                account.account_id == req.account_id
                    && (regions.is_empty() || regions.contains(&req.region))
            })
            .map(|(account, _)| account)
            .collect();

        if matching_accounts.is_empty() {
            state
                .audit_service
                .event(&claims.sub, AuditAction::Ec2Power, AuditOutcome::Denied)
                .account(Some(&req.account_id))
                .region(Some(&req.region))
                .target(Some(&req.instance_id))
                .error(Some("Account not in power entitlements"))
                .metadata(ec2_power_metadata(&audit_ctx, &req, None, None))
                .commit_best_effort();
            return Err((
                axum::http::StatusCode::FORBIDDEN,
                Json(ApiError::forbidden("Account not authorized")),
            ));
        }

        let describe_simulations = required_describe_instance_simulations();
        let Some(describe_account) =
            select_account_for_simulations(&state, &matching_accounts, &describe_simulations).await
        else {
            state
                .audit_service
                .event(&claims.sub, AuditAction::Ec2Power, AuditOutcome::Denied)
                .account(Some(&req.account_id))
                .region(Some(&req.region))
                .target(Some(&req.instance_id))
                .error(Some("No authorized role can describe target instance"))
                .metadata(ec2_power_metadata(&audit_ctx, &req, None, None))
                .commit_best_effort();
            return Err((
                axum::http::StatusCode::FORBIDDEN,
                Json(ApiError::forbidden(format!(
                    "None of the {} authorized roles for account {} can perform {:?}",
                    matching_accounts.len(),
                    req.account_id,
                    simulated_action_names(&describe_simulations)
                ))),
            ));
        };

        let session_ctx = SessionContext {
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
        };
        let effective_config = crate::aws::credentials::resolve_aws_config(
            &state.base_aws_config,
            &describe_account,
            &req.region,
            &session_ctx,
        )
        .await
        .map_err(|err| {
            tracing::error!(
                "AWS config failed for power action {}: {}",
                describe_account.role_arn,
                err
            );
            state
                .audit_service
                .event(&claims.sub, AuditAction::Ec2Power, AuditOutcome::Failure)
                .account(Some(&req.account_id))
                .region(Some(&req.region))
                .target(Some(&req.instance_id))
                .error(Some("Failed to get credentials for target account"))
                .metadata(ec2_power_metadata(&audit_ctx, &req, None, None))
                .commit_best_effort();
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::internal(
                    "Failed to get credentials for target account",
                )),
            )
        })?;

        let ec2_client = AwsClients::ec2(&effective_config);
        let describe_resp = ec2_client
            .describe_instances()
            .instance_ids(&req.instance_id)
            .send()
            .await
            .map_err(|err| {
                tracing::error!(
                    "DescribeInstances failed for power action {}: {}",
                    req.instance_id,
                    err
                );
                state
                    .audit_service
                    .event(&claims.sub, AuditAction::Ec2Power, AuditOutcome::Denied)
                    .account(Some(&req.account_id))
                    .region(Some(&req.region))
                    .target(Some(&req.instance_id))
                    .error(Some("DescribeInstances failed or target not authorized"))
                    .metadata(ec2_power_metadata(&audit_ctx, &req, None, None))
                    .commit_best_effort();
                (
                    axum::http::StatusCode::FORBIDDEN,
                    Json(ApiError::forbidden("Power action not authorized")),
                )
            })?;

        let Some(sdk_instance) = describe_resp
            .reservations()
            .first()
            .and_then(|reservation| reservation.instances().first())
        else {
            state
                .audit_service
                .event(&claims.sub, AuditAction::Ec2Power, AuditOutcome::Denied)
                .account(Some(&req.account_id))
                .region(Some(&req.region))
                .target(Some(&req.instance_id))
                .error(Some("Instance not found or not authorized"))
                .metadata(ec2_power_metadata(&audit_ctx, &req, None, None))
                .commit_best_effort();
            return Err((
                axum::http::StatusCode::FORBIDDEN,
                Json(ApiError::forbidden("Power action not authorized")),
            ));
        };

        convert_sdk_instance(sdk_instance, &req.account_id, &req.region)
    };

    let scoped_target_accounts = ent_service
        .scoped_accounts_for_ec2_instance_feature(&claims, &target_instance, |features| {
            power_feature_enabled(req.action, features)
        })
        .await;

    if scoped_target_accounts.is_empty() {
        state
            .audit_service
            .event(&claims.sub, AuditAction::Ec2Power, AuditOutcome::Denied)
            .account(Some(&req.account_id))
            .region(Some(&req.region))
            .target(Some(&req.instance_id))
            .target_name(target_instance.name.as_deref())
            .error(Some(
                "Instance does not match any allowed power-action tag selector",
            ))
            .metadata(ec2_power_metadata(
                &audit_ctx,
                &req,
                Some(&target_instance.state),
                None,
            ))
            .commit_best_effort();
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden(
                "Instance does not match any allowed power-action tag selector",
            )),
        ));
    }

    let (selected_account, ec2_client) = if state.config.use_mock_aws() {
        (
            AllowedAccount {
                account_id: req.account_id.clone(),
                account_name: "mock".into(),
                role_arn: "direct".into(),
            },
            None,
        )
    } else {
        let required_simulations = required_power_simulations(&req);
        let Some(account) =
            select_account_for_simulations(&state, &scoped_target_accounts, &required_simulations)
                .await
        else {
            state
                .audit_service
                .event(&claims.sub, AuditAction::Ec2Power, AuditOutcome::Denied)
                .account(Some(&req.account_id))
                .region(Some(&req.region))
                .target(Some(&req.instance_id))
                .target_name(target_instance.name.as_deref())
                .error(Some("No authorized role can perform power action"))
                .metadata(ec2_power_metadata(
                    &audit_ctx,
                    &req,
                    Some(&target_instance.state),
                    None,
                ))
                .commit_best_effort();
            return Err((
                axum::http::StatusCode::FORBIDDEN,
                Json(ApiError::forbidden(format!(
                    "None of the {} matching roles for account {} can perform {:?}",
                    scoped_target_accounts.len(),
                    req.account_id,
                    simulated_action_names(&required_simulations)
                ))),
            ));
        };

        let session_ctx = SessionContext {
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
        };
        let effective_config = crate::aws::credentials::resolve_aws_config(
            &state.base_aws_config,
            &account,
            &req.region,
            &session_ctx,
        )
        .await
        .map_err(|err| {
            tracing::error!(
                "AWS config failed for power action {}: {}",
                account.role_arn,
                err
            );
            state
                .audit_service
                .event(&claims.sub, AuditAction::Ec2Power, AuditOutcome::Failure)
                .account(Some(&req.account_id))
                .region(Some(&req.region))
                .target(Some(&req.instance_id))
                .target_name(target_instance.name.as_deref())
                .error(Some("Failed to get credentials for target account"))
                .metadata(ec2_power_metadata(
                    &audit_ctx,
                    &req,
                    Some(&target_instance.state),
                    None,
                ))
                .commit_best_effort();
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::internal(
                    "Failed to get credentials for target account",
                )),
            )
        })?;

        (account, Some(AwsClients::ec2(&effective_config)))
    };

    let requested_state = match requested_state_for_power_action(req.action, &target_instance.state)
    {
        Ok(state) => state,
        Err(error_kind) => {
            state
                .audit_service
                .event(&claims.sub, AuditAction::Ec2Power, AuditOutcome::Denied)
                .account(Some(&req.account_id))
                .region(Some(&req.region))
                .target(Some(&req.instance_id))
                .target_name(target_instance.name.as_deref())
                .error(Some(error_kind))
                .metadata(ec2_power_metadata(
                    &audit_ctx,
                    &req,
                    Some(&target_instance.state),
                    None,
                ))
                .commit_best_effort();
            return Err((
                axum::http::StatusCode::CONFLICT,
                Json(ApiError::new("CONFLICT", error_kind)),
            ));
        }
    };

    let requested_state = if let Some(ec2_client) = ec2_client {
        match req.action {
            Ec2PowerAction::Start => {
                let resp = ec2_client
                    .start_instances()
                    .instance_ids(&req.instance_id)
                    .send()
                    .await
                    .map_err(|err| {
                        tracing::error!("StartInstances failed for {}: {}", req.instance_id, err);
                        state
                            .audit_service
                            .event(&claims.sub, AuditAction::Ec2Power, AuditOutcome::Failure)
                            .account(Some(&req.account_id))
                            .region(Some(&req.region))
                            .target(Some(&req.instance_id))
                            .target_name(target_instance.name.as_deref())
                            .error(Some("AWS StartInstances failed"))
                            .metadata(ec2_power_metadata(
                                &audit_ctx,
                                &req,
                                Some(&target_instance.state),
                                Some(&requested_state),
                            ))
                            .commit_best_effort();
                        (
                            axum::http::StatusCode::BAD_GATEWAY,
                            Json(ApiError::internal("AWS StartInstances failed")),
                        )
                    })?;
                sdk_state_change_current_state(resp.starting_instances().first(), requested_state)
            }
            Ec2PowerAction::Stop => {
                let resp = ec2_client
                    .stop_instances()
                    .instance_ids(&req.instance_id)
                    .send()
                    .await
                    .map_err(|err| {
                        tracing::error!("StopInstances failed for {}: {}", req.instance_id, err);
                        state
                            .audit_service
                            .event(&claims.sub, AuditAction::Ec2Power, AuditOutcome::Failure)
                            .account(Some(&req.account_id))
                            .region(Some(&req.region))
                            .target(Some(&req.instance_id))
                            .target_name(target_instance.name.as_deref())
                            .error(Some("AWS StopInstances failed"))
                            .metadata(ec2_power_metadata(
                                &audit_ctx,
                                &req,
                                Some(&target_instance.state),
                                Some(&requested_state),
                            ))
                            .commit_best_effort();
                        (
                            axum::http::StatusCode::BAD_GATEWAY,
                            Json(ApiError::internal("AWS StopInstances failed")),
                        )
                    })?;
                sdk_state_change_current_state(resp.stopping_instances().first(), requested_state)
            }
            Ec2PowerAction::Reboot => {
                ec2_client
                    .reboot_instances()
                    .instance_ids(&req.instance_id)
                    .send()
                    .await
                    .map_err(|err| {
                        tracing::error!("RebootInstances failed for {}: {}", req.instance_id, err);
                        state
                            .audit_service
                            .event(&claims.sub, AuditAction::Ec2Power, AuditOutcome::Failure)
                            .account(Some(&req.account_id))
                            .region(Some(&req.region))
                            .target(Some(&req.instance_id))
                            .target_name(target_instance.name.as_deref())
                            .error(Some("AWS RebootInstances failed"))
                            .metadata(ec2_power_metadata(
                                &audit_ctx,
                                &req,
                                Some(&target_instance.state),
                                Some(&requested_state),
                            ))
                            .commit_best_effort();
                        (
                            axum::http::StatusCode::BAD_GATEWAY,
                            Json(ApiError::internal("AWS RebootInstances failed")),
                        )
                    })?;
                requested_state
            }
        }
    } else {
        requested_state
    };

    let response = Ec2PowerResponse {
        instance_id: req.instance_id.clone(),
        action: req.action,
        previous_state: target_instance.state.clone(),
        requested_state: requested_state.clone(),
        message: power_success_message(&req, &requested_state),
    };

    state
        .audit_service
        .event(&claims.sub, AuditAction::Ec2Power, AuditOutcome::Success)
        .account(Some(&req.account_id))
        .region(Some(&req.region))
        .target(Some(&req.instance_id))
        .target_name(target_instance.name.as_deref())
        .metadata(ec2_power_metadata(
            &audit_ctx,
            &req,
            Some(&response.previous_state),
            Some(&response.requested_state),
        ))
        .commit_or_fail()
        .map_err(|audit_err| {
            (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::internal(format!(
                    "Power action blocked: audit write failed ({})",
                    audit_err
                ))),
            )
        })?;

    tracing::info!(
        role = %selected_account.role_arn,
        instance_id = %req.instance_id,
        action = %req.action,
        "EC2 power action requested"
    );

    Ok(Json(response))
}

async fn connect_instance(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
    headers: HeaderMap,
    Json(req): Json<ConnectRequest>,
) -> Result<Json<ConnectResponse>, (axum::http::StatusCode, Json<ApiError>)> {
    // Fail-closed: block connect if durable audit sink is broken
    if !state.audit_service.is_healthy() {
        return Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal(
                "Audit logging is unavailable — privileged operations are suspended",
            )),
        ));
    }
    let audit_ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);

    let ent_service = EntitlementService::new(state.entitlement_store.clone());
    let entitlements = ent_service.evaluate(&claims).await;

    // Scope-aware check: verify that a single rule grants the connect
    // feature AND covers the target account+region+OS user.
    let connect_feature_check = |f: &shared::dto::entitlements::FeatureFlags| -> bool {
        match req.method {
            ConnectMethod::Ssm => f.can_use_ssm,
            ConnectMethod::Ec2InstanceConnect => f.can_use_ec2_instance_connect,
            ConnectMethod::Ssh => f.can_use_ssm || f.can_use_ec2_instance_connect,
        }
    };
    if !ent_service
        .has_feature_for_scope(
            &claims,
            &req.account_id,
            Some(&req.region),
            None,
            req.os_user.as_deref(),
            connect_feature_check,
        )
        .await
    {
        state
            .audit_service
            .event(&claims.sub, AuditAction::Ec2Connect, AuditOutcome::Denied)
            .account(Some(&req.account_id))
            .region(Some(&req.region))
            .target(Some(&req.instance_id))
            .error(Some(
                "Connect not authorized for this scope (cross-group check)",
            ))
            .optional_metadata(Some(ec2_connect_metadata(&audit_ctx, &req)))
            .commit_best_effort();
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("Connect not authorized for this scope")),
        ));
    }

    // Look up the target instance to get its tags for tag-selector enforcement.
    // In production this queries the EC2 API; with mock data use stubs.
    let (instance_tags, target_instance_name, credentials, eic_endpoint_id, selected_account) =
        if state.config.use_mock_aws() {
            let all_instances = mock_instances();
            let inst = all_instances
                .iter()
                .find(|i| i.instance_id == req.instance_id);
            let instance_name = inst.and_then(|i| i.name.clone());
            let mut tags = inst.map(|i| i.tags.clone()).unwrap_or_default();
            // Pass IPs as pseudo-tags for SSH direct connect
            if let Some(i) = inst {
                if let Some(ref ip) = i.private_ip {
                    tags.insert("__private_ip".into(), ip.clone());
                }
                if let Some(ref ip) = i.public_ip {
                    tags.insert("__public_ip".into(), ip.clone());
                }
            }

            let creds = Some(AssumedRoleCredentials {
                access_key_id: "ASIADEVMOCK000000001".into(),
                secret_access_key: "dev-mock-secret-not-real".into(),
                session_token: "dev-mock-session-token".into(),
            });

            // In mock mode, use a synthetic account entry
            let mock_account = AllowedAccount {
                account_id: req.account_id.clone(),
                role_arn: "direct".into(),
                account_name: "mock".into(),
            };
            (tags, instance_name, creds, None::<String>, mock_account)
        } else {
            // Use scope-aware rules to find accounts: only consider entries
            // from rules that grant the connect feature for this account/region,
            // preventing cross-group role splicing.
            let scoped_connect_tuples = ent_service
                .scoped_accounts_for_feature(&claims, connect_feature_check)
                .await;
            let matching_accounts: Vec<_> = scoped_connect_tuples
                .into_iter()
                .filter(|(a, regions)| {
                    a.account_id == req.account_id
                        && (regions.is_empty() || regions.contains(&req.region))
                })
                .map(|(a, _)| a)
                .collect();

            if matching_accounts.is_empty() {
                state
                    .audit_service
                    .event(&claims.sub, AuditAction::Ec2Connect, AuditOutcome::Denied)
                    .account(Some(&req.account_id))
                    .region(Some(&req.region))
                    .target(Some(&req.instance_id))
                    .error(Some("Account not in entitlements"))
                    .optional_metadata(Some(ec2_connect_metadata(&audit_ctx, &req)))
                    .commit_best_effort();
                return Err((
                    axum::http::StatusCode::FORBIDDEN,
                    Json(ApiError::forbidden("Account not authorized")),
                ));
            }

            let use_ssm = matches!(req.method, ConnectMethod::Ssm);
            let use_eic = matches!(req.method, ConnectMethod::Ec2InstanceConnect);
            let use_ssh = matches!(req.method, ConnectMethod::Ssh);
            let ssm_os_user_enforced = use_ssm && req.os_user.is_some();

            // Determine which IAM actions and resources the connect method needs.
            // Simulate each action only against the resources it actually
            // supports; cross-product simulation creates false denies for
            // APIs like ec2:DescribeInstances that only support Resource "*".
            let required_simulations = required_connect_simulations(&req);

            // Pick the first matching account. For direct/profile modes, IAM
            // simulation is not applicable — just use the first match.
            // For real AssumeRole ARNs, use IAM SimulatePrincipalPolicy to find
            // a role that can actually perform the requested connect action.
            let account = {
                let all_local = matching_accounts
                    .iter()
                    .all(|a| a.role_arn == "direct" || a.role_arn.starts_with("profile:"));

                if all_local {
                    // All entries are direct/profile: skip IAM simulation, use first
                    matching_accounts.into_iter().next().unwrap()
                } else {
                    let iam_client = aws_sdk_iam::Client::new(&state.base_aws_config);
                    let mut chosen = None;
                    let mut local_fallback = None;
                    let mut first_assumable = None;
                    let mut all_sim_errored = true;
                    for candidate in &matching_accounts {
                        // Skip local-mode entries in mixed setups — they can't
                        // be evaluated via IAM simulation
                        if candidate.role_arn == "direct"
                            || candidate.role_arn.starts_with("profile:")
                        {
                            // Remember as last-resort fallback (lower priority than
                            // any positively-simulated AssumeRole candidate)
                            if local_fallback.is_none() {
                                local_fallback = Some(candidate.clone());
                            }
                            continue;
                        }
                        // Remember first AssumeRole candidate as fallback
                        if first_assumable.is_none() {
                            first_assumable = Some(candidate.clone());
                        }
                        let mut candidate_allowed = true;
                        let mut candidate_sim_errored = false;
                        for required in &required_simulations {
                            let mut sim = iam_client
                                .simulate_principal_policy()
                                .policy_source_arn(&candidate.role_arn)
                                .action_names(required.action);
                            for resource in &required.resources {
                                sim = sim.resource_arns(resource);
                            }
                            match sim.send().await {
                                Ok(sim_resp) => {
                                    all_sim_errored = false;
                                    let allowed = sim_resp.evaluation_results().iter().all(|r| {
                                        matches!(
                                        r.eval_decision(),
                                        aws_sdk_iam::types::PolicyEvaluationDecisionType::Allowed
                                    )
                                    });
                                    if !allowed {
                                        candidate_allowed = false;
                                        break;
                                    }
                                }
                                Err(e) => {
                                    candidate_sim_errored = true;
                                    tracing::warn!(
                                        role = %candidate.role_arn,
                                        action = required.action,
                                        error = %e,
                                        "IAM simulation failed, skipping candidate"
                                    );
                                    break;
                                }
                            }
                        }
                        if candidate_sim_errored {
                            continue;
                        }
                        if candidate_allowed {
                            chosen = Some(candidate.clone());
                            break;
                        }
                    }
                    // If all simulations errored (e.g. base identity lacks
                    // iam:SimulatePrincipalPolicy), fall back to the first
                    // AssumeRole candidate rather than denying outright.
                    if chosen.is_none() && all_sim_errored {
                        if let Some(fb) = first_assumable {
                            tracing::warn!(
                                "All IAM simulations failed — falling back to first \
                             AssumeRole candidate {}",
                                fb.role_arn
                            );
                            chosen = Some(fb);
                        }
                    }
                    // Use positively-verified role, simulation-error fallback,
                    // or local-mode fallback.
                    match chosen.or(local_fallback) {
                        Some(a) => a,
                        None => {
                            state
                                .audit_service
                                .event(&claims.sub, AuditAction::Ec2Connect, AuditOutcome::Denied)
                                .account(Some(&req.account_id))
                                .region(Some(&req.region))
                                .target(Some(&req.instance_id))
                                .error(Some("No authorized role can perform connect action"))
                                .optional_metadata(Some(ec2_connect_metadata(&audit_ctx, &req)))
                                .commit_best_effort();
                            return Err((
                                axum::http::StatusCode::FORBIDDEN,
                                Json(ApiError::forbidden(format!(
                                "None of the {} authorized roles for account {} can perform {:?}",
                                matching_accounts.len(),
                                req.account_id,
                                simulated_action_names(&required_simulations)
                            ))),
                            ));
                        }
                    }
                }
            };

            // Check region entitlement BEFORE any AWS calls to avoid
            // leaking instance existence via 404 vs 403 timing.
            if !entitlements.allowed_regions.contains(&req.region) {
                state
                    .audit_service
                    .event(&claims.sub, AuditAction::Ec2Connect, AuditOutcome::Denied)
                    .account(Some(&req.account_id))
                    .region(Some(&req.region))
                    .target(Some(&req.instance_id))
                    .error(Some("Region not authorized"))
                    .optional_metadata(Some(ec2_connect_metadata(&audit_ctx, &req)))
                    .commit_best_effort();
                return Err((
                    axum::http::StatusCode::FORBIDDEN,
                    Json(ApiError::forbidden(format!(
                        "Region '{}' not authorized",
                        req.region
                    ))),
                ));
            }

            let session_ctx = SessionContext {
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
            };

            // Resolve AWS config (direct/profile/AssumeRole) to look up instance tags
            let assumed_config = crate::aws::credentials::resolve_aws_config(
                &state.base_aws_config,
                &account,
                &req.region,
                &session_ctx,
            )
            .await
            .map_err(|e| {
                tracing::error!("AWS config failed for {}: {}", account.role_arn, e);
                state
                    .audit_service
                    .event(&claims.sub, AuditAction::Ec2Connect, AuditOutcome::Failure)
                    .account(Some(&req.account_id))
                    .region(Some(&req.region))
                    .target(Some(&req.instance_id))
                    .error(Some("Failed to get credentials for target account"))
                    .optional_metadata(Some(ec2_connect_metadata(&audit_ctx, &req)))
                    .commit_best_effort();
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiError::internal(
                        "Failed to get credentials for target account",
                    )),
                )
            })?;

            // Look up the target instance via DescribeInstances to get its tags
            let ec2_client = AwsClients::ec2(&assumed_config);

            let describe_resp = ec2_client
                .describe_instances()
                .instance_ids(&req.instance_id)
                .send()
                .await
                .map_err(|e| {
                    // Normalize to 403 to avoid leaking instance existence
                    tracing::error!("DescribeInstances failed for {}: {}", req.instance_id, e);
                    state
                        .audit_service
                        .event(&claims.sub, AuditAction::Ec2Connect, AuditOutcome::Denied)
                        .account(Some(&req.account_id))
                        .region(Some(&req.region))
                        .target(Some(&req.instance_id))
                        .error(Some("DescribeInstances failed or target not authorized"))
                        .optional_metadata(Some(ec2_connect_metadata(&audit_ctx, &req)))
                        .commit_best_effort();
                    (
                        axum::http::StatusCode::FORBIDDEN,
                        Json(ApiError::forbidden("Connect not authorized")),
                    )
                })?;

            let sdk_instance = describe_resp
                .reservations()
                .first()
                .and_then(|r| r.instances().first());

            // Extract VPC ID for EIC endpoint resolution, and tags for auth
            let (tags, instance_vpc_id, target_instance_name) = match sdk_instance {
                Some(inst) => {
                    let converted = convert_sdk_instance(inst, &account.account_id, &req.region);
                    let name = converted.name.clone();
                    let mut tags = converted.tags;
                    // Pass IPs as pseudo-tags for SSH direct connect
                    if let Some(ref ip) = converted.private_ip {
                        tags.insert("__private_ip".into(), ip.clone());
                    }
                    if let Some(ref ip) = converted.public_ip {
                        tags.insert("__public_ip".into(), ip.clone());
                    }
                    (tags, converted.vpc_id, name)
                }
                None => {
                    // Return 403 (not 404) to prevent instance-existence oracle.
                    // Callers with account/region access but no connect permission
                    // must not be able to distinguish missing from forbidden.
                    state
                        .audit_service
                        .event(&claims.sub, AuditAction::Ec2Connect, AuditOutcome::Denied)
                        .account(Some(&req.account_id))
                        .region(Some(&req.region))
                        .target(Some(&req.instance_id))
                        .error(Some("Instance not found or not authorized"))
                        .optional_metadata(Some(ec2_connect_metadata(&audit_ctx, &req)))
                        .commit_best_effort();
                    return Err((
                        axum::http::StatusCode::FORBIDDEN,
                        Json(ApiError::forbidden("Connect not authorized")),
                    ));
                }
            };

            // Reject session caps below STS minimum (900s). The entitlement says
            // the session must not exceed N seconds, but STS cannot issue creds
            // shorter than 900s. Rather than silently widening, fail closed.
            if let Some(cap) = entitlements.max_session_seconds {
                if cap > 0 && cap < 900 && !use_ssh {
                    state
                        .audit_service
                        .event(&claims.sub, AuditAction::Ec2Connect, AuditOutcome::Denied)
                        .account(Some(&req.account_id))
                        .region(Some(&req.region))
                        .target(Some(&req.instance_id))
                        .target_name(target_instance_name.as_deref())
                        .error(Some(&format!(
                            "max_session_seconds ({cap}s) is below STS minimum (900s)"
                        )))
                        .metadata(ec2_connect_metadata(&audit_ctx, &req))
                        .commit_best_effort();
                    return Err((
                        axum::http::StatusCode::FORBIDDEN,
                        Json(ApiError::forbidden(format!(
                            "Session cap ({cap}s) is below the minimum enforceable limit (900s). \
                         Increase max_session_seconds to at least 900 or remove the cap.",
                        ))),
                    ));
                }
            }

            // For direct/profile modes with non-SSH methods, we cannot issue
            // scoped STS credentials. Block the connect to prevent the CLI from
            // running with the operator's full ambient permissions.
            let is_local_mode =
                account.role_arn == "direct" || account.role_arn.starts_with("profile:");

            if is_local_mode && !use_ssh {
                state
                    .audit_service
                    .event(&claims.sub, AuditAction::Ec2Connect, AuditOutcome::Denied)
                    .account(Some(&req.account_id))
                    .region(Some(&req.region))
                    .target(Some(&req.instance_id))
                    .target_name(target_instance_name.as_deref())
                    .error(Some(
                        "SSM/EIC connect requires an AssumeRole ARN, not direct/profile credentials",
                    ))
                    .metadata(ec2_connect_metadata(&audit_ctx, &req))
                    .commit_best_effort();
                return Err((
                    axum::http::StatusCode::FORBIDDEN,
                    Json(ApiError::forbidden(
                        "SSM/EIC connect is not supported for direct/profile credential modes. \
                     Configure an AssumeRole ARN to enable scoped connect credentials.",
                    )),
                ));
            }

            let creds = if use_ssh {
                // Direct SSH doesn't go through AWS APIs — no IAM credentials needed.
                None
            } else {
                let policy = connect_session_policy(
                    &req.instance_id,
                    &account.account_id,
                    &req.region,
                    use_ssm,
                    use_eic,
                    ssm_os_user_enforced,
                    req.os_user.as_deref(),
                );
                let scoped_config = assume_role_scoped(
                    &state.base_aws_config,
                    &account,
                    &req.region,
                    &session_ctx,
                    &policy,
                    entitlements.max_session_seconds,
                )
                .await
                .map_err(|e| {
                    tracing::error!("Scoped AssumeRole failed: {}", e);
                    state
                        .audit_service
                        .event(&claims.sub, AuditAction::Ec2Connect, AuditOutcome::Failure)
                        .account(Some(&req.account_id))
                        .region(Some(&req.region))
                        .target(Some(&req.instance_id))
                        .target_name(target_instance_name.as_deref())
                        .error(Some("Failed to create scoped credentials for connect"))
                        .metadata(ec2_connect_metadata(&audit_ctx, &req))
                        .commit_best_effort();
                    (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ApiError::internal(
                            "Failed to create scoped credentials for connect",
                        )),
                    )
                })?;

                let creds_provider = scoped_config.credentials_provider().ok_or_else(|| {
                    state
                        .audit_service
                        .event(&claims.sub, AuditAction::Ec2Connect, AuditOutcome::Failure)
                        .account(Some(&req.account_id))
                        .region(Some(&req.region))
                        .target(Some(&req.instance_id))
                        .target_name(target_instance_name.as_deref())
                        .error(Some("Scoped config missing credentials"))
                        .metadata(ec2_connect_metadata(&audit_ctx, &req))
                        .commit_best_effort();
                    (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ApiError::internal("Scoped config missing credentials")),
                    )
                })?;

                let resolved_creds = creds_provider.provide_credentials().await.map_err(|e| {
                    tracing::error!("Failed to resolve scoped credentials: {}", e);
                    state
                        .audit_service
                        .event(&claims.sub, AuditAction::Ec2Connect, AuditOutcome::Failure)
                        .account(Some(&req.account_id))
                        .region(Some(&req.region))
                        .target(Some(&req.instance_id))
                        .target_name(target_instance_name.as_deref())
                        .error(Some("Failed to resolve scoped credentials"))
                        .metadata(ec2_connect_metadata(&audit_ctx, &req))
                        .commit_best_effort();
                    (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ApiError::internal("Failed to resolve scoped credentials")),
                    )
                })?;

                Some(AssumedRoleCredentials {
                    access_key_id: resolved_creds.access_key_id().to_string(),
                    secret_access_key: resolved_creds.secret_access_key().to_string(),
                    session_token: resolved_creds.session_token().unwrap_or("").to_string(),
                })
            };

            // For EIC, resolve the endpoint server-side so the scoped creds
            // don't need ec2:Describe* (which would break isolation).
            // Filter by the target instance's VPC to avoid selecting an endpoint
            // from a different VPC/subnet, which would fail at connect time.
            let eic_ep = if matches!(req.method, ConnectMethod::Ec2InstanceConnect) {
                let ec2_client = AwsClients::ec2(&assumed_config);
                match ec2_client
                    .describe_instance_connect_endpoints()
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let endpoints = resp.instance_connect_endpoints();
                        // Filter to endpoints in the same VPC as the target instance
                        let matching: Vec<_> = if let Some(ref vpc) = instance_vpc_id {
                            endpoints
                                .iter()
                                .filter(|ep| ep.vpc_id().map(|v| v == vpc).unwrap_or(false))
                                .collect()
                        } else {
                            endpoints.iter().collect()
                        };

                        if matching.len() > 1 {
                            tracing::warn!(
                                count = matching.len(),
                                vpc = ?instance_vpc_id,
                                "Multiple EIC endpoints found — using first match"
                            );
                        }

                        matching
                            .first()
                            .and_then(|ep| ep.instance_connect_endpoint_id().map(|s| s.to_string()))
                    }
                    Err(e) => {
                        tracing::warn!("Failed to resolve EIC endpoint: {}", e);
                        None
                    }
                }
            } else {
                None
            };

            (tags, target_instance_name, creds, eic_ep, account)
        };

    let connect_rule_scopes = ent_service
        .rule_scopes_for_feature(&claims, connect_feature_check)
        .await;
    let mut response = build_connect_command(
        &req,
        &entitlements,
        &instance_tags,
        credentials.as_ref(),
        eic_endpoint_id.as_deref(),
        &connect_rule_scopes,
    );

    // For profile: mode, set AWS_PROFILE so the spawned CLI uses the right credentials.
    // Use the `account` entry that was already selected by IAM simulation
    // (not a fresh lookup) to ensure consistency with the authorized role.
    if response.authorized && !state.config.use_mock_aws() {
        if let Some(profile_name) = selected_account.role_arn.strip_prefix("profile:") {
            response
                .env_vars
                .insert("AWS_PROFILE".into(), profile_name.to_string());
        }
    }

    let outcome = if response.authorized {
        AuditOutcome::Success
    } else {
        AuditOutcome::Denied
    };

    // Fail-closed: block the response if the audit write fails
    if let Err(audit_err) = state
        .audit_service
        .event(&claims.sub, AuditAction::Ec2Connect, outcome)
        .account(Some(&req.account_id))
        .region(Some(&req.region))
        .target(Some(&req.instance_id))
        .target_name(target_instance_name.as_deref())
        .error(response.error.as_deref())
        .metadata(ec2_connect_metadata(&audit_ctx, &req))
        .commit_or_fail()
    {
        return Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal(format!(
                "Connect blocked: audit write failed ({})",
                audit_err
            ))),
        ));
    }

    if !response.authorized {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden(
                response.error.as_deref().unwrap_or("Not authorized"),
            )),
        ));
    }

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connect_req(method: ConnectMethod, os_user: Option<&str>) -> ConnectRequest {
        ConnectRequest {
            instance_id: "i-1234567890abcdef0".into(),
            account_id: "111111111111".into(),
            region: "ap-northeast-1".into(),
            method,
            os_user: os_user.map(str::to_string),
        }
    }

    #[test]
    fn ssm_shell_simulates_only_shell_document() {
        let simulations = required_connect_simulations(&connect_req(ConnectMethod::Ssm, None));
        let ssm = simulations
            .iter()
            .find(|s| s.action == "ssm:StartSession")
            .unwrap();

        assert!(ssm
            .resources
            .iter()
            .any(|r| r.ends_with("document/SSM-SessionManagerRunShell")));
        assert!(!ssm
            .resources
            .iter()
            .any(|r| r.ends_with("document/AWS-StartSSHSession")));
    }

    #[test]
    fn ssm_ssh_simulates_only_ssh_document() {
        let simulations =
            required_connect_simulations(&connect_req(ConnectMethod::Ssm, Some("ubuntu")));
        let ssm = simulations
            .iter()
            .find(|s| s.action == "ssm:StartSession")
            .unwrap();

        assert!(ssm
            .resources
            .iter()
            .any(|r| r.ends_with("document/AWS-StartSSHSession")));
        assert!(!ssm
            .resources
            .iter()
            .any(|r| r.ends_with("document/SSM-SessionManagerRunShell")));
    }

    #[test]
    fn direct_ssh_only_simulates_describe_instances() {
        let simulations = required_connect_simulations(&connect_req(ConnectMethod::Ssh, None));

        assert_eq!(simulations.len(), 1);
        assert_eq!(simulations[0].action, "ec2:DescribeInstances");
        assert_eq!(simulations[0].resources, vec!["*".to_string()]);
    }

    #[test]
    fn eic_simulates_instance_and_endpoint_actions() {
        let simulations = required_connect_simulations(&connect_req(
            ConnectMethod::Ec2InstanceConnect,
            Some("ubuntu"),
        ));

        assert!(simulations
            .iter()
            .any(|s| s.action == "ec2-instance-connect:SendSSHPublicKey"));
        assert!(simulations
            .iter()
            .any(|s| s.action == "ec2-instance-connect:OpenTunnel"));
    }
}
