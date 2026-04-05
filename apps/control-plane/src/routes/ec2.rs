use aws_credential_types::provider::ProvideCredentials;
use axum::{extract::State, routing::post, Json, Router};
use std::sync::Arc;

use crate::aws::clients::AwsClients;
use crate::aws::credentials::{
    assume_role_scoped, connect_session_policy, SessionContext,
};
use crate::aws::ec2_convert::convert_sdk_instance;
use crate::middleware::auth::AuthenticatedUser;
use crate::services::ec2::{
    apply_user_filters, build_connect_command, filter_instances_by_entitlements, mock_instances,
    AssumedRoleCredentials,
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
        let default_region = state.config.aws.default_region.clone()
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
                    &base_config, &account, &region, &session_ctx,
                ).await?;

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
    Json(req): Json<Ec2ListRequest>,
) -> Result<Json<Ec2ListResponse>, (axum::http::StatusCode, Json<ApiError>)> {
    if !state.audit_service.is_healthy() {
        return Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::internal("Audit logging unavailable")),
        ));
    }
    let ent_service = EntitlementService::new(state.entitlement_store.clone());
    let entitlements = ent_service.evaluate(&claims).await;

    if !entitlements.features.can_view_ec2 {
        let _ = state.audit_service.log_event(
            &claims.sub,
            AuditAction::Ec2List,
            AuditOutcome::Denied,
            req.account_id.as_deref(),
            req.region.as_deref(),
            None,
            Some("EC2 view not authorized"),
        );
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("EC2 view not authorized")),
        ));
    }

    // Derive per-rule (account, regions) tuples for scope-aware fan-out.
    let scoped_tuples = ent_service.scoped_accounts_for_feature(
        &claims, |f| f.can_view_ec2,
    ).await;

    // Use mock data or real AWS depending on config.
    let (all_instances, failed_scopes) = if state.config.use_mock_aws() {
        (mock_instances(), vec![])
    } else {
        fetch_instances_from_aws(
            &state,
            &entitlements,
            &scoped_tuples,
            req.account_id.as_deref(),
            req.region.as_deref(),
        ).await?
    };

    // CRITICAL: Server-side entitlement filtering before any client filters.
    // Use per-rule scopes to prevent cross-group tag-selector splicing.
    let rule_scopes = ent_service.rule_scopes_for_feature(&claims, |f| f.can_view_ec2).await;
    let entitled_instances = filter_instances_by_entitlements(all_instances, &entitlements, &rule_scopes);

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

    state.audit_service.log_event(
        &claims.sub,
        AuditAction::Ec2List,
        AuditOutcome::Success,
        req.account_id.as_deref(),
        req.region.as_deref(),
        None,
        None,
    ).map_err(|_| (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        Json(ApiError::internal("Audit logging failed — refusing to return data")),
    ))?;

    Ok(Json(Ec2ListResponse {
        instances: page,
        next_token,
        total_count,
        failed_scopes,
    }))
}

async fn connect_instance(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(claims): AuthenticatedUser,
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
    if !ent_service.has_feature_for_scope(
        &claims,
        &req.account_id,
        Some(&req.region),
        None,
        req.os_user.as_deref(),
        connect_feature_check,
    ).await {
        let _ = state.audit_service.log_event(
            &claims.sub,
            AuditAction::Ec2Connect,
            AuditOutcome::Denied,
            Some(&req.account_id),
            Some(&req.region),
            Some(&req.instance_id),
            Some("Connect not authorized for this scope (cross-group check)"),
        );
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(ApiError::forbidden("Connect not authorized for this scope")),
        ));
    }

    // Look up the target instance to get its tags for tag-selector enforcement.
    // In production this queries the EC2 API; with mock data use stubs.
    let (instance_tags, credentials, eic_endpoint_id, selected_account) = if state.config.use_mock_aws() {
        let all_instances = mock_instances();
        let inst = all_instances
            .iter()
            .find(|i| i.instance_id == req.instance_id);
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
        (tags, creds, None::<String>, mock_account)
    } else {
        // Use scope-aware rules to find accounts: only consider entries
        // from rules that grant the connect feature for this account/region,
        // preventing cross-group role splicing.
        let scoped_connect_tuples = ent_service.scoped_accounts_for_feature(
            &claims, connect_feature_check,
        ).await;
        let matching_accounts: Vec<_> = scoped_connect_tuples
            .into_iter()
            .filter(|(a, regions)| {
                a.account_id == req.account_id
                    && (regions.is_empty() || regions.contains(&req.region))
            })
            .map(|(a, _)| a)
            .collect();

        if matching_accounts.is_empty() {
            let _ = state.audit_service.log_event(
                &claims.sub,
                AuditAction::Ec2Connect,
                AuditOutcome::Denied,
                Some(&req.account_id),
                Some(&req.region),
                Some(&req.instance_id),
                Some("Account not in entitlements"),
            );
            return Err((
                axum::http::StatusCode::FORBIDDEN,
                Json(ApiError::forbidden("Account not authorized")),
            ));
        }

        let use_ssm = matches!(req.method, ConnectMethod::Ssm);
        let use_eic = matches!(req.method, ConnectMethod::Ec2InstanceConnect);
        let use_ssh = matches!(req.method, ConnectMethod::Ssh);
        let ssm_os_user_enforced = use_ssm && req.os_user.is_some();

        // Determine which IAM actions AND resources the connect method needs.
        // Build a complete simulation set so the role chooser proves full access.
        let mut required_actions = vec!["ec2:DescribeInstances".to_string()];
        let mut required_resources = vec![format!(
            "arn:aws:ec2:{}:{}:instance/{}",
            req.region, req.account_id, req.instance_id
        )];

        if use_ssm {
            required_actions.push("ssm:StartSession".to_string());
            if ssm_os_user_enforced {
                required_resources.push(format!(
                    "arn:aws:ssm:{}::document/AWS-StartSSHSession",
                    req.region
                ));
            } else {
                required_resources.push(format!(
                    "arn:aws:ssm:{}::document/AWS-StartSSHSession",
                    req.region
                ));
                required_resources.push(format!(
                    "arn:aws:ssm:{}::document/SSM-SessionManagerRunShell",
                    req.region
                ));
            }
        } else if use_eic {
            required_actions.push("ec2-instance-connect:SendSSHPublicKey".to_string());
            required_actions.push("ec2-instance-connect:OpenTunnel".to_string());
            required_resources.push(format!(
                "arn:aws:ec2:{}:{}:instance-connect-endpoint/*",
                req.region, req.account_id
            ));
        }

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
                    let mut sim = iam_client
                        .simulate_principal_policy()
                        .policy_source_arn(&candidate.role_arn);
                    for resource in &required_resources {
                        sim = sim.resource_arns(resource);
                    }
                    for action in &required_actions {
                        sim = sim.action_names(action);
                    }
                    match sim.send().await {
                        Ok(sim_resp) => {
                            all_sim_errored = false;
                            // All requested actions must be allowed
                            let allowed = sim_resp.evaluation_results().iter().all(|r| {
                                matches!(
                                    r.eval_decision(),
                                    aws_sdk_iam::types::PolicyEvaluationDecisionType::Allowed
                                )
                            });
                            if allowed {
                                chosen = Some(candidate.clone());
                                break;
                            }
                            // Not allowed — try next candidate
                        }
                        Err(e) => {
                            // Simulation error is inconclusive — skip this
                            // candidate and try the next one instead of
                            // blindly selecting it.
                            tracing::warn!(
                                role = %candidate.role_arn,
                                error = %e,
                                "IAM simulation failed, skipping candidate"
                            );
                        }
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
                        return Err((
                            axum::http::StatusCode::FORBIDDEN,
                            Json(ApiError::forbidden(format!(
                                "None of the {} authorized roles for account {} can perform {:?}",
                                matching_accounts.len(),
                                req.account_id,
                                required_actions
                            ))),
                        ));
                    }
                }
            }
        };

        // Check region entitlement BEFORE any AWS calls to avoid
        // leaking instance existence via 404 vs 403 timing.
        if !entitlements.allowed_regions.contains(&req.region) {
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
            &state.base_aws_config, &account, &req.region, &session_ctx,
        )
        .await
        .map_err(|e| {
            tracing::error!("AWS config failed for {}: {}", account.role_arn, e);
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
        let (tags, instance_vpc_id) = match sdk_instance {
            Some(inst) => {
                let converted = convert_sdk_instance(inst, &account.account_id, &req.region);
                let mut tags = converted.tags;
                // Pass IPs as pseudo-tags for SSH direct connect
                if let Some(ref ip) = converted.private_ip {
                    tags.insert("__private_ip".into(), ip.clone());
                }
                if let Some(ref ip) = converted.public_ip {
                    tags.insert("__public_ip".into(), ip.clone());
                }
                (tags, converted.vpc_id)
            }
            None => {
                // Return 403 (not 404) to prevent instance-existence oracle.
                // Callers with account/region access but no connect permission
                // must not be able to distinguish missing from forbidden.
                let _ = state.audit_service.log_event(
                    &claims.sub,
                    AuditAction::Ec2Connect,
                    AuditOutcome::Denied,
                    Some(&req.account_id),
                    Some(&req.region),
                    Some(&req.instance_id),
                    Some("Instance not found or not authorized"),
                );
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
                let _ = state.audit_service.log_event(
                    &claims.sub,
                    AuditAction::Ec2Connect,
                    AuditOutcome::Denied,
                    Some(&req.account_id),
                    Some(&req.region),
                    Some(&req.instance_id),
                    Some(&format!(
                        "max_session_seconds ({cap}s) is below STS minimum (900s)"
                    )),
                );
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
        let is_local_mode = account.role_arn == "direct" || account.role_arn.starts_with("profile:");

        if is_local_mode && !use_ssh {
            let _ = state.audit_service.log_event(
                &claims.sub,
                AuditAction::Ec2Connect,
                AuditOutcome::Denied,
                Some(&req.account_id),
                Some(&req.region),
                Some(&req.instance_id),
                Some("SSM/EIC connect requires an AssumeRole ARN, not direct/profile credentials"),
            );
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
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiError::internal(
                        "Failed to create scoped credentials for connect",
                    )),
                )
            })?;

            let creds_provider = scoped_config.credentials_provider().ok_or_else(|| {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiError::internal("Scoped config missing credentials")),
                )
            })?;

            let resolved_creds = creds_provider.provide_credentials().await.map_err(|e| {
                tracing::error!("Failed to resolve scoped credentials: {}", e);
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

        (tags, creds, eic_ep, account)
    };

    let connect_rule_scopes = ent_service.rule_scopes_for_feature(&claims, connect_feature_check).await;
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
            response.env_vars.insert("AWS_PROFILE".into(), profile_name.to_string());
        }
    }

    let outcome = if response.authorized {
        AuditOutcome::Success
    } else {
        AuditOutcome::Denied
    };

    // Fail-closed: block the response if the audit write fails
    if let Err(audit_err) = state.audit_service.log_event(
        &claims.sub,
        AuditAction::Ec2Connect,
        outcome,
        Some(&req.account_id),
        Some(&req.region),
        Some(&req.instance_id),
        response.error.as_deref(),
    ) {
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
