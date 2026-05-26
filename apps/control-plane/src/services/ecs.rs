use shared::dto::ecs::{
    EcsContainer, EcsExecRequest, EcsExecResponse, EcsTask, DEV_MOCK_CLUSTER_NAME,
};
use shared::dto::entitlements::{AllowedAccount, TagSelector, UserEntitlements};
use std::collections::HashMap;

use crate::services::entitlements::arn_matches_pattern;

pub use shared::dto::ec2::AssumedRoleCredentials;

/// A single rule's scope for ECS access. Account, region, cluster, task tags,
/// deny tags, and sidecar denylist must stay together to prevent privilege
/// splicing across groups.
#[derive(Debug, Clone)]
pub struct EcsRuleScope {
    pub accounts: Vec<AllowedAccount>,
    pub account_ids: Vec<String>,
    pub regions: Vec<String>,
    pub cluster_patterns: Vec<String>,
    pub allow_selectors: Vec<TagSelector>,
    pub deny_selectors: Vec<TagSelector>,
    pub excluded_container_names: Vec<String>,
    pub allow_broad_cluster_discovery: bool,
}

pub fn cluster_arn(region: &str, account_id: &str, cluster_name: &str) -> String {
    format!("arn:aws:ecs:{region}:{account_id}:cluster/{cluster_name}")
}

pub fn cluster_name_from_arn(cluster: &str) -> String {
    cluster
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(cluster)
        .to_string()
}

pub fn task_id_from_arn(task_arn: &str) -> Option<String> {
    task_arn
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

pub fn ecs_arn_region_account(arn: &str) -> Option<(&str, &str)> {
    let mut parts = arn.split(':');
    match (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        (Some("arn"), Some(_partition), Some("ecs"), Some(region), Some(account)) => {
            Some((region, account))
        }
        _ => None,
    }
}

pub fn normalize_cluster_patterns(
    entries: &[String],
    account_ids: &[String],
    regions: &[String],
) -> Vec<String> {
    let effective_regions: Vec<&str> = if regions.is_empty() {
        vec!["*"]
    } else {
        regions.iter().map(String::as_str).collect()
    };

    let mut patterns = Vec::new();
    for entry in entries {
        if entry.starts_with("arn:") {
            if !patterns.contains(entry) {
                patterns.push(entry.clone());
            }
            continue;
        }
        for account in account_ids {
            for region in &effective_regions {
                let pattern = cluster_arn(region, account, entry);
                if !patterns.contains(&pattern) {
                    patterns.push(pattern);
                }
            }
        }
    }
    patterns
}

pub fn cluster_matches_pattern(pattern: &str, cluster_arn: &str) -> bool {
    arn_matches_pattern(pattern, cluster_arn)
}

pub fn convert_sdk_task(
    task: &aws_sdk_ecs::types::Task,
    account_id: &str,
    region: &str,
) -> EcsTask {
    let task_arn = task.task_arn().unwrap_or_default().to_string();
    let cluster_arn_value = task.cluster_arn().unwrap_or_default().to_string();
    let cluster_name = cluster_name_from_arn(&cluster_arn_value);
    let family = task
        .task_definition_arn()
        .and_then(|arn| arn.rsplit('/').next())
        .and_then(|tail| tail.split(':').next())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);

    let launch_type = task
        .launch_type()
        .map(|launch_type| launch_type.as_str().to_string())
        .unwrap_or_else(|| "UNKNOWN".to_string());

    let containers = task
        .containers()
        .iter()
        .map(|container| {
            let execute_command_agent_running = container.managed_agents().iter().any(|agent| {
                let is_exec_agent = agent
                    .name()
                    .map(|name| {
                        matches!(
                            name,
                            aws_sdk_ecs::types::ManagedAgentName::ExecuteCommandAgent
                        )
                    })
                    .unwrap_or(false);
                is_exec_agent && agent.last_status() == Some("RUNNING")
            });

            EcsContainer {
                name: container.name().unwrap_or_default().to_string(),
                last_status: container.last_status().unwrap_or_default().to_string(),
                execute_command_agent_running,
            }
        })
        .collect();

    let tags = task
        .tags()
        .iter()
        .filter_map(|tag| Some((tag.key()?.to_string(), tag.value()?.to_string())))
        .collect();

    EcsTask {
        task_arn: task_arn.clone(),
        cluster_arn: cluster_arn_value,
        cluster_name,
        account_id: account_id.to_string(),
        region: region.to_string(),
        family,
        task_id: task_id_from_arn(&task_arn),
        launch_type,
        last_status: task.last_status().unwrap_or_default().to_string(),
        desired_status: task.desired_status().unwrap_or_default().to_string(),
        enable_execute_command: task.enable_execute_command(),
        containers,
        tags,
    }
}

pub fn filter_tasks_by_entitlements(
    tasks: Vec<EcsTask>,
    entitlements: &UserEntitlements,
    rule_scopes: &[EcsRuleScope],
) -> Vec<EcsTask> {
    tasks
        .into_iter()
        .filter(|task| {
            if rule_scopes.is_empty() {
                if entitlements
                    .excluded_task_tag_selectors
                    .iter()
                    .any(|selector| selector.matches(&task.tags))
                {
                    return false;
                }

                return entitlements
                    .allowed_accounts
                    .iter()
                    .any(|a| a.account_id == task.account_id)
                    && (entitlements.allowed_regions.is_empty()
                        || entitlements.allowed_regions.contains(&task.region))
                    && entitlements
                        .allowed_clusters
                        .iter()
                        .any(|pattern| cluster_matches_pattern(pattern, &task.cluster_arn))
                    && (entitlements.task_tag_selectors.is_empty()
                        || entitlements
                            .task_tag_selectors
                            .iter()
                            .any(|selector| selector.matches(&task.tags)));
            }

            rule_scopes
                .iter()
                .any(|scope| task_matches_rule_scope(task, scope))
        })
        .collect()
}

pub fn task_matches_rule_scope(task: &EcsTask, scope: &EcsRuleScope) -> bool {
    if !scope.account_ids.contains(&task.account_id) {
        return false;
    }
    if !scope.regions.is_empty() && !scope.regions.contains(&task.region) {
        return false;
    }
    if !scope
        .cluster_patterns
        .iter()
        .any(|pattern| cluster_matches_pattern(pattern, &task.cluster_arn))
    {
        return false;
    }
    if !scope.allow_selectors.is_empty()
        && !scope
            .allow_selectors
            .iter()
            .any(|selector| selector.matches(&task.tags))
    {
        return false;
    }
    if scope
        .deny_selectors
        .iter()
        .any(|selector| selector.matches(&task.tags))
    {
        return false;
    }
    true
}

pub fn matching_rule_scopes<'a>(
    task: &EcsTask,
    rule_scopes: &'a [EcsRuleScope],
) -> Vec<&'a EcsRuleScope> {
    rule_scopes
        .iter()
        .filter(|scope| task_matches_rule_scope(task, scope))
        .collect()
}

pub fn build_ecs_exec_command(
    req: &EcsExecRequest,
    entitlements: &UserEntitlements,
    task: &EcsTask,
    credentials: Option<&AssumedRoleCredentials>,
    rule_scopes: &[EcsRuleScope],
) -> Result<EcsExecResponse, String> {
    if req.container_name.trim().is_empty() {
        return Err("Container name is required".into());
    }
    if !entitlements.features.can_use_ecs_exec {
        return Err("ECS exec not authorized".into());
    }
    if !entitlements
        .allowed_accounts
        .iter()
        .any(|a| a.account_id == req.account_id)
    {
        return Err("Account not authorized".into());
    }
    if !entitlements.allowed_regions.is_empty()
        && !entitlements.allowed_regions.contains(&req.region)
    {
        return Err(format!("Region '{}' not authorized", req.region));
    }
    if req.cluster_arn != task.cluster_arn || req.task_arn != task.task_arn {
        return Err("Task does not match requested cluster/task".into());
    }
    if !rule_scopes.is_empty() {
        let matching_scopes = rule_scopes
            .iter()
            .filter(|scope| task_matches_rule_scope(task, scope))
            .collect::<Vec<_>>();
        if matching_scopes.is_empty() {
            return Err("Task does not match any allowed ECS scope".into());
        }
        if !matching_scopes.iter().any(|scope| {
            !scope
                .excluded_container_names
                .iter()
                .any(|excluded| excluded == &req.container_name)
        }) {
            return Err("Container is excluded by ECS sidecar denylist".into());
        }
    }

    let Some(container) = task
        .containers
        .iter()
        .find(|container| container.name == req.container_name)
    else {
        return Err("Container not found in task".into());
    };
    if container.last_status != "RUNNING" {
        return Err("Container is not running".into());
    }
    if !container.execute_command_agent_running {
        return Err("ECS execute-command agent is not running".into());
    }

    let mut env_vars = HashMap::from([("AWS_DEFAULT_REGION".into(), req.region.clone())]);
    if let Some(creds) = credentials {
        env_vars.insert("AWS_ACCESS_KEY_ID".into(), creds.access_key_id.clone());
        env_vars.insert(
            "AWS_SECRET_ACCESS_KEY".into(),
            creds.secret_access_key.clone(),
        );
        env_vars.insert("AWS_SESSION_TOKEN".into(), creds.session_token.clone());
    }

    Ok(EcsExecResponse {
        command: "aws".into(),
        args: vec![
            "ecs".into(),
            "execute-command".into(),
            "--cluster".into(),
            req.cluster_arn.clone(),
            "--task".into(),
            req.task_arn.clone(),
            "--container".into(),
            req.container_name.clone(),
            "--interactive".into(),
            "--command".into(),
            "/bin/sh".into(),
            "--region".into(),
            req.region.clone(),
        ],
        env_vars,
        max_session_seconds: entitlements.max_session_seconds,
    })
}

pub fn mock_tasks() -> Vec<EcsTask> {
    let cluster = cluster_arn("us-east-1", "111111111111", DEV_MOCK_CLUSTER_NAME);
    vec![
        EcsTask {
            task_arn: format!(
                "arn:aws:ecs:us-east-1:111111111111:task/{DEV_MOCK_CLUSTER_NAME}/1111222233334444"
            ),
            cluster_arn: cluster.clone(),
            cluster_name: DEV_MOCK_CLUSTER_NAME.into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            family: Some("web".into()),
            task_id: Some("1111222233334444".into()),
            launch_type: "FARGATE".into(),
            last_status: "RUNNING".into(),
            desired_status: "RUNNING".into(),
            enable_execute_command: true,
            containers: vec![
                EcsContainer {
                    name: "app".into(),
                    last_status: "RUNNING".into(),
                    execute_command_agent_running: true,
                },
                EcsContainer {
                    name: "xray-daemon".into(),
                    last_status: "RUNNING".into(),
                    execute_command_agent_running: true,
                },
            ],
            tags: HashMap::from([
                ("Environment".into(), "production".into()),
                ("Service".into(), "web".into()),
            ]),
        },
        EcsTask {
            task_arn: format!(
                "arn:aws:ecs:us-east-1:111111111111:task/{DEV_MOCK_CLUSTER_NAME}/5555666677778888"
            ),
            cluster_arn: cluster,
            cluster_name: DEV_MOCK_CLUSTER_NAME.into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            family: Some("worker".into()),
            task_id: Some("5555666677778888".into()),
            launch_type: "EC2".into(),
            last_status: "RUNNING".into(),
            desired_status: "RUNNING".into(),
            enable_execute_command: false,
            containers: vec![EcsContainer {
                name: "worker".into(),
                last_status: "RUNNING".into(),
                execute_command_agent_running: false,
            }],
            tags: HashMap::from([
                ("Environment".into(), "production".into()),
                ("Service".into(), "worker".into()),
            ]),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::dto::entitlements::{AllowedAccount, FeatureFlags};

    fn entitlements() -> UserEntitlements {
        UserEntitlements {
            user_id: "user".into(),
            email: "user@example.com".into(),
            display_name: "User".into(),
            groups: vec!["platform".into()],
            features: FeatureFlags {
                can_view_ecs: true,
                can_use_ecs_exec: true,
                ..Default::default()
            },
            allowed_accounts: vec![AllowedAccount {
                account_id: "111111111111".into(),
                account_name: "production".into(),
                role_arn: "arn:aws:iam::111111111111:role/CanopyRole".into(),
            }],
            allowed_regions: vec!["us-east-1".into()],
            allowed_log_group_arns: vec![],
            instance_tag_selectors: vec![],
            excluded_tag_selectors: vec![],
            allowed_clusters: vec![cluster_arn(
                "us-east-1",
                "111111111111",
                DEV_MOCK_CLUSTER_NAME,
            )],
            task_tag_selectors: vec![],
            excluded_task_tag_selectors: vec![],
            excluded_container_names: vec![],
            allow_broad_cluster_discovery: false,
            allowed_os_users: vec![],
            max_session_seconds: Some(3600),
        }
    }

    fn rule_scope() -> EcsRuleScope {
        EcsRuleScope {
            accounts: entitlements().allowed_accounts,
            account_ids: vec!["111111111111".into()],
            regions: vec!["us-east-1".into()],
            cluster_patterns: vec![cluster_arn(
                "us-east-1",
                "111111111111",
                DEV_MOCK_CLUSTER_NAME,
            )],
            allow_selectors: vec![],
            deny_selectors: vec![],
            excluded_container_names: vec!["xray-daemon".into()],
            allow_broad_cluster_discovery: false,
        }
    }

    #[test]
    fn filter_tasks_by_cluster_allowlist_arn_pattern() {
        let tasks = mock_tasks();
        let filtered = filter_tasks_by_entitlements(tasks, &entitlements(), &[rule_scope()]);
        assert_eq!(filtered.len(), 2);
        assert!(filtered
            .iter()
            .all(|task| task.cluster_name == DEV_MOCK_CLUSTER_NAME));
    }

    #[test]
    fn filter_tasks_by_task_tags() {
        let mut scope = rule_scope();
        scope.allow_selectors = vec![TagSelector {
            tags: HashMap::from([("Service".into(), vec!["web".into()])]),
        }];

        let filtered = filter_tasks_by_entitlements(mock_tasks(), &entitlements(), &[scope]);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].family.as_deref(), Some("web"));
    }

    #[test]
    fn excluded_task_tag_selectors_hide_matching() {
        let mut scope = rule_scope();
        scope.deny_selectors = vec![TagSelector {
            tags: HashMap::from([("Service".into(), vec!["worker".into()])]),
        }];

        let filtered = filter_tasks_by_entitlements(mock_tasks(), &entitlements(), &[scope]);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].family.as_deref(), Some("web"));
    }

    #[test]
    fn per_rule_deny_selector_does_not_hide_task_authorized_by_another_rule() {
        let mut ent = entitlements();
        ent.excluded_task_tag_selectors = vec![TagSelector {
            tags: HashMap::from([("Service".into(), vec!["web".into()])]),
        }];

        let mut denying_scope = rule_scope();
        denying_scope.allow_selectors = vec![TagSelector {
            tags: HashMap::from([("Service".into(), vec!["worker".into()])]),
        }];
        denying_scope.deny_selectors = vec![TagSelector {
            tags: HashMap::from([("Service".into(), vec!["web".into()])]),
        }];

        let mut allowing_scope = rule_scope();
        allowing_scope.allow_selectors = vec![TagSelector {
            tags: HashMap::from([("Service".into(), vec!["web".into()])]),
        }];
        allowing_scope.deny_selectors = vec![];

        let filtered =
            filter_tasks_by_entitlements(mock_tasks(), &ent, &[denying_scope, allowing_scope]);
        assert!(filtered
            .iter()
            .any(|task| task.family.as_deref() == Some("web")));
    }

    #[test]
    fn build_ecs_exec_command_authorized_emits_correct_args() {
        let task = mock_tasks().remove(0);
        let req = EcsExecRequest {
            account_id: task.account_id.clone(),
            region: task.region.clone(),
            cluster_arn: task.cluster_arn.clone(),
            task_arn: task.task_arn.clone(),
            container_name: "app".into(),
        };
        let resp =
            build_ecs_exec_command(&req, &entitlements(), &task, None, &[rule_scope()]).unwrap();

        assert_eq!(resp.command, "aws");
        assert_eq!(resp.args[0], "ecs");
        assert!(resp
            .args
            .windows(2)
            .any(|pair| pair == ["--command", "/bin/sh"]));
        assert!(resp
            .args
            .windows(2)
            .any(|pair| pair == ["--container", "app"]));
        assert!(!resp.env_vars.contains_key("AWS_PROFILE"));
    }

    #[test]
    fn build_ecs_exec_command_denies_excluded_container() {
        let task = mock_tasks().remove(0);
        let req = EcsExecRequest {
            account_id: task.account_id.clone(),
            region: task.region.clone(),
            cluster_arn: task.cluster_arn.clone(),
            task_arn: task.task_arn.clone(),
            container_name: "xray-daemon".into(),
        };

        let err = build_ecs_exec_command(&req, &entitlements(), &task, None, &[rule_scope()])
            .unwrap_err();
        assert!(err.contains("sidecar denylist"));
    }

    #[test]
    fn per_rule_container_deny_does_not_hide_container_authorized_by_another_rule() {
        let task = mock_tasks().remove(0);
        let req = EcsExecRequest {
            account_id: task.account_id.clone(),
            region: task.region.clone(),
            cluster_arn: task.cluster_arn.clone(),
            task_arn: task.task_arn.clone(),
            container_name: "xray-daemon".into(),
        };
        let denying_scope = rule_scope();
        let mut allowing_scope = rule_scope();
        allowing_scope.excluded_container_names.clear();

        let resp = build_ecs_exec_command(
            &req,
            &entitlements(),
            &task,
            None,
            &[denying_scope, allowing_scope],
        )
        .unwrap();

        assert!(resp
            .args
            .windows(2)
            .any(|pair| pair == ["--container", "xray-daemon"]));
    }

    #[test]
    fn build_ecs_exec_command_injects_sts_env_vars() {
        let task = mock_tasks().remove(0);
        let req = EcsExecRequest {
            account_id: task.account_id.clone(),
            region: task.region.clone(),
            cluster_arn: task.cluster_arn.clone(),
            task_arn: task.task_arn.clone(),
            container_name: "app".into(),
        };
        let creds = AssumedRoleCredentials {
            access_key_id: "AKIAEXAMPLE".into(),
            secret_access_key: "secret".into(),
            session_token: "session".into(),
        };

        let resp =
            build_ecs_exec_command(&req, &entitlements(), &task, Some(&creds), &[rule_scope()])
                .unwrap();
        assert_eq!(resp.env_vars["AWS_ACCESS_KEY_ID"], "AKIAEXAMPLE");
        assert_eq!(resp.env_vars["AWS_SESSION_TOKEN"], "session");
    }

    #[test]
    fn build_ecs_exec_command_allows_empty_region_scope() {
        let task = mock_tasks().remove(0);
        let req = EcsExecRequest {
            account_id: task.account_id.clone(),
            region: task.region.clone(),
            cluster_arn: task.cluster_arn.clone(),
            task_arn: task.task_arn.clone(),
            container_name: "app".into(),
        };
        let mut ent = entitlements();
        ent.allowed_regions.clear();
        let mut scope = rule_scope();
        scope.regions.clear();
        scope.cluster_patterns = vec![cluster_arn("*", "111111111111", DEV_MOCK_CLUSTER_NAME)];

        let resp = build_ecs_exec_command(&req, &ent, &task, None, &[scope]).unwrap();
        assert_eq!(resp.env_vars["AWS_DEFAULT_REGION"], task.region);
    }

    #[test]
    fn build_ecs_exec_command_unauthorized_account_denied() {
        let task = mock_tasks().remove(0);
        let req = EcsExecRequest {
            account_id: "222222222222".into(),
            region: task.region.clone(),
            cluster_arn: task.cluster_arn.clone(),
            task_arn: task.task_arn.clone(),
            container_name: "app".into(),
        };

        let err = build_ecs_exec_command(&req, &entitlements(), &task, None, &[rule_scope()])
            .unwrap_err();
        assert!(err.contains("Account not authorized"));
    }

    #[test]
    fn build_ecs_exec_command_task_tag_mismatch_denied() {
        let task = mock_tasks().remove(0);
        let req = EcsExecRequest {
            account_id: task.account_id.clone(),
            region: task.region.clone(),
            cluster_arn: task.cluster_arn.clone(),
            task_arn: task.task_arn.clone(),
            container_name: "app".into(),
        };
        let mut scope = rule_scope();
        scope.allow_selectors = vec![TagSelector {
            tags: HashMap::from([("Service".into(), vec!["api".into()])]),
        }];

        let err = build_ecs_exec_command(&req, &entitlements(), &task, None, &[scope]).unwrap_err();
        assert!(err.contains("allowed ECS scope"));
    }

    #[test]
    fn container_name_injection_is_literal_argv_element() {
        let mut task = mock_tasks().remove(0);
        task.containers[0].name = "; rm -rf /;".into();
        let req = EcsExecRequest {
            account_id: task.account_id.clone(),
            region: task.region.clone(),
            cluster_arn: task.cluster_arn.clone(),
            task_arn: task.task_arn.clone(),
            container_name: "; rm -rf /;".into(),
        };

        let resp =
            build_ecs_exec_command(&req, &entitlements(), &task, None, &[rule_scope()]).unwrap();
        assert!(resp
            .args
            .windows(2)
            .any(|pair| pair == ["--container", "; rm -rf /;"]));
    }
}
