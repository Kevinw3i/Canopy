use shared::dto::ec2::*;
use shared::dto::entitlements::{TagSelector, UserEntitlements};
use std::collections::HashMap;

// Re-export for use in route handlers
pub use shared::dto::ec2::AssumedRoleCredentials;

/// A single rule's scope for EC2 access. Used to ensure that account,
/// region, tag selectors, and deny selectors are evaluated together
/// from the same rule, preventing cross-group privilege splicing.
pub struct RuleScope {
    pub account_ids: Vec<String>,
    pub regions: Vec<String>,
    pub allow_selectors: Vec<TagSelector>,
    pub deny_selectors: Vec<TagSelector>,
}

/// Filter EC2 instances server-side based on per-rule entitlement scopes.
/// An instance is visible if at least ONE rule scope grants it:
/// the rule must cover the account, region, AND tag selectors.
/// Deny selectors are applied across all rules (any deny hides the instance).
pub fn filter_instances_by_entitlements(
    instances: Vec<Ec2Instance>,
    entitlements: &UserEntitlements,
    rule_scopes: &[RuleScope],
) -> Vec<Ec2Instance> {
    instances
        .into_iter()
        .filter(|inst| {
            // Deny-list: if instance matches ANY excluded selector from ANY rule, hide it
            if entitlements
                .excluded_tag_selectors
                .iter()
                .any(|sel| sel.matches(&inst.tags))
            {
                return false;
            }

            // If no rule scopes provided, fall back to merged entitlements
            // (for mock mode or when scopes weren't computed)
            if rule_scopes.is_empty() {
                return entitlements
                    .allowed_accounts
                    .iter()
                    .any(|a| a.account_id == inst.account_id)
                    && entitlements.allowed_regions.contains(&inst.region)
                    && (entitlements.instance_tag_selectors.is_empty()
                        || entitlements
                            .instance_tag_selectors
                            .iter()
                            .any(|sel| sel.matches(&inst.tags)));
            }

            // Check that at least one rule scope covers this instance
            rule_scopes.iter().any(|scope| {
                // Account must match
                if !scope.account_ids.contains(&inst.account_id) {
                    return false;
                }
                // Region must match (empty = all regions from this rule)
                if !scope.regions.is_empty() && !scope.regions.contains(&inst.region) {
                    return false;
                }
                // Tag selectors from THIS rule only
                if !scope.allow_selectors.is_empty()
                    && !scope
                        .allow_selectors
                        .iter()
                        .any(|sel| sel.matches(&inst.tags))
                {
                    return false;
                }
                // Per-rule deny selectors
                if scope
                    .deny_selectors
                    .iter()
                    .any(|sel| sel.matches(&inst.tags))
                {
                    return false;
                }
                true
            })
        })
        .collect()
}

/// Apply client-side filters (search text, state, tags) after entitlement filtering
pub fn apply_user_filters(instances: Vec<Ec2Instance>, req: &Ec2ListRequest) -> Vec<Ec2Instance> {
    instances
        .into_iter()
        .filter(|inst| {
            if let Some(ref account) = req.account_id {
                if inst.account_id != *account {
                    return false;
                }
            }
            if let Some(ref region) = req.region {
                if inst.region != *region {
                    return false;
                }
            }
            if let Some(ref states) = req.state_filter {
                if !states.contains(&inst.state) {
                    return false;
                }
            }
            if let Some(ref name_filter) = req.name_filter {
                let name_lower = name_filter.to_lowercase();
                let matches_name = inst
                    .name
                    .as_ref()
                    .map(|n| n.to_lowercase().contains(&name_lower))
                    .unwrap_or(false);
                let matches_id = inst.instance_id.to_lowercase().contains(&name_lower);
                let matches_ip = inst
                    .private_ip
                    .as_ref()
                    .map(|ip| ip.contains(&name_lower))
                    .unwrap_or(false);
                if !matches_name && !matches_id && !matches_ip {
                    return false;
                }
            }
            if let Some(ref tag_filters) = req.tag_filters {
                for (key, value) in tag_filters {
                    match inst.tags.get(key) {
                        Some(v) if v == value => {}
                        _ => return false,
                    }
                }
            }
            true
        })
        .collect()
}

/// Build the connect command for SSM or EC2 Instance Connect.
///
/// `instance_tags` are the tags on the target instance, used to enforce
/// `instance_tag_selectors`. The caller must look up the instance to
/// provide these (see `connect_instance` route handler).
///
/// `credentials` are scoped STS credentials that ONLY allow the specific
/// connect operation (ssm:StartSession or ec2-instance-connect:*) for the
/// target instance. The route handler is responsible for applying an inline
/// session policy before passing them here.
pub fn build_connect_command(
    req: &ConnectRequest,
    entitlements: &UserEntitlements,
    instance_tags: &HashMap<String, String>,
    credentials: Option<&AssumedRoleCredentials>,
    eic_endpoint_id: Option<&str>,
    rule_scopes: &[RuleScope],
) -> ConnectResponse {
    let session_limit = entitlements.max_session_seconds;
    let denied = |msg: String| ConnectResponse {
        authorized: false,
        command: String::new(),
        args: vec![],
        env_vars: HashMap::new(),
        error: Some(msg),
        max_session_seconds: None,
    };

    // Verify account access
    if !entitlements
        .allowed_accounts
        .iter()
        .any(|a| a.account_id == req.account_id)
    {
        return denied("Account not authorized".into());
    }

    // Verify region access
    if !entitlements.allowed_regions.contains(&req.region) {
        return denied(format!("Region '{}' not authorized", req.region));
    }

    // Verify instance tag selectors using per-rule scopes when available.
    // This prevents cross-group tag-selector splicing.
    if !rule_scopes.is_empty() {
        let tag_authorized = rule_scopes.iter().any(|scope| {
            // Account must match
            if !scope.account_ids.contains(&req.account_id) {
                return false;
            }
            // Region must match
            if !scope.regions.is_empty() && !scope.regions.contains(&req.region) {
                return false;
            }
            // Allow selectors from THIS rule
            if !scope.allow_selectors.is_empty()
                && !scope
                    .allow_selectors
                    .iter()
                    .any(|sel| sel.matches(instance_tags))
            {
                return false;
            }
            // Per-rule deny selectors
            if scope
                .deny_selectors
                .iter()
                .any(|sel| sel.matches(instance_tags))
            {
                return false;
            }
            true
        });
        if !tag_authorized {
            return denied("Instance does not match any allowed tag selector".into());
        }
    } else {
        // Fallback to merged selectors (mock mode)
        if !entitlements.instance_tag_selectors.is_empty()
            && !entitlements
                .instance_tag_selectors
                .iter()
                .any(|sel| sel.matches(instance_tags))
        {
            return denied("Instance does not match any allowed tag selector".into());
        }
    }

    // Verify excluded_tag_selectors (deny-list) — must mirror the list filter
    if entitlements
        .excluded_tag_selectors
        .iter()
        .any(|sel| sel.matches(instance_tags))
    {
        return denied("Instance is excluded by tag selector policy".into());
    }

    // Verify feature access
    match req.method {
        ConnectMethod::Ssm => {
            if !entitlements.features.can_use_ssm {
                return denied("SSM access not authorized".into());
            }
        }
        ConnectMethod::Ec2InstanceConnect => {
            if !entitlements.features.can_use_ec2_instance_connect {
                return denied("EC2 Instance Connect access not authorized".into());
            }
        }
        ConnectMethod::Ssh => {
            // SSH uses the same feature flag as SSM for simplicity.
            // Both represent "can connect to this instance".
            if !entitlements.features.can_use_ssm {
                return denied("SSH access not authorized".into());
            }
        }
    }

    // Check if OS users list allows any user (wildcard)
    let os_user_wildcard = entitlements.allowed_os_users.iter().any(|u| u == "*");

    // Verify OS user
    match (&req.method, &req.os_user) {
        // EIC requires an explicit OS user from the entitlement set
        (ConnectMethod::Ec2InstanceConnect, None) => {
            if entitlements.allowed_os_users.is_empty() {
                return denied(
                    "EC2 Instance Connect requires an OS user but none are authorized".into(),
                );
            }
            return denied("EC2 Instance Connect requires an explicit --os-user".into());
        }
        // Any method with an explicit OS user must be in the allowed list (or wildcard)
        (_, Some(os_user)) => {
            if !os_user_wildcard && !entitlements.allowed_os_users.contains(os_user) {
                return denied(format!("OS user '{}' not authorized", os_user));
            }
        }
        // SSM without os_user: allowed only with wildcard opt-in
        (ConnectMethod::Ssm, None) => {
            if !os_user_wildcard {
                return denied(
                    "SSM connect requires an explicit OS user (set allowed_os_users = [\"*\"] for unrestricted shell)"
                        .into(),
                );
            }
        }
        // SSH requires an OS user (it becomes the login user in ssh user@host)
        (ConnectMethod::Ssh, None) => {
            return denied("SSH requires an OS user (e.g. ec2-user, ubuntu)".into());
        }
    }

    let mut env_vars = HashMap::from([("AWS_DEFAULT_REGION".into(), req.region.clone())]);

    // Inject assumed-role credentials so the spawned CLI uses the
    // server-authorized role, not the operator's ambient credentials.
    if let Some(creds) = credentials {
        env_vars.insert("AWS_ACCESS_KEY_ID".into(), creds.access_key_id.clone());
        env_vars.insert(
            "AWS_SECRET_ACCESS_KEY".into(),
            creds.secret_access_key.clone(),
        );
        env_vars.insert("AWS_SESSION_TOKEN".into(), creds.session_token.clone());
    }

    match req.method {
        ConnectMethod::Ssm => {
            if let Some(ref os_user) = req.os_user {
                // When an OS user is specified, use `ssh` with SSM as the
                // ProxyCommand. This enforces the login user at the SSH
                // level — the SSM tunnel is just a transport layer.
                let proxy_cmd = format!(
                    "aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p --region {}",
                    req.region
                );
                ConnectResponse {
                    authorized: true,
                    command: "ssh".into(),
                    args: vec![
                        "-o".into(),
                        format!("ProxyCommand={}", proxy_cmd),
                        "-l".into(),
                        os_user.clone(),
                        req.instance_id.clone(),
                    ],
                    env_vars,
                    error: None,
                    max_session_seconds: session_limit,
                }
            } else {
                // No OS user — plain SSM session (only allowed when
                // allowed_os_users is empty, enforced earlier).
                ConnectResponse {
                    authorized: true,
                    command: "aws".into(),
                    args: vec![
                        "ssm".into(),
                        "start-session".into(),
                        "--target".into(),
                        req.instance_id.clone(),
                        "--region".into(),
                        req.region.clone(),
                    ],
                    env_vars,
                    error: None,
                    max_session_seconds: session_limit,
                }
            }
        }
        ConnectMethod::Ec2InstanceConnect => {
            // Don't force --connection-type eice; let the CLI choose
            // based on instance/network configuration (direct vs EICE).
            let mut args = vec![
                "ec2-instance-connect".into(),
                "ssh".into(),
                "--instance-id".into(),
                req.instance_id.clone(),
                "--region".into(),
                req.region.clone(),
            ];
            if let Some(ref os_user) = req.os_user {
                args.push("--os-user".into());
                args.push(os_user.clone());
            }
            // Pass the server-resolved EIC endpoint so the CLI doesn't
            // need ec2:Describe* permissions (which would break isolation).
            if let Some(ep_id) = eic_endpoint_id {
                args.push("--instance-connect-endpoint-id".into());
                args.push(ep_id.to_string());
            }
            ConnectResponse {
                authorized: true,
                command: "aws".into(),
                args,
                env_vars,
                error: None,
                max_session_seconds: session_limit,
            }
        }
        ConnectMethod::Ssh => {
            // Direct SSH using the operator's own key.
            // Prefer public IP if available, fall back to private IP.
            let ip = instance_tags
                .get("__public_ip")
                .or_else(|| instance_tags.get("__private_ip"));

            let Some(ip) = ip else {
                return denied("Instance has no IP address available".into());
            };

            let os_user = req.os_user.as_ref().expect("enforced earlier");

            ConnectResponse {
                authorized: true,
                command: "ssh".into(),
                args: vec![
                    "-o".into(),
                    "ConnectTimeout=10".into(),
                    "-o".into(),
                    "ServerAliveInterval=15".into(),
                    "-o".into(),
                    "ServerAliveCountMax=3".into(),
                    format!("{}@{}", os_user, ip),
                ],
                env_vars: HashMap::new(), // no AWS env vars needed
                error: None,
                max_session_seconds: session_limit,
            }
        }
    }
}

/// Generate mock EC2 instances for development
pub fn mock_instances() -> Vec<Ec2Instance> {
    vec![
        Ec2Instance {
            instance_id: "i-0123456789abcdef0".into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            name: Some("web-prod-01".into()),
            private_ip: Some("10.0.1.10".into()),
            public_ip: Some("54.123.45.67".into()),
            state: InstanceState::Running,
            platform: Some("Linux/UNIX".into()),
            instance_type: "t3.medium".into(),
            ssm_managed: true,
            instance_connect_capable: true,
            environment: Some("production".into()),
            tags: HashMap::from([
                ("Name".into(), "web-prod-01".into()),
                ("Environment".into(), "production".into()),
                ("Team".into(), "platform".into()),
                ("Service".into(), "web".into()),
            ]),
            launch_time: Some("2025-01-15T10:30:00Z".into()),
            vpc_id: Some("vpc-0abc123".into()),
            subnet_id: Some("subnet-0abc123".into()),
            security_groups: vec!["sg-web-prod".into()],
            iam_role: Some("WebServerRole".into()),
        },
        Ec2Instance {
            instance_id: "i-0bcd2345efg67890b".into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            name: Some("api-prod-01".into()),
            private_ip: Some("10.0.1.20".into()),
            public_ip: None,
            state: InstanceState::Running,
            platform: Some("Linux/UNIX".into()),
            instance_type: "c5.xlarge".into(),
            ssm_managed: true,
            instance_connect_capable: false,
            environment: Some("production".into()),
            tags: HashMap::from([
                ("Name".into(), "api-prod-01".into()),
                ("Environment".into(), "production".into()),
                ("Team".into(), "platform".into()),
                ("Service".into(), "api".into()),
            ]),
            launch_time: Some("2025-02-20T14:00:00Z".into()),
            vpc_id: Some("vpc-0abc123".into()),
            subnet_id: Some("subnet-0def456".into()),
            security_groups: vec!["sg-api-prod".into()],
            iam_role: Some("ApiServerRole".into()),
        },
        Ec2Instance {
            instance_id: "i-0cde3456fgh78901c".into(),
            account_id: "222222222222".into(),
            region: "us-east-1".into(),
            name: Some("web-staging-01".into()),
            private_ip: Some("10.1.1.10".into()),
            public_ip: Some("54.234.56.78".into()),
            state: InstanceState::Running,
            platform: Some("Linux/UNIX".into()),
            instance_type: "t3.small".into(),
            ssm_managed: true,
            instance_connect_capable: true,
            environment: Some("staging".into()),
            tags: HashMap::from([
                ("Name".into(), "web-staging-01".into()),
                ("Environment".into(), "staging".into()),
                ("Team".into(), "platform".into()),
                ("Service".into(), "web".into()),
            ]),
            launch_time: Some("2025-03-01T09:00:00Z".into()),
            vpc_id: Some("vpc-0staging".into()),
            subnet_id: Some("subnet-0staging".into()),
            security_groups: vec!["sg-web-staging".into()],
            iam_role: Some("WebServerRole".into()),
        },
        Ec2Instance {
            instance_id: "i-0def4567ghi89012d".into(),
            account_id: "111111111111".into(),
            region: "us-west-2".into(),
            name: Some("worker-prod-01".into()),
            private_ip: Some("10.2.1.10".into()),
            public_ip: None,
            state: InstanceState::Stopped,
            platform: Some("Linux/UNIX".into()),
            instance_type: "m5.large".into(),
            ssm_managed: false,
            instance_connect_capable: false,
            environment: Some("production".into()),
            tags: HashMap::from([
                ("Name".into(), "worker-prod-01".into()),
                ("Environment".into(), "production".into()),
                ("Team".into(), "data".into()),
                ("Service".into(), "worker".into()),
            ]),
            launch_time: Some("2024-12-10T08:00:00Z".into()),
            vpc_id: Some("vpc-0usw2".into()),
            subnet_id: Some("subnet-0usw2".into()),
            security_groups: vec!["sg-worker-prod".into()],
            iam_role: Some("WorkerRole".into()),
        },
        Ec2Instance {
            instance_id: "i-0efg5678hij90123e".into(),
            account_id: "222222222222".into(),
            region: "us-east-1".into(),
            name: Some("bastion-staging-01".into()),
            private_ip: Some("10.1.0.5".into()),
            public_ip: Some("54.345.67.89".into()),
            state: InstanceState::Running,
            platform: Some("Linux/UNIX".into()),
            instance_type: "t3.micro".into(),
            ssm_managed: true,
            instance_connect_capable: true,
            environment: Some("staging".into()),
            tags: HashMap::from([
                ("Name".into(), "bastion-staging-01".into()),
                ("Environment".into(), "staging".into()),
                ("Team".into(), "platform".into()),
                ("Service".into(), "bastion".into()),
            ]),
            launch_time: Some("2025-01-05T06:00:00Z".into()),
            vpc_id: Some("vpc-0staging".into()),
            subnet_id: Some("subnet-0staging-pub".into()),
            security_groups: vec!["sg-bastion-staging".into()],
            iam_role: Some("BastionRole".into()),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::dto::entitlements::*;

    fn platform_eng_entitlements() -> UserEntitlements {
        UserEntitlements {
            user_id: "test-user".into(),
            email: "test@example.com".into(),
            display_name: "Test User".into(),
            groups: vec!["platform-engineering".into()],
            features: FeatureFlags {
                can_view_ec2: true,
                can_use_cloudwatch_search: true,
                can_use_cloudwatch_tail: true,
                can_use_ssm: true,
                can_use_ec2_instance_connect: true,
                ..Default::default()
            },
            allowed_accounts: vec![
                AllowedAccount {
                    account_id: "111111111111".into(),
                    account_name: "production".into(),
                    role_arn: "arn:aws:iam::111111111111:role/CanopyRole".into(),
                },
                AllowedAccount {
                    account_id: "222222222222".into(),
                    account_name: "staging".into(),
                    role_arn: "arn:aws:iam::222222222222:role/CanopyRole".into(),
                },
            ],
            allowed_regions: vec!["us-east-1".into(), "us-west-2".into()],
            allowed_log_group_arns: vec![],
            instance_tag_selectors: vec![TagSelector {
                tags: HashMap::from([(
                    "Environment".into(),
                    vec!["production".into(), "staging".into()],
                )]),
            }],
            excluded_tag_selectors: vec![],
            allowed_clusters: vec![],
            task_tag_selectors: vec![],
            excluded_task_tag_selectors: vec![],
            excluded_container_names: vec![],
            allow_broad_cluster_discovery: false,
            allowed_os_users: vec!["ec2-user".into(), "ubuntu".into()],
            max_session_seconds: None,
        }
    }

    fn readonly_entitlements() -> UserEntitlements {
        UserEntitlements {
            user_id: "readonly".into(),
            email: "readonly@example.com".into(),
            display_name: "Read Only".into(),
            groups: vec!["readonly-ops".into()],
            features: FeatureFlags {
                can_view_ec2: true,
                can_use_cloudwatch_search: true,
                can_use_cloudwatch_tail: false,
                can_use_ssm: false,
                can_use_ec2_instance_connect: false,
                ..Default::default()
            },
            allowed_accounts: vec![AllowedAccount {
                account_id: "222222222222".into(),
                account_name: "staging".into(),
                role_arn: "arn:aws:iam::222222222222:role/ReadOnly".into(),
            }],
            allowed_regions: vec!["us-east-1".into()],
            allowed_log_group_arns: vec![],
            instance_tag_selectors: vec![TagSelector {
                tags: HashMap::from([("Environment".into(), vec!["staging".into()])]),
            }],
            excluded_tag_selectors: vec![],
            allowed_clusters: vec![],
            task_tag_selectors: vec![],
            excluded_task_tag_selectors: vec![],
            excluded_container_names: vec![],
            allow_broad_cluster_discovery: false,
            allowed_os_users: vec![],
            max_session_seconds: Some(3600),
        }
    }

    #[test]
    fn test_filter_by_entitlements_admin() {
        let instances = mock_instances();
        let ent = platform_eng_entitlements();
        let filtered = filter_instances_by_entitlements(instances, &ent, &[]);
        // Admin can see all 5 instances (all match environment production or staging)
        assert_eq!(filtered.len(), 5);
    }

    #[test]
    fn test_filter_by_entitlements_readonly() {
        let instances = mock_instances();
        let ent = readonly_entitlements();
        let filtered = filter_instances_by_entitlements(instances, &ent, &[]);
        // Readonly only sees staging account (222222222222) + us-east-1 + staging env
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|i| i.account_id == "222222222222"));
        assert!(filtered.iter().all(|i| i.region == "us-east-1"));
    }

    #[test]
    fn test_excluded_tag_selectors_hide_matching_instances() {
        let instances = mock_instances();
        let mut ent = platform_eng_entitlements();
        // Admin normally sees 5 instances. Exclude Service=web.
        ent.excluded_tag_selectors = vec![TagSelector {
            tags: HashMap::from([("Service".into(), vec!["web".into()])]),
        }];
        let filtered = filter_instances_by_entitlements(instances, &ent, &[]);
        // web-prod-01 and web-staging-01 should be excluded
        assert_eq!(filtered.len(), 3);
        assert!(filtered
            .iter()
            .all(|i| { i.tags.get("Service").map(|s| s.as_str()) != Some("web") }));
    }

    #[test]
    fn test_excluded_tag_selectors_multiple_rules() {
        let instances = mock_instances();
        let mut ent = platform_eng_entitlements();
        // Exclude Service=web AND Service=bastion (two separate selectors)
        ent.excluded_tag_selectors = vec![
            TagSelector {
                tags: HashMap::from([("Service".into(), vec!["web".into()])]),
            },
            TagSelector {
                tags: HashMap::from([("Service".into(), vec!["bastion".into()])]),
            },
        ];
        let filtered = filter_instances_by_entitlements(instances, &ent, &[]);
        // web-prod-01, web-staging-01, bastion-staging-01 excluded → 2 left
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_excluded_tag_selectors_empty_does_nothing() {
        let instances = mock_instances();
        let mut ent = platform_eng_entitlements();
        ent.excluded_tag_selectors = vec![];
        let filtered = filter_instances_by_entitlements(instances, &ent, &[]);
        assert_eq!(filtered.len(), 5);
    }

    #[test]
    fn test_user_filters_by_name() {
        let instances = mock_instances();
        let req = Ec2ListRequest {
            name_filter: Some("web".into()),
            account_id: None,
            region: None,
            state_filter: None,
            tag_filters: None,
            next_token: None,
            page_size: 50,
        };
        let filtered = apply_user_filters(instances, &req);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_user_filters_by_state() {
        let instances = mock_instances();
        let req = Ec2ListRequest {
            name_filter: None,
            account_id: None,
            region: None,
            state_filter: Some(vec![InstanceState::Stopped]),
            tag_filters: None,
            next_token: None,
            page_size: 50,
        };
        let filtered = apply_user_filters(instances, &req);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].instance_id, "i-0def4567ghi89012d");
    }

    fn prod_instance_tags() -> HashMap<String, String> {
        HashMap::from([
            ("Name".into(), "web-prod-01".into()),
            ("Environment".into(), "production".into()),
            ("Team".into(), "platform".into()),
        ])
    }

    fn staging_instance_tags() -> HashMap<String, String> {
        HashMap::from([
            ("Name".into(), "web-staging-01".into()),
            ("Environment".into(), "staging".into()),
            ("Team".into(), "platform".into()),
        ])
    }

    #[test]
    fn test_connect_ssm_authorized() {
        let ent = platform_eng_entitlements();
        let tags = prod_instance_tags();
        let req = ConnectRequest {
            instance_id: "i-0123456789abcdef0".into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            method: ConnectMethod::Ssm,
            os_user: Some("ec2-user".into()), // required when allowed_os_users is non-empty
        };
        let resp = build_connect_command(&req, &ent, &tags, None, None, &[]);
        assert!(resp.authorized);
        // With os_user, SSM uses ssh+ProxyCommand instead of plain aws ssm
        assert_eq!(resp.command, "ssh");
        assert!(resp.args.iter().any(|a| a.contains("ssm start-session")));
        assert!(resp.args.contains(&"ec2-user".to_string()));
    }

    #[test]
    fn test_connect_ssm_denied_readonly() {
        let ent = readonly_entitlements();
        let tags = staging_instance_tags();
        let req = ConnectRequest {
            instance_id: "i-0cde3456fgh78901c".into(),
            account_id: "222222222222".into(),
            region: "us-east-1".into(),
            method: ConnectMethod::Ssm,
            os_user: None,
        };
        let resp = build_connect_command(&req, &ent, &tags, None, None, &[]);
        assert!(!resp.authorized);
    }

    #[test]
    fn test_connect_wrong_account_denied() {
        let ent = readonly_entitlements();
        let tags = prod_instance_tags();
        let req = ConnectRequest {
            instance_id: "i-0123456789abcdef0".into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            method: ConnectMethod::Ssm,
            os_user: None,
        };
        let resp = build_connect_command(&req, &ent, &tags, None, None, &[]);
        assert!(!resp.authorized);
        assert!(resp.error.unwrap().contains("Account not authorized"));
    }

    #[test]
    fn test_connect_wrong_region_denied() {
        let ent = readonly_entitlements();
        let tags = staging_instance_tags();
        let req = ConnectRequest {
            instance_id: "i-0cde3456fgh78901c".into(),
            account_id: "222222222222".into(),
            region: "eu-west-1".into(),
            method: ConnectMethod::Ssm,
            os_user: None,
        };
        let resp = build_connect_command(&req, &ent, &tags, None, None, &[]);
        assert!(!resp.authorized);
        assert!(resp
            .error
            .unwrap()
            .contains("Region 'eu-west-1' not authorized"));
    }

    #[test]
    fn test_connect_wrong_tags_denied() {
        let ent = readonly_entitlements();
        // Instance has "development" env, but readonly only allows "staging"
        let dev_tags = HashMap::from([("Environment".into(), "development".into())]);
        let req = ConnectRequest {
            instance_id: "i-0xxx".into(),
            account_id: "222222222222".into(),
            region: "us-east-1".into(),
            method: ConnectMethod::Ssm,
            os_user: None,
        };
        let resp = build_connect_command(&req, &ent, &dev_tags, None, None, &[]);
        assert!(!resp.authorized);
        assert!(resp.error.unwrap().contains("tag selector"));
    }

    #[test]
    fn test_connect_os_user_denied() {
        let ent = platform_eng_entitlements();
        let tags = prod_instance_tags();
        let req = ConnectRequest {
            instance_id: "i-0123456789abcdef0".into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            method: ConnectMethod::Ec2InstanceConnect,
            os_user: Some("root".into()),
        };
        let resp = build_connect_command(&req, &ent, &tags, None, None, &[]);
        assert!(!resp.authorized);
        assert!(resp
            .error
            .unwrap()
            .contains("OS user 'root' not authorized"));
    }

    #[test]
    fn test_connect_with_credentials_injects_env_vars() {
        let ent = platform_eng_entitlements();
        let tags = prod_instance_tags();
        let creds = AssumedRoleCredentials {
            access_key_id: "ASIATEST123".into(),
            secret_access_key: "secret123".into(),
            session_token: "token123".into(),
        };
        let req = ConnectRequest {
            instance_id: "i-0123456789abcdef0".into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            method: ConnectMethod::Ssm,
            os_user: Some("ec2-user".into()),
        };
        let resp = build_connect_command(&req, &ent, &tags, Some(&creds), None, &[]);
        assert!(resp.authorized);
        assert_eq!(
            resp.env_vars.get("AWS_ACCESS_KEY_ID").unwrap(),
            "ASIATEST123"
        );
        assert_eq!(
            resp.env_vars.get("AWS_SECRET_ACCESS_KEY").unwrap(),
            "secret123"
        );
        assert_eq!(resp.env_vars.get("AWS_SESSION_TOKEN").unwrap(), "token123");
    }
}
