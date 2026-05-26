use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Full entitlements for a user, returned after authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEntitlements {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    pub groups: Vec<String>,
    pub features: FeatureFlags,
    pub allowed_accounts: Vec<AllowedAccount>,
    pub allowed_regions: Vec<String>,
    pub allowed_log_group_arns: Vec<String>,
    pub instance_tag_selectors: Vec<TagSelector>,
    /// Deny-list: instances matching ANY excluded selector are hidden,
    /// even if they passed the allow checks above.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_tag_selectors: Vec<TagSelector>,
    pub allowed_os_users: Vec<String>,
    /// Maximum SSH/SSM session duration in seconds.
    /// 0 or None = no limit. Enforced by the TUI client via TMOUT or
    /// a background timer that kills the spawned process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_session_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub database_scopes: Vec<DatabaseScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FeatureFlags {
    pub can_view_ec2: bool,
    pub can_use_cloudwatch_search: bool,
    pub can_use_cloudwatch_tail: bool,
    pub can_use_ssm: bool,
    pub can_use_ec2_instance_connect: bool,
    /// Power-action flags. `#[serde(default)]` keeps existing
    /// entitlements.toml files (and any persisted JSON) backward-compatible:
    /// if these keys are absent the flag is simply false.
    #[serde(default)]
    pub can_start_ec2: bool,
    #[serde(default)]
    pub can_stop_ec2: bool,
    #[serde(default)]
    pub can_reboot_ec2: bool,
    /// Master switch for the local MCP server surface.
    #[serde(default)]
    pub can_use_mcp: bool,
    /// Allows MCP CloudWatch tools when combined with `can_use_mcp`.
    #[serde(default)]
    pub can_use_mcp_cloudwatch: bool,
    /// Reserved for future MCP EC2 tools. Product Phase 2 does not expose EC2 MCP tools.
    #[serde(default)]
    pub can_use_mcp_ec2: bool,
    /// Allows MCP database tools. The control-plane still enforces
    /// database_scopes, SQL validation, EXPLAIN gates, and DB credentials.
    #[serde(default)]
    pub can_use_mcp_database: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedAccount {
    pub account_id: String,
    pub account_name: String,
    pub role_arn: String,
}

/// Tag selector for EC2 instance filtering
/// Instances must match ALL specified tags to be visible
///
/// Equality is intentionally order-sensitive for each tag's allowed values
/// because values are stored as `Vec<String>`. Entitlement authors should keep
/// value ordering canonical when they expect duplicate selectors to deduplicate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TagSelector {
    pub tags: HashMap<String, Vec<String>>,
}

impl TagSelector {
    /// Check if an instance's tags match this selector.
    /// All tag keys in the selector must be present on the instance,
    /// and the instance's value must be in the selector's allowed values.
    pub fn matches(&self, instance_tags: &HashMap<String, String>) -> bool {
        self.tags.iter().all(|(key, allowed_values)| {
            instance_tags
                .get(key)
                .map(|v| allowed_values.contains(v))
                .unwrap_or(false)
        })
    }
}

/// Entitlement rule as stored in the backend.
/// All Vec fields default to empty when omitted from config files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementRule {
    pub id: String,
    pub group: String,
    #[serde(default)]
    pub features: FeatureFlags,
    #[serde(default)]
    pub allowed_accounts: Vec<AllowedAccount>,
    #[serde(default)]
    pub allowed_regions: Vec<String>,
    #[serde(default)]
    pub allowed_log_group_arns: Vec<String>,
    #[serde(default)]
    pub instance_tag_selectors: Vec<TagSelector>,
    /// Deny-list: instances matching ANY excluded selector are hidden.
    #[serde(default)]
    pub excluded_tag_selectors: Vec<TagSelector>,
    #[serde(default)]
    pub allowed_os_users: Vec<String>,
    /// Maximum session duration in seconds. 0 or omitted = no limit.
    #[serde(default)]
    pub max_session_seconds: Option<u64>,
    #[serde(default)]
    pub database_scopes: Vec<DatabaseScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatabaseScope {
    pub name: String,
    pub connection: String,
    pub environment: String,
    #[serde(default)]
    pub allowed_schemas: Vec<String>,
    #[serde(default)]
    pub allowed_tables: Vec<String>,
    #[serde(default)]
    pub allowed_actions: Vec<String>,
    pub max_rows: u64,
    pub statement_timeout_ms: u64,
    #[serde(default = "default_true")]
    pub require_explain: bool,
    pub max_examined_rows: u64,
    #[serde(default)]
    pub allow_full_table_scan: bool,
    /// Whether MCP queries against this scope may read MySQL VIEW objects
    /// instead of BASE TABLEs. Defaults to `false` for least-privilege:
    /// the control-plane queries `information_schema.tables` for every
    /// referenced entry in `allowed_tables` and rejects any that resolves
    /// to a VIEW. Set `true` only after the operator has reviewed each
    /// view's DEFINER, base-table expansion, and cross-schema reads — the
    /// audit record will tag every query with `views_allowed = true` so
    /// reviewers can spot scopes that took this opt-in.
    #[serde(default)]
    pub allow_views: bool,
}

fn default_true() -> bool {
    true
}

/// Membership record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMembership {
    pub user_id: String,
    pub group: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_selector_matches_all_tags() {
        let selector = TagSelector {
            tags: HashMap::from([
                (
                    "Environment".into(),
                    vec!["production".into(), "staging".into()],
                ),
                ("Team".into(), vec!["platform".into()]),
            ]),
        };

        let tags = HashMap::from([
            ("Environment".into(), "production".into()),
            ("Team".into(), "platform".into()),
            ("Name".into(), "web-01".into()),
        ]);
        assert!(selector.matches(&tags));
    }

    #[test]
    fn test_tag_selector_rejects_missing_key() {
        let selector = TagSelector {
            tags: HashMap::from([
                ("Environment".into(), vec!["production".into()]),
                ("Team".into(), vec!["platform".into()]),
            ]),
        };

        let tags = HashMap::from([("Environment".into(), "production".into())]);
        assert!(!selector.matches(&tags));
    }

    #[test]
    fn test_tag_selector_rejects_wrong_value() {
        let selector = TagSelector {
            tags: HashMap::from([("Environment".into(), vec!["production".into()])]),
        };

        let tags = HashMap::from([("Environment".into(), "development".into())]);
        assert!(!selector.matches(&tags));
    }

    #[test]
    fn test_empty_selector_matches_everything() {
        let selector = TagSelector {
            tags: HashMap::new(),
        };
        let tags = HashMap::from([("anything".into(), "value".into())]);
        assert!(selector.matches(&tags));
    }

    #[test]
    fn feature_flags_default_all_false() {
        let flags = FeatureFlags::default();
        assert!(!flags.can_view_ec2);
        assert!(!flags.can_use_cloudwatch_search);
        assert!(!flags.can_use_cloudwatch_tail);
        assert!(!flags.can_use_ssm);
        assert!(!flags.can_use_ec2_instance_connect);
        // Power-action flags default to false (least-privilege).
        assert!(!flags.can_start_ec2);
        assert!(!flags.can_stop_ec2);
        assert!(!flags.can_reboot_ec2);
        assert!(!flags.can_use_mcp);
        assert!(!flags.can_use_mcp_cloudwatch);
        assert!(!flags.can_use_mcp_ec2);
        assert!(!flags.can_use_mcp_database);
    }

    #[test]
    fn feature_flags_roundtrip() {
        let flags = FeatureFlags {
            can_view_ec2: true,
            can_use_cloudwatch_search: true,
            can_use_cloudwatch_tail: false,
            can_use_ssm: true,
            can_use_ec2_instance_connect: false,
            can_start_ec2: true,
            can_stop_ec2: true,
            can_reboot_ec2: false,
            can_use_mcp: true,
            can_use_mcp_cloudwatch: true,
            can_use_mcp_ec2: false,
            can_use_mcp_database: true,
        };
        let json = serde_json::to_value(&flags).unwrap();
        assert_eq!(json["can_view_ec2"], true);
        assert_eq!(json["can_use_ssm"], true);
        assert_eq!(json["can_start_ec2"], true);
        assert_eq!(json["can_stop_ec2"], true);
        assert_eq!(json["can_reboot_ec2"], false);
        assert_eq!(json["can_use_mcp"], true);
        assert_eq!(json["can_use_mcp_cloudwatch"], true);
        assert_eq!(json["can_use_mcp_ec2"], false);
        assert_eq!(json["can_use_mcp_database"], true);
        let back: FeatureFlags = serde_json::from_value(json).unwrap();
        assert!(back.can_view_ec2);
        assert!(!back.can_use_ec2_instance_connect);
        assert!(back.can_start_ec2);
        assert!(back.can_stop_ec2);
        assert!(!back.can_reboot_ec2);
        assert!(back.can_use_mcp);
        assert!(back.can_use_mcp_cloudwatch);
        assert!(!back.can_use_mcp_ec2);
        assert!(back.can_use_mcp_database);
    }

    /// Existing entitlements.toml / persisted JSON without the new
    /// power flags must still parse — `#[serde(default)]` ensures the
    /// missing keys decode as `false`, never as a deserialization error.
    #[test]
    fn feature_flags_backward_compat_without_power_keys() {
        let json = serde_json::json!({
            "can_view_ec2": true,
            "can_use_cloudwatch_search": false,
            "can_use_cloudwatch_tail": false,
            "can_use_ssm": true,
            "can_use_ec2_instance_connect": false,
        });
        let flags: FeatureFlags = serde_json::from_value(json).unwrap();
        assert!(flags.can_view_ec2);
        assert!(flags.can_use_ssm);
        assert!(!flags.can_start_ec2);
        assert!(!flags.can_stop_ec2);
        assert!(!flags.can_reboot_ec2);
        assert!(!flags.can_use_mcp);
        assert!(!flags.can_use_mcp_cloudwatch);
        assert!(!flags.can_use_mcp_ec2);
        assert!(!flags.can_use_mcp_database);
    }

    #[test]
    fn feature_flags_backward_compat_without_mcp_keys() {
        let json = serde_json::json!({
            "can_view_ec2": true,
            "can_use_cloudwatch_search": true,
            "can_use_cloudwatch_tail": false,
            "can_use_ssm": false,
            "can_use_ec2_instance_connect": false,
            "can_start_ec2": false,
            "can_stop_ec2": false,
            "can_reboot_ec2": false
        });
        let flags: FeatureFlags = serde_json::from_value(json).unwrap();
        assert!(flags.can_view_ec2);
        assert!(flags.can_use_cloudwatch_search);
        assert!(!flags.can_use_mcp);
        assert!(!flags.can_use_mcp_cloudwatch);
        assert!(!flags.can_use_mcp_ec2);
        assert!(!flags.can_use_mcp_database);
    }

    #[test]
    fn entitlement_rule_defaults_empty_vecs() {
        let json = serde_json::json!({
            "id": "r1",
            "group": "ops"
        });
        let rule: EntitlementRule = serde_json::from_value(json).unwrap();
        assert_eq!(rule.id, "r1");
        assert_eq!(rule.group, "ops");
        assert!(rule.allowed_accounts.is_empty());
        assert!(rule.allowed_regions.is_empty());
        assert!(rule.allowed_log_group_arns.is_empty());
        assert!(rule.instance_tag_selectors.is_empty());
        assert!(rule.excluded_tag_selectors.is_empty());
        assert!(rule.allowed_os_users.is_empty());
        assert!(rule.max_session_seconds.is_none());
        assert!(rule.database_scopes.is_empty());
        // features should default to all-false
        assert!(!rule.features.can_view_ec2);
    }

    #[test]
    fn user_entitlements_omits_empty_excluded_selectors() {
        let ent = UserEntitlements {
            user_id: "u1".into(),
            email: "u@x.com".into(),
            display_name: "U".into(),
            groups: vec!["ops".into()],
            features: FeatureFlags::default(),
            allowed_accounts: vec![],
            allowed_regions: vec![],
            allowed_log_group_arns: vec![],
            instance_tag_selectors: vec![],
            excluded_tag_selectors: vec![],
            allowed_os_users: vec![],
            max_session_seconds: None,
            database_scopes: vec![],
        };
        let json = serde_json::to_string(&ent).unwrap();
        assert!(!json.contains("excluded_tag_selectors"));
        assert!(!json.contains("max_session_seconds"));
    }

    #[test]
    fn user_entitlements_full_roundtrip() {
        let ent = UserEntitlements {
            user_id: "u1".into(),
            email: "u@x.com".into(),
            display_name: "User One".into(),
            groups: vec!["ops".into(), "dev".into()],
            features: FeatureFlags {
                can_view_ec2: true,
                can_use_cloudwatch_search: true,
                can_use_cloudwatch_tail: true,
                can_use_ssm: true,
                can_use_ec2_instance_connect: false,
                ..Default::default()
            },
            allowed_accounts: vec![AllowedAccount {
                account_id: "111".into(),
                account_name: "prod".into(),
                role_arn: "arn:aws:iam::111:role/ops".into(),
            }],
            allowed_regions: vec!["us-east-1".into()],
            allowed_log_group_arns: vec!["arn:aws:logs:us-east-1:111:log-group:/app".into()],
            instance_tag_selectors: vec![TagSelector {
                tags: HashMap::from([("env".into(), vec!["prod".into()])]),
            }],
            excluded_tag_selectors: vec![TagSelector {
                tags: HashMap::from([("temp".into(), vec!["true".into()])]),
            }],
            allowed_os_users: vec!["ec2-user".into()],
            max_session_seconds: Some(3600),
            database_scopes: vec![DatabaseScope {
                name: "orders_prod_readonly".into(),
                connection: "orders_prod".into(),
                environment: "production".into(),
                allowed_schemas: vec!["orders".into()],
                allowed_tables: vec!["orders".into(), "order_items".into()],
                allowed_actions: vec!["select".into()],
                max_rows: 100,
                statement_timeout_ms: 5000,
                require_explain: true,
                max_examined_rows: 10000,
                allow_full_table_scan: false,
                allow_views: false,
            }],
        };
        let json = serde_json::to_value(&ent).unwrap();
        let back: UserEntitlements = serde_json::from_value(json).unwrap();
        assert_eq!(back.user_id, "u1");
        assert_eq!(back.groups.len(), 2);
        assert!(back.features.can_use_ssm);
        assert_eq!(back.allowed_accounts[0].account_id, "111");
        assert_eq!(back.excluded_tag_selectors.len(), 1);
        assert_eq!(back.max_session_seconds, Some(3600));
        assert_eq!(back.database_scopes.len(), 1);
    }

    #[test]
    fn database_scope_roundtrip() {
        let toml = r#"
            name = "orders_prod_readonly"
            connection = "orders_prod"
            environment = "production"
            allowed_schemas = ["orders"]
            allowed_tables = ["orders", "order_items"]
            allowed_actions = ["select"]
            max_rows = 100
            statement_timeout_ms = 5000
            require_explain = true
            max_examined_rows = 10000
            allow_full_table_scan = false
        "#;
        let scope: DatabaseScope = toml::from_str(toml).unwrap();
        assert_eq!(scope.name, "orders_prod_readonly");
        assert_eq!(scope.connection, "orders_prod");
        assert!(scope.require_explain);
        assert!(!scope.allow_full_table_scan);
    }

    #[test]
    fn group_membership_roundtrip() {
        let gm = GroupMembership {
            user_id: "u1".into(),
            group: "ops".into(),
        };
        let json = serde_json::to_value(&gm).unwrap();
        let back: GroupMembership = serde_json::from_value(json).unwrap();
        assert_eq!(back.user_id, "u1");
        assert_eq!(back.group, "ops");
    }
}
