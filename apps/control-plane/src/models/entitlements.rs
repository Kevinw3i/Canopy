use serde::Deserialize;
use shared::dto::entitlements::*;
use std::collections::HashMap;
use std::path::Path;

/// In-memory entitlement store. In production, loaded from an entitlements
/// config file. The file format mirrors the struct layout (TOML/JSON).
#[derive(Debug, Clone, Deserialize)]
pub struct EntitlementStore {
    pub rules: Vec<EntitlementRule>,
    pub memberships: Vec<GroupMembership>,
}

impl EntitlementStore {
    /// Evaluate all entitlements for a user by merging rules from all their groups.
    /// Uses additive merge: if any group grants a feature, the user has it.
    ///
    /// `email_verified`: when true, memberships may match by email in addition
    /// to `sub`. When false or None, only `sub` is used to prevent privilege
    /// escalation via unverified email claims.
    pub fn evaluate(
        &self,
        user_id: &str,
        email: &str,
        display_name: &str,
        email_verified: bool,
    ) -> UserEntitlements {
        // Match memberships by user_id (OIDC sub). Only fall back to email
        // when the IdP has confirmed the email is verified.
        let user_groups: Vec<String> = self
            .memberships
            .iter()
            .filter(|m| m.user_id == user_id || (email_verified && m.user_id == email))
            .map(|m| m.group.clone())
            .collect();

        let matching_rules: Vec<&EntitlementRule> = self
            .rules
            .iter()
            .filter(|r| user_groups.contains(&r.group))
            .collect();

        let mut features = FeatureFlags::default();
        let mut allowed_accounts: Vec<AllowedAccount> = Vec::new();
        let mut allowed_regions: Vec<String> = Vec::new();
        let mut allowed_log_group_arns: Vec<String> = Vec::new();
        let mut instance_tag_selectors: Vec<TagSelector> = Vec::new();
        let mut excluded_tag_selectors: Vec<TagSelector> = Vec::new();
        let mut allowed_os_users: Vec<String> = Vec::new();
        let mut max_session_seconds: Option<u64> = None;
        let mut database_scopes: Vec<DatabaseScope> = Vec::new();
        let mut ambiguous_database_scope_keys: Vec<DatabaseScopeKey> = Vec::new();

        for rule in &matching_rules {
            // Additive merge for feature flags
            features.can_view_ec2 |= rule.features.can_view_ec2;
            features.can_use_cloudwatch_search |= rule.features.can_use_cloudwatch_search;
            features.can_use_cloudwatch_tail |= rule.features.can_use_cloudwatch_tail;
            features.can_use_ssm |= rule.features.can_use_ssm;
            features.can_use_ec2_instance_connect |= rule.features.can_use_ec2_instance_connect;
            // Power-action flags follow the same additive rule: if any
            // matching group grants it, the user has it.
            //
            // IMPORTANT: the power route MUST NOT rely solely on the
            // merged `features.can_*_ec2` view (or on
            // `has_feature_for_scope`, which only checks
            // feature/account/region/log-group/os-user). Per-instance
            // `instance_tag_selectors` and `excluded_tag_selectors` are
            // NOT enforced by `has_feature_for_scope` and would let a
            // user with a tag-limited rule operate on out-of-scope
            // instances in the same account+region. The power-action
            // route must DescribeInstances first, then re-validate the
            // target instance's tags against the matching rule's
            // selectors before any AWS power call (mirroring the
            // EC2 list/connect tag boundary).
            features.can_start_ec2 |= rule.features.can_start_ec2;
            features.can_stop_ec2 |= rule.features.can_stop_ec2;
            features.can_reboot_ec2 |= rule.features.can_reboot_ec2;
            features.can_use_mcp |= rule.features.can_use_mcp;
            features.can_use_mcp_cloudwatch |= rule.features.can_use_mcp_cloudwatch;
            features.can_view_mcp_raw_audit_plaintext |=
                rule.features.can_view_mcp_raw_audit_plaintext;
            features.can_use_mcp_ec2 |= rule.features.can_use_mcp_ec2;
            features.can_use_mcp_database |= rule.features.can_use_mcp_database;

            for acct in &rule.allowed_accounts {
                // Dedup by (account_id, role_arn) so that two groups
                // granting the same account with different roles both
                // survive the merge.
                if !allowed_accounts
                    .iter()
                    .any(|a| a.account_id == acct.account_id && a.role_arn == acct.role_arn)
                {
                    allowed_accounts.push(acct.clone());
                }
            }

            for region in &rule.allowed_regions {
                if !allowed_regions.contains(region) {
                    allowed_regions.push(region.clone());
                }
            }

            for arn in &rule.allowed_log_group_arns {
                if !allowed_log_group_arns.contains(arn) {
                    allowed_log_group_arns.push(arn.clone());
                }
            }

            for selector in &rule.instance_tag_selectors {
                if !instance_tag_selectors.contains(selector) {
                    instance_tag_selectors.push(selector.clone());
                }
            }
            for selector in &rule.excluded_tag_selectors {
                if !excluded_tag_selectors.contains(selector) {
                    excluded_tag_selectors.push(selector.clone());
                }
            }

            for user in &rule.allowed_os_users {
                if !allowed_os_users.contains(user) {
                    allowed_os_users.push(user.clone());
                }
            }

            // Use the strictest (smallest non-zero) session limit across groups
            if let Some(secs) = rule.max_session_seconds {
                if secs > 0 {
                    max_session_seconds =
                        Some(max_session_seconds.map_or(secs, |existing| existing.min(secs)));
                }
            }

            if rule.features.can_use_mcp && rule.features.can_use_mcp_database {
                for scope in &rule.database_scopes {
                    push_unambiguous_database_scope(
                        &mut database_scopes,
                        &mut ambiguous_database_scope_keys,
                        scope,
                    );
                }
            }
        }

        UserEntitlements {
            user_id: user_id.to_string(),
            email: email.to_string(),
            display_name: display_name.to_string(),
            groups: user_groups,
            features,
            allowed_accounts,
            allowed_regions,
            allowed_log_group_arns,
            instance_tag_selectors,
            excluded_tag_selectors,
            allowed_os_users,
            max_session_seconds,
            database_scopes,
        }
    }

    pub fn matching_database_scope(
        &self,
        user_id: &str,
        email: &str,
        email_verified: bool,
        scope_name: &str,
        connection: Option<&str>,
        environment: Option<&str>,
    ) -> Option<DatabaseScope> {
        let user_groups: Vec<String> = self
            .memberships
            .iter()
            .filter(|m| m.user_id == user_id || (email_verified && m.user_id == email))
            .map(|m| m.group.clone())
            .collect();

        let matches = self
            .rules
            .iter()
            .filter(|rule| {
                user_groups.contains(&rule.group)
                    && rule.features.can_use_mcp
                    && rule.features.can_use_mcp_database
            })
            .flat_map(|rule| rule.database_scopes.iter())
            .filter(|scope| {
                scope.name == scope_name
                    && connection.is_none_or(|value| scope.connection == value)
                    && environment.is_none_or(|value| scope.environment == value)
            })
            .cloned()
            .collect::<Vec<_>>();

        let mut unique_matches = Vec::new();
        for scope in matches {
            if !unique_matches.contains(&scope) {
                unique_matches.push(scope);
            }
        }

        if unique_matches.len() == 1 {
            unique_matches.pop()
        } else {
            None
        }
    }

    pub fn database_scopes_for_user(
        &self,
        user_id: &str,
        email: &str,
        email_verified: bool,
    ) -> Vec<DatabaseScope> {
        let user_groups: Vec<String> = self
            .memberships
            .iter()
            .filter(|m| m.user_id == user_id || (email_verified && m.user_id == email))
            .map(|m| m.group.clone())
            .collect();

        let mut scopes = Vec::new();
        let mut ambiguous_scope_keys = Vec::new();
        for rule in self.rules.iter().filter(|rule| {
            user_groups.contains(&rule.group)
                && rule.features.can_use_mcp
                && rule.features.can_use_mcp_database
        }) {
            for scope in &rule.database_scopes {
                push_unambiguous_database_scope(&mut scopes, &mut ambiguous_scope_keys, scope);
            }
        }
        scopes
    }

    /// Check if a user has a *single rule* that grants the given feature
    /// AND access to the specified scope. This prevents cross-group
    /// privilege escalation where a feature from one group is applied
    /// to resources from another group.
    ///
    /// Optionally validates region, log group ARN, and OS user against
    /// the *same rule* that grants the feature and account access.
    #[allow(clippy::too_many_arguments)]
    pub fn has_feature_for_scope(
        &self,
        user_id: &str,
        email: &str,
        email_verified: bool,
        account_id: &str,
        region: Option<&str>,
        log_group_arn: Option<&str>,
        os_user: Option<&str>,
        feature_check: impl Fn(&FeatureFlags) -> bool,
    ) -> bool {
        let user_groups: Vec<String> = self
            .memberships
            .iter()
            .filter(|m| m.user_id == user_id || (email_verified && m.user_id == email))
            .map(|m| m.group.clone())
            .collect();

        self.rules.iter().any(|rule| {
            if !user_groups.contains(&rule.group) {
                return false;
            }
            if !feature_check(&rule.features) {
                return false;
            }
            if !rule
                .allowed_accounts
                .iter()
                .any(|a| a.account_id == account_id)
            {
                return false;
            }
            if let Some(region) = region {
                if !rule.allowed_regions.is_empty()
                    && !rule.allowed_regions.contains(&region.to_string())
                {
                    return false;
                }
            }
            if let Some(lg_arn) = log_group_arn {
                if !rule.allowed_log_group_arns.is_empty()
                    && !rule.allowed_log_group_arns.iter().any(|pattern| {
                        crate::services::entitlements::arn_matches_pattern(pattern, lg_arn)
                    })
                {
                    return false;
                }
            }
            if let Some(user) = os_user {
                let has_wildcard = rule.allowed_os_users.iter().any(|u| u == "*");
                if !rule.allowed_os_users.is_empty()
                    && !has_wildcard
                    && !rule.allowed_os_users.contains(&user.to_string())
                {
                    return false;
                }
            }
            true
        })
    }

    /// Return all rules that match the user AND grant the given feature
    /// for the specified account. Callers should use these rules' scope
    /// fields (regions, log groups, tag selectors, OS users) for
    /// downstream filtering instead of the merged UserEntitlements.
    pub fn matching_rules_for_scope(
        &self,
        user_id: &str,
        email: &str,
        email_verified: bool,
        account_id: &str,
        feature_check: impl Fn(&FeatureFlags) -> bool,
    ) -> Vec<&EntitlementRule> {
        let user_groups: Vec<String> = self
            .memberships
            .iter()
            .filter(|m| m.user_id == user_id || (email_verified && m.user_id == email))
            .map(|m| m.group.clone())
            .collect();

        self.rules
            .iter()
            .filter(|rule| {
                user_groups.contains(&rule.group)
                    && feature_check(&rule.features)
                    && rule
                        .allowed_accounts
                        .iter()
                        .any(|a| a.account_id == account_id)
            })
            .collect()
    }

    pub fn mcp_cloudwatch_raw_audit_plaintext_allowed(
        &self,
        user_id: &str,
        email: &str,
        email_verified: bool,
        account_id: &str,
        region: &str,
        log_group_names: &[String],
    ) -> bool {
        if log_group_names.is_empty() {
            return false;
        }

        let user_groups: Vec<String> = self
            .memberships
            .iter()
            .filter(|m| m.user_id == user_id || (email_verified && m.user_id == email))
            .map(|m| m.group.clone())
            .collect();

        self.rules.iter().any(|rule| {
            if !user_groups.contains(&rule.group)
                || !rule.features.can_use_mcp
                || !rule.features.can_use_mcp_cloudwatch
                || !rule.features.can_view_mcp_raw_audit_plaintext
            {
                return false;
            }
            if !rule
                .allowed_accounts
                .iter()
                .any(|account| account.account_id == account_id)
            {
                return false;
            }
            if !rule.allowed_regions.is_empty()
                && !rule.allowed_regions.iter().any(|allowed| allowed == region)
            {
                return false;
            }
            if rule.allowed_log_group_arns.is_empty() {
                return true;
            }
            log_group_names.iter().all(|name| {
                let variants = {
                    let base = format!("arn:aws:logs:{region}:{account_id}:log-group:{name}");
                    [base.clone(), format!("{base}:*")]
                };
                rule.allowed_log_group_arns.iter().any(|pattern| {
                    variants
                        .iter()
                        .any(|arn| crate::services::entitlements::arn_matches_pattern(pattern, arn))
                })
            })
        })
    }

    /// Convenience: check feature + account only.
    pub fn has_feature_for_account(
        &self,
        user_id: &str,
        email: &str,
        email_verified: bool,
        account_id: &str,
        feature_check: impl Fn(&FeatureFlags) -> bool,
    ) -> bool {
        self.has_feature_for_scope(
            user_id,
            email,
            email_verified,
            account_id,
            None,
            None,
            None,
            feature_check,
        )
    }

    /// Load entitlements from a TOML file.
    pub fn load_from_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read entitlements file {:?}: {}", path, e))?;
        let store: EntitlementStore = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse entitlements file {:?}: {}", path, e))?;

        tracing::info!(
            rules = store.rules.len(),
            memberships = store.memberships.len(),
            "Loaded entitlements from {:?}",
            path
        );

        // Validate: reject rules that enable SSM without explicit OS users
        // unless "*" is set as an explicit opt-in for unrestricted shells.
        for rule in &store.rules {
            if rule.features.can_use_ssm && rule.allowed_os_users.is_empty() {
                anyhow::bail!(
                    "Rule '{}' (group '{}') has can_use_ssm=true but no allowed_os_users. \
                     This would grant unrestricted SSM shell access. \
                     Set allowed_os_users to specific users, or [\"*\"] to explicitly opt in \
                     to unrestricted shell access.",
                    rule.id,
                    rule.group
                );
            }
            for scope in &rule.database_scopes {
                validate_database_scope_identifiers(&rule.id, scope)?;
            }
        }

        Ok(store)
    }

    /// Sample data for development
    pub fn dev_defaults() -> Self {
        Self {
            rules: vec![
                EntitlementRule {
                    id: "rule-platform-eng".into(),
                    group: "platform-engineering".into(),
                    features: FeatureFlags {
                        can_view_ec2: true,
                        can_use_cloudwatch_search: true,
                        can_use_cloudwatch_tail: true,
                        can_use_ssm: true,
                        can_use_ec2_instance_connect: true,
                        can_use_mcp: true,
                        can_use_mcp_cloudwatch: true,
                        can_use_mcp_database: true,
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
                    allowed_regions: vec![
                        "us-east-1".into(),
                        "us-west-2".into(),
                        "eu-west-1".into(),
                    ],
                    allowed_log_group_arns: vec![
                        "arn:aws:logs:*:111111111111:log-group:/app/*".into(),
                        "arn:aws:logs:*:222222222222:log-group:/app/*".into(),
                    ],
                    instance_tag_selectors: vec![TagSelector {
                        tags: HashMap::from([(
                            "Environment".into(),
                            vec!["production".into(), "staging".into()],
                        )]),
                    }],
                    excluded_tag_selectors: vec![],
                    allowed_os_users: vec!["ec2-user".into(), "ubuntu".into()],
                    max_session_seconds: None, // no limit for admin
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
                },
                EntitlementRule {
                    id: "rule-platform-eng-power".into(),
                    group: "platform-engineering".into(),
                    features: FeatureFlags {
                        can_start_ec2: true,
                        can_stop_ec2: true,
                        can_reboot_ec2: true,
                        ..Default::default()
                    },
                    allowed_accounts: vec![
                        AllowedAccount {
                            account_id: "111111111111".into(),
                            account_name: "production".into(),
                            role_arn: "arn:aws:iam::111111111111:role/CanopyOperatorRole".into(),
                        },
                        AllowedAccount {
                            account_id: "222222222222".into(),
                            account_name: "staging".into(),
                            role_arn: "arn:aws:iam::222222222222:role/CanopyOperatorRole".into(),
                        },
                    ],
                    allowed_regions: vec![
                        "us-east-1".into(),
                        "us-west-2".into(),
                        "eu-west-1".into(),
                    ],
                    allowed_log_group_arns: vec![],
                    instance_tag_selectors: vec![TagSelector {
                        tags: HashMap::from([(
                            "Environment".into(),
                            vec!["production".into(), "staging".into()],
                        )]),
                    }],
                    excluded_tag_selectors: vec![],
                    allowed_os_users: vec![],
                    max_session_seconds: None,
                    database_scopes: vec![],
                },
                EntitlementRule {
                    id: "rule-readonly".into(),
                    group: "readonly-ops".into(),
                    features: FeatureFlags {
                        can_view_ec2: true,
                        can_use_cloudwatch_search: true,
                        can_use_cloudwatch_tail: false,
                        can_use_ssm: false,
                        can_use_ec2_instance_connect: false,
                        can_use_mcp: true,
                        can_use_mcp_cloudwatch: true,
                        ..Default::default()
                    },
                    allowed_accounts: vec![AllowedAccount {
                        account_id: "222222222222".into(),
                        account_name: "staging".into(),
                        role_arn: "arn:aws:iam::222222222222:role/CanopyReadOnly".into(),
                    }],
                    allowed_regions: vec!["us-east-1".into()],
                    allowed_log_group_arns: vec![
                        "arn:aws:logs:*:222222222222:log-group:/app/*".into()
                    ],
                    instance_tag_selectors: vec![TagSelector {
                        tags: HashMap::from([("Environment".into(), vec!["staging".into()])]),
                    }],
                    excluded_tag_selectors: vec![],
                    allowed_os_users: vec![],
                    max_session_seconds: Some(3600), // 60 min for readonly
                    database_scopes: vec![],
                },
            ],
            memberships: vec![
                GroupMembership {
                    user_id: "dev-admin".into(),
                    group: "platform-engineering".into(),
                },
                GroupMembership {
                    user_id: "dev-readonly".into(),
                    group: "readonly-ops".into(),
                },
            ],
        }
    }
}

/// Refuse to load an entitlement file whose database scope identifiers are
/// not lowercase ASCII. The query-side validator already rejects mixed-case
/// table/schema references; symmetrically rejecting them on the entitlement
/// side closes the gap where `allowed_tables = ["Orders"]` would be silently
/// normalized to `orders` and let a lowercase `orders` query through on
/// case-sensitive MySQL servers.
fn validate_database_scope_identifiers(rule_id: &str, scope: &DatabaseScope) -> anyhow::Result<()> {
    fn check(kind: &str, rule_id: &str, scope: &DatabaseScope, ident: &str) -> anyhow::Result<()> {
        if ident.chars().any(|c| c.is_ascii_uppercase()) {
            anyhow::bail!(
                "Rule '{rule_id}' database scope '{scope_name}' has {kind} '{ident}' \
                 with uppercase characters. Identifiers must be lowercase ASCII so the \
                 control-plane never silently conflates case-sensitive MySQL table names.",
                scope_name = scope.name
            );
        }
        Ok(())
    }
    for schema in &scope.allowed_schemas {
        check("allowed_schema", rule_id, scope, schema)?;
    }
    for table in &scope.allowed_tables {
        check("allowed_table", rule_id, scope, table)?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DatabaseScopeKey {
    name: String,
    connection: String,
    environment: String,
}

impl From<&DatabaseScope> for DatabaseScopeKey {
    fn from(scope: &DatabaseScope) -> Self {
        Self {
            name: scope.name.clone(),
            connection: scope.connection.clone(),
            environment: scope.environment.clone(),
        }
    }
}

fn push_unambiguous_database_scope(
    scopes: &mut Vec<DatabaseScope>,
    ambiguous_keys: &mut Vec<DatabaseScopeKey>,
    scope: &DatabaseScope,
) {
    let key = DatabaseScopeKey::from(scope);
    if ambiguous_keys.contains(&key) {
        return;
    }

    if let Some(existing_index) = scopes
        .iter()
        .position(|existing| DatabaseScopeKey::from(existing) == key)
    {
        if scopes[existing_index] != *scope {
            scopes.remove(existing_index);
            ambiguous_keys.push(key);
        }
        return;
    }

    scopes.push(scope.clone());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> EntitlementStore {
        EntitlementStore::dev_defaults()
    }

    #[test]
    fn test_admin_gets_all_features() {
        let store = test_store();
        let ent = store.evaluate("dev-admin", "admin@example.com", "Admin", true);
        assert!(ent.features.can_view_ec2);
        assert!(ent.features.can_use_cloudwatch_search);
        assert!(ent.features.can_use_cloudwatch_tail);
        assert!(ent.features.can_use_ssm);
        assert!(ent.features.can_use_ec2_instance_connect);
        assert!(ent.features.can_start_ec2);
        assert!(ent.features.can_stop_ec2);
        assert!(ent.features.can_reboot_ec2);
        assert!(ent.features.can_use_mcp);
        assert!(ent.features.can_use_mcp_cloudwatch);
        assert!(!ent.features.can_view_mcp_raw_audit_plaintext);
        assert!(!ent.features.can_use_mcp_ec2);
        assert!(ent.features.can_use_mcp_database);
        assert_eq!(ent.database_scopes.len(), 1);
        assert_eq!(ent.allowed_accounts.len(), 4);
        assert_eq!(ent.allowed_regions.len(), 3);
    }

    #[test]
    fn test_readonly_has_limited_features() {
        let store = test_store();
        let ent = store.evaluate("dev-readonly", "readonly@example.com", "Read Only", true);
        assert!(ent.features.can_view_ec2);
        assert!(ent.features.can_use_cloudwatch_search);
        assert!(!ent.features.can_use_cloudwatch_tail);
        assert!(!ent.features.can_use_ssm);
        assert!(!ent.features.can_use_ec2_instance_connect);
        assert!(!ent.features.can_start_ec2);
        assert!(!ent.features.can_stop_ec2);
        assert!(!ent.features.can_reboot_ec2);
        assert!(ent.features.can_use_mcp);
        assert!(ent.features.can_use_mcp_cloudwatch);
        assert!(!ent.features.can_view_mcp_raw_audit_plaintext);
        assert!(!ent.features.can_use_mcp_ec2);
        assert!(!ent.features.can_use_mcp_database);
        assert_eq!(ent.allowed_accounts.len(), 1);
        assert_eq!(ent.allowed_regions.len(), 1);
    }

    #[test]
    fn test_unknown_user_gets_nothing() {
        let store = test_store();
        let ent = store.evaluate("unknown", "nobody@example.com", "Nobody", true);
        assert!(!ent.features.can_view_ec2);
        assert!(ent.allowed_accounts.is_empty());
        assert!(ent.groups.is_empty());
    }

    #[test]
    fn test_multi_group_merges_additively() {
        let mut store = test_store();
        // Give dev-readonly BOTH groups
        store.memberships.push(GroupMembership {
            user_id: "dev-readonly".into(),
            group: "platform-engineering".into(),
        });
        let ent = store.evaluate("dev-readonly", "readonly@example.com", "Read Only", true);
        // Should now have all features from both groups
        assert!(ent.features.can_use_ssm);
        assert!(ent.features.can_use_ec2_instance_connect);
        assert!(ent.features.can_start_ec2);
        assert!(ent.features.can_stop_ec2);
        assert!(ent.features.can_reboot_ec2);
        assert!(ent.features.can_use_mcp);
        assert!(ent.features.can_use_mcp_cloudwatch);
        assert!(!ent.features.can_view_mcp_raw_audit_plaintext);
        assert!(ent.features.can_use_mcp_database);
        // 5 account entries: two read/connect roles, two operator roles,
        // plus the readonly staging role (distinct role ARNs are preserved).
        assert_eq!(ent.allowed_accounts.len(), 5);
    }

    #[test]
    fn mcp_cloudwatch_raw_audit_plaintext_requires_same_scoped_rule() {
        let mut store = test_store();
        store.rules.push(EntitlementRule {
            id: "rule-raw-audit-reviewer".into(),
            group: "raw-audit-reviewers".into(),
            features: FeatureFlags {
                can_use_mcp: true,
                can_use_mcp_cloudwatch: true,
                can_view_mcp_raw_audit_plaintext: true,
                ..Default::default()
            },
            allowed_accounts: vec![AllowedAccount {
                account_id: "111111111111".into(),
                account_name: "production".into(),
                role_arn: "arn:aws:iam::111111111111:role/CanopyAuditRole".into(),
            }],
            allowed_regions: vec!["us-east-1".into()],
            allowed_log_group_arns: vec!["arn:aws:logs:*:111111111111:log-group:/infra/*".into()],
            instance_tag_selectors: vec![],
            excluded_tag_selectors: vec![],
            allowed_os_users: vec![],
            max_session_seconds: None,
            database_scopes: vec![],
        });
        store.memberships.push(GroupMembership {
            user_id: "dev-admin".into(),
            group: "raw-audit-reviewers".into(),
        });

        assert!(!store.mcp_cloudwatch_raw_audit_plaintext_allowed(
            "dev-admin",
            "admin@example.com",
            true,
            "111111111111",
            "us-east-1",
            &["/app/web-service".into()],
        ));
    }

    #[test]
    fn mcp_cloudwatch_raw_audit_plaintext_allows_matching_scoped_rule() {
        let mut store = test_store();
        store.rules[0].features.can_view_mcp_raw_audit_plaintext = true;

        assert!(store.mcp_cloudwatch_raw_audit_plaintext_allowed(
            "dev-admin",
            "admin@example.com",
            true,
            "111111111111",
            "us-east-1",
            &["/app/web-service".into()],
        ));
        assert!(!store.mcp_cloudwatch_raw_audit_plaintext_allowed(
            "dev-admin",
            "admin@example.com",
            true,
            "111111111111",
            "us-east-1",
            &[],
        ));
    }

    // ── Boundary tests ─────────────────────────────────

    #[test]
    fn test_deny_by_default_no_memberships() {
        // A store with rules but no memberships → every user is denied
        let store = EntitlementStore {
            rules: test_store().rules,
            memberships: vec![],
        };
        let ent = store.evaluate("anyone", "anyone@example.com", "Anyone", true);
        assert!(!ent.features.can_view_ec2);
        assert!(!ent.features.can_use_ssm);
        assert!(ent.allowed_accounts.is_empty());
        assert!(ent.allowed_regions.is_empty());
        assert!(ent.groups.is_empty());
    }

    #[test]
    fn test_deny_by_default_no_rules() {
        // A store with memberships but no matching rules → denied
        let store = EntitlementStore {
            rules: vec![],
            memberships: vec![GroupMembership {
                user_id: "user1".into(),
                group: "some-group".into(),
            }],
        };
        let ent = store.evaluate("user1", "user1@example.com", "User 1", true);
        assert!(!ent.features.can_view_ec2);
        assert!(ent.allowed_accounts.is_empty());
        // User still has the group membership, just no permissions from it
        assert_eq!(ent.groups, vec!["some-group".to_string()]);
    }

    #[test]
    fn test_multi_group_preserves_distinct_roles_for_same_account() {
        let mut store = test_store();
        // Both groups grant account 222222222222 but with different role ARNs
        // (CanopyRole vs CanopyReadOnly). Both should be preserved.
        store.memberships.push(GroupMembership {
            user_id: "dev-admin".into(),
            group: "readonly-ops".into(),
        });
        let ent = store.evaluate("dev-admin", "admin@example.com", "Admin", true);
        let staging_entries: Vec<_> = ent
            .allowed_accounts
            .iter()
            .filter(|a| a.account_id == "222222222222")
            .collect();
        assert_eq!(
            staging_entries.len(),
            3,
            "Account 222222222222 with three distinct role ARNs should appear three times"
        );
        // Verify at least two entries have different role ARNs.
        assert_ne!(staging_entries[0].role_arn, staging_entries[1].role_arn);
    }

    #[test]
    fn test_multi_group_deduplicates_same_account_same_role() {
        let mut store = test_store();
        // Add a second rule for the same account+role — should still dedup
        store.rules.push(EntitlementRule {
            id: "rule-extra".into(),
            group: "extra-group".into(),
            features: FeatureFlags::default(),
            allowed_accounts: vec![AllowedAccount {
                account_id: "111111111111".into(),
                account_name: "production".into(),
                role_arn: "arn:aws:iam::111111111111:role/CanopyRole".into(),
            }],
            allowed_regions: vec![],
            allowed_log_group_arns: vec![],
            instance_tag_selectors: vec![],
            excluded_tag_selectors: vec![],
            allowed_os_users: vec![],
            max_session_seconds: None,
            database_scopes: vec![],
        });
        store.memberships.push(GroupMembership {
            user_id: "dev-admin".into(),
            group: "extra-group".into(),
        });
        let ent = store.evaluate("dev-admin", "admin@example.com", "Admin", true);
        let prod_count = ent
            .allowed_accounts
            .iter()
            .filter(|a| {
                a.account_id == "111111111111"
                    && a.role_arn == "arn:aws:iam::111111111111:role/CanopyRole"
            })
            .count();
        assert_eq!(prod_count, 1, "Same account+role should appear only once");
    }

    #[test]
    fn test_matching_database_scope_deduplicates_identical_grants() {
        let mut store = test_store();
        let scope = store.rules[0].database_scopes[0].clone();
        store.rules.push(EntitlementRule {
            id: "rule-duplicate-db-scope".into(),
            group: "duplicate-db-scope".into(),
            features: FeatureFlags {
                can_use_mcp: true,
                can_use_mcp_database: true,
                ..Default::default()
            },
            allowed_accounts: vec![],
            allowed_regions: vec![],
            allowed_log_group_arns: vec![],
            instance_tag_selectors: vec![],
            excluded_tag_selectors: vec![],
            allowed_os_users: vec![],
            max_session_seconds: None,
            database_scopes: vec![scope.clone()],
        });
        store.memberships.push(GroupMembership {
            user_id: "dev-admin".into(),
            group: "duplicate-db-scope".into(),
        });

        let matched = store
            .matching_database_scope(
                "dev-admin",
                "admin@example.com",
                true,
                "orders_prod_readonly",
                Some("orders_prod"),
                Some("production"),
            )
            .unwrap();
        assert_eq!(matched, scope);

        let listed = store.database_scopes_for_user("dev-admin", "admin@example.com", true);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0], scope);
    }

    #[test]
    fn test_database_scope_list_hides_ambiguous_policy_grants() {
        let mut store = test_store();
        let mut conflicting_scope = store.rules[0].database_scopes[0].clone();
        conflicting_scope.max_rows = 50;
        conflicting_scope.allowed_tables = vec!["orders".into()];
        store.rules.push(EntitlementRule {
            id: "rule-conflicting-db-scope".into(),
            group: "conflicting-db-scope".into(),
            features: FeatureFlags {
                can_use_mcp: true,
                can_use_mcp_database: true,
                ..Default::default()
            },
            allowed_accounts: vec![],
            allowed_regions: vec![],
            allowed_log_group_arns: vec![],
            instance_tag_selectors: vec![],
            excluded_tag_selectors: vec![],
            allowed_os_users: vec![],
            max_session_seconds: None,
            database_scopes: vec![conflicting_scope],
        });
        store.memberships.push(GroupMembership {
            user_id: "dev-admin".into(),
            group: "conflicting-db-scope".into(),
        });

        assert!(store
            .matching_database_scope(
                "dev-admin",
                "admin@example.com",
                true,
                "orders_prod_readonly",
                Some("orders_prod"),
                Some("production"),
            )
            .is_none());

        let listed = store.database_scopes_for_user("dev-admin", "admin@example.com", true);
        assert!(
            listed.is_empty(),
            "scope list should not advertise a scope that query would reject as ambiguous"
        );

        let ent = store.evaluate("dev-admin", "admin@example.com", "Admin", true);
        assert!(
            ent.database_scopes.is_empty(),
            "merged entitlements should follow the same ambiguity policy as database query matching"
        );
    }

    #[test]
    fn test_database_scopes_require_same_rule_database_feature() {
        let mut store = test_store();
        let leaked_scope = store.rules[0].database_scopes[0].clone();
        store.rules[0].database_scopes.clear();
        store.rules.push(EntitlementRule {
            id: "rule-db-scope-without-feature".into(),
            group: "db-scope-without-feature".into(),
            features: FeatureFlags {
                can_use_mcp: true,
                can_use_mcp_database: false,
                ..Default::default()
            },
            allowed_accounts: vec![],
            allowed_regions: vec![],
            allowed_log_group_arns: vec![],
            instance_tag_selectors: vec![],
            excluded_tag_selectors: vec![],
            allowed_os_users: vec![],
            max_session_seconds: None,
            database_scopes: vec![leaked_scope],
        });
        store.memberships.push(GroupMembership {
            user_id: "dev-admin".into(),
            group: "db-scope-without-feature".into(),
        });

        let ent = store.evaluate("dev-admin", "admin@example.com", "Admin", true);

        assert!(ent.features.can_use_mcp_database);
        assert!(
            ent.database_scopes.is_empty(),
            "database scopes must come from the same matching rule that grants can_use_mcp_database"
        );
    }

    #[test]
    fn test_multi_group_no_duplicate_regions() {
        let mut store = test_store();
        store.memberships.push(GroupMembership {
            user_id: "dev-admin".into(),
            group: "readonly-ops".into(),
        });
        let ent = store.evaluate("dev-admin", "admin@example.com", "Admin", true);
        let ue1_count = ent
            .allowed_regions
            .iter()
            .filter(|r| *r == "us-east-1")
            .count();
        assert_eq!(ue1_count, 1, "us-east-1 should appear only once");
    }

    #[test]
    fn test_tag_selectors_merge_across_groups() {
        let mut store = test_store();
        store.memberships.push(GroupMembership {
            user_id: "dev-admin".into(),
            group: "readonly-ops".into(),
        });
        let ent = store.evaluate("dev-admin", "admin@example.com", "Admin", true);
        // platform-engineering has 1 tag selector, readonly-ops has 1 → 2 total
        assert_eq!(ent.instance_tag_selectors.len(), 2);
    }

    #[test]
    fn test_tag_selectors_dedup_across_groups() {
        let mut store = test_store();
        let duplicate_selector = TagSelector {
            tags: HashMap::from([(
                "Environment".into(),
                vec!["production".into(), "staging".into()],
            )]),
        };
        store.rules.push(EntitlementRule {
            id: "rule-duplicate-selector".into(),
            group: "duplicate-selector".into(),
            features: FeatureFlags::default(),
            allowed_accounts: vec![],
            allowed_regions: vec![],
            allowed_log_group_arns: vec![],
            instance_tag_selectors: vec![duplicate_selector],
            excluded_tag_selectors: vec![],
            allowed_os_users: vec![],
            max_session_seconds: None,
            database_scopes: vec![],
        });
        store.memberships.push(GroupMembership {
            user_id: "dev-admin".into(),
            group: "duplicate-selector".into(),
        });

        let ent = store.evaluate("dev-admin", "admin@example.com", "Admin", true);
        let prod_selector_count = ent
            .instance_tag_selectors
            .iter()
            .filter(|selector| {
                selector.tags.get("Environment")
                    == Some(&vec!["production".into(), "staging".into()])
            })
            .count();
        assert_eq!(prod_selector_count, 1);
    }

    #[test]
    fn test_empty_os_users_denies_all() {
        let store = test_store();
        let ent = store.evaluate("dev-readonly", "readonly@example.com", "Read Only", true);
        assert!(
            ent.allowed_os_users.is_empty(),
            "readonly-ops should have no allowed OS users"
        );
    }

    #[test]
    fn test_user_id_is_case_sensitive() {
        let store = test_store();
        let ent = store.evaluate("DEV-ADMIN", "admin@example.com", "Admin", true);
        // "DEV-ADMIN" != "dev-admin" → no groups, no permissions
        assert!(ent.groups.is_empty());
        assert!(!ent.features.can_view_ec2);
    }

    #[test]
    fn uppercase_database_scope_identifier_rejected_at_load_time() {
        // The runtime validator rejects mixed-case table identifiers in
        // queries, and the entitlement side must reject the same mixed-case
        // spelling instead of silently lowercasing it. Now `load_from_file`
        // refuses to accept an `allowed_tables` entry that contains uppercase
        // characters, so a hand-written TOML typo can never get the server to
        // authorize `orders` on the basis of a grant for `Orders` on
        // case-sensitive MySQL deployments.
        let bad_scope = DatabaseScope {
            name: "orders_prod_readonly".into(),
            connection: "orders_prod".into(),
            environment: "production".into(),
            allowed_schemas: vec!["orders".into()],
            allowed_tables: vec!["Orders".into()],
            allowed_actions: vec!["select".into()],
            max_rows: 100,
            statement_timeout_ms: 5000,
            require_explain: true,
            max_examined_rows: 10000,
            allow_full_table_scan: false,
            allow_views: false,
        };
        let err = super::validate_database_scope_identifiers("rule-bad", &bad_scope)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("uppercase"),
            "expected uppercase rejection, got: {err}"
        );

        let bad_schema = DatabaseScope {
            allowed_schemas: vec!["Orders".into()],
            allowed_tables: vec!["orders".into()],
            ..bad_scope
        };
        let err = super::validate_database_scope_identifiers("rule-bad", &bad_schema)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("uppercase"),
            "expected uppercase rejection, got: {err}"
        );
    }

    #[test]
    fn test_load_from_toml_string() {
        let toml_str = r#"
[[rules]]
id = "test-rule"
group = "testers"
allowed_accounts = []
allowed_regions = ["us-east-1"]
allowed_log_group_arns = []
instance_tag_selectors = []
allowed_os_users = []

[rules.features]
can_view_ec2 = true
can_use_cloudwatch_search = false
can_use_cloudwatch_tail = false
can_use_ssm = false
can_use_ec2_instance_connect = false

[[memberships]]
user_id = "tester1"
group = "testers"
"#;
        let store: EntitlementStore = toml::from_str(toml_str).unwrap();
        assert_eq!(store.rules.len(), 1);
        assert_eq!(store.memberships.len(), 1);
        let ent = store.evaluate("tester1", "t@t.com", "Tester", true);
        assert!(ent.features.can_view_ec2);
        assert!(!ent.features.can_use_ssm);
        assert_eq!(ent.allowed_regions, vec!["us-east-1"]);
    }
}
