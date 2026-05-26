use rusqlite::{params, Connection};
use serde::Deserialize;
use shared::dto::ecs::DEV_MOCK_CLUSTER_NAME;
use shared::dto::entitlements::*;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// In-memory entitlement store. In production, loaded from an entitlements
/// config file. The file format mirrors the struct layout (TOML/JSON).
#[derive(Debug, Clone, Deserialize)]
pub struct EntitlementStore {
    pub rules: Vec<EntitlementRule>,
    pub memberships: Vec<GroupMembership>,
}

pub const ORGANIZATION_ACCOUNT_PLACEHOLDER: &str = "*";
pub const ORGANIZATION_ACCOUNT_ID_TOKEN: &str = "{account_id}";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredOrganizationAccount {
    pub account_id: String,
    pub account_name: String,
}

const SQLITE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS entitlement_rules (
    id TEXT PRIMARY KEY,
    group_name TEXT NOT NULL,
    can_view_ec2 INTEGER NOT NULL DEFAULT 0 CHECK (can_view_ec2 IN (0, 1)),
    can_use_cloudwatch_search INTEGER NOT NULL DEFAULT 0 CHECK (can_use_cloudwatch_search IN (0, 1)),
    can_use_cloudwatch_tail INTEGER NOT NULL DEFAULT 0 CHECK (can_use_cloudwatch_tail IN (0, 1)),
    can_use_ssm INTEGER NOT NULL DEFAULT 0 CHECK (can_use_ssm IN (0, 1)),
    can_use_ec2_instance_connect INTEGER NOT NULL DEFAULT 0 CHECK (can_use_ec2_instance_connect IN (0, 1)),
    can_start_ec2 INTEGER NOT NULL DEFAULT 0 CHECK (can_start_ec2 IN (0, 1)),
    can_stop_ec2 INTEGER NOT NULL DEFAULT 0 CHECK (can_stop_ec2 IN (0, 1)),
    can_reboot_ec2 INTEGER NOT NULL DEFAULT 0 CHECK (can_reboot_ec2 IN (0, 1)),
    can_view_ecs INTEGER NOT NULL DEFAULT 0 CHECK (can_view_ecs IN (0, 1)),
    can_use_ecs_exec INTEGER NOT NULL DEFAULT 0 CHECK (can_use_ecs_exec IN (0, 1)),
    allow_broad_cluster_discovery INTEGER NOT NULL DEFAULT 0 CHECK (allow_broad_cluster_discovery IN (0, 1)),
    max_session_seconds INTEGER CHECK (max_session_seconds IS NULL OR max_session_seconds >= 0)
);

CREATE INDEX IF NOT EXISTS idx_entitlement_rules_group_name
    ON entitlement_rules(group_name);

CREATE TABLE IF NOT EXISTS entitlement_memberships (
    user_id TEXT NOT NULL,
    group_name TEXT NOT NULL,
    PRIMARY KEY (user_id, group_name)
);

CREATE INDEX IF NOT EXISTS idx_entitlement_memberships_group_name
    ON entitlement_memberships(group_name);

CREATE TABLE IF NOT EXISTS entitlement_allowed_accounts (
    rule_id TEXT NOT NULL REFERENCES entitlement_rules(id) ON DELETE CASCADE,
    position INTEGER NOT NULL DEFAULT 0,
    account_id TEXT NOT NULL,
    account_name TEXT NOT NULL,
    role_arn TEXT NOT NULL,
    PRIMARY KEY (rule_id, account_id, role_arn)
);

CREATE INDEX IF NOT EXISTS idx_entitlement_allowed_accounts_rule
    ON entitlement_allowed_accounts(rule_id, position);

CREATE TABLE IF NOT EXISTS entitlement_allowed_regions (
    rule_id TEXT NOT NULL REFERENCES entitlement_rules(id) ON DELETE CASCADE,
    position INTEGER NOT NULL DEFAULT 0,
    region TEXT NOT NULL,
    PRIMARY KEY (rule_id, region)
);

CREATE INDEX IF NOT EXISTS idx_entitlement_allowed_regions_rule
    ON entitlement_allowed_regions(rule_id, position);

CREATE TABLE IF NOT EXISTS entitlement_allowed_log_group_arns (
    rule_id TEXT NOT NULL REFERENCES entitlement_rules(id) ON DELETE CASCADE,
    position INTEGER NOT NULL DEFAULT 0,
    arn TEXT NOT NULL,
    PRIMARY KEY (rule_id, arn)
);

CREATE INDEX IF NOT EXISTS idx_entitlement_allowed_log_groups_rule
    ON entitlement_allowed_log_group_arns(rule_id, position);

CREATE TABLE IF NOT EXISTS entitlement_allowed_os_users (
    rule_id TEXT NOT NULL REFERENCES entitlement_rules(id) ON DELETE CASCADE,
    position INTEGER NOT NULL DEFAULT 0,
    os_user TEXT NOT NULL,
    PRIMARY KEY (rule_id, os_user)
);

CREATE INDEX IF NOT EXISTS idx_entitlement_allowed_os_users_rule
    ON entitlement_allowed_os_users(rule_id, position);

CREATE TABLE IF NOT EXISTS entitlement_allowed_clusters (
    rule_id TEXT NOT NULL REFERENCES entitlement_rules(id) ON DELETE CASCADE,
    position INTEGER NOT NULL DEFAULT 0,
    cluster TEXT NOT NULL,
    PRIMARY KEY (rule_id, cluster)
);

CREATE INDEX IF NOT EXISTS idx_entitlement_allowed_clusters_rule
    ON entitlement_allowed_clusters(rule_id, position);

CREATE TABLE IF NOT EXISTS entitlement_excluded_container_names (
    rule_id TEXT NOT NULL REFERENCES entitlement_rules(id) ON DELETE CASCADE,
    position INTEGER NOT NULL DEFAULT 0,
    container_name TEXT NOT NULL,
    PRIMARY KEY (rule_id, container_name)
);

CREATE INDEX IF NOT EXISTS idx_entitlement_excluded_containers_rule
    ON entitlement_excluded_container_names(rule_id, position);

CREATE TABLE IF NOT EXISTS entitlement_instance_tag_selectors (
    rule_id TEXT NOT NULL REFERENCES entitlement_rules(id) ON DELETE CASCADE,
    position INTEGER NOT NULL DEFAULT 0,
    selector_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entitlement_instance_tag_selectors_rule
    ON entitlement_instance_tag_selectors(rule_id, position);

CREATE TABLE IF NOT EXISTS entitlement_excluded_tag_selectors (
    rule_id TEXT NOT NULL REFERENCES entitlement_rules(id) ON DELETE CASCADE,
    position INTEGER NOT NULL DEFAULT 0,
    selector_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entitlement_excluded_tag_selectors_rule
    ON entitlement_excluded_tag_selectors(rule_id, position);

CREATE TABLE IF NOT EXISTS entitlement_task_tag_selectors (
    rule_id TEXT NOT NULL REFERENCES entitlement_rules(id) ON DELETE CASCADE,
    position INTEGER NOT NULL DEFAULT 0,
    selector_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entitlement_task_tag_selectors_rule
    ON entitlement_task_tag_selectors(rule_id, position);

CREATE TABLE IF NOT EXISTS entitlement_excluded_task_tag_selectors (
    rule_id TEXT NOT NULL REFERENCES entitlement_rules(id) ON DELETE CASCADE,
    position INTEGER NOT NULL DEFAULT 0,
    selector_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entitlement_excluded_task_tag_selectors_rule
    ON entitlement_excluded_task_tag_selectors(rule_id, position);
"#;

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
        let mut allowed_clusters: Vec<String> = Vec::new();
        let mut task_tag_selectors: Vec<TagSelector> = Vec::new();
        let mut excluded_task_tag_selectors: Vec<TagSelector> = Vec::new();
        let mut excluded_container_names: Vec<String> = Vec::new();
        let mut allow_broad_cluster_discovery = false;
        let mut allowed_os_users: Vec<String> = Vec::new();
        let mut max_session_seconds: Option<u64> = None;

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
            features.can_view_ecs |= rule.features.can_view_ecs;
            features.can_use_ecs_exec |= rule.features.can_use_ecs_exec;

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

            let normalized_clusters = normalize_allowed_clusters(
                &rule.allowed_clusters,
                &rule.allowed_accounts,
                &rule.allowed_regions,
            );
            for cluster in normalized_clusters {
                if !allowed_clusters.contains(&cluster) {
                    allowed_clusters.push(cluster);
                }
            }
            for selector in &rule.task_tag_selectors {
                if !task_tag_selectors.contains(selector) {
                    task_tag_selectors.push(selector.clone());
                }
            }
            for selector in &rule.excluded_task_tag_selectors {
                if !excluded_task_tag_selectors.contains(selector) {
                    excluded_task_tag_selectors.push(selector.clone());
                }
            }
            for container in &rule.excluded_container_names {
                if !excluded_container_names.contains(container) {
                    excluded_container_names.push(container.clone());
                }
            }
            allow_broad_cluster_discovery |= rule.allow_broad_cluster_discovery;

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
            allowed_clusters,
            task_tag_selectors,
            excluded_task_tag_selectors,
            excluded_container_names,
            allow_broad_cluster_discovery,
            allowed_os_users,
            max_session_seconds,
        }
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

    pub fn sqlite_schema() -> &'static str {
        SQLITE_SCHEMA
    }

    pub fn has_organization_account_placeholders(&self) -> bool {
        self.rules.iter().any(|rule| {
            rule.allowed_accounts
                .iter()
                .any(is_organization_account_placeholder)
        })
    }

    /// Expand `account_id = "*"` entries by replacing `{account_id}` in the
    /// role ARN template with each ACTIVE account discovered from AWS
    /// Organizations. Placeholder entries are removed before the store is used
    /// by routes, so runtime scope checks only see concrete account IDs.
    pub fn expand_organization_account_placeholders(
        &mut self,
        accounts: &[DiscoveredOrganizationAccount],
    ) -> anyhow::Result<usize> {
        let mut expanded_count = 0usize;

        for rule in &mut self.rules {
            let mut expanded_accounts = Vec::new();
            let mut seen: HashSet<(String, String)> = HashSet::new();

            for account in &rule.allowed_accounts {
                if is_organization_account_placeholder(account) {
                    validate_organization_account_placeholder(account, &rule.id, &rule.group)?;
                    for discovered in accounts {
                        let role_arn = render_organization_role_arn_template(
                            &account.role_arn,
                            &discovered.account_id,
                            &rule.id,
                            &rule.group,
                        )?;
                        let key = (discovered.account_id.clone(), role_arn.clone());
                        if seen.insert(key) {
                            expanded_accounts.push(AllowedAccount {
                                account_id: discovered.account_id.clone(),
                                account_name: discovered.account_name.clone(),
                                role_arn,
                            });
                            expanded_count += 1;
                        }
                    }
                    continue;
                }

                if account.role_arn.contains(ORGANIZATION_ACCOUNT_ID_TOKEN) {
                    anyhow::bail!(
                        "Rule '{}' (group '{}') uses {} in role_arn for concrete account '{}'. \
                         Set account_id=\"*\" to opt in to AWS Organizations account discovery.",
                        rule.id,
                        rule.group,
                        ORGANIZATION_ACCOUNT_ID_TOKEN,
                        account.account_id
                    );
                }

                let key = (account.account_id.clone(), account.role_arn.clone());
                if seen.insert(key) {
                    expanded_accounts.push(account.clone());
                }
            }

            rule.allowed_accounts = expanded_accounts;
        }

        Ok(expanded_count)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        self.validate_with_options(false)
    }

    pub fn validate_allowing_organization_account_placeholders(&self) -> anyhow::Result<()> {
        self.validate_with_options(true)
    }

    fn validate_with_options(
        &self,
        allow_organization_account_placeholders: bool,
    ) -> anyhow::Result<()> {
        for rule in &self.rules {
            for account in &rule.allowed_accounts {
                validate_account_entry(
                    account,
                    &rule.id,
                    &rule.group,
                    allow_organization_account_placeholders,
                )?;
            }
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
            if rule.features.can_use_ecs_exec && !rule.features.can_view_ecs {
                anyhow::bail!(
                    "Rule '{}' (group '{}') has can_use_ecs_exec=true but can_view_ecs=false. \
                     ECS exec must imply ECS view in the same rule.",
                    rule.id,
                    rule.group
                );
            }
            if (rule.features.can_view_ecs || rule.features.can_use_ecs_exec)
                && rule.allowed_clusters.is_empty()
            {
                anyhow::bail!(
                    "Rule '{}' (group '{}') grants ECS access but allowed_clusters is empty.",
                    rule.id,
                    rule.group
                );
            }
            for cluster in &rule.allowed_clusters {
                validate_cluster_pattern(cluster, rule.allow_broad_cluster_discovery).map_err(
                    |reason| {
                        anyhow::anyhow!(
                            "Rule '{}' (group '{}') has invalid allowed_clusters entry '{}': {}",
                            rule.id,
                            rule.group,
                            cluster,
                            reason
                        )
                    },
                )?;
            }
        }

        Ok(())
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

        store.validate()?;

        Ok(store)
    }

    /// Load entitlements before startup account discovery. This accepts
    /// organization placeholders, but callers must expand them and then call
    /// `validate()` before exposing the store to routes.
    pub fn load_from_file_allowing_organization_account_placeholders(
        path: &Path,
    ) -> anyhow::Result<Self> {
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

        store.validate_allowing_organization_account_placeholders()?;

        Ok(store)
    }

    pub fn load_from_database_url(url: &str) -> anyhow::Result<Self> {
        let store = Self::load_from_database_url_allowing_organization_account_placeholders(url)?;
        store.validate()?;
        Ok(store)
    }

    pub fn load_from_database_url_allowing_organization_account_placeholders(
        url: &str,
    ) -> anyhow::Result<Self> {
        let path = sqlite_path_from_url(url)?;
        let conn = Connection::open(&path)
            .map_err(|e| anyhow::anyhow!("Failed to open entitlement database '{}': {}", url, e))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        let store = Self::load_from_sqlite_connection(&conn)?;
        tracing::info!(
            rules = store.rules.len(),
            memberships = store.memberships.len(),
            "Loaded entitlements from database"
        );
        store.validate_allowing_organization_account_placeholders()?;
        Ok(store)
    }

    fn load_from_sqlite_connection(conn: &Connection) -> anyhow::Result<Self> {
        let mut stmt = conn.prepare(
            "SELECT id, group_name, can_view_ec2, can_use_cloudwatch_search,
                    can_use_cloudwatch_tail, can_use_ssm, can_use_ec2_instance_connect,
                    can_start_ec2, can_stop_ec2, can_reboot_ec2, can_view_ecs,
                    can_use_ecs_exec, allow_broad_cluster_discovery, max_session_seconds
             FROM entitlement_rules
             ORDER BY id",
        )?;
        let mut rows = stmt.query([])?;
        let mut rules = Vec::new();

        while let Some(row) = rows.next()? {
            let id: String = row.get("id")?;
            let max_session_seconds = sqlite_optional_u64(row.get("max_session_seconds")?)?;
            rules.push(EntitlementRule {
                id: id.clone(),
                group: row.get("group_name")?,
                features: FeatureFlags {
                    can_view_ec2: sqlite_bool(row.get("can_view_ec2")?),
                    can_use_cloudwatch_search: sqlite_bool(row.get("can_use_cloudwatch_search")?),
                    can_use_cloudwatch_tail: sqlite_bool(row.get("can_use_cloudwatch_tail")?),
                    can_use_ssm: sqlite_bool(row.get("can_use_ssm")?),
                    can_use_ec2_instance_connect: sqlite_bool(
                        row.get("can_use_ec2_instance_connect")?,
                    ),
                    can_start_ec2: sqlite_bool(row.get("can_start_ec2")?),
                    can_stop_ec2: sqlite_bool(row.get("can_stop_ec2")?),
                    can_reboot_ec2: sqlite_bool(row.get("can_reboot_ec2")?),
                    can_view_ecs: sqlite_bool(row.get("can_view_ecs")?),
                    can_use_ecs_exec: sqlite_bool(row.get("can_use_ecs_exec")?),
                },
                allowed_accounts: load_allowed_accounts(conn, &id)?,
                allowed_regions: load_string_list(
                    conn,
                    "entitlement_allowed_regions",
                    "region",
                    &id,
                )?,
                allowed_log_group_arns: load_string_list(
                    conn,
                    "entitlement_allowed_log_group_arns",
                    "arn",
                    &id,
                )?,
                instance_tag_selectors: load_tag_selectors(
                    conn,
                    "entitlement_instance_tag_selectors",
                    &id,
                )?,
                excluded_tag_selectors: load_tag_selectors(
                    conn,
                    "entitlement_excluded_tag_selectors",
                    &id,
                )?,
                allowed_clusters: load_string_list(
                    conn,
                    "entitlement_allowed_clusters",
                    "cluster",
                    &id,
                )?,
                task_tag_selectors: load_tag_selectors(
                    conn,
                    "entitlement_task_tag_selectors",
                    &id,
                )?,
                excluded_task_tag_selectors: load_tag_selectors(
                    conn,
                    "entitlement_excluded_task_tag_selectors",
                    &id,
                )?,
                excluded_container_names: load_string_list(
                    conn,
                    "entitlement_excluded_container_names",
                    "container_name",
                    &id,
                )?,
                allow_broad_cluster_discovery: sqlite_bool(
                    row.get("allow_broad_cluster_discovery")?,
                ),
                allowed_os_users: load_string_list(
                    conn,
                    "entitlement_allowed_os_users",
                    "os_user",
                    &id,
                )?,
                max_session_seconds,
            });
        }

        let memberships = load_memberships(conn)?;
        Ok(Self { rules, memberships })
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
                        can_view_ecs: true,
                        can_use_ecs_exec: true,
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
                    allowed_clusters: vec![DEV_MOCK_CLUSTER_NAME.into()],
                    task_tag_selectors: vec![TagSelector {
                        tags: HashMap::from([(
                            "Environment".into(),
                            vec!["production".into(), "staging".into()],
                        )]),
                    }],
                    excluded_task_tag_selectors: vec![],
                    excluded_container_names: vec!["xray-daemon".into()],
                    allow_broad_cluster_discovery: false,
                    allowed_os_users: vec!["ec2-user".into(), "ubuntu".into()],
                    max_session_seconds: None, // no limit for admin
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
                    allowed_clusters: vec![],
                    task_tag_selectors: vec![],
                    excluded_task_tag_selectors: vec![],
                    excluded_container_names: vec![],
                    allow_broad_cluster_discovery: false,
                    allowed_os_users: vec![],
                    max_session_seconds: None,
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
                    allowed_clusters: vec![],
                    task_tag_selectors: vec![],
                    excluded_task_tag_selectors: vec![],
                    excluded_container_names: vec![],
                    allow_broad_cluster_discovery: false,
                    allowed_os_users: vec![],
                    max_session_seconds: Some(3600), // 60 min for readonly
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

fn sqlite_path_from_url(url: &str) -> anyhow::Result<String> {
    if url == "sqlite::memory:" || url == "sqlite://:memory:" {
        return Ok(":memory:".into());
    }

    let path = if let Some(path) = url.strip_prefix("sqlite://") {
        path
    } else if let Some(path) = url.strip_prefix("sqlite:") {
        path
    } else {
        anyhow::bail!("Only sqlite entitlement database URLs are supported");
    };

    if path.is_empty() {
        anyhow::bail!("SQLite entitlement database URL must include a path");
    }

    Ok(path.to_string())
}

fn sqlite_bool(value: i64) -> bool {
    value != 0
}

fn sqlite_optional_u64(value: Option<i64>) -> anyhow::Result<Option<u64>> {
    value
        .map(|value| {
            u64::try_from(value).map_err(|_| {
                anyhow::anyhow!("SQLite entitlement max_session_seconds must be non-negative")
            })
        })
        .transpose()
}

fn load_allowed_accounts(conn: &Connection, rule_id: &str) -> anyhow::Result<Vec<AllowedAccount>> {
    let mut stmt = conn.prepare(
        "SELECT account_id, account_name, role_arn
         FROM entitlement_allowed_accounts
         WHERE rule_id = ?1
         ORDER BY position, account_id, role_arn",
    )?;
    let rows = stmt.query_map(params![rule_id], |row| {
        Ok(AllowedAccount {
            account_id: row.get(0)?,
            account_name: row.get(1)?,
            role_arn: row.get(2)?,
        })
    })?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn load_string_list(
    conn: &Connection,
    table: &str,
    column: &str,
    rule_id: &str,
) -> anyhow::Result<Vec<String>> {
    let sql = format!(
        "SELECT {column}
         FROM {table}
         WHERE rule_id = ?1
         ORDER BY position, {column}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![rule_id], |row| row.get::<_, String>(0))?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn load_tag_selectors(
    conn: &Connection,
    table: &str,
    rule_id: &str,
) -> anyhow::Result<Vec<TagSelector>> {
    let sql = format!(
        "SELECT selector_json
         FROM {table}
         WHERE rule_id = ?1
         ORDER BY position"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![rule_id], |row| row.get::<_, String>(0))?;
    let mut selectors = Vec::new();

    for row in rows {
        let json = row?;
        selectors.push(parse_tag_selector(&json)?);
    }

    Ok(selectors)
}

fn parse_tag_selector(json: &str) -> anyhow::Result<TagSelector> {
    serde_json::from_str::<TagSelector>(json).or_else(|_| {
        serde_json::from_str::<HashMap<String, Vec<String>>>(json)
            .map(|tags| TagSelector { tags })
            .map_err(Into::into)
    })
}

fn load_memberships(conn: &Connection) -> anyhow::Result<Vec<GroupMembership>> {
    let mut stmt = conn.prepare(
        "SELECT user_id, group_name
         FROM entitlement_memberships
         ORDER BY user_id, group_name",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(GroupMembership {
            user_id: row.get(0)?,
            group: row.get(1)?,
        })
    })?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn validate_cluster_pattern(
    pattern: &str,
    allow_broad_cluster_discovery: bool,
) -> anyhow::Result<()> {
    if pattern == "*" {
        anyhow::bail!("bare '*' is not allowed");
    }

    let cluster_name = pattern
        .rsplit_once("cluster/")
        .map(|(_, name)| name)
        .unwrap_or(pattern);

    for ch in ['?', '[', ']', '{', '}', '\\'] {
        if cluster_name.contains(ch) {
            anyhow::bail!("only literal characters and '*' are allowed in cluster name patterns");
        }
    }

    if let Some(first_star) = cluster_name.find('*') {
        let literal_prefix_len = cluster_name[..first_star].chars().count();
        if literal_prefix_len < 3 && !allow_broad_cluster_discovery {
            anyhow::bail!(
                "wildcard cluster patterns require at least 3 literal characters before '*' \
                 unless allow_broad_cluster_discovery=true"
            );
        }
    }

    Ok(())
}

fn is_organization_account_placeholder(account: &AllowedAccount) -> bool {
    account.account_id == ORGANIZATION_ACCOUNT_PLACEHOLDER
}

fn validate_account_entry(
    account: &AllowedAccount,
    rule_id: &str,
    group: &str,
    allow_organization_account_placeholders: bool,
) -> anyhow::Result<()> {
    if is_organization_account_placeholder(account) {
        if !allow_organization_account_placeholders {
            anyhow::bail!(
                "Rule '{}' (group '{}') has unresolved AWS Organizations account placeholder. \
                 Startup must expand account_id=\"*\" before the entitlement store is used.",
                rule_id,
                group
            );
        }
        validate_organization_account_placeholder(account, rule_id, group)?;
    } else if account.role_arn.contains(ORGANIZATION_ACCOUNT_ID_TOKEN) {
        anyhow::bail!(
            "Rule '{}' (group '{}') uses {} in role_arn for concrete account '{}'. \
             Set account_id=\"*\" to opt in to AWS Organizations account discovery.",
            rule_id,
            group,
            ORGANIZATION_ACCOUNT_ID_TOKEN,
            account.account_id
        );
    }

    Ok(())
}

fn validate_organization_account_placeholder(
    account: &AllowedAccount,
    rule_id: &str,
    group: &str,
) -> anyhow::Result<()> {
    if account.role_arn == "direct" || account.role_arn.starts_with("profile:") {
        anyhow::bail!(
            "Rule '{}' (group '{}') has account_id=\"*\" but role_arn uses local credentials. \
             AWS Organizations discovery requires an IAM role ARN template containing {}.",
            rule_id,
            group,
            ORGANIZATION_ACCOUNT_ID_TOKEN
        );
    }

    let token_count = account
        .role_arn
        .matches(ORGANIZATION_ACCOUNT_ID_TOKEN)
        .count();
    if token_count != 1 {
        anyhow::bail!(
            "Rule '{}' (group '{}') has account_id=\"*\" but role_arn does not contain exactly one {} token.",
            rule_id,
            group,
            ORGANIZATION_ACCOUNT_ID_TOKEN
        );
    }

    let rendered = account
        .role_arn
        .replace(ORGANIZATION_ACCOUNT_ID_TOKEN, "123456789012");
    if !rendered.starts_with("arn:") || !rendered.contains(":iam::123456789012:role/") {
        anyhow::bail!(
            "Rule '{}' (group '{}') has account_id=\"*\" but role_arn is not an IAM role ARN template.",
            rule_id,
            group
        );
    }

    Ok(())
}

fn render_organization_role_arn_template(
    template: &str,
    account_id: &str,
    rule_id: &str,
    group: &str,
) -> anyhow::Result<String> {
    if !is_valid_account_id(account_id) {
        anyhow::bail!(
            "AWS Organizations returned invalid account id '{}' while expanding rule '{}' (group '{}')",
            account_id,
            rule_id,
            group
        );
    }

    Ok(template.replace(ORGANIZATION_ACCOUNT_ID_TOKEN, account_id))
}

fn is_valid_account_id(account_id: &str) -> bool {
    account_id.len() == 12 && account_id.bytes().all(|byte| byte.is_ascii_digit())
}

fn normalize_allowed_clusters(
    entries: &[String],
    accounts: &[AllowedAccount],
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

        for account in accounts {
            for region in &effective_regions {
                let pattern = format!(
                    "arn:aws:ecs:{}:{}:cluster/{}",
                    region, account.account_id, entry
                );
                if !patterns.contains(&pattern) {
                    patterns.push(pattern);
                }
            }
        }
    }
    patterns
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_store() -> EntitlementStore {
        EntitlementStore::dev_defaults()
    }

    fn load_from_temp_toml(content: &str) -> anyhow::Result<EntitlementStore> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "canopy-entitlements-test-{}-{nonce}.toml",
            std::process::id()
        ));
        std::fs::write(&path, content)?;
        let result = EntitlementStore::load_from_file(&path);
        let _ = std::fs::remove_file(&path);
        result
    }

    fn temp_sqlite_path(name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "canopy-entitlements-{name}-{}-{nonce}.db",
            std::process::id()
        ))
    }

    fn minimal_rule_with_accounts(accounts: Vec<AllowedAccount>) -> EntitlementRule {
        EntitlementRule {
            id: "org-discovery".into(),
            group: "ops".into(),
            features: FeatureFlags {
                can_view_ec2: true,
                ..Default::default()
            },
            allowed_accounts: accounts,
            allowed_regions: vec!["us-east-1".into()],
            allowed_log_group_arns: vec![],
            instance_tag_selectors: vec![],
            excluded_tag_selectors: vec![],
            allowed_clusters: vec![],
            task_tag_selectors: vec![],
            excluded_task_tag_selectors: vec![],
            excluded_container_names: vec![],
            allow_broad_cluster_discovery: false,
            allowed_os_users: vec![],
            max_session_seconds: None,
        }
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
        assert!(ent.features.can_view_ecs);
        assert!(ent.features.can_use_ecs_exec);
        assert_eq!(ent.allowed_accounts.len(), 4);
        assert_eq!(ent.allowed_regions.len(), 3);
        assert!(ent.allowed_clusters.contains(&format!(
            "arn:aws:ecs:us-east-1:111111111111:cluster/{DEV_MOCK_CLUSTER_NAME}"
        )));
        assert_eq!(ent.allowed_clusters.len(), 6);
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
        assert!(!ent.features.can_view_ecs);
        assert!(!ent.features.can_use_ecs_exec);
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
        assert!(ent.features.can_view_ecs);
        assert!(ent.features.can_use_ecs_exec);
        // 5 account entries: two read/connect roles, two operator roles,
        // plus the readonly staging role (distinct role ARNs are preserved).
        assert_eq!(ent.allowed_accounts.len(), 5);
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
            allowed_clusters: vec![],
            task_tag_selectors: vec![],
            excluded_task_tag_selectors: vec![],
            excluded_container_names: vec![],
            allow_broad_cluster_discovery: false,
            allowed_os_users: vec![],
            max_session_seconds: None,
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
    fn organization_account_placeholder_expands_to_concrete_accounts() {
        let mut store = EntitlementStore {
            rules: vec![minimal_rule_with_accounts(vec![
                AllowedAccount {
                    account_id: "999999999999".into(),
                    account_name: "explicit".into(),
                    role_arn: "arn:aws:iam::999999999999:role/CanopyRole".into(),
                },
                AllowedAccount {
                    account_id: ORGANIZATION_ACCOUNT_PLACEHOLDER.into(),
                    account_name: "organization".into(),
                    role_arn: "arn:aws:iam::{account_id}:role/CanopyRole".into(),
                },
            ])],
            memberships: vec![GroupMembership {
                user_id: "alice".into(),
                group: "ops".into(),
            }],
        };

        store
            .validate_allowing_organization_account_placeholders()
            .unwrap();
        let expanded = store
            .expand_organization_account_placeholders(&[
                DiscoveredOrganizationAccount {
                    account_id: "111111111111".into(),
                    account_name: "prod".into(),
                },
                DiscoveredOrganizationAccount {
                    account_id: "222222222222".into(),
                    account_name: "staging".into(),
                },
            ])
            .unwrap();

        assert_eq!(expanded, 2);
        assert!(!store.has_organization_account_placeholders());
        store.validate().unwrap();

        let ent = store.evaluate("alice", "alice@example.com", "Alice", true);
        let account_ids: Vec<&str> = ent
            .allowed_accounts
            .iter()
            .map(|account| account.account_id.as_str())
            .collect();
        assert_eq!(
            account_ids,
            vec!["999999999999", "111111111111", "222222222222"]
        );
        assert_eq!(
            ent.allowed_accounts[1].role_arn,
            "arn:aws:iam::111111111111:role/CanopyRole"
        );
    }

    #[test]
    fn strict_validation_rejects_unexpanded_organization_placeholder() {
        let store = EntitlementStore {
            rules: vec![minimal_rule_with_accounts(vec![AllowedAccount {
                account_id: ORGANIZATION_ACCOUNT_PLACEHOLDER.into(),
                account_name: "organization".into(),
                role_arn: "arn:aws:iam::{account_id}:role/CanopyRole".into(),
            }])],
            memberships: vec![],
        };

        let err = store.validate().unwrap_err().to_string();
        assert!(err.contains("unresolved AWS Organizations account placeholder"));
    }

    #[test]
    fn organization_placeholder_requires_role_template() {
        let store = EntitlementStore {
            rules: vec![minimal_rule_with_accounts(vec![AllowedAccount {
                account_id: ORGANIZATION_ACCOUNT_PLACEHOLDER.into(),
                account_name: "organization".into(),
                role_arn: "arn:aws:iam::123456789012:role/CanopyRole".into(),
            }])],
            memberships: vec![],
        };

        let err = store
            .validate_allowing_organization_account_placeholders()
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not contain exactly one {account_id} token"));
    }

    #[test]
    fn organization_placeholder_deduplicates_explicit_account() {
        let mut store = EntitlementStore {
            rules: vec![minimal_rule_with_accounts(vec![
                AllowedAccount {
                    account_id: "111111111111".into(),
                    account_name: "prod-explicit".into(),
                    role_arn: "arn:aws:iam::111111111111:role/CanopyRole".into(),
                },
                AllowedAccount {
                    account_id: ORGANIZATION_ACCOUNT_PLACEHOLDER.into(),
                    account_name: "organization".into(),
                    role_arn: "arn:aws:iam::{account_id}:role/CanopyRole".into(),
                },
            ])],
            memberships: vec![],
        };

        let expanded = store
            .expand_organization_account_placeholders(&[DiscoveredOrganizationAccount {
                account_id: "111111111111".into(),
                account_name: "prod-discovered".into(),
            }])
            .unwrap();

        assert_eq!(expanded, 0);
        assert!(!store.has_organization_account_placeholders());
        assert_eq!(store.rules[0].allowed_accounts.len(), 1);
        assert_eq!(
            store.rules[0].allowed_accounts[0].account_name,
            "prod-explicit"
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
            allowed_clusters: vec![],
            task_tag_selectors: vec![],
            excluded_task_tag_selectors: vec![],
            excluded_container_names: vec![],
            allow_broad_cluster_discovery: false,
            allowed_os_users: vec![],
            max_session_seconds: None,
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
    fn ecs_cluster_and_task_scopes_merge_and_dedup() {
        let mut store = test_store();
        store.memberships.push(GroupMembership {
            user_id: "dev-admin".into(),
            group: "ecs-extra".into(),
        });
        store.rules.push(EntitlementRule {
            id: "rule-ecs-extra".into(),
            group: "ecs-extra".into(),
            features: FeatureFlags {
                can_view_ecs: true,
                can_use_ecs_exec: true,
                ..Default::default()
            },
            allowed_accounts: vec![AllowedAccount {
                account_id: "333333333333".into(),
                account_name: "demo".into(),
                role_arn: "arn:aws:iam::333333333333:role/CanopyRole".into(),
            }],
            allowed_regions: vec!["ap-northeast-1".into()],
            allowed_log_group_arns: vec![],
            instance_tag_selectors: vec![],
            excluded_tag_selectors: vec![],
            allowed_clusters: vec![DEV_MOCK_CLUSTER_NAME.into(), "prod-*".into()],
            task_tag_selectors: vec![TagSelector {
                tags: HashMap::from([("Service".into(), vec!["api".into()])]),
            }],
            excluded_task_tag_selectors: vec![TagSelector {
                tags: HashMap::from([("CanopyDeny".into(), vec!["true".into()])]),
            }],
            excluded_container_names: vec!["fluent-bit".into()],
            allow_broad_cluster_discovery: true,
            allowed_os_users: vec![],
            max_session_seconds: None,
        });

        let ent = store.evaluate("dev-admin", "admin@example.com", "Admin", true);
        assert!(ent.allowed_clusters.iter().any(|cluster| cluster
            == &format!("arn:aws:ecs:us-east-1:111111111111:cluster/{DEV_MOCK_CLUSTER_NAME}")));
        assert!(ent
            .allowed_clusters
            .contains(&"arn:aws:ecs:ap-northeast-1:333333333333:cluster/prod-*".to_string()));
        assert_eq!(ent.task_tag_selectors.len(), 2);
        assert_eq!(ent.excluded_task_tag_selectors.len(), 1);
        assert!(ent.excluded_container_names.contains(&"fluent-bit".into()));
        assert!(ent.allow_broad_cluster_discovery);
    }

    #[test]
    fn validate_cluster_pattern_rejects_broad_wildcard_without_opt_in() {
        assert!(
            validate_cluster_pattern("arn:aws:ecs:us-east-1:111111111111:cluster/*", false)
                .is_err()
        );
        assert!(validate_cluster_pattern("cluster/p*", false).is_err());
        assert!(validate_cluster_pattern("cluster/prod*", false).is_ok());
        assert!(validate_cluster_pattern("cluster/*", true).is_ok());
    }

    #[test]
    fn validate_cluster_pattern_rejects_non_star_glob_chars() {
        assert!(validate_cluster_pattern("cluster/p?od-*", true).is_err());
        assert!(validate_cluster_pattern("cluster/pr[od]uction", true).is_err());
    }

    #[test]
    fn load_from_file_rejects_ecs_exec_without_view() {
        let err = load_from_temp_toml(
            r#"
[[rules]]
id = "ecs-exec-only"
group = "ops"
allowed_accounts = [{ account_id = "111111111111", account_name = "prod", role_arn = "arn:aws:iam::111111111111:role/CanopyRole" }]
allowed_regions = ["ap-northeast-1"]
allowed_clusters = ["prod-*"]

[rules.features]
can_use_ecs_exec = true

[[memberships]]
user_id = "alice"
group = "ops"
"#,
        )
        .expect_err("ECS exec must require ECS view in the same rule");

        assert!(err.to_string().contains("can_use_ecs_exec=true"));
    }

    #[test]
    fn load_from_file_rejects_ecs_access_without_clusters() {
        let err = load_from_temp_toml(
            r#"
[[rules]]
id = "ecs-no-clusters"
group = "ops"
allowed_accounts = [{ account_id = "111111111111", account_name = "prod", role_arn = "arn:aws:iam::111111111111:role/CanopyRole" }]
allowed_regions = ["ap-northeast-1"]

[rules.features]
can_view_ecs = true

[[memberships]]
user_id = "alice"
group = "ops"
"#,
        )
        .expect_err("ECS view must require an explicit cluster allowlist");

        assert!(err.to_string().contains("allowed_clusters is empty"));
    }

    #[test]
    fn load_from_file_rejects_broad_cluster_without_opt_in() {
        let err = load_from_temp_toml(
            r#"
[[rules]]
id = "ecs-broad-cluster"
group = "ops"
allowed_accounts = [{ account_id = "111111111111", account_name = "prod", role_arn = "arn:aws:iam::111111111111:role/CanopyRole" }]
allowed_regions = ["ap-northeast-1"]
allowed_clusters = ["cluster/*"]

[rules.features]
can_view_ecs = true

[[memberships]]
user_id = "alice"
group = "ops"
"#,
        )
        .expect_err("broad ECS cluster discovery must require explicit opt-in");

        assert!(err
            .to_string()
            .contains("allow_broad_cluster_discovery=true"));
    }

    #[test]
    fn load_from_file_allows_mixed_ec2_ssm_and_ecs_rule_with_os_users() {
        let store = load_from_temp_toml(
            r#"
[[rules]]
id = "mixed-ec2-ecs"
group = "ops"
allowed_accounts = [{ account_id = "111111111111", account_name = "prod", role_arn = "arn:aws:iam::111111111111:role/CanopyRole" }]
allowed_regions = ["ap-northeast-1"]
allowed_clusters = ["prod-*"]
allowed_os_users = ["ec2-user"]

[rules.features]
can_view_ec2 = true
can_use_ssm = true
can_view_ecs = true
can_use_ecs_exec = true

[[memberships]]
user_id = "alice"
group = "ops"
"#,
        )
        .expect("mixed EC2/SSM and ECS rules should load");

        let ent = store.evaluate("alice", "alice@example.com", "Alice", true);
        assert!(ent.features.can_use_ssm);
        assert!(ent.features.can_view_ecs);
        assert!(ent.features.can_use_ecs_exec);
        assert_eq!(ent.allowed_os_users, vec!["ec2-user"]);
        assert_eq!(
            ent.allowed_clusters,
            vec!["arn:aws:ecs:ap-northeast-1:111111111111:cluster/prod-*"]
        );
    }

    #[test]
    fn load_from_sqlite_database_matches_entitlement_shape() -> anyhow::Result<()> {
        let path = temp_sqlite_path("load");
        let conn = Connection::open(&path)?;
        conn.execute_batch(EntitlementStore::sqlite_schema())?;
        conn.execute(
            "INSERT INTO entitlement_rules (
                id, group_name, can_view_ec2, can_use_cloudwatch_search,
                can_use_cloudwatch_tail, can_use_ssm, can_use_ec2_instance_connect,
                can_view_ecs, can_use_ecs_exec, max_session_seconds
            ) VALUES (?1, ?2, 1, 1, 1, 1, 1, 1, 1, ?3)",
            params!["db-platform", "platform", 1800_i64],
        )?;
        conn.execute(
            "INSERT INTO entitlement_allowed_accounts
                (rule_id, position, account_id, account_name, role_arn)
             VALUES (?1, 0, ?2, ?3, ?4)",
            params![
                "db-platform",
                "111111111111",
                "production",
                "arn:aws:iam::111111111111:role/CanopyRole"
            ],
        )?;
        conn.execute(
            "INSERT INTO entitlement_allowed_regions (rule_id, position, region)
             VALUES (?1, 0, ?2)",
            params!["db-platform", "ap-northeast-1"],
        )?;
        conn.execute(
            "INSERT INTO entitlement_allowed_log_group_arns (rule_id, position, arn)
             VALUES (?1, 0, ?2)",
            params![
                "db-platform",
                "arn:aws:logs:*:111111111111:log-group:/app/*"
            ],
        )?;
        conn.execute(
            "INSERT INTO entitlement_allowed_os_users (rule_id, position, os_user)
             VALUES (?1, 0, ?2)",
            params!["db-platform", "ec2-user"],
        )?;
        conn.execute(
            "INSERT INTO entitlement_allowed_clusters (rule_id, position, cluster)
             VALUES (?1, 0, ?2)",
            params!["db-platform", "prod-*"],
        )?;
        conn.execute(
            "INSERT INTO entitlement_instance_tag_selectors (rule_id, position, selector_json)
             VALUES (?1, 0, ?2)",
            params!["db-platform", r#"{"tags":{"Environment":["production"]}}"#],
        )?;
        conn.execute(
            "INSERT INTO entitlement_task_tag_selectors (rule_id, position, selector_json)
             VALUES (?1, 0, ?2)",
            params!["db-platform", r#"{"Service":["api"]}"#],
        )?;
        conn.execute(
            "INSERT INTO entitlement_memberships (user_id, group_name)
             VALUES (?1, ?2)",
            params!["alice@example.com", "platform"],
        )?;
        drop(conn);

        let store =
            EntitlementStore::load_from_database_url(&format!("sqlite://{}", path.display()))?;
        let _ = std::fs::remove_file(&path);

        assert_eq!(store.rules.len(), 1);
        assert_eq!(store.memberships.len(), 1);
        let ent = store.evaluate("alice", "alice@example.com", "Alice", true);
        assert_eq!(ent.groups, vec!["platform"]);
        assert!(ent.features.can_use_cloudwatch_tail);
        assert!(ent.features.can_use_ecs_exec);
        assert_eq!(ent.allowed_accounts.len(), 1);
        assert_eq!(ent.allowed_regions, vec!["ap-northeast-1"]);
        assert_eq!(ent.allowed_os_users, vec!["ec2-user"]);
        assert_eq!(ent.max_session_seconds, Some(1800));
        assert_eq!(
            ent.allowed_clusters,
            vec!["arn:aws:ecs:ap-northeast-1:111111111111:cluster/prod-*"]
        );
        assert_eq!(
            ent.instance_tag_selectors[0].tags["Environment"],
            vec!["production"]
        );
        assert_eq!(ent.task_tag_selectors[0].tags["Service"], vec!["api"]);

        Ok(())
    }

    #[test]
    fn load_from_sqlite_database_reuses_entitlement_validation() -> anyhow::Result<()> {
        let path = temp_sqlite_path("invalid");
        let conn = Connection::open(&path)?;
        conn.execute_batch(EntitlementStore::sqlite_schema())?;
        conn.execute(
            "INSERT INTO entitlement_rules (id, group_name, can_use_ssm)
             VALUES (?1, ?2, 1)",
            params!["invalid-ssm", "ops"],
        )?;
        conn.execute(
            "INSERT INTO entitlement_allowed_accounts
                (rule_id, position, account_id, account_name, role_arn)
             VALUES (?1, 0, ?2, ?3, ?4)",
            params![
                "invalid-ssm",
                "111111111111",
                "production",
                "arn:aws:iam::111111111111:role/CanopyRole"
            ],
        )?;
        conn.execute(
            "INSERT INTO entitlement_memberships (user_id, group_name)
             VALUES (?1, ?2)",
            params!["alice", "ops"],
        )?;
        drop(conn);

        let err = EntitlementStore::load_from_database_url(&format!("sqlite://{}", path.display()))
            .expect_err("SQLite backend must share entitlement validation");
        let _ = std::fs::remove_file(&path);

        assert!(err.to_string().contains("allowed_os_users"));
        Ok(())
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
