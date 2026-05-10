use shared::dto::entitlements::UserEntitlements;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::models::entitlements::EntitlementStore;
use crate::services::auth::Claims;

pub struct EntitlementService {
    store: Arc<RwLock<EntitlementStore>>,
}

impl EntitlementService {
    pub fn new(store: Arc<RwLock<EntitlementStore>>) -> Self {
        Self { store }
    }

    /// Evaluate entitlements for authenticated user from JWT claims
    pub async fn evaluate(&self, claims: &Claims) -> UserEntitlements {
        let store = self.store.read().await;
        store.evaluate(
            &claims.sub,
            &claims.email,
            &claims.name,
            claims.email_verified,
        )
    }

    /// Scope-aware feature check: verifies that at least one single rule
    /// grants the requested feature AND access to the full scope.
    /// This prevents cross-group privilege escalation.
    pub async fn has_feature_for_scope(
        &self,
        claims: &Claims,
        account_id: &str,
        region: Option<&str>,
        log_group_arn: Option<&str>,
        os_user: Option<&str>,
        feature_check: impl Fn(&shared::dto::entitlements::FeatureFlags) -> bool,
    ) -> bool {
        let store = self.store.read().await;
        store.has_feature_for_scope(
            &claims.sub,
            &claims.email,
            claims.email_verified,
            account_id,
            region,
            log_group_arn,
            os_user,
            feature_check,
        )
    }

    /// Return the set of allowed log-group ARN patterns from rules that
    /// individually grant the feature for the given account AND region.
    /// This prevents cross-group log-group pattern leaking.
    pub async fn allowed_log_group_arns_for_scope(
        &self,
        claims: &Claims,
        account_id: &str,
        region: &str,
        feature_check: impl Fn(&shared::dto::entitlements::FeatureFlags) -> bool,
    ) -> Vec<String> {
        let store = self.store.read().await;
        let rules = store.matching_rules_for_scope(
            &claims.sub,
            &claims.email,
            claims.email_verified,
            account_id,
            feature_check,
        );
        let mut arns = Vec::new();
        for rule in rules {
            // Only include patterns from rules that also grant this region
            if !rule.allowed_regions.is_empty()
                && !rule.allowed_regions.contains(&region.to_string())
            {
                continue;
            }
            for arn in &rule.allowed_log_group_arns {
                if !arns.contains(arn) {
                    arns.push(arn.clone());
                }
            }
        }
        arns
    }

    /// Return the set of allowed accounts from rules that individually
    /// grant the given feature AND region. Used for scope-aware EC2
    /// fan-out instead of merged cartesian products.
    pub async fn scoped_accounts_for_feature(
        &self,
        claims: &Claims,
        feature_check: impl Fn(&shared::dto::entitlements::FeatureFlags) -> bool,
    ) -> Vec<(shared::dto::entitlements::AllowedAccount, Vec<String>)> {
        let store = self.store.read().await;
        let user_groups: Vec<String> = store
            .memberships
            .iter()
            .filter(|m| {
                m.user_id == claims.sub || (claims.email_verified && m.user_id == claims.email)
            })
            .map(|m| m.group.clone())
            .collect();

        let mut result = Vec::new();
        for rule in &store.rules {
            if !user_groups.contains(&rule.group) || !feature_check(&rule.features) {
                continue;
            }
            for acct in &rule.allowed_accounts {
                // Pair each account with ONLY the regions from this rule
                let regions = rule.allowed_regions.clone();
                if !result.iter().any(
                    |(a, r): &(shared::dto::entitlements::AllowedAccount, Vec<String>)| {
                        a.account_id == acct.account_id
                            && a.role_arn == acct.role_arn
                            && *r == regions
                    },
                ) {
                    result.push((acct.clone(), regions));
                }
            }
        }
        result
    }

    /// Return per-rule scope objects for EC2 filtering. Each RuleScope
    /// contains only the account/region/selectors from a single rule
    /// that grants the given feature.
    pub async fn rule_scopes_for_feature(
        &self,
        claims: &Claims,
        feature_check: impl Fn(&shared::dto::entitlements::FeatureFlags) -> bool,
    ) -> Vec<crate::services::ec2::RuleScope> {
        let store = self.store.read().await;
        let user_groups: Vec<String> = store
            .memberships
            .iter()
            .filter(|m| {
                m.user_id == claims.sub || (claims.email_verified && m.user_id == claims.email)
            })
            .map(|m| m.group.clone())
            .collect();

        store
            .rules
            .iter()
            .filter(|rule| user_groups.contains(&rule.group) && feature_check(&rule.features))
            .map(|rule| crate::services::ec2::RuleScope {
                account_ids: rule
                    .allowed_accounts
                    .iter()
                    .map(|a| a.account_id.clone())
                    .collect(),
                regions: rule.allowed_regions.clone(),
                allow_selectors: rule.instance_tag_selectors.clone(),
                deny_selectors: rule.excluded_tag_selectors.clone(),
            })
            .collect()
    }

    /// Convenience: check feature + account only.
    pub async fn has_feature_for_account(
        &self,
        claims: &Claims,
        account_id: &str,
        feature_check: impl Fn(&shared::dto::entitlements::FeatureFlags) -> bool,
    ) -> bool {
        self.has_feature_for_scope(claims, account_id, None, None, None, feature_check)
            .await
    }

    /// Check if user is allowed to access a specific account
    pub async fn check_account_access(&self, claims: &Claims, account_id: &str) -> bool {
        let entitlements = self.evaluate(claims).await;
        entitlements
            .allowed_accounts
            .iter()
            .any(|a| a.account_id == account_id)
    }

    /// Check if user is allowed to access a specific region
    pub async fn check_region_access(&self, claims: &Claims, region: &str) -> bool {
        let entitlements = self.evaluate(claims).await;
        entitlements.allowed_regions.contains(&region.to_string())
    }

    /// Check if a log group ARN matches any of the user's allowed patterns
    pub async fn check_log_group_access(&self, claims: &Claims, log_group_arn: &str) -> bool {
        let entitlements = self.evaluate(claims).await;
        entitlements
            .allowed_log_group_arns
            .iter()
            .any(|pattern| arn_matches_pattern(pattern, log_group_arn))
    }
}

/// Simple ARN pattern matcher supporting * wildcards
pub fn arn_matches_pattern(pattern: &str, arn: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.split('*').collect();
    if pattern_parts.len() == 1 {
        return pattern == arn;
    }

    let mut remaining = arn;
    for (i, part) in pattern_parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !remaining.starts_with(part) {
                return false;
            }
            remaining = &remaining[part.len()..];
        } else if i == pattern_parts.len() - 1 {
            if !remaining.ends_with(part) {
                return false;
            }
            return true;
        } else {
            match remaining.find(part) {
                Some(pos) => remaining = &remaining[pos + part.len()..],
                None => return false,
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arn_exact_match() {
        assert!(arn_matches_pattern(
            "arn:aws:logs:us-east-1:123:log-group:/app/web",
            "arn:aws:logs:us-east-1:123:log-group:/app/web"
        ));
    }

    #[test]
    fn test_arn_wildcard_suffix() {
        assert!(arn_matches_pattern(
            "arn:aws:logs:*:111111111111:log-group:/app/*",
            "arn:aws:logs:us-east-1:111111111111:log-group:/app/web-service"
        ));
    }

    #[test]
    fn test_arn_wildcard_no_match() {
        assert!(!arn_matches_pattern(
            "arn:aws:logs:*:111111111111:log-group:/app/*",
            "arn:aws:logs:us-east-1:999999999999:log-group:/app/web-service"
        ));
    }

    #[test]
    fn test_arn_wildcard_region() {
        assert!(arn_matches_pattern(
            "arn:aws:logs:*:111111111111:log-group:/app/*",
            "arn:aws:logs:eu-west-1:111111111111:log-group:/app/api"
        ));
    }

    // ── Additional arn_matches_pattern tests ────────────────────────────

    #[test]
    fn test_arn_pure_wildcard_matches_anything() {
        assert!(arn_matches_pattern(
            "*",
            "arn:aws:logs:us-east-1:123:log-group:/any"
        ));
        assert!(arn_matches_pattern("*", ""));
        assert!(arn_matches_pattern("*", "literally-anything"));
    }

    #[test]
    fn test_arn_no_match_different_prefix() {
        assert!(!arn_matches_pattern(
            "arn:aws:logs:us-east-1:123:log-group:/app/web",
            "arn:aws:logs:us-east-1:123:log-group:/other/web"
        ));
    }

    #[test]
    fn test_arn_multiple_wildcards() {
        assert!(arn_matches_pattern(
            "arn:*:logs:*:111:log-group:*",
            "arn:aws:logs:ap-southeast-1:111:log-group:/app/anything"
        ));
    }

    #[test]
    fn test_arn_empty_pattern_only_matches_empty() {
        assert!(arn_matches_pattern("", ""));
        assert!(!arn_matches_pattern("", "non-empty"));
    }

    #[test]
    fn test_arn_empty_arn_no_match() {
        assert!(!arn_matches_pattern("arn:aws:logs:*:123:*", ""));
    }

    #[test]
    fn test_arn_pattern_longer_than_arn() {
        assert!(!arn_matches_pattern(
            "arn:aws:logs:us-east-1:123456789012:log-group:/very/long/path",
            "arn:aws:logs:us-east-1:123"
        ));
    }

    // ── EntitlementService async method tests ──────────────────────────

    use crate::models::entitlements::EntitlementStore;
    use crate::services::auth::Claims;
    use shared::dto::entitlements::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn test_claims(sub: &str, email: &str) -> Claims {
        Claims {
            sub: sub.into(),
            email: email.into(),
            name: sub.into(),
            groups: vec![],
            exp: 9999999999,
            iat: 0,
            email_verified: true,
        }
    }

    fn test_store() -> EntitlementStore {
        EntitlementStore {
            rules: vec![
                EntitlementRule {
                    id: "rule-eng".into(),
                    group: "eng".into(),
                    features: FeatureFlags {
                        can_view_ec2: true,
                        can_use_cloudwatch_search: true,
                        can_use_cloudwatch_tail: false,
                        can_use_ssm: false,
                        can_use_ec2_instance_connect: false,
                        ..Default::default()
                    },
                    allowed_accounts: vec![AllowedAccount {
                        account_id: "111".into(),
                        account_name: "prod".into(),
                        role_arn: "arn:aws:iam::111:role/Eng".into(),
                    }],
                    allowed_regions: vec!["us-east-1".into()],
                    allowed_log_group_arns: vec!["arn:aws:logs:*:111:log-group:/app/*".into()],
                    instance_tag_selectors: vec![],
                    excluded_tag_selectors: vec![],
                    allowed_os_users: vec!["ec2-user".into()],
                    max_session_seconds: None,
                },
                EntitlementRule {
                    id: "rule-ops".into(),
                    group: "ops".into(),
                    features: FeatureFlags {
                        can_view_ec2: true,
                        can_use_cloudwatch_search: true,
                        can_use_cloudwatch_tail: true,
                        can_use_ssm: true,
                        can_use_ec2_instance_connect: false,
                        ..Default::default()
                    },
                    allowed_accounts: vec![AllowedAccount {
                        account_id: "222".into(),
                        account_name: "staging".into(),
                        role_arn: "arn:aws:iam::222:role/Ops".into(),
                    }],
                    allowed_regions: vec!["eu-west-1".into()],
                    allowed_log_group_arns: vec!["arn:aws:logs:*:222:log-group:/infra/*".into()],
                    instance_tag_selectors: vec![TagSelector {
                        tags: HashMap::from([("Env".into(), vec!["staging".into()])]),
                    }],
                    excluded_tag_selectors: vec![],
                    allowed_os_users: vec!["ubuntu".into()],
                    max_session_seconds: Some(1800),
                },
            ],
            memberships: vec![
                GroupMembership {
                    user_id: "alice".into(),
                    group: "eng".into(),
                },
                GroupMembership {
                    user_id: "bob".into(),
                    group: "ops".into(),
                },
                GroupMembership {
                    user_id: "charlie".into(),
                    group: "eng".into(),
                },
                GroupMembership {
                    user_id: "charlie".into(),
                    group: "ops".into(),
                },
            ],
        }
    }

    fn make_service() -> EntitlementService {
        EntitlementService::new(Arc::new(RwLock::new(test_store())))
    }

    #[tokio::test]
    async fn test_evaluate_returns_correct_entitlements() {
        let svc = make_service();
        let claims = test_claims("alice", "alice@example.com");
        let ent = svc.evaluate(&claims).await;
        assert_eq!(ent.user_id, "alice");
        assert!(ent.features.can_view_ec2);
        assert!(ent.features.can_use_cloudwatch_search);
        assert!(!ent.features.can_use_ssm, "eng group should not have SSM");
        assert_eq!(ent.allowed_accounts.len(), 1);
        assert_eq!(ent.allowed_accounts[0].account_id, "111");
    }

    #[tokio::test]
    async fn test_check_account_access_allowed() {
        let svc = make_service();
        let claims = test_claims("alice", "alice@example.com");
        assert!(svc.check_account_access(&claims, "111").await);
    }

    #[tokio::test]
    async fn test_check_account_access_denied() {
        let svc = make_service();
        let claims = test_claims("alice", "alice@example.com");
        assert!(!svc.check_account_access(&claims, "222").await);
    }

    #[tokio::test]
    async fn test_check_region_access_allowed_denied() {
        let svc = make_service();
        let claims = test_claims("bob", "bob@example.com");
        assert!(svc.check_region_access(&claims, "eu-west-1").await);
        assert!(!svc.check_region_access(&claims, "us-east-1").await);
    }

    #[tokio::test]
    async fn test_check_log_group_access_with_wildcard() {
        let svc = make_service();
        let claims = test_claims("alice", "alice@example.com");
        assert!(
            svc.check_log_group_access(&claims, "arn:aws:logs:us-east-1:111:log-group:/app/web")
                .await
        );
        assert!(
            !svc.check_log_group_access(&claims, "arn:aws:logs:us-east-1:222:log-group:/infra/db")
                .await
        );
    }

    #[tokio::test]
    async fn test_has_feature_for_scope_prevents_cross_group() {
        let svc = make_service();
        // alice is in eng only → has cloudwatch_search for account 111
        let claims = test_claims("alice", "alice@example.com");
        assert!(
            svc.has_feature_for_scope(&claims, "111", Some("us-east-1"), None, None, |f| f
                .can_use_cloudwatch_search,)
                .await
        );
        // alice should NOT have cloudwatch_search for account 222 (ops group only)
        assert!(
            !svc.has_feature_for_scope(&claims, "222", Some("eu-west-1"), None, None, |f| f
                .can_use_cloudwatch_search,)
                .await
        );
    }

    #[tokio::test]
    async fn test_allowed_log_group_arns_filters_by_region() {
        let svc = make_service();
        // charlie is in both groups
        let claims = test_claims("charlie", "charlie@example.com");
        // For account 111, region us-east-1 → only eng rule's ARNs
        let arns = svc
            .allowed_log_group_arns_for_scope(&claims, "111", "us-east-1", |f| {
                f.can_use_cloudwatch_search
            })
            .await;
        assert_eq!(arns.len(), 1);
        assert!(arns[0].contains("111"));
        // For account 222, region eu-west-1 → only ops rule's ARNs
        let arns = svc
            .allowed_log_group_arns_for_scope(&claims, "222", "eu-west-1", |f| {
                f.can_use_cloudwatch_search
            })
            .await;
        assert_eq!(arns.len(), 1);
        assert!(arns[0].contains("222"));
    }

    #[tokio::test]
    async fn test_scoped_accounts_deduplicates() {
        let svc = make_service();
        let claims = test_claims("charlie", "charlie@example.com");
        let accounts = svc
            .scoped_accounts_for_feature(&claims, |f| f.can_view_ec2)
            .await;
        // charlie has eng (account 111) and ops (account 222) → 2 entries
        assert_eq!(accounts.len(), 2);
        let ids: Vec<&str> = accounts
            .iter()
            .map(|(a, _)| a.account_id.as_str())
            .collect();
        assert!(ids.contains(&"111"));
        assert!(ids.contains(&"222"));
    }
}
