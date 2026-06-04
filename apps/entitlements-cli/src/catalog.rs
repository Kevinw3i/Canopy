use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::process::Command as ProcessCommand;

use anyhow::{anyhow, Context};
use entitlements::{
    EntitlementStore, GroupMapping, ORGANIZATION_ACCOUNT_ID_TOKEN, ORGANIZATION_ACCOUNT_PLACEHOLDER,
};
use serde::{Deserialize, Serialize};
use shared::dto::entitlements::{
    AllowedAccount, DatabaseScope, EntitlementRule, FeatureFlags, GroupMembership,
    McpEc2DiagnosticScope, RuleMetadata, TagSelector, UserEntitlements,
};

const CATALOG_FEATURE_FIELDS: &[(&str, &str)] = &[
    ("ec2:view", "can_view_ec2"),
    ("cloudwatch:search", "can_use_cloudwatch_search"),
    ("cloudwatch:tail", "can_use_cloudwatch_tail"),
    ("ssm:shell", "can_use_ssm"),
    ("ec2:instance-connect", "can_use_ec2_instance_connect"),
    ("ec2:start", "can_start_ec2"),
    ("ec2:stop", "can_stop_ec2"),
    ("ec2:reboot", "can_reboot_ec2"),
    ("mcp:use", "can_use_mcp"),
    ("mcp:cloudwatch", "can_use_mcp_cloudwatch"),
    (
        "mcp:raw-audit-plaintext",
        "can_view_mcp_raw_audit_plaintext",
    ),
    ("mcp:ec2", "can_use_mcp_ec2"),
    ("mcp:database", "can_use_mcp_database"),
    ("ecs:view", "can_view_ecs"),
    ("ecs:exec", "can_use_ecs_exec"),
];

const HIGH_RISK_FEATURES: &[&str] = &[
    "ssm:shell",
    "ec2:start",
    "ec2:stop",
    "ec2:reboot",
    "mcp:raw-audit-plaintext",
    "mcp:ec2",
    "mcp:database",
    "ecs:exec",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    #[serde(default)]
    pub accounts: Vec<CatalogAccount>,
    #[serde(default)]
    pub roles: Vec<CatalogRole>,
    #[serde(default)]
    pub scopes: Vec<CatalogScope>,
    #[serde(default)]
    pub packages: Vec<CatalogPackage>,
    #[serde(default)]
    pub bindings: Vec<CatalogBinding>,
    #[serde(default)]
    pub group_mappings: Vec<GroupMapping>,
    #[serde(default)]
    pub memberships: Vec<CatalogMembership>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogAccount {
    pub id: String,
    pub account_id: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogRole {
    pub id: String,
    pub role_arn: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CatalogScope {
    pub id: String,
    #[serde(default)]
    pub accounts: Vec<String>,
    #[serde(default)]
    pub regions: Vec<String>,
    #[serde(default, alias = "allowed_log_group_arns")]
    pub log_group_arns: Vec<String>,
    #[serde(default, alias = "allowed_clusters")]
    pub clusters: Vec<String>,
    #[serde(default)]
    pub instance_tag_selectors: Vec<TagSelector>,
    #[serde(default)]
    pub excluded_tag_selectors: Vec<TagSelector>,
    #[serde(default)]
    pub task_tag_selectors: Vec<TagSelector>,
    #[serde(default)]
    pub excluded_task_tag_selectors: Vec<TagSelector>,
    #[serde(default)]
    pub excluded_container_names: Vec<String>,
    #[serde(default)]
    pub allow_broad_cluster_discovery: bool,
    #[serde(default, alias = "allowed_os_users")]
    pub os_users: Vec<String>,
    #[serde(default)]
    pub database_scopes: Vec<DatabaseScope>,
    #[serde(default)]
    pub mcp_ec2_diagnostic_scopes: Vec<McpEc2DiagnosticScope>,
    #[serde(default)]
    pub metadata: RuleMetadata,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogPackage {
    pub id: String,
    #[serde(default)]
    pub features: Vec<String>,
    pub scope: String,
    pub role: String,
    #[serde(default)]
    pub max_session_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogBinding {
    pub group: String,
    pub package: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogMembership {
    pub user_id: String,
    pub group: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeEntitlements {
    pub rules: Vec<EntitlementRule>,
    pub group_mappings: Vec<GroupMapping>,
    pub memberships: Vec<GroupMembership>,
}

#[derive(Debug, Clone)]
pub struct GeneratedRuntime {
    pub runtime: RuntimeEntitlements,
    pub toml: String,
}

impl GeneratedRuntime {
    fn store(&self) -> EntitlementStore {
        EntitlementStore {
            rules: self.runtime.rules.clone(),
            group_mappings: self.runtime.group_mappings.clone(),
            memberships: self.runtime.memberships.clone(),
        }
    }
}

impl Catalog {
    pub fn from_str(input: &str) -> anyhow::Result<Self> {
        toml::from_str(input).context("failed to parse entitlement catalog")
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read catalog file '{}'", path.display()))?;
        Self::from_str(&content)
    }

    pub fn generate_runtime(&self) -> anyhow::Result<GeneratedRuntime> {
        let account_by_id = index_by_id(&self.accounts, "account", |account| &account.id)?;
        let role_by_id = index_by_id(&self.roles, "role", |role| &role.id)?;
        let scope_by_id = index_by_id(&self.scopes, "scope", |scope| &scope.id)?;
        let package_by_id = index_by_id(&self.packages, "package", |package| &package.id)?;

        let mut seen_binding_ids = HashSet::new();
        let mut rules = Vec::new();

        for binding in &self.bindings {
            let package = package_by_id.get(binding.package.as_str()).ok_or_else(|| {
                anyhow!(
                    "binding for group '{}' references unknown package '{}'",
                    binding.group,
                    binding.package
                )
            })?;
            let scope = scope_by_id.get(package.scope.as_str()).ok_or_else(|| {
                anyhow!(
                    "package '{}' references unknown scope '{}'",
                    package.id,
                    package.scope
                )
            })?;
            let role = role_by_id.get(package.role.as_str()).ok_or_else(|| {
                anyhow!(
                    "package '{}' references unknown role '{}'",
                    package.id,
                    package.role
                )
            })?;

            let rule_id = stable_rule_id(&binding.group, &package.id);
            if !seen_binding_ids.insert(rule_id.clone()) {
                anyhow::bail!(
                    "duplicate binding output rule id '{}'; split or rename the binding/package",
                    rule_id
                );
            }

            rules.push(EntitlementRule {
                id: rule_id,
                group: binding.group.clone(),
                metadata: scope.metadata.clone(),
                features: features_from_catalog(&package.features)
                    .with_context(|| format!("package '{}'", package.id))?,
                allowed_accounts: allowed_accounts_for_scope(scope, role, &account_by_id)
                    .with_context(|| format!("package '{}'", package.id))?,
                allowed_regions: scope.regions.clone(),
                allowed_log_group_arns: scope.log_group_arns.clone(),
                instance_tag_selectors: scope.instance_tag_selectors.clone(),
                excluded_tag_selectors: scope.excluded_tag_selectors.clone(),
                allowed_clusters: scope.clusters.clone(),
                task_tag_selectors: scope.task_tag_selectors.clone(),
                excluded_task_tag_selectors: scope.excluded_task_tag_selectors.clone(),
                excluded_container_names: scope.excluded_container_names.clone(),
                allow_broad_cluster_discovery: scope.allow_broad_cluster_discovery,
                allowed_os_users: scope.os_users.clone(),
                max_session_seconds: package.max_session_seconds,
                database_scopes: scope.database_scopes.clone(),
                mcp_ec2_diagnostic_scopes: scope.mcp_ec2_diagnostic_scopes.clone(),
            });
        }

        let runtime = RuntimeEntitlements {
            rules,
            group_mappings: self.group_mappings.clone(),
            memberships: self
                .memberships
                .iter()
                .map(|membership| GroupMembership {
                    user_id: membership.user_id.clone(),
                    group: membership.group.clone(),
                })
                .collect(),
        };

        EntitlementStore {
            rules: runtime.rules.clone(),
            group_mappings: runtime.group_mappings.clone(),
            memberships: runtime.memberships.clone(),
        }
        .validate_allowing_organization_account_placeholders()
        .context("generated runtime entitlement validation failed")?;

        let toml = toml::to_string_pretty(&runtime)
            .context("failed to encode generated runtime entitlements")?;

        Ok(GeneratedRuntime { runtime, toml })
    }

    pub fn preview_group(&self, group: &str) -> anyhow::Result<PreviewOutput> {
        self.generate_runtime()?;
        let account_by_id = index_by_id(&self.accounts, "account", |account| &account.id)?;
        let role_by_id = index_by_id(&self.roles, "role", |role| &role.id)?;
        let scope_by_id = index_by_id(&self.scopes, "scope", |scope| &scope.id)?;
        let package_by_id = index_by_id(&self.packages, "package", |package| &package.id)?;

        let mut packages = Vec::new();
        for binding in self
            .bindings
            .iter()
            .filter(|binding| binding.group == group)
        {
            let package = package_by_id
                .get(binding.package.as_str())
                .expect("generate_runtime validates package references");
            let scope = scope_by_id
                .get(package.scope.as_str())
                .expect("generate_runtime validates scope references");
            let role = role_by_id
                .get(package.role.as_str())
                .expect("generate_runtime validates role references");
            let allowed_accounts = allowed_accounts_for_scope(scope, role, &account_by_id)
                .expect("generate_runtime validates account and role references");
            let high_risk_features = package
                .features
                .iter()
                .filter(|feature| is_high_risk_feature(feature))
                .cloned()
                .collect();

            packages.push(PackagePreview {
                package: package.id.clone(),
                features: package.features.clone(),
                high_risk_features,
                accounts: allowed_accounts,
                regions: scope.regions.clone(),
                log_group_arns: scope.log_group_arns.clone(),
                clusters: scope.clusters.clone(),
                instance_tag_selectors: scope.instance_tag_selectors.clone(),
                excluded_tag_selectors: scope.excluded_tag_selectors.clone(),
                task_tag_selectors: scope.task_tag_selectors.clone(),
                excluded_task_tag_selectors: scope.excluded_task_tag_selectors.clone(),
                excluded_container_names: scope.excluded_container_names.clone(),
                os_users: scope.os_users.clone(),
                database_scopes: scope
                    .database_scopes
                    .iter()
                    .map(|scope| scope.name.clone())
                    .collect(),
                mcp_ec2_diagnostic_scopes: scope
                    .mcp_ec2_diagnostic_scopes
                    .iter()
                    .map(|scope| scope.id.clone())
                    .collect(),
                max_session_seconds: package.max_session_seconds,
            });
        }

        Ok(PreviewOutput {
            status: "ok",
            command: "preview",
            group: group.to_string(),
            packages,
        })
    }

    pub fn semantic_grants(&self) -> anyhow::Result<BTreeSet<SemanticGrant>> {
        self.generate_runtime()?;
        let account_by_id = index_by_id(&self.accounts, "account", |account| &account.id)?;
        let role_by_id = index_by_id(&self.roles, "role", |role| &role.id)?;
        let scope_by_id = index_by_id(&self.scopes, "scope", |scope| &scope.id)?;
        let package_by_id = index_by_id(&self.packages, "package", |package| &package.id)?;
        let mut grants = BTreeSet::new();

        for binding in &self.bindings {
            let package = package_by_id
                .get(binding.package.as_str())
                .expect("generate_runtime validates package references");
            let scope = scope_by_id
                .get(package.scope.as_str())
                .expect("generate_runtime validates scope references");
            let role = role_by_id
                .get(package.role.as_str())
                .expect("generate_runtime validates role references");

            for feature in &package.features {
                grants.insert(SemanticGrant::new(
                    &binding.group,
                    &package.id,
                    "feature",
                    feature,
                ));
            }
            for account in allowed_accounts_for_scope(scope, role, &account_by_id)
                .expect("generate_runtime validates account and role references")
            {
                grants.insert(SemanticGrant::new(
                    &binding.group,
                    &package.id,
                    "account_role",
                    format!(
                        "{}|{}|{}",
                        account.account_id, account.account_name, account.role_arn
                    ),
                ));
            }
            for region in &scope.regions {
                grants.insert(SemanticGrant::new(
                    &binding.group,
                    &package.id,
                    "region",
                    region,
                ));
            }
            for log_group in &scope.log_group_arns {
                grants.insert(SemanticGrant::new(
                    &binding.group,
                    &package.id,
                    "log_group",
                    log_group,
                ));
            }
            for cluster in &scope.clusters {
                grants.insert(SemanticGrant::new(
                    &binding.group,
                    &package.id,
                    "cluster",
                    cluster,
                ));
            }
            for selector in &scope.instance_tag_selectors {
                grants.insert(SemanticGrant::new(
                    &binding.group,
                    &package.id,
                    "instance_tag_selector",
                    selector_key(selector),
                ));
            }
            for selector in &scope.excluded_tag_selectors {
                grants.insert(SemanticGrant::new(
                    &binding.group,
                    &package.id,
                    "excluded_instance_tag_selector",
                    selector_key(selector),
                ));
            }
            for selector in &scope.task_tag_selectors {
                grants.insert(SemanticGrant::new(
                    &binding.group,
                    &package.id,
                    "task_tag_selector",
                    selector_key(selector),
                ));
            }
            for selector in &scope.excluded_task_tag_selectors {
                grants.insert(SemanticGrant::new(
                    &binding.group,
                    &package.id,
                    "excluded_task_tag_selector",
                    selector_key(selector),
                ));
            }
            for container in &scope.excluded_container_names {
                grants.insert(SemanticGrant::new(
                    &binding.group,
                    &package.id,
                    "excluded_container",
                    container,
                ));
            }
            for os_user in &scope.os_users {
                grants.insert(SemanticGrant::new(
                    &binding.group,
                    &package.id,
                    "os_user",
                    os_user,
                ));
            }
            for database_scope in &scope.database_scopes {
                grants.insert(SemanticGrant::new(
                    &binding.group,
                    &package.id,
                    "database_scope",
                    &database_scope.name,
                ));
            }
            for ec2_scope in &scope.mcp_ec2_diagnostic_scopes {
                grants.insert(SemanticGrant::new(
                    &binding.group,
                    &package.id,
                    "mcp_ec2_diagnostic_scope",
                    &ec2_scope.id,
                ));
            }
            if let Some(max_session_seconds) = package.max_session_seconds {
                grants.insert(SemanticGrant::new(
                    &binding.group,
                    &package.id,
                    "session_cap",
                    max_session_seconds.to_string(),
                ));
            }
        }

        Ok(grants)
    }

    pub fn explain(&self, request: ExplainRequest) -> anyhow::Result<ExplainOutput> {
        let generated = self.generate_runtime()?;
        let store = generated.store();
        let email = request.email.clone().unwrap_or_default();
        let mapping_hits = request
            .external_groups
            .iter()
            .filter_map(|external_group| {
                store
                    .group_mappings
                    .iter()
                    .find(|mapping| mapping.external_group == *external_group)
                    .cloned()
            })
            .collect::<Vec<_>>();
        let unmapped_external_groups = request
            .external_groups
            .iter()
            .filter(|external_group| {
                !store
                    .group_mappings
                    .iter()
                    .any(|mapping| mapping.external_group == **external_group)
            })
            .cloned()
            .collect::<Vec<_>>();
        let local_membership_hits = store
            .memberships
            .iter()
            .filter(|membership| {
                membership.user_id == request.sub
                    || (request.email_verified && !email.is_empty() && membership.user_id == email)
            })
            .cloned()
            .collect::<Vec<_>>();
        let resolved_groups = store.resolve_groups(
            &request.external_groups,
            &request.sub,
            &email,
            request.email_verified,
        );
        let effective_entitlements =
            store.evaluate_for_groups(&resolved_groups, &request.sub, &email, &request.sub);
        let matched_packages = self
            .bindings
            .iter()
            .filter(|binding| resolved_groups.contains(&binding.group))
            .map(|binding| binding.package.clone())
            .collect();

        Ok(ExplainOutput {
            status: "ok",
            command: "explain",
            sub: request.sub,
            email,
            email_verified: request.email_verified,
            external_groups: request.external_groups,
            mapping_hits,
            unmapped_external_groups,
            local_membership_hits,
            resolved_groups,
            matched_packages,
            effective_entitlements,
        })
    }

    pub fn dry_run(&self, request: DryRunRequest) -> anyhow::Result<DryRunOutput> {
        let generated = self.generate_runtime()?;
        let store = generated.store();
        let email = request.email.clone().unwrap_or_default();
        let resolved_groups = store.resolve_groups(
            &request.external_groups,
            &request.sub,
            &email,
            request.email_verified,
        );

        let result = match request.operation.as_str() {
            "ec2-view" => {
                required(&request.region, "--region")?;
                dry_run_feature_scope(
                    &store,
                    &resolved_groups,
                    &request,
                    |features| features.can_view_ec2,
                    "ec2:view",
                )?
            }
            "ec2-start" => dry_run_ec2_tags(
                &store,
                &resolved_groups,
                &request,
                |features| features.can_start_ec2,
                "ec2:start",
            )?,
            "ec2-stop" => dry_run_ec2_tags(
                &store,
                &resolved_groups,
                &request,
                |features| features.can_stop_ec2,
                "ec2:stop",
            )?,
            "ec2-reboot" => dry_run_ec2_tags(
                &store,
                &resolved_groups,
                &request,
                |features| features.can_reboot_ec2,
                "ec2:reboot",
            )?,
            "cloudwatch-search" => {
                required(&request.region, "--region")?;
                required(&request.log_group_arn, "--log-group-arn")?;
                dry_run_feature_scope(
                    &store,
                    &resolved_groups,
                    &request,
                    |features| features.can_use_cloudwatch_search,
                    "cloudwatch:search",
                )?
            }
            "ssm-shell" => {
                required(&request.region, "--region")?;
                required(&request.os_user, "--os-user")?;
                dry_run_feature_scope(
                    &store,
                    &resolved_groups,
                    &request,
                    |features| features.can_use_ssm,
                    "ssm:shell",
                )?
            }
            "ecs-exec" => dry_run_ecs_exec(&store, &resolved_groups, &request)?,
            other => anyhow::bail!(
                "unsupported dry-run operation '{}'; supported operations: ec2-view, ec2-start, ec2-stop, ec2-reboot, cloudwatch-search, ssm-shell, ecs-exec",
                other
            ),
        };

        Ok(DryRunOutput {
            status: "ok",
            command: "dry-run",
            operation: request.operation,
            allow: result.allow,
            reason: result.reason,
            resolved_groups,
            matched_rule: result.matched_rule,
        })
    }
}

pub fn generate_runtime_file(
    catalog_path: &Path,
    output_path: &Path,
) -> anyhow::Result<GenerateStatus> {
    let catalog = Catalog::load(catalog_path)?;
    let generated = catalog.generate_runtime()?;
    std::fs::write(output_path, generated.toml)
        .with_context(|| format!("failed to write runtime file '{}'", output_path.display()))?;

    Ok(GenerateStatus {
        status: "generated",
        command: "generate",
        catalog: catalog_path.display().to_string(),
        output: output_path.display().to_string(),
        rules: generated.runtime.rules.len(),
        group_mappings: generated.runtime.group_mappings.len(),
        memberships: generated.runtime.memberships.len(),
    })
}

pub fn validate_catalog_files(
    catalog_path: &Path,
    runtime_path: &Path,
    tfvars_path: &Path,
) -> anyhow::Result<ValidateStatus> {
    let script_path = validate_entitlements_script_path()?;
    validate_catalog_files_with_script(catalog_path, runtime_path, tfvars_path, &script_path)
}

pub fn validate_catalog_files_with_script(
    catalog_path: &Path,
    runtime_path: &Path,
    tfvars_path: &Path,
    script_path: &Path,
) -> anyhow::Result<ValidateStatus> {
    let catalog = Catalog::load(catalog_path)?;
    let generated = catalog.generate_runtime()?;
    let runtime_content = std::fs::read_to_string(runtime_path)
        .with_context(|| format!("failed to read runtime file '{}'", runtime_path.display()))?;
    if generated.toml != runtime_content {
        anyhow::bail!(
            "runtime file drift detected: regenerate '{}' from '{}'",
            runtime_path.display(),
            catalog_path.display()
        );
    }

    let runtime_store =
        EntitlementStore::load_from_file_allowing_organization_account_placeholders(runtime_path)
            .with_context(|| {
            format!(
                "failed to load runtime entitlement file '{}'",
                runtime_path.display()
            )
        })?;

    run_deployment_validation(script_path, runtime_path, tfvars_path)?;

    Ok(ValidateStatus {
        status: "valid",
        command: "validate",
        catalog: catalog_path.display().to_string(),
        runtime_file: runtime_path.display().to_string(),
        tfvars: tfvars_path.display().to_string(),
        generated_rules: generated.runtime.rules.len(),
        runtime_rules: runtime_store.rules.len(),
        group_mappings: runtime_store.group_mappings.len(),
        memberships: runtime_store.memberships.len(),
        deployment_validation: true,
    })
}

pub fn preview_catalog_file(catalog_path: &Path, group: &str) -> anyhow::Result<PreviewOutput> {
    Catalog::load(catalog_path)?.preview_group(group)
}

pub fn diff_catalog_files(old_path: &Path, new_path: &Path) -> anyhow::Result<DiffOutput> {
    let old = Catalog::load(old_path)?;
    let new = Catalog::load(new_path)?;
    let old_grants = old.semantic_grants()?;
    let new_grants = new.semantic_grants()?;

    let added: Vec<_> = new_grants.difference(&old_grants).cloned().collect();
    let removed: Vec<_> = old_grants.difference(&new_grants).cloned().collect();
    let high_risk_changes = added
        .iter()
        .filter(|grant| grant.kind == "feature" && is_high_risk_feature(&grant.value))
        .cloned()
        .collect();

    Ok(DiffOutput {
        status: "ok",
        command: "diff",
        old: old_path.display().to_string(),
        new: new_path.display().to_string(),
        added,
        removed,
        high_risk_changes,
    })
}

pub fn explain_catalog_file(
    catalog_path: &Path,
    request: ExplainRequest,
) -> anyhow::Result<ExplainOutput> {
    Catalog::load(catalog_path)?.explain(request)
}

pub fn dry_run_catalog_file(
    catalog_path: &Path,
    request: DryRunRequest,
) -> anyhow::Result<DryRunOutput> {
    Catalog::load(catalog_path)?.dry_run(request)
}

#[derive(Debug, Clone, Serialize)]
pub struct GenerateStatus {
    pub status: &'static str,
    pub command: &'static str,
    pub catalog: String,
    pub output: String,
    pub rules: usize,
    pub group_mappings: usize,
    pub memberships: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidateStatus {
    pub status: &'static str,
    pub command: &'static str,
    pub catalog: String,
    pub runtime_file: String,
    pub tfvars: String,
    pub generated_rules: usize,
    pub runtime_rules: usize,
    pub group_mappings: usize,
    pub memberships: usize,
    pub deployment_validation: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreviewOutput {
    pub status: &'static str,
    pub command: &'static str,
    pub group: String,
    pub packages: Vec<PackagePreview>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackagePreview {
    pub package: String,
    pub features: Vec<String>,
    pub high_risk_features: Vec<String>,
    pub accounts: Vec<AllowedAccount>,
    pub regions: Vec<String>,
    pub log_group_arns: Vec<String>,
    pub clusters: Vec<String>,
    pub instance_tag_selectors: Vec<TagSelector>,
    pub excluded_tag_selectors: Vec<TagSelector>,
    pub task_tag_selectors: Vec<TagSelector>,
    pub excluded_task_tag_selectors: Vec<TagSelector>,
    pub excluded_container_names: Vec<String>,
    pub os_users: Vec<String>,
    pub database_scopes: Vec<String>,
    pub mcp_ec2_diagnostic_scopes: Vec<String>,
    pub max_session_seconds: Option<u64>,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct SemanticGrant {
    pub group: String,
    pub package: String,
    pub kind: String,
    pub value: String,
}

impl SemanticGrant {
    fn new(
        group: impl Into<String>,
        package: impl Into<String>,
        kind: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            group: group.into(),
            package: package.into(),
            kind: kind.into(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffOutput {
    pub status: &'static str,
    pub command: &'static str,
    pub old: String,
    pub new: String,
    pub added: Vec<SemanticGrant>,
    pub removed: Vec<SemanticGrant>,
    pub high_risk_changes: Vec<SemanticGrant>,
}

#[derive(Debug, Clone)]
pub struct ExplainRequest {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub external_groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExplainOutput {
    pub status: &'static str,
    pub command: &'static str,
    pub sub: String,
    pub email: String,
    pub email_verified: bool,
    pub external_groups: Vec<String>,
    pub mapping_hits: Vec<GroupMapping>,
    pub unmapped_external_groups: Vec<String>,
    pub local_membership_hits: Vec<GroupMembership>,
    pub resolved_groups: Vec<String>,
    pub matched_packages: Vec<String>,
    pub effective_entitlements: UserEntitlements,
}

#[derive(Debug, Clone)]
pub struct DryRunRequest {
    pub operation: String,
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub external_groups: Vec<String>,
    pub account: Option<String>,
    pub region: Option<String>,
    pub cluster: Option<String>,
    pub log_group_arn: Option<String>,
    pub os_user: Option<String>,
    pub instance_tags: Vec<String>,
    pub task_tags: Vec<String>,
    pub container: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DryRunOutput {
    pub status: &'static str,
    pub command: &'static str,
    pub operation: String,
    pub allow: bool,
    pub reason: String,
    pub resolved_groups: Vec<String>,
    pub matched_rule: Option<String>,
}

pub fn feature_field_names() -> &'static [(&'static str, &'static str)] {
    CATALOG_FEATURE_FIELDS
}

fn validate_entitlements_script_path() -> anyhow::Result<std::path::PathBuf> {
    if let Some(path) = std::env::var_os("CANOPY_VALIDATE_ENTITLEMENTS_SCRIPT") {
        return Ok(path.into());
    }

    if let Ok(cwd) = std::env::current_dir() {
        if let Some(path) = find_validate_entitlements_script_from(&cwd) {
            return Ok(path);
        }
    }

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    if let Some(path) = find_validate_entitlements_script_from(manifest_dir) {
        return Ok(path);
    }

    anyhow::bail!("could not find scripts/validate-entitlements.sh")
}

fn find_validate_entitlements_script_from(start: &Path) -> Option<std::path::PathBuf> {
    for ancestor in start.ancestors() {
        let candidate = ancestor.join("scripts/validate-entitlements.sh");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn run_deployment_validation(
    script_path: &Path,
    runtime_path: &Path,
    tfvars_path: &Path,
) -> anyhow::Result<()> {
    let output = ProcessCommand::new(script_path)
        .arg(runtime_path)
        .arg(tfvars_path)
        .output()
        .with_context(|| {
            format!(
                "failed to run deployment validation script '{}'",
                script_path.display()
            )
        })?;

    if output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    anyhow::bail!(
        "deployment validation failed with status {}: {}{}{}",
        output.status,
        stdout.trim(),
        if stdout.trim().is_empty() || stderr.trim().is_empty() {
            ""
        } else {
            "\n"
        },
        stderr.trim()
    );
}

fn features_from_catalog(features: &[String]) -> anyhow::Result<FeatureFlags> {
    let mut flags = FeatureFlags::default();
    for feature in features {
        apply_catalog_feature(feature, &mut flags)?;
    }
    Ok(flags)
}

fn apply_catalog_feature(feature: &str, flags: &mut FeatureFlags) -> anyhow::Result<()> {
    match feature {
        "ec2:view" => flags.can_view_ec2 = true,
        "cloudwatch:search" => flags.can_use_cloudwatch_search = true,
        "cloudwatch:tail" => flags.can_use_cloudwatch_tail = true,
        "ssm:shell" => flags.can_use_ssm = true,
        "ec2:instance-connect" => flags.can_use_ec2_instance_connect = true,
        "ec2:start" => flags.can_start_ec2 = true,
        "ec2:stop" => flags.can_stop_ec2 = true,
        "ec2:reboot" => flags.can_reboot_ec2 = true,
        "mcp:use" => flags.can_use_mcp = true,
        "mcp:cloudwatch" => flags.can_use_mcp_cloudwatch = true,
        "mcp:raw-audit-plaintext" => flags.can_view_mcp_raw_audit_plaintext = true,
        "mcp:ec2" => flags.can_use_mcp_ec2 = true,
        "mcp:database" => flags.can_use_mcp_database = true,
        "ecs:view" => flags.can_view_ecs = true,
        "ecs:exec" => flags.can_use_ecs_exec = true,
        _ => anyhow::bail!("unknown catalog feature '{}'", feature),
    }
    Ok(())
}

fn is_high_risk_feature(feature: &str) -> bool {
    HIGH_RISK_FEATURES.contains(&feature)
}

fn selector_key(selector: &TagSelector) -> String {
    let mut parts = Vec::new();
    for (key, values) in &selector.tags {
        let mut values = values.clone();
        values.sort();
        parts.push(format!("{key}={}", values.join("|")));
    }
    parts.sort();
    parts.join(",")
}

struct DryRunDecision {
    allow: bool,
    reason: String,
    matched_rule: Option<String>,
}

fn allow(reason: impl Into<String>, rule_id: impl Into<String>) -> DryRunDecision {
    DryRunDecision {
        allow: true,
        reason: reason.into(),
        matched_rule: Some(rule_id.into()),
    }
}

fn deny(reason: impl Into<String>) -> DryRunDecision {
    DryRunDecision {
        allow: false,
        reason: reason.into(),
        matched_rule: None,
    }
}

fn dry_run_feature_scope(
    store: &EntitlementStore,
    groups: &[String],
    request: &DryRunRequest,
    feature_check: impl Fn(&FeatureFlags) -> bool + Copy,
    feature_name: &str,
) -> anyhow::Result<DryRunDecision> {
    let account = required(&request.account, "--account")?;
    let region = request.region.as_deref();
    let log_group = request.log_group_arn.as_deref();
    let os_user = request.os_user.as_deref();

    if store.has_feature_for_scope_for_groups(
        groups,
        account,
        region,
        log_group,
        os_user,
        feature_check,
    ) {
        let matched_rule = store
            .matching_rules_for_scope_for_groups(groups, account, feature_check)
            .into_iter()
            .find(|rule| {
                region.is_none_or(|region| {
                    rule.allowed_regions.is_empty()
                        || rule.allowed_regions.iter().any(|allowed| allowed == region)
                }) && log_group.is_none_or(|log_group| {
                    rule.allowed_log_group_arns.is_empty()
                        || rule
                            .allowed_log_group_arns
                            .iter()
                            .any(|pattern| entitlements::arn_matches_pattern(pattern, log_group))
                }) && os_user.is_none_or(|os_user| {
                    rule.allowed_os_users.is_empty()
                        || rule.allowed_os_users.iter().any(|allowed| allowed == "*")
                        || rule
                            .allowed_os_users
                            .iter()
                            .any(|allowed| allowed == os_user)
                })
            })
            .map(|rule| rule.id.clone())
            .unwrap_or_default();
        return Ok(allow(
            format!("{feature_name} allowed by one matching rule"),
            matched_rule,
        ));
    }

    Ok(deny(format!(
        "{feature_name} denied: no resolved group has one rule matching the requested feature and scope"
    )))
}

fn dry_run_ec2_tags(
    store: &EntitlementStore,
    groups: &[String],
    request: &DryRunRequest,
    feature_check: impl Fn(&FeatureFlags) -> bool + Copy,
    feature_name: &str,
) -> anyhow::Result<DryRunDecision> {
    let account = required(&request.account, "--account")?;
    let region = required(&request.region, "--region")?;
    let instance_tags = parse_key_values(&request.instance_tags, "--instance-tags")?;

    for rule in store.matching_rules_for_scope_for_groups(groups, account, feature_check) {
        if !rule.allowed_regions.is_empty() && !rule.allowed_regions.iter().any(|r| r == region) {
            continue;
        }
        if !rule.instance_tag_selectors.is_empty() {
            if instance_tags.is_empty() {
                return Ok(deny(format!(
                    "{feature_name} denied: --instance-tags are required for selector-scoped rules"
                )));
            }
            if !rule
                .instance_tag_selectors
                .iter()
                .any(|selector| selector.matches(&instance_tags))
            {
                continue;
            }
        }
        if rule
            .excluded_tag_selectors
            .iter()
            .any(|selector| selector.matches(&instance_tags))
        {
            continue;
        }
        return Ok(allow(
            format!("{feature_name} allowed by one matching rule"),
            &rule.id,
        ));
    }

    Ok(deny(format!(
        "{feature_name} denied: no resolved group has one rule matching the requested feature, account, region, and instance tags"
    )))
}

fn dry_run_ecs_exec(
    store: &EntitlementStore,
    groups: &[String],
    request: &DryRunRequest,
) -> anyhow::Result<DryRunDecision> {
    let account = required(&request.account, "--account")?;
    let region = required(&request.region, "--region")?;
    let cluster = required(&request.cluster, "--cluster")?;
    let container = required(&request.container, "--container")?;
    let task_tags = parse_key_values(&request.task_tags, "--task-tags")?;

    let cluster_variants = [
        cluster.to_string(),
        format!("arn:aws:ecs:{region}:{account}:cluster/{cluster}"),
    ];

    for rule in store
        .matching_rules_for_scope_for_groups(groups, account, |features| features.can_use_ecs_exec)
    {
        if !rule.allowed_regions.is_empty() && !rule.allowed_regions.iter().any(|r| r == region) {
            continue;
        }
        if !rule.allowed_clusters.iter().any(|pattern| {
            cluster_variants
                .iter()
                .any(|candidate| entitlements::arn_matches_pattern(pattern, candidate))
        }) {
            continue;
        }
        if rule
            .excluded_container_names
            .iter()
            .any(|excluded| excluded == container)
        {
            continue;
        }
        if !rule.task_tag_selectors.is_empty() {
            if task_tags.is_empty() {
                return Ok(deny(
                    "ecs:exec denied: --task-tags are required for selector-scoped rules",
                ));
            }
            if !rule
                .task_tag_selectors
                .iter()
                .any(|selector| selector.matches(&task_tags))
            {
                continue;
            }
        }
        if rule
            .excluded_task_tag_selectors
            .iter()
            .any(|selector| selector.matches(&task_tags))
        {
            continue;
        }
        return Ok(allow("ecs:exec allowed by one matching rule", &rule.id));
    }

    Ok(deny(
        "ecs:exec denied: no resolved group has one rule matching the requested feature, account, region, cluster, task tags, and container",
    ))
}

fn required<'a>(value: &'a Option<String>, name: &str) -> anyhow::Result<&'a str> {
    value
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("{name} is required for this dry-run operation"))
}

fn parse_key_values(values: &[String], flag: &str) -> anyhow::Result<HashMap<String, String>> {
    let mut result = HashMap::new();
    for value in values {
        let Some((key, tag_value)) = value.split_once('=') else {
            anyhow::bail!("{flag} must use KEY=VALUE entries");
        };
        if key.trim().is_empty() || tag_value.trim().is_empty() {
            anyhow::bail!("{flag} must use non-empty KEY=VALUE entries");
        }
        result.insert(key.to_string(), tag_value.to_string());
    }
    Ok(result)
}

fn allowed_accounts_for_scope(
    scope: &CatalogScope,
    role: &CatalogRole,
    account_by_id: &HashMap<&str, &CatalogAccount>,
) -> anyhow::Result<Vec<AllowedAccount>> {
    let mut accounts = Vec::new();
    for account_ref in &scope.accounts {
        let account = account_by_id.get(account_ref.as_str()).ok_or_else(|| {
            anyhow!(
                "scope '{}' references unknown account '{}'",
                scope.id,
                account_ref
            )
        })?;
        accounts.push(AllowedAccount {
            account_id: account.account_id.clone(),
            account_name: account.name.clone(),
            role_arn: render_role_arn(&role.role_arn, &account.account_id).with_context(|| {
                format!(
                    "role '{}' cannot be used with account '{}' ({})",
                    role.id, account.id, account.account_id
                )
            })?,
        });
    }
    Ok(accounts)
}

fn render_role_arn(role_arn: &str, account_id: &str) -> anyhow::Result<String> {
    if role_arn == "direct" || role_arn.starts_with("profile:") {
        return Ok(role_arn.to_string());
    }
    if role_arn.contains(ORGANIZATION_ACCOUNT_ID_TOKEN) {
        if account_id == ORGANIZATION_ACCOUNT_PLACEHOLDER {
            return Ok(role_arn.to_string());
        }
        return Ok(role_arn.replace(ORGANIZATION_ACCOUNT_ID_TOKEN, account_id));
    }
    if let Some(role_account_id) = iam_role_account_id(role_arn) {
        if role_account_id == account_id {
            return Ok(role_arn.to_string());
        }
        anyhow::bail!(
            "concrete role ARN belongs to account '{}' but scope account is '{}'",
            role_account_id,
            account_id
        );
    }
    anyhow::bail!(
        "role_arn must be direct, profile:*, a concrete IAM role ARN, or contain {}",
        ORGANIZATION_ACCOUNT_ID_TOKEN
    );
}

fn iam_role_account_id(role_arn: &str) -> Option<&str> {
    let parts: Vec<&str> = role_arn.split(':').collect();
    if parts.len() >= 6 && parts[0] == "arn" && parts[2] == "iam" && parts[5].starts_with("role/") {
        Some(parts[4])
    } else {
        None
    }
}

fn index_by_id<'a, T>(
    items: &'a [T],
    kind: &str,
    id: impl Fn(&'a T) -> &'a str,
) -> anyhow::Result<HashMap<&'a str, &'a T>> {
    let mut result = HashMap::new();
    for item in items {
        let item_id = id(item);
        if item_id.trim().is_empty() {
            anyhow::bail!("{kind} id must not be empty");
        }
        if result.insert(item_id, item).is_some() {
            anyhow::bail!("duplicate {kind} id '{}'", item_id);
        }
    }
    Ok(result)
}

fn stable_rule_id(group: &str, package: &str) -> String {
    format!(
        "catalog-{}-{}",
        stable_id_part(group),
        stable_id_part(package)
    )
}

fn stable_id_part(value: &str) -> String {
    let mut output = String::new();
    let mut last_dash = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' {
            output.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            output.push('-');
            last_dash = true;
        }
    }
    let trimmed = output.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "unnamed".into()
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashMap};
    use std::time::{SystemTime, UNIX_EPOCH};

    const MINIMAL_CATALOG: &str = r#"
        [[accounts]]
        id = "prod"
        account_id = "123456789012"
        name = "production"

        [[roles]]
        id = "canopy"
        role_arn = "arn:aws:iam::{account_id}:role/CanopyRole"

        [[scopes]]
        id = "prod-ec2"
        accounts = ["prod"]
        regions = ["ap-northeast-1"]

        [[packages]]
        id = "ec2-readonly"
        features = ["ec2:view", "cloudwatch:search"]
        scope = "prod-ec2"
        role = "canopy"
        max_session_seconds = 1800

        [[bindings]]
        group = "platform-engineering"
        package = "ec2-readonly"

        [[group_mappings]]
        external_group = "canopy-platform-engineering"
        canopy_group = "platform-engineering"

        [[memberships]]
        user_id = "break-glass@example.com"
        group = "platform-engineering"
    "#;

    #[test]
    fn generate_runtime_compiles_binding_to_one_rule() {
        let catalog = Catalog::from_str(MINIMAL_CATALOG).unwrap();
        let generated = catalog.generate_runtime().unwrap();

        assert_eq!(generated.runtime.rules.len(), 1);
        let rule = &generated.runtime.rules[0];
        assert_eq!(rule.id, "catalog-platform-engineering-ec2-readonly");
        assert_eq!(rule.group, "platform-engineering");
        assert!(rule.features.can_view_ec2);
        assert!(rule.features.can_use_cloudwatch_search);
        assert_eq!(rule.allowed_regions, vec!["ap-northeast-1"]);
        assert_eq!(rule.max_session_seconds, Some(1800));
        assert_eq!(rule.allowed_accounts[0].account_id, "123456789012");
        assert_eq!(
            rule.allowed_accounts[0].role_arn,
            "arn:aws:iam::123456789012:role/CanopyRole"
        );
        assert_eq!(generated.runtime.group_mappings.len(), 1);
        assert_eq!(generated.runtime.memberships.len(), 1);
    }

    #[test]
    fn catalog_generates_mcp_ec2_diagnostic_scopes_on_same_rule() {
        let catalog = Catalog::from_str(
            r#"
            [[accounts]]
            id = "prod"
            account_id = "123456789012"
            name = "production"

            [[roles]]
            id = "canopy"
            role_arn = "arn:aws:iam::{account_id}:role/CanopyRole"

            [[scopes]]
            id = "prod-ec2-diagnostics"
            accounts = ["prod"]
            regions = ["ap-northeast-1"]

            [[scopes.mcp_ec2_diagnostic_scopes]]
            id = "rails-nginx-health"
            max_lines = 100
            max_since_seconds = 1800
            max_timeout_seconds = 30
            max_matches = 50
            connectivity_probe_budget_per_window = 20
            budget_window_seconds = 600
            denylist_version = "2026-06-04"
            allowlist_rule_id = "rails-nginx-health-v1"
            private_target_refs = ["service:orders-api"]

            [[scopes.mcp_ec2_diagnostic_scopes.allowed_log_paths]]
            path_pattern = "/var/log/nginx/error.log"
            canonical_safe_prefix = "/var/log/nginx/"
            safe_for_mcp_output = true

            [[scopes.mcp_ec2_diagnostic_scopes.allowed_http_urls]]
            normalized_url = "https://10.0.1.20/health"
            query_policy = "no_query"
            safe_for_mcp_output = true
            private_target_ref = "service:orders-api"

            [[scopes.mcp_ec2_diagnostic_scopes.allowed_dns_targets]]
            host = "orders.example.com"
            record_types = ["A", "AAAA"]
            safe_for_mcp_output = true

            [[packages]]
            id = "mcp-ec2-diagnostics"
            features = ["mcp:use", "mcp:ec2"]
            scope = "prod-ec2-diagnostics"
            role = "canopy"

            [[bindings]]
            group = "platform-engineering"
            package = "mcp-ec2-diagnostics"

            [[memberships]]
            user_id = "platform@example.com"
            group = "platform-engineering"
            "#,
        )
        .unwrap();

        let generated = catalog.generate_runtime().unwrap();
        let rule = &generated.runtime.rules[0];
        assert!(rule.features.can_use_mcp);
        assert!(rule.features.can_use_mcp_ec2);
        assert_eq!(rule.mcp_ec2_diagnostic_scopes.len(), 1);
        assert_eq!(rule.mcp_ec2_diagnostic_scopes[0].id, "rails-nginx-health");

        let store: EntitlementStore = toml::from_str(&generated.toml).unwrap();
        assert_eq!(store.rules[0].mcp_ec2_diagnostic_scopes.len(), 1);

        let preview = catalog.preview_group("platform-engineering").unwrap();
        assert_eq!(
            preview.packages[0].high_risk_features,
            vec!["mcp:ec2".to_string()]
        );
        assert_eq!(
            preview.packages[0].mcp_ec2_diagnostic_scopes,
            vec!["rails-nginx-health".to_string()]
        );

        let grants = catalog.semantic_grants().unwrap();
        assert!(grants.contains(&SemanticGrant::new(
            "platform-engineering",
            "mcp-ec2-diagnostics",
            "mcp_ec2_diagnostic_scope",
            "rails-nginx-health"
        )));
    }

    #[test]
    fn generated_toml_loads_through_entitlement_core() {
        let catalog = Catalog::from_str(MINIMAL_CATALOG).unwrap();
        let generated = catalog.generate_runtime().unwrap();
        let store: EntitlementStore = toml::from_str(&generated.toml).unwrap();

        store.validate().unwrap();
        assert_eq!(
            store.resolve_groups(
                &["canopy-platform-engineering".into()],
                "sub",
                "user@example.com",
                true
            ),
            vec!["platform-engineering"]
        );
    }

    #[test]
    fn every_feature_flag_has_catalog_mapping() {
        let low_level_fields: BTreeSet<String> = serde_json::to_value(FeatureFlags::default())
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        let mapped_fields: BTreeSet<String> = feature_field_names()
            .iter()
            .map(|(_, field)| (*field).to_string())
            .collect();

        assert_eq!(mapped_fields, low_level_fields);
    }

    #[test]
    fn unknown_catalog_feature_fails() {
        let mut catalog = Catalog::from_str(MINIMAL_CATALOG).unwrap();
        catalog.packages[0].features.push("not:a-feature".into());

        let err = format!("{:#}", catalog.generate_runtime().unwrap_err());
        assert!(err.contains("unknown catalog feature"));
    }

    #[test]
    fn membership_email_field_fails_catalog_parse() {
        let err = Catalog::from_str(
            r#"
            [[memberships]]
            user_id = "alice"
            email = "alice@example.com"
            group = "platform-engineering"
            "#,
        )
        .unwrap_err();
        let err = format!("{err:#}");

        assert!(err.contains("unknown field"));
    }

    #[test]
    fn concrete_role_must_match_scope_account() {
        let mut catalog = Catalog::from_str(MINIMAL_CATALOG).unwrap();
        catalog.roles[0].role_arn = "arn:aws:iam::999999999999:role/CanopyRole".into();

        let err = format!("{:#}", catalog.generate_runtime().unwrap_err());
        assert!(err.contains("cannot be used with account"));
    }

    #[test]
    fn organization_placeholder_account_preserves_role_template() {
        let mut catalog = Catalog::from_str(MINIMAL_CATALOG).unwrap();
        catalog.accounts[0].account_id = "*".into();

        let generated = catalog.generate_runtime().unwrap();

        assert_eq!(
            generated.runtime.rules[0].allowed_accounts[0].account_id,
            "*"
        );
        assert_eq!(
            generated.runtime.rules[0].allowed_accounts[0].role_arn,
            "arn:aws:iam::{account_id}:role/CanopyRole"
        );
    }

    #[test]
    fn preview_group_includes_packages_roles_and_high_risk_features() {
        let mut catalog = Catalog::from_str(MINIMAL_CATALOG).unwrap();
        catalog.packages[0].features.push("ec2:start".into());

        let preview = catalog.preview_group("platform-engineering").unwrap();

        assert_eq!(preview.group, "platform-engineering");
        assert_eq!(preview.packages.len(), 1);
        let package = &preview.packages[0];
        assert_eq!(package.package, "ec2-readonly");
        assert!(package.features.contains(&"ec2:view".into()));
        assert_eq!(package.high_risk_features, vec!["ec2:start"]);
        assert_eq!(package.accounts[0].account_id, "123456789012");
        assert_eq!(package.regions, vec!["ap-northeast-1"]);
        assert_eq!(package.max_session_seconds, Some(1800));
    }

    #[test]
    fn diff_catalogs_reports_added_high_risk_feature() {
        let old = Catalog::from_str(MINIMAL_CATALOG).unwrap();
        let mut new = Catalog::from_str(MINIMAL_CATALOG).unwrap();
        new.packages[0].features.push("ec2:start".into());

        let old_path = write_catalog_fixture("diff-old", &old);
        let new_path = write_catalog_fixture("diff-new", &new);

        let diff = diff_catalog_files(&old_path, &new_path).unwrap();

        assert!(diff
            .added
            .iter()
            .any(|grant| { grant.kind == "feature" && grant.value == "ec2:start" }));
        assert_eq!(diff.high_risk_changes.len(), 1);
        assert_eq!(diff.high_risk_changes[0].value, "ec2:start");

        let _ = std::fs::remove_file(old_path);
        let _ = std::fs::remove_file(new_path);
    }

    #[test]
    fn selector_key_is_deterministic() {
        let selector = TagSelector {
            tags: HashMap::from([
                ("Team".into(), vec!["platform".into()]),
                (
                    "Environment".into(),
                    vec!["staging".into(), "production".into()],
                ),
            ]),
        };

        assert_eq!(
            selector_key(&selector),
            "Environment=production|staging,Team=platform"
        );
    }

    #[test]
    fn explain_resolves_external_groups_and_effective_entitlements() {
        let catalog = Catalog::from_str(MINIMAL_CATALOG).unwrap();

        let output = catalog
            .explain(ExplainRequest {
                sub: "user-sub".into(),
                email: Some("user@example.com".into()),
                email_verified: true,
                external_groups: vec!["canopy-platform-engineering".into(), "unmapped".into()],
            })
            .unwrap();

        assert_eq!(output.resolved_groups, vec!["platform-engineering"]);
        assert_eq!(output.mapping_hits.len(), 1);
        assert_eq!(output.unmapped_external_groups, vec!["unmapped"]);
        assert_eq!(output.matched_packages, vec!["ec2-readonly"]);
        assert!(output.effective_entitlements.features.can_view_ec2);
    }

    #[test]
    fn dry_run_ec2_view_uses_resolved_groups_and_core_scope_check() {
        let catalog = Catalog::from_str(MINIMAL_CATALOG).unwrap();

        let output = catalog
            .dry_run(DryRunRequest {
                operation: "ec2-view".into(),
                sub: "user-sub".into(),
                email: None,
                email_verified: false,
                external_groups: vec!["canopy-platform-engineering".into()],
                account: Some("123456789012".into()),
                region: Some("ap-northeast-1".into()),
                cluster: None,
                log_group_arn: None,
                os_user: None,
                instance_tags: vec![],
                task_tags: vec![],
                container: None,
            })
            .unwrap();

        assert!(output.allow);
        assert_eq!(
            output.matched_rule.as_deref(),
            Some("catalog-platform-engineering-ec2-readonly")
        );
    }

    #[test]
    fn validate_catalog_files_runs_deployment_validation() {
        let temp_dir = temp_test_dir("validate-success");
        let catalog_path = temp_dir.join("entitlements.catalog.toml");
        let runtime_path = temp_dir.join("entitlements.generated.toml");
        let tfvars_path = temp_dir.join("terraform.tfvars");
        let script_path = temp_dir.join("validate-entitlements.sh");
        let marker_path = temp_dir.join("script-args.txt");

        std::fs::write(&catalog_path, MINIMAL_CATALOG).unwrap();
        let generated = Catalog::from_str(MINIMAL_CATALOG)
            .unwrap()
            .generate_runtime()
            .unwrap();
        std::fs::write(&runtime_path, generated.toml).unwrap();
        std::fs::write(&tfvars_path, "enable_direct_access = false\n").unwrap();
        write_executable_script(
            &script_path,
            &format!(
                "#!/usr/bin/env bash\nprintf '%s\\n%s\\n' \"$1\" \"$2\" > '{}'\n",
                marker_path.display()
            ),
        );

        let status = validate_catalog_files_with_script(
            &catalog_path,
            &runtime_path,
            &tfvars_path,
            &script_path,
        )
        .unwrap();

        assert_eq!(status.status, "valid");
        assert_eq!(status.generated_rules, 1);
        assert_eq!(status.runtime_rules, 1);
        let marker = std::fs::read_to_string(marker_path).unwrap();
        assert!(marker.contains(runtime_path.to_str().unwrap()));
        assert!(marker.contains(tfvars_path.to_str().unwrap()));

        std::fs::remove_dir_all(temp_dir).unwrap();
    }

    #[test]
    fn validate_catalog_files_surfaces_deployment_validation_failure() {
        let temp_dir = temp_test_dir("validate-failure");
        let catalog_path = temp_dir.join("entitlements.catalog.toml");
        let runtime_path = temp_dir.join("entitlements.generated.toml");
        let tfvars_path = temp_dir.join("terraform.tfvars");
        let script_path = temp_dir.join("validate-entitlements.sh");

        std::fs::write(&catalog_path, MINIMAL_CATALOG).unwrap();
        let generated = Catalog::from_str(MINIMAL_CATALOG)
            .unwrap()
            .generate_runtime()
            .unwrap();
        std::fs::write(&runtime_path, generated.toml).unwrap();
        std::fs::write(&tfvars_path, "enable_direct_access = false\n").unwrap();
        write_executable_script(
            &script_path,
            "#!/usr/bin/env bash\necho deployment failed >&2\nexit 42\n",
        );

        let err = validate_catalog_files_with_script(
            &catalog_path,
            &runtime_path,
            &tfvars_path,
            &script_path,
        )
        .unwrap_err();
        let err = format!("{err:#}");

        assert!(err.contains("deployment validation failed"));
        assert!(err.contains("deployment failed"));

        std::fs::remove_dir_all(temp_dir).unwrap();
    }

    #[test]
    fn validate_catalog_files_rejects_runtime_drift() {
        let temp_dir = temp_test_dir("validate-drift");
        let catalog_path = temp_dir.join("entitlements.catalog.toml");
        let runtime_path = temp_dir.join("entitlements.generated.toml");
        let tfvars_path = temp_dir.join("terraform.tfvars");
        let script_path = temp_dir.join("validate-entitlements.sh");

        std::fs::write(&catalog_path, MINIMAL_CATALOG).unwrap();
        let generated = Catalog::from_str(MINIMAL_CATALOG)
            .unwrap()
            .generate_runtime()
            .unwrap();
        std::fs::write(&runtime_path, format!("{}\n# hand edit\n", generated.toml)).unwrap();
        std::fs::write(&tfvars_path, "enable_direct_access = false\n").unwrap();
        write_executable_script(&script_path, "#!/usr/bin/env bash\nexit 0\n");

        let err = validate_catalog_files_with_script(
            &catalog_path,
            &runtime_path,
            &tfvars_path,
            &script_path,
        )
        .unwrap_err();
        let err = format!("{err:#}");

        assert!(err.contains("runtime file drift"));

        std::fs::remove_dir_all(temp_dir).unwrap();
    }

    fn temp_test_dir(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "canopy-entitlements-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    fn write_executable_script(path: &Path, content: &str) {
        std::fs::write(path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut perms = std::fs::metadata(path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(path, perms).unwrap();
        }
    }

    fn write_catalog_fixture(name: &str, catalog: &Catalog) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "canopy-entitlements-{name}-{}-{}.toml",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let runtime = catalog.generate_runtime().unwrap();
        let mut catalog_text = MINIMAL_CATALOG.to_string();
        if runtime.runtime.rules[0].features.can_start_ec2 {
            catalog_text = catalog_text.replace(
                r#"features = ["ec2:view", "cloudwatch:search"]"#,
                r#"features = ["ec2:view", "cloudwatch:search", "ec2:start"]"#,
            );
        }
        std::fs::write(&path, catalog_text).unwrap();
        path
    }
}
