use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::{self, Write};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;

use crate::catalog::{
    self, Catalog, CatalogAccount, CatalogBinding, CatalogMembership, CatalogPackage, CatalogRole,
    CatalogScope,
};
use entitlements::GroupMapping;
use shared::dto::entitlements::{
    DatabaseScope, McpEc2DiagnosticScope, McpEc2DnsRecordType, McpEc2DnsTargetScope,
    McpEc2HttpQueryPolicy, McpEc2HttpUrlScope, McpEc2JournalUnitScope, McpEc2LogPathScope,
    McpEc2TcpTargetScope,
};

#[cfg(unix)]
unsafe extern "C" {
    fn geteuid() -> u32;
}

const INDEX_HTML: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/ui/index.html"));
const APP_CSS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/ui/app.css"));
const APP_JS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/ui/app.js"));
const BOOTSTRAP_PRELUDE_SHA256: &str = "sha256-an3CoGClAY6wOoPLbFMpUWqHNojbkzVCUcsL2GhYWsQ=";
const CONTENT_SECURITY_POLICY: &str =
    "default-src 'self'; script-src 'self' 'sha256-an3CoGClAY6wOoPLbFMpUWqHNojbkzVCUcsL2GhYWsQ='; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
const BOOTSTRAP_CODE_TTL: Duration = Duration::from_secs(30);
const UI_SESSION_TTL: Duration = Duration::from_secs(8 * 60 * 60);
const SESSION_COOKIE_NAME: &str = "canopy_ui_session";

#[derive(Clone, Debug)]
pub struct UiArgs {
    pub catalog: PathBuf,
    pub runtime: PathBuf,
    pub import_runtime: Option<PathBuf>,
    pub deployment_mode: Option<String>,
    pub tfvars: Option<PathBuf>,
    pub deployment_config: Option<PathBuf>,
    pub auth_config: Option<PathBuf>,
    pub db_config: Option<PathBuf>,
    pub dev_admin_group: String,
    pub identity_source: String,
    pub operator_jwt: Option<PathBuf>,
    pub allow_dev_identity: bool,
    pub dev_operator_sub: Option<String>,
    pub dev_operator_email: Option<String>,
    pub dev_operator_email_verified: bool,
    pub dev_operator_external_groups: Vec<String>,
    pub bind: SocketAddr,
}

#[derive(Debug, Serialize)]
pub struct UiLaunchStatus {
    pub status: &'static str,
    pub command: &'static str,
    pub url: String,
    pub catalog: String,
    pub runtime: String,
    pub mode: &'static str,
}

pub fn run_blocking<W: Write>(args: UiArgs, stdout: &mut W) -> anyhow::Result<()> {
    validate_bind_addr(args.bind)?;
    validate_ui_file_paths(&args)?;
    let bootstrap_code = random_url_token();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create UI runtime")?;
    let listener = runtime
        .block_on(TcpListener::bind(args.bind))
        .with_context(|| format!("failed to bind UI listener at {}", args.bind))?;
    let addr = listener
        .local_addr()
        .context("failed to read UI listener address")?;
    validate_bind_addr(addr)?;
    let status = UiLaunchStatus {
        status: "serving",
        command: "ui",
        url: format!("http://{addr}/#code={bootstrap_code}"),
        catalog: args.catalog.display().to_string(),
        runtime: args.runtime.display().to_string(),
        mode: "local-auth-shell",
    };
    writeln!(
        stdout,
        "serving Entitlement Catalog UI at {} ({})",
        status.url, status.mode
    )?;
    let state = UiAppState::new(args, bootstrap_code, Instant::now() + BOOTSTRAP_CODE_TTL);
    runtime.block_on(async move { serve_listener(listener, state).await })
}

async fn serve_listener(listener: TcpListener, state: UiAppState) -> anyhow::Result<()> {
    axum::serve(listener, router(state))
        .await
        .context("UI server failed")
}

fn router(state: UiAppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/index.html", get(index))
        .route("/app.css", get(app_css))
        .route("/app.js", get(app_js))
        .route("/healthz", get(healthz))
        .route("/api/session/exchange", post(exchange_session))
        .route("/api/state", get(api_state))
        .route("/api/preview", post(post_preview))
        .route("/api/explain", post(post_explain))
        .route("/api/dry-run", post(post_dry_run))
        .route("/api/validate", post(post_validate))
        .route("/api/apply", post(post_apply))
        .route("/api/import-runtime", post(post_import_runtime))
        .route("/api/draft/accounts", put(put_draft_account))
        .route("/api/draft/roles", put(put_draft_role))
        .route("/api/draft/bindings", put(put_draft_binding))
        .route("/api/draft/memberships", put(put_draft_membership))
        .route("/api/draft/group-mappings", put(put_draft_group_mapping))
        .route("/api/draft/scopes/resources", put(put_draft_scope_resource))
        .route("/api/draft/scopes/database", put(put_draft_database_scope))
        .route("/api/draft/scopes/mcp-ec2", put(put_draft_mcp_ec2_scope))
        .route("/api/draft/packages", put(put_draft_package))
        .route(
            "/api/draft/packages/features",
            put(put_draft_package_feature),
        )
        .route(
            "/api/draft/db-connections",
            put(put_draft_database_connection),
        )
        .fallback(not_found)
        .with_state(state)
}

#[derive(Clone, Debug)]
struct UiAppState {
    args: Arc<UiArgs>,
    apply_baseline: Arc<ApplyBaselineSnapshot>,
    bootstrap: Arc<Mutex<BootstrapState>>,
    sessions: Arc<Mutex<HashMap<String, SessionRecord>>>,
    draft: Arc<Mutex<DraftState>>,
    database_connections: Arc<Mutex<DatabaseConnectionsDraftState>>,
}

impl UiAppState {
    fn new(args: UiArgs, code: String, expires_at: Instant) -> Self {
        let apply_baseline = ApplyBaselineSnapshot::capture(&args);
        let draft = DraftState::load(&args.catalog);
        let database_connections = DatabaseConnectionsDraftState::load(args.db_config.as_deref());
        Self {
            apply_baseline: Arc::new(apply_baseline),
            args: Arc::new(args),
            bootstrap: Arc::new(Mutex::new(BootstrapState {
                code: Some(code),
                expires_at,
            })),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            draft: Arc::new(Mutex::new(draft)),
            database_connections: Arc::new(Mutex::new(database_connections)),
        }
    }

    #[cfg(test)]
    fn for_test(args: UiArgs, code: &str, expires_at: Instant) -> Self {
        Self::new(args, code.to_owned(), expires_at)
    }
}

#[derive(Clone, Debug)]
struct SessionRecord {
    expires_at: Instant,
}

#[derive(Debug)]
struct BootstrapState {
    code: Option<String>,
    expires_at: Instant,
}

#[derive(Debug)]
struct DraftState {
    baseline: Option<Catalog>,
    draft: Option<Catalog>,
    load_error: Option<String>,
    dirty: bool,
    revision: u64,
}

#[derive(Debug)]
struct DatabaseConnectionsDraftState {
    source_path: Option<PathBuf>,
    baseline: BTreeMap<String, DbConnectionMetadata>,
    draft: BTreeMap<String, DbConnectionMetadata>,
    load_error: Option<UiValidationIssue>,
    dirty: bool,
    revision: u64,
}

#[derive(Debug)]
struct ApplyBaselineSnapshot {
    catalog: ApplyFileBaseline,
    runtime: ApplyFileBaseline,
    db_config: Option<ApplyFileBaseline>,
}

#[derive(Debug)]
struct ApplyFileBaseline {
    artifact: &'static str,
    path: PathBuf,
    digest: ApplyFileDigest,
}

#[derive(Clone, Debug)]
struct ApplyFileDigest {
    exists: bool,
    sha256: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UiAuthConfigFile {
    admin_group: Option<String>,
}

impl ApplyBaselineSnapshot {
    fn capture(args: &UiArgs) -> Self {
        Self {
            catalog: ApplyFileBaseline::capture("catalog", &args.catalog),
            runtime: ApplyFileBaseline::capture("runtime", &args.runtime),
            db_config: args
                .db_config
                .as_deref()
                .map(|path| ApplyFileBaseline::capture("db_config", path)),
        }
    }

    fn transaction_status(&self, args: &UiArgs) -> UiApplyTransactionStatus {
        let mut baseline = Vec::new();
        let mut baseline_mismatches = Vec::new();
        for file in [&self.catalog, &self.runtime]
            .into_iter()
            .chain(self.db_config.as_ref())
        {
            let (digest, mismatch) = file.current_digest();
            baseline.push(digest);
            if let Some(mismatch) = mismatch {
                baseline_mismatches.push(mismatch);
            }
        }
        let (lock_path, manifest_path) = transaction_artifact_paths(&args.catalog);
        let (lock_exists, lock_error) = transaction_lock_status(&lock_path);
        let (manifest_exists, manifest_error) = transaction_artifact_status(&manifest_path);
        let state = if lock_exists || lock_error.is_some() {
            "lock_blocked"
        } else if manifest_exists || manifest_error.is_some() {
            "manifest_blocked"
        } else if baseline_mismatches.is_empty() {
            "not_started"
        } else {
            "baseline_mismatch"
        };
        UiApplyTransactionStatus {
            state,
            catalog_path: args.catalog.display().to_string(),
            runtime_path: args.runtime.display().to_string(),
            db_config_path: args
                .db_config
                .as_deref()
                .map(|path| path.display().to_string()),
            lock_path: Some(lock_path.display().to_string()),
            manifest_path: Some(manifest_path.display().to_string()),
            lock_exists,
            lock_error,
            manifest_exists,
            manifest_error,
            baseline,
            baseline_mismatches,
        }
    }
}

impl ApplyFileBaseline {
    fn capture(artifact: &'static str, path: &Path) -> Self {
        Self {
            artifact,
            path: path.to_path_buf(),
            digest: ApplyFileDigest::read(path),
        }
    }

    fn current_digest(&self) -> (UiApplyBaselineDigest, Option<UiApplyBaselineMismatch>) {
        let current = ApplyFileDigest::read(&self.path);
        let digest = UiApplyBaselineDigest {
            artifact: self.artifact,
            path: self.path.display().to_string(),
            startup_exists: self.digest.exists,
            current_exists: current.exists,
            startup_sha256: self.digest.sha256.clone(),
            current_sha256: current.sha256.clone(),
            startup_error: self.digest.error.clone(),
            current_error: current.error.clone(),
        };
        let mismatch = self.baseline_mismatch(&current);
        (digest, mismatch)
    }

    fn baseline_mismatch(&self, current: &ApplyFileDigest) -> Option<UiApplyBaselineMismatch> {
        let (reason_code, detail) = if self.digest.exists && self.digest.sha256.is_none() {
            ("baseline_unreadable", "was unreadable when the UI started")
        } else if current.exists && current.sha256.is_none() {
            ("current_unreadable", "is unreadable now")
        } else if self.digest.exists && !current.exists {
            ("baseline_file_deleted", "was deleted after the UI started")
        } else if !self.digest.exists && current.exists {
            ("baseline_file_created", "was created after the UI started")
        } else if self.digest.sha256 != current.sha256 {
            ("baseline_digest_mismatch", "changed after the UI started")
        } else {
            return None;
        };
        Some(UiApplyBaselineMismatch {
            artifact: self.artifact,
            path: self.path.display().to_string(),
            reason_code,
            message: format!(
                "{} file '{}' {detail}; restart or refresh the UI after reviewing the external change.",
                self.artifact,
                self.path.display()
            ),
            startup_sha256: self.digest.sha256.clone(),
            current_sha256: current.sha256.clone(),
        })
    }
}

impl ApplyFileDigest {
    fn read(path: &Path) -> Self {
        match fs::read(path) {
            Ok(bytes) => Self {
                exists: true,
                sha256: Some(hex::encode(Sha256::digest(bytes))),
                error: None,
            },
            Err(err) if err.kind() == io::ErrorKind::NotFound => Self {
                exists: false,
                sha256: None,
                error: None,
            },
            Err(err) => Self {
                exists: true,
                sha256: None,
                error: Some(err.kind().to_string()),
            },
        }
    }
}

#[derive(Debug, Deserialize)]
struct ExchangeRequest {
    code: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftBindingRequest {
    group: String,
    package: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftMembershipRequest {
    group: String,
    user_id: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftGroupMappingRequest {
    group: String,
    external_group: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftAccountRequest {
    id: String,
    account_id: String,
    name: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftRoleRequest {
    id: String,
    role_arn: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftPackageRequest {
    id: String,
    scope: String,
    role: String,
    max_session_seconds: Option<u64>,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftScopeResourceRequest {
    scope: String,
    field: String,
    value: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftDatabaseScopeRequest {
    scope: String,
    name: String,
    connection: String,
    environment: String,
    allowed_schemas: Vec<String>,
    allowed_tables: Vec<String>,
    allowed_actions: Vec<String>,
    max_rows: u64,
    statement_timeout_ms: u64,
    require_explain: bool,
    max_examined_rows: u64,
    allow_full_table_scan: bool,
    allow_views: bool,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftMcpEc2ScopeRequest {
    scope: String,
    id: String,
    allowed_log_paths: Vec<McpEc2LogPathScope>,
    allowed_journal_units: Vec<McpEc2JournalUnitScope>,
    allowed_http_urls: Vec<McpEc2HttpUrlScope>,
    allowed_tcp_targets: Vec<McpEc2TcpTargetScope>,
    allowed_dns_targets: Vec<McpEc2DnsTargetScope>,
    private_target_refs: Vec<String>,
    max_lines: u16,
    max_since_seconds: u64,
    max_timeout_seconds: u8,
    max_matches: u16,
    connectivity_probe_budget_per_window: u32,
    budget_window_seconds: u64,
    denylist_version: String,
    allowlist_rule_id: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftPackageFeatureRequest {
    package: String,
    feature: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftDatabaseConnectionRequest {
    name: String,
    engine: String,
    host: String,
    port: i64,
    database: String,
    secret_arn: Option<String>,
    readonly: bool,
    connect_timeout_ms: i64,
    statement_timeout_ms: i64,
    explain_timeout_ms: i64,
    max_connections: i64,
    require_tls: bool,
    accept_invalid_tls_certs: bool,
    skip_tls_hostname_verification: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewRequest {
    group: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplainRequestBody {
    sub: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
    external_groups: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DryRunRequestBody {
    operation: String,
    sub: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
    external_groups: Option<Vec<String>>,
    account: Option<String>,
    region: Option<String>,
    cluster: Option<String>,
    log_group_arn: Option<String>,
    os_user: Option<String>,
    #[serde(default)]
    instance_tags: Vec<String>,
    #[serde(default)]
    task_tags: Vec<String>,
    container: Option<String>,
    scope: Option<String>,
    connection: Option<String>,
    environment: Option<String>,
    schema: Option<String>,
    table: Option<String>,
    action: Option<String>,
}

#[derive(Debug, Serialize)]
struct ExchangeResponse {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct UiStateResponse {
    status: &'static str,
    mode: &'static str,
    catalog: UiFileStatus,
    runtime: UiFileStatus,
    import_runtime: Option<UiFileStatus>,
    deployment: UiDeploymentState,
    database_config: Option<UiFileStatus>,
    database_connections: UiDatabaseConnectionsState,
    identity: UiIdentityState,
    capabilities: UiCapabilities,
    draft: UiDraftResponse,
    changes: UiPendingChanges,
}

#[derive(Debug, Serialize)]
struct UiFileStatus {
    path: String,
    exists: bool,
    readable: bool,
    sha256: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct UiDeploymentState {
    mode: Option<String>,
    tfvars: Option<UiFileStatus>,
    deployment_config: Option<UiFileStatus>,
}

#[derive(Debug, Serialize)]
struct UiIdentityState {
    source: String,
    dev_identity_allowed: bool,
    dev_admin_group: String,
    operator_sub_configured: bool,
    operator_email_configured: bool,
    operator_external_group_count: usize,
    operator_jwt_configured: bool,
    auth_config_configured: bool,
}

#[derive(Debug, Serialize)]
struct UiCapabilities {
    state: bool,
    preview: bool,
    explain: bool,
    dry_run: bool,
    import_runtime: bool,
    draft_write: bool,
    validate: bool,
    apply: bool,
}

#[derive(Debug, Serialize)]
struct UiValidateOutput {
    status: &'static str,
    command: &'static str,
    valid: bool,
    revision: u64,
    generated: Option<UiValidateGeneratedRuntime>,
    deployment: UiValidateDeployment,
    database_connections: UiValidateDatabaseConnections,
    blocking_errors: Vec<UiValidationIssue>,
    warnings: Vec<UiValidationIssue>,
}

#[derive(Debug, Serialize)]
struct UiValidateGeneratedRuntime {
    runtime_path: String,
    temp_runtime_path: String,
    temp_runtime_sha256: String,
    temp_runtime_removed: bool,
    generated_rules: usize,
    group_mappings: usize,
    memberships: usize,
    runtime_exists: bool,
    runtime_drift: bool,
}

#[derive(Debug, Serialize)]
struct UiValidateDeployment {
    mode: Option<String>,
    canonical_path: Option<String>,
    canonical_sha256: Option<String>,
    checked: bool,
}

#[derive(Debug, Serialize)]
struct UiValidateDatabaseConnections {
    required: Vec<String>,
    local_config: Vec<String>,
    deployment_source: Vec<String>,
}

#[derive(Debug, Serialize)]
struct UiApplyOutput {
    status: &'static str,
    command: &'static str,
    applied: bool,
    revision: u64,
    gate: UiApplyGate,
    transaction: UiApplyTransactionStatus,
    validation: UiValidateOutput,
}

#[derive(Debug, Serialize)]
struct UiApplyGate {
    state: &'static str,
    reason_code: &'static str,
    message: String,
    identity_source: String,
    admin_group: String,
    dev_identity_allowed: bool,
    can_apply: bool,
}

#[derive(Debug, Serialize)]
struct UiApplyTransactionStatus {
    state: &'static str,
    catalog_path: String,
    runtime_path: String,
    db_config_path: Option<String>,
    lock_path: Option<String>,
    manifest_path: Option<String>,
    lock_exists: bool,
    lock_error: Option<String>,
    manifest_exists: bool,
    manifest_error: Option<String>,
    baseline: Vec<UiApplyBaselineDigest>,
    baseline_mismatches: Vec<UiApplyBaselineMismatch>,
}

#[derive(Debug, Serialize)]
struct UiApplyBaselineDigest {
    artifact: &'static str,
    path: String,
    startup_exists: bool,
    current_exists: bool,
    startup_sha256: Option<String>,
    current_sha256: Option<String>,
    startup_error: Option<String>,
    current_error: Option<String>,
}

#[derive(Debug, Serialize)]
struct UiApplyBaselineMismatch {
    artifact: &'static str,
    path: String,
    reason_code: &'static str,
    message: String,
    startup_sha256: Option<String>,
    current_sha256: Option<String>,
}

#[derive(Debug, Serialize)]
struct UiDatabaseConnectionsState {
    configured: bool,
    dirty: bool,
    revision: u64,
    source_path: Option<String>,
    required: Vec<String>,
    missing_required: Vec<String>,
    local: Vec<UiDatabaseConnectionSummary>,
    issues: Vec<UiValidationIssue>,
}

#[derive(Debug, Serialize)]
struct UiDatabaseConnectionSummary {
    name: String,
    engine: String,
    host: String,
    port: i64,
    database: String,
    readonly: bool,
    require_tls: bool,
    accept_invalid_tls_certs: bool,
    skip_tls_hostname_verification: bool,
    connect_timeout_ms: i64,
    statement_timeout_ms: i64,
    explain_timeout_ms: i64,
    max_connections: i64,
    secret_ref_configured: bool,
    required_by_scope_count: usize,
    safety: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct UiValidationIssue {
    code: String,
    message: String,
    path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DbConnectionMetadata {
    engine: String,
    host: String,
    port: i64,
    database: String,
    secret_arn: String,
    readonly: bool,
    connect_timeout_ms: i64,
    statement_timeout_ms: i64,
    explain_timeout_ms: i64,
    max_connections: i64,
    require_tls: bool,
    accept_invalid_tls_certs: bool,
    skip_tls_hostname_verification: bool,
}

#[derive(Debug, Serialize)]
struct UiDraftResponse {
    loaded: bool,
    status: &'static str,
    revision: u64,
    dirty: bool,
    groups: Vec<UiGroupSummary>,
    accounts: Vec<UiAccountSummary>,
    roles: Vec<UiRoleSummary>,
    packages: Vec<UiPackageSummary>,
    available_features: Vec<UiFeatureSummary>,
    scopes: Vec<UiScopeSummary>,
    bindings: Vec<UiBindingSummary>,
    selected_group: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct UiGroupSummary {
    id: String,
    member_count: usize,
    external_mapping_count: usize,
    package_count: usize,
    high_risk_package_count: usize,
    members: Vec<String>,
    external_mappings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct UiAccountSummary {
    id: String,
    account_id: String,
    name: String,
    scopes: Vec<String>,
    packages: Vec<String>,
    roles: Vec<String>,
}

#[derive(Debug, Serialize)]
struct UiRoleSummary {
    id: String,
    role_arn: String,
    mode: &'static str,
    accounts: Vec<String>,
    packages: Vec<String>,
}

#[derive(Debug, Serialize)]
struct UiPackageSummary {
    id: String,
    features: Vec<String>,
    high_risk_features: Vec<String>,
    scope: String,
    role: String,
    database_scope_count: usize,
    database_scopes: Vec<UiDatabaseScopeSummary>,
    mcp_ec2_diagnostic_scope_count: usize,
    max_session_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
struct UiFeatureSummary {
    id: &'static str,
    high_risk: bool,
}

#[derive(Debug, Serialize)]
struct UiScopeSummary {
    id: String,
    description: Option<String>,
    business_scopes: Vec<String>,
    accounts: Vec<String>,
    regions: Vec<String>,
    log_group_arns: Vec<String>,
    clusters: Vec<String>,
    os_users: Vec<String>,
    instance_tag_selectors: Vec<String>,
    excluded_tag_selectors: Vec<String>,
    task_tag_selectors: Vec<String>,
    excluded_task_tag_selectors: Vec<String>,
    excluded_container_names: Vec<String>,
    allow_broad_cluster_discovery: bool,
    database_scopes: Vec<UiDatabaseScopeSummary>,
    mcp_ec2_diagnostic_scopes: Vec<UiMcpEc2ScopeSummary>,
    packages: Vec<String>,
}

#[derive(Debug, Serialize)]
struct UiDatabaseScopeSummary {
    name: String,
    connection: String,
    environment: String,
    allowed_schemas: Vec<String>,
    allowed_tables: Vec<String>,
    allowed_actions: Vec<String>,
    max_rows: u64,
    statement_timeout_ms: u64,
    require_explain: bool,
    max_examined_rows: u64,
    allow_full_table_scan: bool,
    allow_views: bool,
}

#[derive(Debug, Serialize)]
struct UiMcpEc2ScopeSummary {
    id: String,
    log_paths: Vec<String>,
    journal_units: Vec<String>,
    http_urls: Vec<String>,
    tcp_targets: Vec<String>,
    dns_targets: Vec<String>,
    allowed_log_paths: Vec<UiMcpEc2LogPathSummary>,
    allowed_journal_units: Vec<UiMcpEc2JournalUnitSummary>,
    allowed_http_urls: Vec<UiMcpEc2HttpUrlSummary>,
    allowed_tcp_targets: Vec<UiMcpEc2TcpTargetSummary>,
    allowed_dns_targets: Vec<UiMcpEc2DnsTargetSummary>,
    private_target_refs: Vec<String>,
    max_lines: u16,
    max_since_seconds: u64,
    max_timeout_seconds: u8,
    max_matches: u16,
    connectivity_probe_budget_per_window: u32,
    budget_window_seconds: u64,
    denylist_version: String,
    allowlist_rule_id: String,
    unsafe_output_count: usize,
}

#[derive(Debug, Serialize)]
struct UiMcpEc2LogPathSummary {
    path_pattern: String,
    canonical_safe_prefix: String,
    safe_for_mcp_output: bool,
}

#[derive(Debug, Serialize)]
struct UiMcpEc2JournalUnitSummary {
    unit: String,
    safe_for_mcp_output: bool,
}

#[derive(Debug, Serialize)]
struct UiMcpEc2HttpUrlSummary {
    normalized_url: String,
    query_policy: McpEc2HttpQueryPolicy,
    safe_for_mcp_output: bool,
    private_target_ref: Option<String>,
}

#[derive(Debug, Serialize)]
struct UiMcpEc2TcpTargetSummary {
    host: String,
    port: u16,
    private_target_ref: Option<String>,
}

#[derive(Debug, Serialize)]
struct UiMcpEc2DnsTargetSummary {
    host: String,
    record_types: Vec<McpEc2DnsRecordType>,
    safe_for_mcp_output: bool,
    private_target_ref: Option<String>,
}

#[derive(Debug, Serialize)]
struct UiBindingSummary {
    group: String,
    package: String,
}

#[derive(Debug, Serialize)]
struct UiPendingChanges {
    added_bindings: Vec<UiBindingChange>,
    removed_bindings: Vec<UiBindingChange>,
    added_memberships: Vec<UiMembershipChange>,
    removed_memberships: Vec<UiMembershipChange>,
    added_group_mappings: Vec<UiGroupMappingChange>,
    removed_group_mappings: Vec<UiGroupMappingChange>,
    added_scope_resources: Vec<UiScopeResourceChange>,
    removed_scope_resources: Vec<UiScopeResourceChange>,
    added_accounts: Vec<UiAccountChange>,
    removed_accounts: Vec<UiAccountChange>,
    updated_accounts: Vec<UiAccountChange>,
    added_roles: Vec<UiRoleChange>,
    removed_roles: Vec<UiRoleChange>,
    updated_roles: Vec<UiRoleChange>,
    added_packages: Vec<UiPackageChange>,
    removed_packages: Vec<UiPackageChange>,
    updated_packages: Vec<UiPackageChange>,
    high_risk_added: usize,
    high_risk_removed: usize,
    semantic_diff: UiSemanticDiff,
}

#[derive(Debug, Serialize)]
struct UiAccountChange {
    id: String,
    account_id: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct UiRoleChange {
    id: String,
    role_arn: String,
}

#[derive(Debug, Serialize)]
struct UiPackageChange {
    id: String,
    scope: String,
    role: String,
    features: Vec<String>,
    max_session_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
struct UiScopeResourceChange {
    scope: String,
    field: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct UiMembershipChange {
    group: String,
    user_id: String,
}

#[derive(Debug, Serialize)]
struct UiGroupMappingChange {
    group: String,
    external_group: String,
}

#[derive(Debug, Serialize)]
struct UiSemanticDiff {
    added: Vec<catalog::SemanticGrant>,
    removed: Vec<catalog::SemanticGrant>,
    high_risk: Vec<catalog::SemanticGrant>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct UiBindingChange {
    group: String,
    package: String,
    high_risk: bool,
    features: Vec<String>,
}

#[derive(Debug, Serialize)]
struct UiErrorResponse {
    error: UiErrorBody,
}

#[derive(Debug, Serialize)]
struct UiErrorBody {
    code: &'static str,
    message: String,
}

#[derive(Debug)]
struct UiRequestError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl UiRequestError {
    fn into_response(self) -> Response<Body> {
        error_response(self.status, self.code, self.message)
    }
}

#[derive(Debug)]
struct UiMutationError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl UiMutationError {
    fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
            message: message.into(),
        }
    }

    fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
            message: message.into(),
        }
    }
}

async fn index() -> Response<Body> {
    static_response("text/html; charset=utf-8", INDEX_HTML)
}

async fn app_css() -> Response<Body> {
    static_response("text/css; charset=utf-8", APP_CSS)
}

async fn app_js() -> Response<Body> {
    static_response("application/javascript; charset=utf-8", APP_JS)
}

async fn healthz() -> Response<Body> {
    static_response("text/plain; charset=utf-8", "ok\n")
}

async fn exchange_session(
    State(state): State<UiAppState>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    if uri.query().is_some() {
        state.invalidate_bootstrap();
        return error_response(
            StatusCode::BAD_REQUEST,
            "query_token_rejected",
            "bootstrap code must be sent in the JSON body, not the query string",
        );
    }
    if let Err(err) = validate_local_host(&headers) {
        state.invalidate_bootstrap();
        return err.into_response();
    }
    if let Err(err) = validate_local_origin(&headers) {
        state.invalidate_bootstrap();
        return err.into_response();
    }
    let request = match serde_json::from_slice::<ExchangeRequest>(&body) {
        Ok(request) => request,
        Err(_) => {
            state.invalidate_bootstrap();
            return error_response(
                StatusCode::BAD_REQUEST,
                "malformed_exchange_request",
                "exchange request must be valid JSON",
            );
        }
    };
    if request.code.is_empty() {
        state.invalidate_bootstrap();
        return error_response(
            StatusCode::BAD_REQUEST,
            "missing_bootstrap_code",
            "bootstrap code is required",
        );
    }
    if !state.claim_bootstrap_code(&request.code) {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_bootstrap_code",
            "bootstrap code is invalid, expired, or already used",
        );
    }

    let session = random_url_token();
    state.store_session(session.clone());
    let mut response = json_response(
        StatusCode::OK,
        &ExchangeResponse {
            status: "exchanged",
        },
    );
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&session_cookie_header(&session))
            .expect("generated session cookie value should be valid"),
    );
    response
}

async fn api_state(State(state): State<UiAppState>, headers: HeaderMap) -> Response<Body> {
    if let Err(err) = validate_local_host(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_session_headers(&state, &headers) {
        return err.into_response();
    }
    json_response(StatusCode::OK, &state.sanitized_state())
}

async fn put_draft_binding(
    State(state): State<UiAppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    if let Err(err) = validate_local_host(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_local_origin(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_session_headers(&state, &headers) {
        return err.into_response();
    }

    let request = match serde_json::from_slice::<DraftBindingRequest>(&body) {
        Ok(request) => request,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "malformed_draft_binding_request",
                "draft binding request must be valid JSON",
            );
        }
    };

    match state.update_binding(request) {
        Ok(()) => json_response(StatusCode::OK, &state.sanitized_state()),
        Err(err) => error_response(err.status, err.code, err.message),
    }
}

async fn put_draft_membership(
    State(state): State<UiAppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    if let Err(err) = validate_local_host(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_local_origin(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_session_headers(&state, &headers) {
        return err.into_response();
    }

    let request = match serde_json::from_slice::<DraftMembershipRequest>(&body) {
        Ok(request) => request,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "malformed_draft_membership_request",
                "draft membership request must be valid JSON",
            );
        }
    };

    match state.update_membership(request) {
        Ok(()) => json_response(StatusCode::OK, &state.sanitized_state()),
        Err(err) => error_response(err.status, err.code, err.message),
    }
}

async fn put_draft_group_mapping(
    State(state): State<UiAppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    if let Err(err) = validate_local_host(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_local_origin(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_session_headers(&state, &headers) {
        return err.into_response();
    }

    let request = match serde_json::from_slice::<DraftGroupMappingRequest>(&body) {
        Ok(request) => request,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "malformed_draft_group_mapping_request",
                "draft group mapping request must be valid JSON",
            );
        }
    };

    match state.update_group_mapping(request) {
        Ok(()) => json_response(StatusCode::OK, &state.sanitized_state()),
        Err(err) => error_response(err.status, err.code, err.message),
    }
}

async fn put_draft_scope_resource(
    State(state): State<UiAppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    if let Err(err) = validate_local_host(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_local_origin(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_session_headers(&state, &headers) {
        return err.into_response();
    }

    let request = match serde_json::from_slice::<DraftScopeResourceRequest>(&body) {
        Ok(request) => request,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "malformed_draft_scope_resource_request",
                "draft scope resource request must be valid JSON",
            );
        }
    };

    match state.update_scope_resource(request) {
        Ok(()) => json_response(StatusCode::OK, &state.sanitized_state()),
        Err(err) => error_response(err.status, err.code, err.message),
    }
}

async fn put_draft_database_scope(
    State(state): State<UiAppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    if let Err(err) = validate_local_host(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_local_origin(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_session_headers(&state, &headers) {
        return err.into_response();
    }

    let request = match serde_json::from_slice::<DraftDatabaseScopeRequest>(&body) {
        Ok(request) => request,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "malformed_draft_database_scope_request",
                "draft database scope request must be valid JSON",
            );
        }
    };

    match state.update_database_scope(request) {
        Ok(()) => json_response(StatusCode::OK, &state.sanitized_state()),
        Err(err) => error_response(err.status, err.code, err.message),
    }
}

async fn put_draft_mcp_ec2_scope(
    State(state): State<UiAppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    if let Err(err) = validate_local_host(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_local_origin(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_session_headers(&state, &headers) {
        return err.into_response();
    }

    let request = match serde_json::from_slice::<DraftMcpEc2ScopeRequest>(&body) {
        Ok(request) => request,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "malformed_draft_mcp_ec2_scope_request",
                "draft MCP EC2 scope request must be valid JSON",
            );
        }
    };

    match state.update_mcp_ec2_scope(request) {
        Ok(()) => json_response(StatusCode::OK, &state.sanitized_state()),
        Err(err) => error_response(err.status, err.code, err.message),
    }
}

async fn put_draft_package_feature(
    State(state): State<UiAppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    if let Err(err) = validate_local_host(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_local_origin(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_session_headers(&state, &headers) {
        return err.into_response();
    }

    let request = match serde_json::from_slice::<DraftPackageFeatureRequest>(&body) {
        Ok(request) => request,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "malformed_draft_package_feature_request",
                "draft package feature request must be valid JSON",
            );
        }
    };

    match state.update_package_feature(request) {
        Ok(()) => json_response(StatusCode::OK, &state.sanitized_state()),
        Err(err) => error_response(err.status, err.code, err.message),
    }
}

async fn put_draft_database_connection(
    State(state): State<UiAppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    if let Err(err) = validate_local_host(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_local_origin(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_session_headers(&state, &headers) {
        return err.into_response();
    }

    let request = match serde_json::from_slice::<DraftDatabaseConnectionRequest>(&body) {
        Ok(request) => request,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "malformed_draft_database_connection_request",
                "draft database connection request must be valid JSON",
            );
        }
    };

    match state.update_database_connection(request) {
        Ok(()) => json_response(StatusCode::OK, &state.sanitized_state()),
        Err(err) => error_response(err.status, err.code, err.message),
    }
}

async fn post_preview(
    State(state): State<UiAppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    if let Err(err) = validate_local_host(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_local_origin(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_session_headers(&state, &headers) {
        return err.into_response();
    }

    let request = match serde_json::from_slice::<PreviewRequest>(&body) {
        Ok(request) => request,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "malformed_preview_request",
                "preview request must be valid JSON",
            );
        }
    };

    match state.preview_group(request) {
        Ok(preview) => json_response(StatusCode::OK, &preview),
        Err(err) => error_response(err.status, err.code, err.message),
    }
}

async fn post_explain(
    State(state): State<UiAppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    if let Err(err) = validate_local_host(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_local_origin(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_session_headers(&state, &headers) {
        return err.into_response();
    }

    let request = match serde_json::from_slice::<ExplainRequestBody>(&body) {
        Ok(request) => request,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "malformed_explain_request",
                "explain request must be valid JSON",
            );
        }
    };

    match state.explain(request) {
        Ok(explain) => json_response(StatusCode::OK, &explain),
        Err(err) => error_response(err.status, err.code, err.message),
    }
}

async fn post_dry_run(
    State(state): State<UiAppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    if let Err(err) = validate_local_host(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_local_origin(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_session_headers(&state, &headers) {
        return err.into_response();
    }

    let request = match serde_json::from_slice::<DryRunRequestBody>(&body) {
        Ok(request) => request,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "malformed_dry_run_request",
                "dry-run request must be valid JSON",
            );
        }
    };

    match state.dry_run(request) {
        Ok(output) => json_response(StatusCode::OK, &output),
        Err(err) => error_response(err.status, err.code, err.message),
    }
}

async fn post_validate(State(state): State<UiAppState>, headers: HeaderMap) -> Response<Body> {
    if let Err(err) = validate_local_host(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_local_origin(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_session_headers(&state, &headers) {
        return err.into_response();
    }

    match state.validate_draft() {
        Ok(output) => json_response(StatusCode::OK, &output),
        Err(err) => error_response(err.status, err.code, err.message),
    }
}

async fn post_apply(State(state): State<UiAppState>, headers: HeaderMap) -> Response<Body> {
    if let Err(err) = validate_local_host(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_local_origin(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_session_headers(&state, &headers) {
        return err.into_response();
    }

    match state.apply_draft() {
        Ok((status, output)) => json_response(status, &output),
        Err(err) => error_response(err.status, err.code, err.message),
    }
}

async fn post_import_runtime(
    State(state): State<UiAppState>,
    headers: HeaderMap,
) -> Response<Body> {
    if let Err(err) = validate_local_host(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_local_origin(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_session_headers(&state, &headers) {
        return err.into_response();
    }

    match state.import_runtime_draft() {
        Ok(()) => json_response(StatusCode::OK, &state.sanitized_state()),
        Err(err) => error_response(err.status, err.code, err.message),
    }
}

async fn put_draft_account(
    State(state): State<UiAppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    if let Err(err) = validate_local_host(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_local_origin(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_session_headers(&state, &headers) {
        return err.into_response();
    }

    let request = match serde_json::from_slice::<DraftAccountRequest>(&body) {
        Ok(request) => request,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "malformed_draft_account_request",
                "draft account request must be valid JSON",
            );
        }
    };

    match state.update_account(request) {
        Ok(()) => json_response(StatusCode::OK, &state.sanitized_state()),
        Err(err) => error_response(err.status, err.code, err.message),
    }
}

async fn put_draft_role(
    State(state): State<UiAppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    if let Err(err) = validate_local_host(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_local_origin(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_session_headers(&state, &headers) {
        return err.into_response();
    }

    let request = match serde_json::from_slice::<DraftRoleRequest>(&body) {
        Ok(request) => request,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "malformed_draft_role_request",
                "draft role request must be valid JSON",
            );
        }
    };

    match state.update_role(request) {
        Ok(()) => json_response(StatusCode::OK, &state.sanitized_state()),
        Err(err) => error_response(err.status, err.code, err.message),
    }
}

async fn put_draft_package(
    State(state): State<UiAppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    if let Err(err) = validate_local_host(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_local_origin(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_session_headers(&state, &headers) {
        return err.into_response();
    }

    let request = match serde_json::from_slice::<DraftPackageRequest>(&body) {
        Ok(request) => request,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "malformed_draft_package_request",
                "draft package request must be valid JSON",
            );
        }
    };

    match state.update_package(request) {
        Ok(()) => json_response(StatusCode::OK, &state.sanitized_state()),
        Err(err) => error_response(err.status, err.code, err.message),
    }
}

async fn not_found() -> impl IntoResponse {
    let mut response = static_response("text/plain; charset=utf-8", "not found\n");
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
}

fn static_response(content_type: &'static str, body: &'static str) -> Response<Body> {
    let mut response = Response::new(Body::from(body));
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    apply_security_headers(&mut response);
    response
}

fn apply_security_headers(response: &mut Response<Body>) {
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response<Body> {
    let mut response = (status, Json(body)).into_response();
    apply_security_headers(&mut response);
    response
}

fn error_response(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> Response<Body> {
    json_response(
        status,
        &UiErrorResponse {
            error: UiErrorBody {
                code,
                message: message.into(),
            },
        },
    )
}

impl UiAppState {
    fn claim_bootstrap_code(&self, candidate: &str) -> bool {
        let mut bootstrap = self
            .bootstrap
            .lock()
            .expect("bootstrap mutex should not be poisoned");
        let Some(code) = bootstrap.code.take() else {
            return false;
        };
        if Instant::now() > bootstrap.expires_at {
            return false;
        }
        code.as_bytes().ct_eq(candidate.as_bytes()).into()
    }

    fn invalidate_bootstrap(&self) {
        self.bootstrap
            .lock()
            .expect("bootstrap mutex should not be poisoned")
            .code = None;
    }

    fn store_session(&self, token: String) {
        self.sessions
            .lock()
            .expect("session mutex should not be poisoned")
            .insert(
                token,
                SessionRecord {
                    expires_at: Instant::now() + UI_SESSION_TTL,
                },
            );
    }

    fn validate_session(&self, token: &str) -> bool {
        let mut sessions = self
            .sessions
            .lock()
            .expect("session mutex should not be poisoned");
        let now = Instant::now();
        sessions.retain(|_, session| session.expires_at > now);
        sessions.contains_key(token)
    }

    fn update_binding(&self, request: DraftBindingRequest) -> Result<(), UiMutationError> {
        let mut draft = self
            .draft
            .lock()
            .expect("draft mutex should not be poisoned");
        draft.update_binding(request)
    }

    fn update_membership(&self, request: DraftMembershipRequest) -> Result<(), UiMutationError> {
        let mut draft = self
            .draft
            .lock()
            .expect("draft mutex should not be poisoned");
        draft.update_membership(request)
    }

    fn update_group_mapping(
        &self,
        request: DraftGroupMappingRequest,
    ) -> Result<(), UiMutationError> {
        let mut draft = self
            .draft
            .lock()
            .expect("draft mutex should not be poisoned");
        draft.update_group_mapping(request)
    }

    fn update_account(&self, request: DraftAccountRequest) -> Result<(), UiMutationError> {
        let mut draft = self
            .draft
            .lock()
            .expect("draft mutex should not be poisoned");
        draft.update_account(request)
    }

    fn update_role(&self, request: DraftRoleRequest) -> Result<(), UiMutationError> {
        let mut draft = self
            .draft
            .lock()
            .expect("draft mutex should not be poisoned");
        draft.update_role(request)
    }

    fn update_scope_resource(
        &self,
        request: DraftScopeResourceRequest,
    ) -> Result<(), UiMutationError> {
        let mut draft = self
            .draft
            .lock()
            .expect("draft mutex should not be poisoned");
        draft.update_scope_resource(request)
    }

    fn update_database_scope(
        &self,
        request: DraftDatabaseScopeRequest,
    ) -> Result<(), UiMutationError> {
        let mut draft = self
            .draft
            .lock()
            .expect("draft mutex should not be poisoned");
        draft.update_database_scope(request)
    }

    fn update_mcp_ec2_scope(
        &self,
        request: DraftMcpEc2ScopeRequest,
    ) -> Result<(), UiMutationError> {
        let mut draft = self
            .draft
            .lock()
            .expect("draft mutex should not be poisoned");
        draft.update_mcp_ec2_scope(request)
    }

    fn update_package_feature(
        &self,
        request: DraftPackageFeatureRequest,
    ) -> Result<(), UiMutationError> {
        let mut draft = self
            .draft
            .lock()
            .expect("draft mutex should not be poisoned");
        draft.update_package_feature(request)
    }

    fn update_package(&self, request: DraftPackageRequest) -> Result<(), UiMutationError> {
        let mut draft = self
            .draft
            .lock()
            .expect("draft mutex should not be poisoned");
        draft.update_package(request)
    }

    fn update_database_connection(
        &self,
        request: DraftDatabaseConnectionRequest,
    ) -> Result<(), UiMutationError> {
        self.database_connections
            .lock()
            .expect("database connection draft mutex should not be poisoned")
            .update_connection(request)
    }

    fn preview_group(
        &self,
        request: PreviewRequest,
    ) -> Result<catalog::PreviewOutput, UiMutationError> {
        let draft = self
            .draft
            .lock()
            .expect("draft mutex should not be poisoned");
        draft.preview_group(request)
    }

    fn explain(
        &self,
        request: ExplainRequestBody,
    ) -> Result<catalog::ExplainOutput, UiMutationError> {
        let catalog_request = explain_request_from_body(self.args.as_ref(), request)?;
        let draft = self
            .draft
            .lock()
            .expect("draft mutex should not be poisoned");
        draft.explain(catalog_request)
    }

    fn dry_run(
        &self,
        request: DryRunRequestBody,
    ) -> Result<catalog::DryRunOutput, UiMutationError> {
        let catalog_request = dry_run_request_from_body(self.args.as_ref(), request)?;
        let draft = self
            .draft
            .lock()
            .expect("draft mutex should not be poisoned");
        draft.dry_run(catalog_request)
    }

    fn validate_draft(&self) -> Result<UiValidateOutput, UiMutationError> {
        let (draft, revision) = {
            let draft = self
                .draft
                .lock()
                .expect("draft mutex should not be poisoned");
            draft.clone_draft()?
        };
        let database_connections = self
            .database_connections
            .lock()
            .expect("database connection draft mutex should not be poisoned")
            .snapshot();
        Ok(validate_draft_catalog(
            self.args.as_ref(),
            &draft,
            revision,
            &database_connections,
        ))
    }

    fn apply_draft(&self) -> Result<(StatusCode, UiApplyOutput), UiMutationError> {
        let validation = self.validate_draft()?;
        let baseline = self
            .draft
            .lock()
            .expect("draft mutex should not be poisoned")
            .clone_baseline();
        let transaction = self.apply_baseline.transaction_status(self.args.as_ref());
        let (status, apply_status, gate) = apply_gate_status(
            self.args.as_ref(),
            &validation,
            baseline.as_ref(),
            &transaction,
        );
        let output = UiApplyOutput {
            status: apply_status,
            command: "apply",
            applied: false,
            revision: validation.revision,
            transaction,
            gate,
            validation,
        };
        Ok((status, output))
    }

    fn import_runtime_draft(&self) -> Result<(), UiMutationError> {
        validate_ui_file_paths(self.args.as_ref()).map_err(|err| {
            UiMutationError::conflict("import_runtime_path_collision", format!("{err:#}"))
        })?;
        let Some(import_runtime) = self.args.import_runtime.as_deref() else {
            return Err(UiMutationError::conflict(
                "import_runtime_unconfigured",
                "start the UI with --import-runtime before calling /api/import-runtime",
            ));
        };
        let imported = catalog::import_runtime_file(import_runtime).map_err(|err| {
            UiMutationError::conflict(
                "import_runtime_failed",
                format!(
                    "failed to import runtime entitlement file '{}': {err:#}",
                    import_runtime.display()
                ),
            )
        })?;
        self.draft
            .lock()
            .expect("draft mutex should not be poisoned")
            .replace_with_imported_catalog(imported);
        Ok(())
    }

    fn sanitized_state(&self) -> UiStateResponse {
        let args = self.args.as_ref();
        let (draft, changes, draft_catalog) = {
            let draft = self
                .draft
                .lock()
                .expect("draft mutex should not be poisoned");
            let draft_catalog = draft.draft.clone();
            let (draft, changes) = draft.summarize();
            (draft, changes, draft_catalog)
        };
        let database_connections = self
            .database_connections
            .lock()
            .expect("database connection draft mutex should not be poisoned")
            .snapshot();
        let draft_write = draft.loaded;
        UiStateResponse {
            status: "ok",
            mode: "local-auth-shell",
            catalog: file_status(&args.catalog),
            runtime: file_status(&args.runtime),
            import_runtime: args.import_runtime.as_deref().map(file_status),
            deployment: UiDeploymentState {
                mode: args.deployment_mode.clone(),
                tfvars: args.tfvars.as_deref().map(file_status),
                deployment_config: args.deployment_config.as_deref().map(file_status),
            },
            database_config: args.db_config.as_deref().map(file_status),
            database_connections: database_connections_state(
                &database_connections,
                draft_catalog.as_ref(),
            ),
            identity: UiIdentityState {
                source: args.identity_source.clone(),
                dev_identity_allowed: args.allow_dev_identity,
                dev_admin_group: args.dev_admin_group.clone(),
                operator_sub_configured: args.dev_operator_sub.is_some(),
                operator_email_configured: args.dev_operator_email.is_some(),
                operator_external_group_count: args.dev_operator_external_groups.len(),
                operator_jwt_configured: args.operator_jwt.is_some(),
                auth_config_configured: args.auth_config.is_some(),
            },
            capabilities: UiCapabilities {
                state: true,
                preview: draft_write,
                explain: draft_write,
                dry_run: draft_write,
                import_runtime: args.import_runtime.is_some(),
                draft_write,
                validate: draft_write,
                apply: false,
            },
            draft,
            changes,
        }
    }
}

impl DraftState {
    fn load(path: &Path) -> Self {
        match Catalog::load(path) {
            Ok(catalog) => Self {
                baseline: Some(catalog.clone()),
                draft: Some(catalog),
                load_error: None,
                dirty: false,
                revision: 0,
            },
            Err(_) => Self {
                baseline: None,
                draft: None,
                load_error: Some(format!(
                    "failed to load catalog draft from '{}'; run canopy-entitlements validate for details",
                    path.display(),
                )),
                dirty: false,
                revision: 0,
            },
        }
    }

    fn update_binding(&mut self, request: DraftBindingRequest) -> Result<(), UiMutationError> {
        let group = request.group.trim();
        let package = request.package.trim();
        if group.is_empty() || package.is_empty() {
            return Err(UiMutationError::bad_request(
                "empty_draft_binding_id",
                "group and package are required",
            ));
        }

        let Some(draft) = self.draft.as_mut() else {
            return Err(UiMutationError::conflict(
                "draft_unavailable",
                self.load_error
                    .clone()
                    .unwrap_or_else(|| "catalog draft is unavailable".to_owned()),
            ));
        };

        if !known_groups(draft).contains(group) {
            return Err(UiMutationError::bad_request(
                "unknown_group",
                format!("group '{group}' does not exist in the draft"),
            ));
        }
        if !draft
            .packages
            .iter()
            .any(|candidate| candidate.id == package)
        {
            return Err(UiMutationError::bad_request(
                "unknown_package",
                format!("package '{package}' does not exist in the draft"),
            ));
        }

        let existing = draft
            .bindings
            .iter()
            .position(|binding| binding.group == group && binding.package == package);
        let changed = match (request.enabled, existing) {
            (true, None) => {
                draft.bindings.push(CatalogBinding {
                    group: group.to_owned(),
                    package: package.to_owned(),
                });
                true
            }
            (false, Some(index)) => {
                draft.bindings.remove(index);
                true
            }
            _ => false,
        };

        if changed {
            self.mark_changed();
        }
        Ok(())
    }

    fn update_membership(
        &mut self,
        request: DraftMembershipRequest,
    ) -> Result<(), UiMutationError> {
        let group = request.group.trim();
        let user_id = request.user_id.trim();
        if group.is_empty() || user_id.is_empty() {
            return Err(UiMutationError::bad_request(
                "empty_draft_membership_id",
                "group and user_id are required",
            ));
        }

        let Some(draft) = self.draft.as_mut() else {
            return Err(UiMutationError::conflict(
                "draft_unavailable",
                self.load_error
                    .clone()
                    .unwrap_or_else(|| "catalog draft is unavailable".to_owned()),
            ));
        };

        let existing = draft
            .memberships
            .iter()
            .position(|membership| membership.group == group && membership.user_id == user_id);
        let changed = match (request.enabled, existing) {
            (true, None) => {
                draft.memberships.push(CatalogMembership {
                    user_id: user_id.to_owned(),
                    group: group.to_owned(),
                });
                true
            }
            (false, Some(index)) => {
                draft.memberships.remove(index);
                true
            }
            _ => false,
        };

        if changed {
            self.mark_changed();
        }
        Ok(())
    }

    fn update_group_mapping(
        &mut self,
        request: DraftGroupMappingRequest,
    ) -> Result<(), UiMutationError> {
        let group = request.group.trim();
        let external_group = request.external_group.trim();
        if group.is_empty() || external_group.is_empty() {
            return Err(UiMutationError::bad_request(
                "empty_draft_group_mapping_id",
                "group and external_group are required",
            ));
        }

        let Some(draft) = self.draft.as_mut() else {
            return Err(UiMutationError::conflict(
                "draft_unavailable",
                self.load_error
                    .clone()
                    .unwrap_or_else(|| "catalog draft is unavailable".to_owned()),
            ));
        };

        let existing = draft
            .group_mappings
            .iter()
            .position(|mapping| mapping.external_group == external_group);
        let changed = match (request.enabled, existing) {
            (true, None) => {
                draft.group_mappings.push(GroupMapping {
                    external_group: external_group.to_owned(),
                    canopy_group: group.to_owned(),
                });
                true
            }
            (true, Some(index)) if draft.group_mappings[index].canopy_group == group => false,
            (true, Some(index)) => {
                let existing_group = draft.group_mappings[index].canopy_group.clone();
                return Err(UiMutationError::bad_request(
                    "duplicate_external_group_mapping",
                    format!(
                        "external_group '{external_group}' is already mapped to group '{existing_group}'",
                    ),
                ));
            }
            (false, Some(index)) if draft.group_mappings[index].canopy_group == group => {
                draft.group_mappings.remove(index);
                true
            }
            _ => false,
        };

        if changed {
            self.mark_changed();
        }
        Ok(())
    }

    fn update_account(&mut self, request: DraftAccountRequest) -> Result<(), UiMutationError> {
        let id = request.id.trim();
        let account_id = request.account_id.trim();
        let name = request.name.trim();
        if id.is_empty() || (request.enabled && (account_id.is_empty() || name.is_empty())) {
            return Err(UiMutationError::bad_request(
                "empty_draft_account_id",
                "account id, account_id, and name are required when saving an account",
            ));
        }

        let Some(draft) = self.draft.as_mut() else {
            return Err(UiMutationError::conflict(
                "draft_unavailable",
                self.load_error
                    .clone()
                    .unwrap_or_else(|| "catalog draft is unavailable".to_owned()),
            ));
        };

        let existing = draft.accounts.iter().position(|account| account.id == id);
        let changed = if request.enabled {
            if draft
                .accounts
                .iter()
                .any(|account| account.id != id && account.account_id == account_id)
            {
                return Err(UiMutationError::bad_request(
                    "duplicate_account_id",
                    format!("account_id '{account_id}' is already used by another account"),
                ));
            }

            let next = CatalogAccount {
                id: id.to_owned(),
                account_id: account_id.to_owned(),
                name: name.to_owned(),
            };
            match existing {
                Some(index) if draft.accounts[index] == next => false,
                Some(index) => {
                    draft.accounts[index] = next;
                    true
                }
                None => {
                    draft.accounts.push(next);
                    true
                }
            }
        } else if let Some(index) = existing {
            if draft
                .scopes
                .iter()
                .any(|scope| scope.accounts.iter().any(|account| account == id))
            {
                return Err(UiMutationError::bad_request(
                    "account_in_use",
                    format!("account '{id}' is still referenced by at least one scope"),
                ));
            }
            draft.accounts.remove(index);
            true
        } else {
            false
        };

        if changed {
            self.mark_changed();
        }
        Ok(())
    }

    fn update_role(&mut self, request: DraftRoleRequest) -> Result<(), UiMutationError> {
        let id = request.id.trim();
        let role_arn = request.role_arn.trim();
        if id.is_empty() || (request.enabled && role_arn.is_empty()) {
            return Err(UiMutationError::bad_request(
                "empty_draft_role_id",
                "role id and role_arn are required when saving a role",
            ));
        }

        let Some(draft) = self.draft.as_mut() else {
            return Err(UiMutationError::conflict(
                "draft_unavailable",
                self.load_error
                    .clone()
                    .unwrap_or_else(|| "catalog draft is unavailable".to_owned()),
            ));
        };

        let existing = draft.roles.iter().position(|role| role.id == id);
        let changed = if request.enabled {
            let next = CatalogRole {
                id: id.to_owned(),
                role_arn: role_arn.to_owned(),
            };
            match existing {
                Some(index) if draft.roles[index] == next => false,
                Some(index) => {
                    draft.roles[index] = next;
                    true
                }
                None => {
                    draft.roles.push(next);
                    true
                }
            }
        } else if let Some(index) = existing {
            if draft.packages.iter().any(|package| package.role == id) {
                return Err(UiMutationError::bad_request(
                    "role_in_use",
                    format!("role '{id}' is still referenced by at least one package"),
                ));
            }
            draft.roles.remove(index);
            true
        } else {
            false
        };

        if changed {
            self.mark_changed();
        }
        Ok(())
    }

    fn update_scope_resource(
        &mut self,
        request: DraftScopeResourceRequest,
    ) -> Result<(), UiMutationError> {
        let scope_id = request.scope.trim();
        let field = request.field.trim();
        let value = request.value.trim();
        if scope_id.is_empty() || field.is_empty() || value.is_empty() {
            return Err(UiMutationError::bad_request(
                "empty_draft_scope_resource_id",
                "scope, field, and value are required",
            ));
        }

        let Some(draft) = self.draft.as_mut() else {
            return Err(UiMutationError::conflict(
                "draft_unavailable",
                self.load_error
                    .clone()
                    .unwrap_or_else(|| "catalog draft is unavailable".to_owned()),
            ));
        };

        if request.enabled
            && field == "accounts"
            && !draft.accounts.iter().any(|account| account.id == value)
        {
            return Err(UiMutationError::bad_request(
                "unknown_account",
                format!("account '{value}' does not exist in the draft"),
            ));
        }

        let Some(scope) = draft
            .scopes
            .iter_mut()
            .find(|candidate| candidate.id == scope_id)
        else {
            return Err(UiMutationError::bad_request(
                "unknown_scope",
                format!("scope '{scope_id}' does not exist in the draft"),
            ));
        };

        let values = match field {
            "accounts" => &mut scope.accounts,
            "regions" => &mut scope.regions,
            "log_group_arns" => &mut scope.log_group_arns,
            "clusters" => &mut scope.clusters,
            "os_users" => &mut scope.os_users,
            _ => {
                return Err(UiMutationError::bad_request(
                    "unknown_scope_resource_field",
                    format!("scope resource field '{field}' is not editable"),
                ));
            }
        };

        let exists = values.iter().any(|candidate| candidate == value);
        let changed = match (request.enabled, exists) {
            (true, false) => {
                values.push(value.to_owned());
                true
            }
            (false, true) => {
                values.retain(|candidate| candidate != value);
                true
            }
            _ => false,
        };

        if changed {
            self.mark_changed();
        }
        Ok(())
    }

    fn update_database_scope(
        &mut self,
        request: DraftDatabaseScopeRequest,
    ) -> Result<(), UiMutationError> {
        let scope_id = request.scope.trim().to_owned();
        let name = request.name.trim().to_owned();
        if scope_id.is_empty() || name.is_empty() {
            return Err(UiMutationError::bad_request(
                "empty_draft_database_scope_id",
                "scope and database scope name are required",
            ));
        }
        validate_database_scope_key("database scope name", &name)?;

        let Some(draft) = self.draft.as_mut() else {
            return Err(UiMutationError::conflict(
                "draft_unavailable",
                self.load_error
                    .clone()
                    .unwrap_or_else(|| "catalog draft is unavailable".to_owned()),
            ));
        };

        let Some(scope) = draft
            .scopes
            .iter_mut()
            .find(|candidate| candidate.id == scope_id)
        else {
            return Err(UiMutationError::bad_request(
                "unknown_scope",
                format!("scope '{scope_id}' does not exist in the draft"),
            ));
        };

        let existing = scope
            .database_scopes
            .iter()
            .position(|database_scope| database_scope.name == name);
        let changed = if request.enabled {
            let next = database_scope_from_request(&name, request)?;
            match existing {
                Some(index) if scope.database_scopes[index] == next => false,
                Some(index) => {
                    scope.database_scopes[index] = next;
                    true
                }
                None => {
                    scope.database_scopes.push(next);
                    true
                }
            }
        } else if let Some(index) = existing {
            scope.database_scopes.remove(index);
            true
        } else {
            false
        };

        if changed {
            self.mark_changed();
        }
        Ok(())
    }

    fn update_mcp_ec2_scope(
        &mut self,
        request: DraftMcpEc2ScopeRequest,
    ) -> Result<(), UiMutationError> {
        let scope_id = request.scope.trim().to_owned();
        let id = request.id.trim().to_owned();
        if scope_id.is_empty() || id.is_empty() {
            return Err(UiMutationError::bad_request(
                "empty_draft_mcp_ec2_scope_id",
                "scope and MCP EC2 scope id are required",
            ));
        }
        validate_mcp_ec2_scope_id(&id)?;

        let Some(draft) = self.draft.as_mut() else {
            return Err(UiMutationError::conflict(
                "draft_unavailable",
                self.load_error
                    .clone()
                    .unwrap_or_else(|| "catalog draft is unavailable".to_owned()),
            ));
        };

        let Some(scope) = draft
            .scopes
            .iter_mut()
            .find(|candidate| candidate.id == scope_id)
        else {
            return Err(UiMutationError::bad_request(
                "unknown_scope",
                format!("scope '{scope_id}' does not exist in the draft"),
            ));
        };

        let existing = scope
            .mcp_ec2_diagnostic_scopes
            .iter()
            .position(|ec2_scope| ec2_scope.id == id);
        let changed = if request.enabled {
            let next = mcp_ec2_scope_from_request(&id, request)?;
            match existing {
                Some(index) if scope.mcp_ec2_diagnostic_scopes[index] == next => false,
                Some(index) => {
                    scope.mcp_ec2_diagnostic_scopes[index] = next;
                    true
                }
                None => {
                    scope.mcp_ec2_diagnostic_scopes.push(next);
                    true
                }
            }
        } else if let Some(index) = existing {
            scope.mcp_ec2_diagnostic_scopes.remove(index);
            true
        } else {
            false
        };

        if changed {
            self.mark_changed();
        }
        Ok(())
    }

    fn update_package_feature(
        &mut self,
        request: DraftPackageFeatureRequest,
    ) -> Result<(), UiMutationError> {
        let package_id = request.package.trim();
        let feature = request.feature.trim();
        if package_id.is_empty() || feature.is_empty() {
            return Err(UiMutationError::bad_request(
                "empty_draft_package_feature_id",
                "package and feature are required",
            ));
        }
        if !known_catalog_feature(feature) {
            return Err(UiMutationError::bad_request(
                "unknown_catalog_feature",
                format!("feature '{feature}' is not supported by the catalog model"),
            ));
        }

        let Some(draft) = self.draft.as_mut() else {
            return Err(UiMutationError::conflict(
                "draft_unavailable",
                self.load_error
                    .clone()
                    .unwrap_or_else(|| "catalog draft is unavailable".to_owned()),
            ));
        };

        let Some(package) = draft
            .packages
            .iter_mut()
            .find(|candidate| candidate.id == package_id)
        else {
            return Err(UiMutationError::bad_request(
                "unknown_package",
                format!("package '{package_id}' does not exist in the draft"),
            ));
        };

        let mut next_features = package.features.clone();
        if request.enabled {
            if let Some(required) = required_base_feature(feature) {
                add_feature_once(&mut next_features, required);
            }
            add_feature_once(&mut next_features, feature);
        } else {
            if disabling_required_base(feature, &next_features) {
                return Err(UiMutationError::bad_request(
                    "required_base_feature",
                    format!("feature '{feature}' is required by another enabled package feature"),
                ));
            }
            next_features.retain(|candidate| candidate != feature);
        }
        order_catalog_features(&mut next_features);

        if package.features != next_features {
            package.features = next_features;
            self.mark_changed();
        }
        Ok(())
    }

    fn update_package(&mut self, request: DraftPackageRequest) -> Result<(), UiMutationError> {
        let id = request.id.trim();
        let scope = request.scope.trim();
        let role = request.role.trim();
        if id.is_empty() || (request.enabled && (scope.is_empty() || role.is_empty())) {
            return Err(UiMutationError::bad_request(
                "empty_draft_package_id",
                "package id, scope, and role are required when saving a package",
            ));
        }
        if request.max_session_seconds == Some(0) {
            return Err(UiMutationError::bad_request(
                "invalid_package_session_cap",
                "max_session_seconds must be greater than zero when configured",
            ));
        }

        let Some(draft) = self.draft.as_mut() else {
            return Err(UiMutationError::conflict(
                "draft_unavailable",
                self.load_error
                    .clone()
                    .unwrap_or_else(|| "catalog draft is unavailable".to_owned()),
            ));
        };

        let existing = draft.packages.iter().position(|package| package.id == id);
        let changed = if request.enabled {
            if !draft.scopes.iter().any(|candidate| candidate.id == scope) {
                return Err(UiMutationError::bad_request(
                    "unknown_scope",
                    format!("scope '{scope}' does not exist in the draft"),
                ));
            }
            if !draft.roles.iter().any(|candidate| candidate.id == role) {
                return Err(UiMutationError::bad_request(
                    "unknown_role",
                    format!("role '{role}' does not exist in the draft"),
                ));
            }

            let next = CatalogPackage {
                id: id.to_owned(),
                features: existing
                    .map(|index| draft.packages[index].features.clone())
                    .unwrap_or_default(),
                scope: scope.to_owned(),
                role: role.to_owned(),
                max_session_seconds: request.max_session_seconds,
            };
            match existing {
                Some(index) if draft.packages[index] == next => false,
                Some(index) => {
                    draft.packages[index] = next;
                    true
                }
                None => {
                    draft.packages.push(next);
                    true
                }
            }
        } else if let Some(index) = existing {
            if draft.bindings.iter().any(|binding| binding.package == id) {
                return Err(UiMutationError::bad_request(
                    "package_in_use",
                    format!("package '{id}' is still referenced by at least one binding"),
                ));
            }
            draft.packages.remove(index);
            true
        } else {
            false
        };

        if changed {
            self.mark_changed();
        }
        Ok(())
    }

    fn replace_with_imported_catalog(&mut self, catalog: Catalog) {
        self.dirty = self
            .baseline
            .as_ref()
            .is_none_or(|baseline| baseline != &catalog);
        self.draft = Some(catalog);
        self.load_error = None;
        self.revision = self.revision.saturating_add(1);
    }

    fn mark_changed(&mut self) {
        self.revision = self.revision.saturating_add(1);
        self.dirty = self
            .baseline
            .as_ref()
            .is_none_or(|baseline| self.draft.as_ref().is_some_and(|draft| baseline != draft));
    }

    fn preview_group(
        &self,
        request: PreviewRequest,
    ) -> Result<catalog::PreviewOutput, UiMutationError> {
        let group = request.group.trim();
        if group.is_empty() {
            return Err(UiMutationError::bad_request(
                "empty_preview_group",
                "group is required",
            ));
        }

        let Some(draft) = self.draft.as_ref() else {
            return Err(UiMutationError::conflict(
                "draft_unavailable",
                self.load_error
                    .clone()
                    .unwrap_or_else(|| "catalog draft is unavailable".to_owned()),
            ));
        };

        if !known_groups(draft).contains(group) {
            return Err(UiMutationError::bad_request(
                "unknown_group",
                format!("group '{group}' does not exist in the draft"),
            ));
        }

        draft.preview_group(group).map_err(|err| {
            UiMutationError::conflict(
                "draft_preview_failed",
                format!("draft preview failed: {err}"),
            )
        })
    }

    fn explain(
        &self,
        request: catalog::ExplainRequest,
    ) -> Result<catalog::ExplainOutput, UiMutationError> {
        let Some(draft) = self.draft.as_ref() else {
            return Err(UiMutationError::conflict(
                "draft_unavailable",
                self.load_error
                    .clone()
                    .unwrap_or_else(|| "catalog draft is unavailable".to_owned()),
            ));
        };
        draft.explain(request).map_err(|err| {
            UiMutationError::conflict(
                "draft_explain_failed",
                format!("draft explain failed: {err}"),
            )
        })
    }

    fn dry_run(
        &self,
        request: catalog::DryRunRequest,
    ) -> Result<catalog::DryRunOutput, UiMutationError> {
        let Some(draft) = self.draft.as_ref() else {
            return Err(UiMutationError::conflict(
                "draft_unavailable",
                self.load_error
                    .clone()
                    .unwrap_or_else(|| "catalog draft is unavailable".to_owned()),
            ));
        };
        draft.dry_run(request).map_err(|err| {
            UiMutationError::bad_request(
                "draft_dry_run_failed",
                format!("draft dry-run failed: {err}"),
            )
        })
    }

    fn clone_draft(&self) -> Result<(Catalog, u64), UiMutationError> {
        let Some(draft) = self.draft.as_ref() else {
            return Err(UiMutationError::conflict(
                "draft_unavailable",
                self.load_error
                    .clone()
                    .unwrap_or_else(|| "catalog draft is unavailable".to_owned()),
            ));
        };
        Ok((draft.clone(), self.revision))
    }

    fn clone_baseline(&self) -> Option<Catalog> {
        self.baseline.clone()
    }

    fn summarize(&self) -> (UiDraftResponse, UiPendingChanges) {
        let Some(draft) = self.draft.as_ref() else {
            return (
                UiDraftResponse {
                    loaded: false,
                    status: "unavailable",
                    revision: self.revision,
                    dirty: self.dirty,
                    groups: Vec::new(),
                    accounts: Vec::new(),
                    roles: Vec::new(),
                    packages: Vec::new(),
                    available_features: feature_summaries(),
                    scopes: Vec::new(),
                    bindings: Vec::new(),
                    selected_group: None,
                    error: self.load_error.clone(),
                },
                UiPendingChanges::empty(),
            );
        };

        let changes = self
            .baseline
            .as_ref()
            .map(|baseline| pending_changes(baseline, draft))
            .unwrap_or_else(UiPendingChanges::empty);
        let groups = group_summaries(draft);
        let selected_group = groups.first().map(|group| group.id.clone());
        (
            UiDraftResponse {
                loaded: true,
                status: "loaded",
                revision: self.revision,
                dirty: self.dirty,
                groups,
                accounts: account_summaries(draft),
                roles: role_summaries(draft),
                packages: package_summaries(draft),
                available_features: feature_summaries(),
                scopes: scope_summaries(draft),
                bindings: binding_summaries(draft),
                selected_group,
                error: None,
            },
            changes,
        )
    }
}

#[derive(Debug, Clone)]
struct DatabaseConnectionsSnapshot {
    source_path: Option<PathBuf>,
    draft: BTreeMap<String, DbConnectionMetadata>,
    load_error: Option<UiValidationIssue>,
    dirty: bool,
    revision: u64,
}

impl DatabaseConnectionsDraftState {
    fn load(path: Option<&Path>) -> Self {
        let Some(path) = path else {
            return Self {
                source_path: None,
                baseline: BTreeMap::new(),
                draft: BTreeMap::new(),
                load_error: None,
                dirty: false,
                revision: 0,
            };
        };
        match load_connection_registry_from_file(path) {
            Ok(registry) => Self {
                source_path: Some(path.to_path_buf()),
                baseline: registry.clone(),
                draft: registry,
                load_error: None,
                dirty: false,
                revision: 0,
            },
            Err(issue) => Self {
                source_path: Some(path.to_path_buf()),
                baseline: BTreeMap::new(),
                draft: BTreeMap::new(),
                load_error: Some(issue),
                dirty: false,
                revision: 0,
            },
        }
    }

    fn snapshot(&self) -> DatabaseConnectionsSnapshot {
        DatabaseConnectionsSnapshot {
            source_path: self.source_path.clone(),
            draft: self.draft.clone(),
            load_error: self.load_error.clone(),
            dirty: self.dirty,
            revision: self.revision,
        }
    }

    fn update_connection(
        &mut self,
        request: DraftDatabaseConnectionRequest,
    ) -> Result<(), UiMutationError> {
        let name = request.name.trim().to_owned();
        validate_database_connection_name(&name)?;
        let existing = self.draft.get(&name);
        let metadata = database_metadata_from_request(&name, existing, request)?;
        let changed = self.draft.get(&name) != Some(&metadata);
        self.draft.insert(name, metadata);
        self.load_error = None;
        if changed {
            self.revision = self.revision.saturating_add(1);
            self.dirty = self.baseline != self.draft;
        }
        Ok(())
    }
}

fn validate_database_connection_name(name: &str) -> Result<(), UiMutationError> {
    if name.is_empty() {
        return Err(UiMutationError::bad_request(
            "empty_database_connection_name",
            "database connection name is required",
        ));
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err(UiMutationError::bad_request(
            "empty_database_connection_name",
            "database connection name is required",
        ));
    };
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(UiMutationError::bad_request(
            "invalid_database_connection_name",
            "database connection name must start with a lowercase ASCII letter or digit",
        ));
    }
    if !chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-') {
        return Err(UiMutationError::bad_request(
            "invalid_database_connection_name",
            "database connection name may only contain lowercase ASCII letters, digits, '_' or '-'",
        ));
    }
    Ok(())
}

fn database_scope_from_request(
    name: &str,
    request: DraftDatabaseScopeRequest,
) -> Result<DatabaseScope, UiMutationError> {
    let connection = required_nonempty_request_string("connection", request.connection)?;
    let environment = required_nonempty_request_string("environment", request.environment)?;
    validate_database_scope_key("database scope connection", &connection)?;
    validate_database_scope_key("database scope environment", &environment)?;

    let allowed_schemas =
        normalize_database_scope_identifiers("allowed_schemas", request.allowed_schemas)?;
    let allowed_tables =
        normalize_database_scope_identifiers("allowed_tables", request.allowed_tables)?;
    let allowed_actions = normalize_database_scope_actions(request.allowed_actions)?;

    validate_positive_u64_limit("max_rows", request.max_rows)?;
    validate_positive_u64_limit("statement_timeout_ms", request.statement_timeout_ms)?;
    validate_positive_u64_limit("max_examined_rows", request.max_examined_rows)?;

    if !request.require_explain {
        return Err(UiMutationError::bad_request(
            "database_scope_explain_disabled",
            format!("database scope '{name}' must keep require_explain=true"),
        ));
    }

    Ok(DatabaseScope {
        name: name.to_owned(),
        connection,
        environment,
        allowed_schemas,
        allowed_tables,
        allowed_actions,
        max_rows: request.max_rows,
        statement_timeout_ms: request.statement_timeout_ms,
        require_explain: true,
        max_examined_rows: request.max_examined_rows,
        allow_full_table_scan: request.allow_full_table_scan,
        allow_views: request.allow_views,
    })
}

fn mcp_ec2_scope_from_request(
    id: &str,
    request: DraftMcpEc2ScopeRequest,
) -> Result<McpEc2DiagnosticScope, UiMutationError> {
    validate_mcp_ec2_range("max_lines", u64::from(request.max_lines), 1, 500)?;
    validate_mcp_ec2_range("max_since_seconds", request.max_since_seconds, 1, 1800)?;
    validate_mcp_ec2_range(
        "max_timeout_seconds",
        u64::from(request.max_timeout_seconds),
        1,
        120,
    )?;
    validate_mcp_ec2_range("max_matches", u64::from(request.max_matches), 1, 500)?;
    validate_mcp_ec2_range(
        "connectivity_probe_budget_per_window",
        u64::from(request.connectivity_probe_budget_per_window),
        1,
        u64::MAX,
    )?;
    validate_mcp_ec2_range(
        "budget_window_seconds",
        request.budget_window_seconds,
        1,
        u64::MAX,
    )?;

    let private_target_refs = normalize_mcp_ec2_private_target_refs(request.private_target_refs)?;
    let private_target_ref_set = private_target_refs
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let allowed_log_paths = normalize_mcp_ec2_log_paths(request.allowed_log_paths)?;
    let allowed_journal_units = normalize_mcp_ec2_journal_units(request.allowed_journal_units)?;
    let allowed_http_urls =
        normalize_mcp_ec2_http_urls(request.allowed_http_urls, &private_target_ref_set)?;
    let allowed_tcp_targets =
        normalize_mcp_ec2_tcp_targets(request.allowed_tcp_targets, &private_target_ref_set)?;
    let allowed_dns_targets =
        normalize_mcp_ec2_dns_targets(request.allowed_dns_targets, &private_target_ref_set)?;

    if allowed_log_paths.is_empty()
        && allowed_journal_units.is_empty()
        && allowed_http_urls.is_empty()
        && allowed_tcp_targets.is_empty()
        && allowed_dns_targets.is_empty()
    {
        return Err(UiMutationError::bad_request(
            "empty_mcp_ec2_scope_commands",
            "MCP EC2 diagnostic scope requires at least one log, journal, HTTP, TCP, or DNS target",
        ));
    }

    let denylist_version =
        required_nonempty_mcp_ec2_string("denylist_version", request.denylist_version)?;
    let allowlist_rule_id =
        required_nonempty_mcp_ec2_string("allowlist_rule_id", request.allowlist_rule_id)?;

    Ok(McpEc2DiagnosticScope {
        id: id.to_owned(),
        allowed_log_paths,
        allowed_journal_units,
        allowed_http_urls,
        allowed_tcp_targets,
        allowed_dns_targets,
        private_target_refs,
        max_lines: request.max_lines,
        max_since_seconds: request.max_since_seconds,
        max_timeout_seconds: request.max_timeout_seconds,
        max_matches: request.max_matches,
        connectivity_probe_budget_per_window: request.connectivity_probe_budget_per_window,
        budget_window_seconds: request.budget_window_seconds,
        denylist_version,
        allowlist_rule_id,
    })
}

fn validate_mcp_ec2_range(
    field: &'static str,
    value: u64,
    minimum: u64,
    maximum: u64,
) -> Result<(), UiMutationError> {
    if value < minimum || value > maximum {
        return Err(UiMutationError::bad_request(
            "invalid_mcp_ec2_scope_limit",
            format!("MCP EC2 diagnostic scope {field} must be between {minimum} and {maximum}"),
        ));
    }
    Ok(())
}

fn required_nonempty_mcp_ec2_string(
    field: &'static str,
    value: String,
) -> Result<String, UiMutationError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(UiMutationError::bad_request(
            "empty_mcp_ec2_scope_field",
            format!("MCP EC2 diagnostic scope {field} is required"),
        ));
    }
    Ok(value.to_owned())
}

fn normalize_mcp_ec2_private_target_refs(
    values: Vec<String>,
) -> Result<Vec<String>, UiMutationError> {
    let mut refs = BTreeSet::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        validate_mcp_ec2_private_ref_identifier("MCP EC2 private target ref", value)?;
        refs.insert(value.to_owned());
    }
    Ok(refs.into_iter().collect())
}

fn normalize_mcp_ec2_log_paths(
    values: Vec<McpEc2LogPathScope>,
) -> Result<Vec<McpEc2LogPathScope>, UiMutationError> {
    let mut normalized = Vec::new();
    let mut seen = BTreeSet::new();
    for value in values {
        let path_pattern =
            required_nonempty_mcp_ec2_string("log path_pattern", value.path_pattern)?;
        let canonical_safe_prefix = required_nonempty_mcp_ec2_string(
            "log canonical_safe_prefix",
            value.canonical_safe_prefix,
        )?;
        if !seen.insert(path_pattern.clone()) {
            continue;
        }
        normalized.push(McpEc2LogPathScope {
            path_pattern,
            canonical_safe_prefix,
            safe_for_mcp_output: value.safe_for_mcp_output,
        });
    }
    Ok(normalized)
}

fn normalize_mcp_ec2_journal_units(
    values: Vec<McpEc2JournalUnitScope>,
) -> Result<Vec<McpEc2JournalUnitScope>, UiMutationError> {
    let mut normalized = Vec::new();
    let mut seen = BTreeSet::new();
    for value in values {
        let unit = required_nonempty_mcp_ec2_string("journal unit", value.unit)?;
        if !seen.insert(unit.clone()) {
            continue;
        }
        normalized.push(McpEc2JournalUnitScope {
            unit,
            safe_for_mcp_output: value.safe_for_mcp_output,
        });
    }
    Ok(normalized)
}

fn normalize_mcp_ec2_http_urls(
    values: Vec<McpEc2HttpUrlScope>,
    private_target_refs: &BTreeSet<&str>,
) -> Result<Vec<McpEc2HttpUrlScope>, UiMutationError> {
    let mut normalized = Vec::new();
    let mut seen = BTreeSet::new();
    for value in values {
        let normalized_url = required_nonempty_mcp_ec2_string("HTTP URL", value.normalized_url)?;
        let private_target_ref =
            normalize_mcp_ec2_optional_private_target_ref(value.private_target_ref)?;
        validate_mcp_ec2_private_target_ref_defined(
            "HTTP URL private_target_ref",
            private_target_ref.as_deref(),
            private_target_refs,
        )?;
        let query_policy_key = format!("{:?}", value.query_policy);
        if !seen.insert((
            normalized_url.clone(),
            query_policy_key,
            private_target_ref.clone(),
        )) {
            continue;
        }
        normalized.push(McpEc2HttpUrlScope {
            normalized_url,
            query_policy: value.query_policy,
            safe_for_mcp_output: value.safe_for_mcp_output,
            private_target_ref,
        });
    }
    Ok(normalized)
}

fn normalize_mcp_ec2_tcp_targets(
    values: Vec<McpEc2TcpTargetScope>,
    private_target_refs: &BTreeSet<&str>,
) -> Result<Vec<McpEc2TcpTargetScope>, UiMutationError> {
    let mut normalized = Vec::new();
    let mut seen = BTreeSet::new();
    for value in values {
        let host = required_nonempty_mcp_ec2_string("TCP host", value.host)?;
        if value.port == 0 {
            return Err(UiMutationError::bad_request(
                "invalid_mcp_ec2_scope_target",
                "MCP EC2 TCP target port must be greater than zero",
            ));
        }
        let private_target_ref =
            normalize_mcp_ec2_optional_private_target_ref(value.private_target_ref)?;
        validate_mcp_ec2_private_target_ref_defined(
            "TCP target private_target_ref",
            private_target_ref.as_deref(),
            private_target_refs,
        )?;
        if !seen.insert((host.clone(), value.port, private_target_ref.clone())) {
            continue;
        }
        normalized.push(McpEc2TcpTargetScope {
            host,
            port: value.port,
            private_target_ref,
        });
    }
    Ok(normalized)
}

fn normalize_mcp_ec2_dns_targets(
    values: Vec<McpEc2DnsTargetScope>,
    private_target_refs: &BTreeSet<&str>,
) -> Result<Vec<McpEc2DnsTargetScope>, UiMutationError> {
    let mut normalized = Vec::new();
    let mut seen = BTreeSet::new();
    for value in values {
        let host = required_nonempty_mcp_ec2_string("DNS host", value.host)?;
        if value.record_types.is_empty() {
            return Err(UiMutationError::bad_request(
                "empty_mcp_ec2_scope_field",
                "MCP EC2 DNS target record_types requires at least one value",
            ));
        }
        let private_target_ref =
            normalize_mcp_ec2_optional_private_target_ref(value.private_target_ref)?;
        validate_mcp_ec2_private_target_ref_defined(
            "DNS target private_target_ref",
            private_target_ref.as_deref(),
            private_target_refs,
        )?;
        let record_key = value
            .record_types
            .iter()
            .map(|record| format!("{record:?}"))
            .collect::<Vec<_>>()
            .join(",");
        if !seen.insert((host.clone(), record_key, private_target_ref.clone())) {
            continue;
        }
        normalized.push(McpEc2DnsTargetScope {
            host,
            record_types: value.record_types,
            safe_for_mcp_output: value.safe_for_mcp_output,
            private_target_ref,
        });
    }
    Ok(normalized)
}

fn normalize_mcp_ec2_optional_private_target_ref(
    value: Option<String>,
) -> Result<Option<String>, UiMutationError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    validate_mcp_ec2_private_ref_identifier("MCP EC2 private target ref", value)?;
    Ok(Some(value.to_owned()))
}

fn validate_mcp_ec2_private_target_ref_defined(
    field: &'static str,
    value: Option<&str>,
    private_target_refs: &BTreeSet<&str>,
) -> Result<(), UiMutationError> {
    let Some(value) = value else {
        return Ok(());
    };
    if !private_target_refs.contains(value) {
        return Err(UiMutationError::bad_request(
            "undefined_mcp_ec2_private_target_ref",
            format!("{field} '{value}' is not listed in private_target_refs"),
        ));
    }
    Ok(())
}

fn validate_mcp_ec2_scope_id(value: &str) -> Result<(), UiMutationError> {
    if value.is_empty() {
        return Err(UiMutationError::bad_request(
            "empty_mcp_ec2_scope_field",
            "MCP EC2 scope id is required",
        ));
    }
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err(UiMutationError::bad_request(
            "empty_mcp_ec2_scope_field",
            "MCP EC2 scope id is required",
        ));
    };
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(UiMutationError::bad_request(
            "invalid_mcp_ec2_scope_identifier",
            "MCP EC2 scope id must start with a lowercase ASCII letter or digit",
        ));
    }
    if !chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-') {
        return Err(UiMutationError::bad_request(
            "invalid_mcp_ec2_scope_identifier",
            "MCP EC2 scope id may only contain lowercase ASCII letters, digits, '_' or '-'",
        ));
    }
    Ok(())
}

fn validate_mcp_ec2_private_ref_identifier(
    field: &'static str,
    value: &str,
) -> Result<(), UiMutationError> {
    if value.is_empty() {
        return Err(UiMutationError::bad_request(
            "empty_mcp_ec2_scope_field",
            format!("{field} is required"),
        ));
    }
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err(UiMutationError::bad_request(
            "empty_mcp_ec2_scope_field",
            format!("{field} is required"),
        ));
    };
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(UiMutationError::bad_request(
            "invalid_mcp_ec2_scope_identifier",
            format!("{field} must start with a lowercase ASCII letter or digit"),
        ));
    }
    if !chars.all(|ch| {
        ch.is_ascii_lowercase()
            || ch.is_ascii_digit()
            || ch == '_'
            || ch == '-'
            || ch == ':'
            || ch == '/'
    }) {
        return Err(UiMutationError::bad_request(
            "invalid_mcp_ec2_scope_identifier",
            format!(
                "{field} may only contain lowercase ASCII letters, digits, '_', '-', ':' or '/'"
            ),
        ));
    }
    Ok(())
}

fn validate_database_scope_key(field: &'static str, value: &str) -> Result<(), UiMutationError> {
    if value.is_empty() {
        return Err(UiMutationError::bad_request(
            "empty_database_scope_field",
            format!("{field} is required"),
        ));
    }
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err(UiMutationError::bad_request(
            "empty_database_scope_field",
            format!("{field} is required"),
        ));
    };
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(UiMutationError::bad_request(
            "invalid_database_scope_identifier",
            format!("{field} must start with a lowercase ASCII letter or digit"),
        ));
    }
    if !chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-') {
        return Err(UiMutationError::bad_request(
            "invalid_database_scope_identifier",
            format!("{field} may only contain lowercase ASCII letters, digits, '_' or '-'"),
        ));
    }
    Ok(())
}

fn normalize_database_scope_identifiers(
    field: &'static str,
    values: Vec<String>,
) -> Result<Vec<String>, UiMutationError> {
    let mut normalized = BTreeSet::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            return Err(UiMutationError::bad_request(
                "empty_database_scope_field",
                format!("{field} must not contain empty values"),
            ));
        }
        if !value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
        {
            return Err(UiMutationError::bad_request(
                "invalid_database_scope_identifier",
                format!(
                    "{field} value '{value}' may only contain lowercase ASCII letters, digits, or '_'"
                ),
            ));
        }
        normalized.insert(value.to_owned());
    }
    if normalized.is_empty() {
        return Err(UiMutationError::bad_request(
            "empty_database_scope_field",
            format!("{field} requires at least one value"),
        ));
    }
    Ok(normalized.into_iter().collect())
}

fn normalize_database_scope_actions(values: Vec<String>) -> Result<Vec<String>, UiMutationError> {
    let mut normalized = BTreeSet::new();
    for value in values {
        let value = value.trim().to_ascii_lowercase();
        if value.is_empty() {
            return Err(UiMutationError::bad_request(
                "empty_database_scope_field",
                "allowed_actions must not contain empty values",
            ));
        }
        if value != "select" {
            return Err(UiMutationError::bad_request(
                "unsupported_database_scope_action",
                "only select is supported for MCP database scopes",
            ));
        }
        normalized.insert(value);
    }
    if normalized.is_empty() {
        return Err(UiMutationError::bad_request(
            "empty_database_scope_field",
            "allowed_actions requires at least one value",
        ));
    }
    Ok(normalized.into_iter().collect())
}

fn database_metadata_from_request(
    name: &str,
    existing: Option<&DbConnectionMetadata>,
    request: DraftDatabaseConnectionRequest,
) -> Result<DbConnectionMetadata, UiMutationError> {
    let engine = required_nonempty_request_string("engine", request.engine)?;
    if engine != "mysql" {
        return Err(UiMutationError::bad_request(
            "unsupported_database_engine",
            "only mysql database connections are supported",
        ));
    }
    let host = required_nonempty_request_string("host", request.host)?;
    let database = required_nonempty_request_string("database", request.database)?;
    if request.port <= 0 || request.port > 65535 {
        return Err(UiMutationError::bad_request(
            "invalid_database_connection_port",
            "database connection port must be between 1 and 65535",
        ));
    }
    validate_positive_limit("connect_timeout_ms", request.connect_timeout_ms)?;
    validate_positive_limit("statement_timeout_ms", request.statement_timeout_ms)?;
    validate_positive_limit("explain_timeout_ms", request.explain_timeout_ms)?;
    validate_positive_limit("max_connections", request.max_connections)?;

    if !request.readonly {
        return Err(UiMutationError::bad_request(
            "database_connection_not_readonly",
            format!("database connection '{name}' must set readonly=true"),
        ));
    }
    if !request.require_tls {
        return Err(UiMutationError::bad_request(
            "database_connection_tls_disabled",
            format!("database connection '{name}' must keep require_tls=true"),
        ));
    }
    if request.accept_invalid_tls_certs {
        return Err(UiMutationError::bad_request(
            "database_connection_accepts_invalid_tls",
            format!("database connection '{name}' must keep accept_invalid_tls_certs=false"),
        ));
    }
    if request.skip_tls_hostname_verification {
        return Err(UiMutationError::bad_request(
            "database_connection_skips_tls_hostname",
            format!("database connection '{name}' must keep skip_tls_hostname_verification=false"),
        ));
    }

    let secret_arn = match request.secret_arn {
        Some(secret_arn) if !secret_arn.trim().is_empty() => secret_arn.trim().to_owned(),
        Some(_) => {
            return Err(UiMutationError::bad_request(
                "database_connection_empty_secret_ref",
                format!("database connection '{name}' secret_arn must not be empty"),
            ));
        }
        None => existing
            .map(|metadata| metadata.secret_arn.clone())
            .filter(|secret_arn| !secret_arn.trim().is_empty())
            .ok_or_else(|| {
                UiMutationError::bad_request(
                    "database_connection_missing_secret_ref",
                    format!("database connection '{name}' requires a secret_arn reference"),
                )
            })?,
    };

    Ok(DbConnectionMetadata {
        engine,
        host,
        port: request.port,
        database,
        secret_arn,
        readonly: true,
        connect_timeout_ms: request.connect_timeout_ms,
        statement_timeout_ms: request.statement_timeout_ms,
        explain_timeout_ms: request.explain_timeout_ms,
        max_connections: request.max_connections,
        require_tls: true,
        accept_invalid_tls_certs: false,
        skip_tls_hostname_verification: false,
    })
}

fn required_nonempty_request_string(
    field: &'static str,
    value: String,
) -> Result<String, UiMutationError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(UiMutationError::bad_request(
            "empty_database_connection_field",
            format!("database connection {field} is required"),
        ));
    }
    Ok(value.to_owned())
}

fn validate_positive_limit(field: &'static str, value: i64) -> Result<(), UiMutationError> {
    if value <= 0 {
        return Err(UiMutationError::bad_request(
            "invalid_database_connection_limit",
            format!("database connection {field} must be greater than zero"),
        ));
    }
    Ok(())
}

fn validate_positive_u64_limit(field: &'static str, value: u64) -> Result<(), UiMutationError> {
    if value == 0 {
        return Err(UiMutationError::bad_request(
            "invalid_database_scope_limit",
            format!("database scope {field} must be greater than zero"),
        ));
    }
    Ok(())
}

fn file_status(path: &Path) -> UiFileStatus {
    match fs::read(path) {
        Ok(bytes) => UiFileStatus {
            path: path.display().to_string(),
            exists: true,
            readable: true,
            sha256: Some(hex::encode(Sha256::digest(bytes))),
            error: None,
        },
        Err(err) if err.kind() == io::ErrorKind::NotFound => UiFileStatus {
            path: path.display().to_string(),
            exists: false,
            readable: false,
            sha256: None,
            error: None,
        },
        Err(err) => UiFileStatus {
            path: path.display().to_string(),
            exists: true,
            readable: false,
            sha256: None,
            error: Some(err.kind().to_string()),
        },
    }
}

fn database_connections_state(
    database_connections: &DatabaseConnectionsSnapshot,
    draft: Option<&Catalog>,
) -> UiDatabaseConnectionsState {
    let required_counts = required_database_connection_counts(draft);
    let required = required_counts.keys().cloned().collect::<Vec<_>>();
    let source_path = database_connections
        .source_path
        .as_deref()
        .map(|path| path.display().to_string());
    if let Some(issue) = database_connections.load_error.clone() {
        return UiDatabaseConnectionsState {
            configured: database_connections.source_path.is_some(),
            dirty: database_connections.dirty,
            revision: database_connections.revision,
            source_path,
            missing_required: required.clone(),
            required,
            local: Vec::new(),
            issues: vec![issue],
        };
    }

    if database_connections.source_path.is_none() && database_connections.draft.is_empty() {
        let issues = if required.is_empty() {
            Vec::new()
        } else {
            vec![validation_issue(
                "missing_db_config",
                "draft uses database scopes, but --db-config was not provided",
                None,
            )]
        };
        return UiDatabaseConnectionsState {
            configured: false,
            dirty: database_connections.dirty,
            revision: database_connections.revision,
            source_path,
            missing_required: required.clone(),
            required,
            local: Vec::new(),
            issues,
        };
    }

    database_connections_state_from_registry(
        database_connections,
        &required_counts,
        &database_connections.draft,
    )
}

fn required_database_connection_counts(draft: Option<&Catalog>) -> BTreeMap<String, usize> {
    let Some(draft) = draft else {
        return BTreeMap::new();
    };
    let mut required = BTreeMap::new();
    for scope in &draft.scopes {
        for database_scope in &scope.database_scopes {
            *required
                .entry(database_scope.connection.clone())
                .or_insert(0) += 1;
        }
    }
    required
}

fn database_connections_state_from_registry(
    database_connections: &DatabaseConnectionsSnapshot,
    required_counts: &BTreeMap<String, usize>,
    registry: &BTreeMap<String, DbConnectionMetadata>,
) -> UiDatabaseConnectionsState {
    let required = required_counts.keys().cloned().collect::<Vec<_>>();
    let source_path = database_connections
        .source_path
        .as_deref()
        .map(|path| path.display().to_string());
    let issue_path = source_path
        .clone()
        .unwrap_or_else(|| "database connection draft".to_owned());
    let missing_required = required
        .iter()
        .filter(|connection| !registry.contains_key(*connection))
        .cloned()
        .collect::<Vec<_>>();
    let mut issues = Vec::new();
    for connection in &missing_required {
        issues.push(validation_issue(
            "missing_database_connection",
            format!("db_config is missing required database connection '{connection}'"),
            Some(issue_path.clone()),
        ));
    }
    let local = registry
        .iter()
        .map(|(name, metadata)| {
            collect_database_connection_safety_issues(
                "db_config",
                &issue_path,
                name,
                metadata,
                &mut issues,
            );
            UiDatabaseConnectionSummary {
                name: name.clone(),
                engine: metadata.engine.clone(),
                host: metadata.host.clone(),
                port: metadata.port,
                database: metadata.database.clone(),
                readonly: metadata.readonly,
                require_tls: metadata.require_tls,
                accept_invalid_tls_certs: metadata.accept_invalid_tls_certs,
                skip_tls_hostname_verification: metadata.skip_tls_hostname_verification,
                connect_timeout_ms: metadata.connect_timeout_ms,
                statement_timeout_ms: metadata.statement_timeout_ms,
                explain_timeout_ms: metadata.explain_timeout_ms,
                max_connections: metadata.max_connections,
                secret_ref_configured: !metadata.secret_arn.trim().is_empty(),
                required_by_scope_count: *required_counts.get(name).unwrap_or(&0),
                safety: if required_counts.contains_key(name)
                    && connection_has_blocking_safety_issue(metadata)
                {
                    "blocking"
                } else if connection_has_blocking_safety_issue(metadata) {
                    "attention"
                } else if required_counts.contains_key(name) {
                    "required"
                } else {
                    "unused"
                },
            }
        })
        .collect();
    UiDatabaseConnectionsState {
        configured: true,
        dirty: database_connections.dirty,
        revision: database_connections.revision,
        source_path,
        required,
        missing_required,
        local,
        issues,
    }
}

fn collect_database_connection_safety_issues(
    source: &str,
    path: &str,
    name: &str,
    metadata: &DbConnectionMetadata,
    issues: &mut Vec<UiValidationIssue>,
) {
    if !metadata.readonly {
        issues.push(validation_issue(
            "database_connection_not_readonly",
            format!("{source} database connection '{name}' must set readonly=true"),
            Some(path.to_owned()),
        ));
    }
    if !metadata.require_tls {
        issues.push(validation_issue(
            "database_connection_tls_disabled",
            format!("{source} database connection '{name}' must keep require_tls=true"),
            Some(path.to_owned()),
        ));
    }
    if metadata.accept_invalid_tls_certs {
        issues.push(validation_issue(
            "database_connection_accepts_invalid_tls",
            format!(
                "{source} database connection '{name}' must keep accept_invalid_tls_certs=false"
            ),
            Some(path.to_owned()),
        ));
    }
    if metadata.skip_tls_hostname_verification {
        issues.push(validation_issue(
            "database_connection_skips_tls_hostname",
            format!(
                "{source} database connection '{name}' must keep skip_tls_hostname_verification=false"
            ),
            Some(path.to_owned()),
        ));
    }
}

fn connection_has_blocking_safety_issue(metadata: &DbConnectionMetadata) -> bool {
    !metadata.readonly
        || !metadata.require_tls
        || metadata.accept_invalid_tls_certs
        || metadata.skip_tls_hostname_verification
}

fn validate_draft_catalog(
    args: &UiArgs,
    draft: &Catalog,
    revision: u64,
    database_connections: &DatabaseConnectionsSnapshot,
) -> UiValidateOutput {
    let mut blocking_errors = Vec::new();
    let mut warnings = Vec::new();
    let mut generated_summary = None;
    let mut required_connections = BTreeSet::new();

    match draft.generate_runtime() {
        Ok(generated) => {
            for rule in &generated.runtime.rules {
                for scope in &rule.database_scopes {
                    required_connections.insert(scope.connection.clone());
                }
            }
            let temp_runtime_path = std::env::temp_dir().join(format!(
                "canopy-entitlements-ui-validate-{}.toml",
                random_url_token()
            ));
            let temp_runtime_sha256 = hex::encode(Sha256::digest(generated.toml.as_bytes()));
            let mut temp_runtime_removed = false;
            match fs::write(&temp_runtime_path, &generated.toml) {
                Ok(()) => match fs::remove_file(&temp_runtime_path) {
                    Ok(()) => {
                        temp_runtime_removed = true;
                    }
                    Err(err) => warnings.push(validation_issue(
                        "temp_runtime_cleanup_failed",
                        format!(
                            "temporary runtime '{}' could not be removed: {}",
                            temp_runtime_path.display(),
                            err.kind()
                        ),
                        Some(temp_runtime_path.display().to_string()),
                    )),
                },
                Err(err) => blocking_errors.push(validation_issue(
                    "temp_runtime_write_failed",
                    format!(
                        "failed to write temporary runtime '{}': {}",
                        temp_runtime_path.display(),
                        err.kind()
                    ),
                    Some(temp_runtime_path.display().to_string()),
                )),
            }

            let runtime_status = file_status(&args.runtime);
            let runtime_drift = match fs::read_to_string(&args.runtime) {
                Ok(runtime_content) => runtime_content != generated.toml,
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    warnings.push(validation_issue(
                        "runtime_missing",
                        format!(
                            "runtime file '{}' does not exist yet; apply would need to create it",
                            args.runtime.display()
                        ),
                        Some(args.runtime.display().to_string()),
                    ));
                    false
                }
                Err(err) => {
                    blocking_errors.push(validation_issue(
                        "runtime_unreadable",
                        format!(
                            "runtime file '{}' could not be read: {}",
                            args.runtime.display(),
                            err.kind()
                        ),
                        Some(args.runtime.display().to_string()),
                    ));
                    false
                }
            };
            if runtime_drift {
                warnings.push(validation_issue(
                    "runtime_drift",
                    format!(
                        "runtime file '{}' differs from the current draft output",
                        args.runtime.display()
                    ),
                    Some(args.runtime.display().to_string()),
                ));
            }

            generated_summary = Some(UiValidateGeneratedRuntime {
                runtime_path: args.runtime.display().to_string(),
                temp_runtime_path: temp_runtime_path.display().to_string(),
                temp_runtime_sha256,
                temp_runtime_removed,
                generated_rules: generated.runtime.rules.len(),
                group_mappings: generated.runtime.group_mappings.len(),
                memberships: generated.runtime.memberships.len(),
                runtime_exists: runtime_status.exists,
                runtime_drift,
            });
        }
        Err(err) => blocking_errors.push(validation_issue(
            "draft_runtime_generation_failed",
            format!("draft runtime generation failed: {err:#}"),
            Some(args.catalog.display().to_string()),
        )),
    }

    let required = required_connections.into_iter().collect::<Vec<_>>();
    let mut local_config_names = Vec::new();
    let mut local_registry = BTreeMap::new();
    if required.is_empty() {
        if args.db_config.is_none() {
            warnings.push(validation_issue(
                "db_config_not_required",
                "draft has no database scopes; no local DB connection snippet is required",
                None,
            ));
        }
    } else if let Some(issue) = database_connections.load_error.clone() {
        blocking_errors.push(issue);
    } else if database_connections.source_path.is_some() || !database_connections.draft.is_empty() {
        local_config_names = database_connections.draft.keys().cloned().collect();
        let local_path = database_connections
            .source_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("database connection draft"));
        validate_required_connections(
            "db_config",
            &local_path,
            &required,
            &database_connections.draft,
            &mut blocking_errors,
        );
        local_registry = database_connections.draft.clone();
    } else {
        blocking_errors.push(validation_issue(
            "missing_db_config",
            "draft uses database scopes, but --db-config was not provided",
            None,
        ));
    }

    let mut deployment = UiValidateDeployment {
        mode: args.deployment_mode.clone(),
        canonical_path: None,
        canonical_sha256: None,
        checked: false,
    };
    let mut deployment_names = Vec::new();
    if required.is_empty() && args.deployment_mode.is_none() {
        warnings.push(validation_issue(
            "deployment_source_not_required",
            "draft has no database scopes; deployment source cross-check was skipped",
            None,
        ));
    } else {
        validate_deployment_source(
            args,
            &required,
            &local_registry,
            &mut deployment,
            &mut deployment_names,
            &mut blocking_errors,
        );
    }

    let valid = blocking_errors.is_empty();
    UiValidateOutput {
        status: if valid { "valid" } else { "invalid" },
        command: "validate",
        valid,
        revision,
        generated: generated_summary,
        deployment,
        database_connections: UiValidateDatabaseConnections {
            required,
            local_config: local_config_names,
            deployment_source: deployment_names,
        },
        blocking_errors,
        warnings,
    }
}

fn apply_gate_status(
    args: &UiArgs,
    validation: &UiValidateOutput,
    baseline: Option<&Catalog>,
    transaction: &UiApplyTransactionStatus,
) -> (StatusCode, &'static str, UiApplyGate) {
    let admin_group = if args.allow_dev_identity {
        args.dev_admin_group.clone()
    } else {
        "admin".to_owned()
    };
    let mut gate = UiApplyGate {
        state: "locked",
        reason_code: "apply_locked",
        message: String::new(),
        identity_source: args.identity_source.clone(),
        admin_group,
        dev_identity_allowed: args.allow_dev_identity,
        can_apply: false,
    };

    if !validation.valid {
        gate.state = "validation_blocked";
        gate.reason_code = "validation_blocked";
        gate.message =
            "Apply requires a clean validation result; fix blocking validation issues first."
                .to_owned();
        return (StatusCode::CONFLICT, "blocked", gate);
    }

    if args.identity_source == "dev-claims" || args.allow_dev_identity {
        gate.reason_code = "dev_identity_apply_disabled";
        gate.message = "Development identity claims can preview, validate, explain, and dry-run drafts, but cannot apply true catalog or runtime files.".to_owned();
        return (StatusCode::FORBIDDEN, "locked", gate);
    }

    match canonical_admin_group(args) {
        Ok(admin_group) => gate.admin_group = admin_group,
        Err(message) => {
            gate.state = "admin_blocked";
            gate.reason_code = "canonical_auth_config_invalid";
            gate.message = message;
            return (StatusCode::CONFLICT, "blocked", gate);
        }
    }

    let Some(baseline) = baseline else {
        gate.state = "admin_blocked";
        gate.reason_code = "baseline_catalog_unavailable";
        gate.message =
            "Apply requires the persisted baseline catalog for the canonical admin gate."
                .to_owned();
        return (StatusCode::CONFLICT, "blocked", gate);
    };

    let operator = match startup_operator_explain_request(args) {
        Ok(operator) => operator,
        Err(message) => {
            gate.state = "admin_blocked";
            gate.reason_code = "operator_identity_unavailable";
            gate.message = message;
            return (StatusCode::FORBIDDEN, "locked", gate);
        }
    };
    match baseline.explain(operator) {
        Ok(explain) => {
            if !explain
                .resolved_groups
                .iter()
                .any(|group| group == &gate.admin_group)
            {
                gate.state = "admin_blocked";
                gate.reason_code = "non_admin_identity";
                gate.message = format!(
                    "Operator identity did not resolve to canonical admin group '{}' in the persisted baseline catalog.",
                    gate.admin_group
                );
                return (StatusCode::FORBIDDEN, "locked", gate);
            }
        }
        Err(err) => {
            gate.state = "admin_blocked";
            gate.reason_code = "baseline_admin_resolution_failed";
            gate.message = format!("baseline admin gate resolution failed: {err}");
            return (StatusCode::CONFLICT, "blocked", gate);
        }
    }

    if transaction.lock_exists {
        gate.state = "transaction_blocked";
        gate.reason_code = "transaction_lock_exists";
        gate.message = format!(
            "Apply requires exclusive transaction ownership, but lock file '{}' already exists; recover or remove the incomplete transaction before retrying.",
            transaction.lock_path.as_deref().unwrap_or("unknown")
        );
        return (StatusCode::CONFLICT, "blocked", gate);
    }

    if let Some(lock_error) = transaction.lock_error.as_deref() {
        gate.state = "transaction_blocked";
        gate.reason_code = "transaction_lock_unavailable";
        gate.message = format!(
            "Apply could not inspect transaction lock file '{}': {lock_error}.",
            transaction.lock_path.as_deref().unwrap_or("unknown")
        );
        return (StatusCode::CONFLICT, "blocked", gate);
    }

    if transaction.manifest_exists {
        gate.state = "transaction_blocked";
        gate.reason_code = "transaction_manifest_exists";
        gate.message = format!(
            "Apply found transaction manifest '{}' from an incomplete transaction; recover or remove it before retrying.",
            transaction.manifest_path.as_deref().unwrap_or("unknown")
        );
        return (StatusCode::CONFLICT, "blocked", gate);
    }

    if let Some(manifest_error) = transaction.manifest_error.as_deref() {
        gate.state = "transaction_blocked";
        gate.reason_code = "transaction_manifest_unavailable";
        gate.message = format!(
            "Apply could not inspect transaction manifest '{}': {manifest_error}.",
            transaction.manifest_path.as_deref().unwrap_or("unknown")
        );
        return (StatusCode::CONFLICT, "blocked", gate);
    }

    if !transaction.baseline_mismatches.is_empty() {
        gate.state = "transaction_blocked";
        gate.reason_code = "baseline_digest_mismatch";
        gate.message = "Apply requires catalog, runtime, and DB config files to match the startup baseline digest; restart or refresh the UI after reviewing external changes.".to_owned();
        return (StatusCode::CONFLICT, "blocked", gate);
    }

    gate.state = "admin_ready";
    gate.reason_code = "apply_transaction_unavailable";
    gate.message = "Apply remains locked until canonical operator authorization and the catalog/runtime transaction protocol are enabled.".to_owned();
    (StatusCode::FORBIDDEN, "locked", gate)
}

fn canonical_admin_group(args: &UiArgs) -> Result<String, String> {
    let Some(path) = args.auth_config.as_deref() else {
        return Ok("admin".to_owned());
    };
    validate_auth_config_file_path(path).map_err(|err| {
        format!(
            "canonical auth config '{}' failed protected file validation: {err:#}",
            path.display()
        )
    })?;
    let content = fs::read_to_string(path).map_err(|err| {
        format!(
            "failed to read canonical auth config '{}': {err}",
            path.display()
        )
    })?;
    let config = toml::from_str::<UiAuthConfigFile>(&content).map_err(|err| {
        format!(
            "failed to parse canonical auth config '{}': {err}",
            path.display()
        )
    })?;
    let admin_group = config.admin_group.unwrap_or_else(|| "admin".to_owned());
    let admin_group = admin_group.trim();
    if admin_group.is_empty() {
        return Err(format!(
            "canonical auth config '{}' has an empty admin_group",
            path.display()
        ));
    }
    Ok(admin_group.to_owned())
}

fn startup_operator_explain_request(args: &UiArgs) -> Result<catalog::ExplainRequest, String> {
    explain_request_from_body(
        args,
        ExplainRequestBody {
            sub: None,
            email: None,
            email_verified: None,
            external_groups: None,
        },
    )
    .map_err(|err| err.message)
}

fn validate_deployment_source(
    args: &UiArgs,
    required: &[String],
    local_registry: &BTreeMap<String, DbConnectionMetadata>,
    deployment: &mut UiValidateDeployment,
    deployment_names: &mut Vec<String>,
    blocking_errors: &mut Vec<UiValidationIssue>,
) {
    match args.deployment_mode.as_deref() {
        Some("config") => {
            let Some(path) = args.deployment_config.as_deref() else {
                blocking_errors.push(validation_issue(
                    "missing_deployment_config",
                    "deployment-mode=config requires --deployment-config",
                    None,
                ));
                return;
            };
            deployment.canonical_path = Some(path.display().to_string());
            deployment.canonical_sha256 = file_sha256(path);
            match load_connection_registry_from_file(path) {
                Ok(registry) => {
                    deployment.checked = true;
                    *deployment_names = registry.keys().cloned().collect();
                    validate_required_connections(
                        "deployment_config",
                        path,
                        required,
                        &registry,
                        blocking_errors,
                    );
                    validate_deployment_matches_local(
                        path,
                        required,
                        local_registry,
                        &registry,
                        blocking_errors,
                    );
                }
                Err(issue) => blocking_errors.push(issue),
            }
        }
        Some("terraform") => {
            let Some(path) = args.tfvars.as_deref() else {
                blocking_errors.push(validation_issue(
                    "missing_tfvars",
                    "deployment-mode=terraform requires --tfvars",
                    None,
                ));
                return;
            };
            deployment.canonical_path = Some(path.display().to_string());
            deployment.canonical_sha256 = file_sha256(path);
            match load_connection_registry_from_tfvars(path) {
                Ok(registry) => {
                    deployment.checked = true;
                    *deployment_names = registry.keys().cloned().collect();
                    validate_required_connections(
                        "tfvars_database_connections_toml",
                        path,
                        required,
                        &registry,
                        blocking_errors,
                    );
                    validate_deployment_matches_local(
                        path,
                        required,
                        local_registry,
                        &registry,
                        blocking_errors,
                    );
                }
                Err(issue) => blocking_errors.push(issue),
            }
        }
        Some(mode) => blocking_errors.push(validation_issue(
            "unsupported_deployment_mode",
            format!("deployment mode '{mode}' is not supported; use config or terraform"),
            None,
        )),
        None => {
            if !required.is_empty() {
                blocking_errors.push(validation_issue(
                    "missing_deployment_mode",
                    "draft uses database scopes, but --deployment-mode was not provided",
                    None,
                ));
            }
        }
    }
}

fn validate_required_connections(
    source: &str,
    path: &Path,
    required: &[String],
    registry: &BTreeMap<String, DbConnectionMetadata>,
    blocking_errors: &mut Vec<UiValidationIssue>,
) {
    for connection in required {
        let Some(metadata) = registry.get(connection) else {
            blocking_errors.push(validation_issue(
                "missing_database_connection",
                format!("{source} is missing required database connection '{connection}'"),
                Some(path.display().to_string()),
            ));
            continue;
        };
        if !metadata.readonly {
            blocking_errors.push(validation_issue(
                "database_connection_not_readonly",
                format!("{source} database connection '{connection}' must set readonly=true"),
                Some(path.display().to_string()),
            ));
        }
        if !metadata.require_tls {
            blocking_errors.push(validation_issue(
                "database_connection_tls_disabled",
                format!("{source} database connection '{connection}' must keep require_tls=true"),
                Some(path.display().to_string()),
            ));
        }
        if metadata.accept_invalid_tls_certs {
            blocking_errors.push(validation_issue(
                "database_connection_accepts_invalid_tls",
                format!(
                    "{source} database connection '{connection}' must keep accept_invalid_tls_certs=false"
                ),
                Some(path.display().to_string()),
            ));
        }
        if metadata.skip_tls_hostname_verification {
            blocking_errors.push(validation_issue(
                "database_connection_skips_tls_hostname",
                format!(
                    "{source} database connection '{connection}' must keep skip_tls_hostname_verification=false"
                ),
                Some(path.display().to_string()),
            ));
        }
    }
}

fn validate_deployment_matches_local(
    path: &Path,
    required: &[String],
    local: &BTreeMap<String, DbConnectionMetadata>,
    deployment: &BTreeMap<String, DbConnectionMetadata>,
    blocking_errors: &mut Vec<UiValidationIssue>,
) {
    for connection in required {
        let (Some(local), Some(deployed)) = (local.get(connection), deployment.get(connection))
        else {
            continue;
        };
        if local != deployed {
            blocking_errors.push(validation_issue(
                "database_connection_deploy_drift",
                format!(
                    "database connection '{connection}' differs between --db-config and deployment source"
                ),
                Some(path.display().to_string()),
            ));
        }
    }
}

fn load_connection_registry_from_file(
    path: &Path,
) -> Result<BTreeMap<String, DbConnectionMetadata>, UiValidationIssue> {
    let content = fs::read_to_string(path).map_err(|err| {
        validation_issue(
            "database_config_unreadable",
            format!(
                "database connection config '{}' could not be read: {}",
                path.display(),
                err.kind()
            ),
            Some(path.display().to_string()),
        )
    })?;
    parse_connection_registry(&content, path)
}

fn load_connection_registry_from_tfvars(
    path: &Path,
) -> Result<BTreeMap<String, DbConnectionMetadata>, UiValidationIssue> {
    let content = fs::read_to_string(path).map_err(|err| {
        validation_issue(
            "tfvars_unreadable",
            format!(
                "tfvars '{}' could not be read: {}",
                path.display(),
                err.kind()
            ),
            Some(path.display().to_string()),
        )
    })?;
    let snippet = extract_tfvars_database_connections_toml(&content).ok_or_else(|| {
        validation_issue(
            "tfvars_missing_database_connections_toml",
            "tfvars does not define database_connections_toml",
            Some(path.display().to_string()),
        )
    })?;
    parse_connection_registry(&snippet, path)
}

fn parse_connection_registry(
    content: &str,
    path: &Path,
) -> Result<BTreeMap<String, DbConnectionMetadata>, UiValidationIssue> {
    let value = content.parse::<toml::Value>().map_err(|err| {
        validation_issue(
            "database_config_parse_failed",
            format!(
                "database connection TOML '{}' could not be parsed: {err}",
                path.display()
            ),
            Some(path.display().to_string()),
        )
    })?;
    let Some(connections) = value
        .get("database_connections")
        .and_then(toml::Value::as_table)
    else {
        return Ok(BTreeMap::new());
    };
    let mut registry = BTreeMap::new();
    for (name, raw) in connections {
        let table = raw.as_table().ok_or_else(|| {
            validation_issue(
                "database_connection_not_table",
                format!("database_connections.{name} must be a table"),
                Some(path.display().to_string()),
            )
        })?;
        if table.contains_key("username") || table.contains_key("password") {
            return Err(validation_issue(
                "database_connection_inline_secret",
                format!("database_connections.{name} must not contain username or password"),
                Some(path.display().to_string()),
            ));
        }
        let engine = required_nonempty_toml_string(table, "engine", name, path)?;
        let host = required_nonempty_toml_string(table, "host", name, path)?;
        let database = required_nonempty_toml_string(table, "database", name, path)?;
        let secret_arn = required_toml_string(table, "secret_arn", name, path)?;
        if secret_arn.trim().is_empty() {
            return Err(validation_issue(
                "database_connection_empty_secret_ref",
                format!("database_connections.{name}.secret_arn must not be empty"),
                Some(path.display().to_string()),
            ));
        }
        registry.insert(
            name.clone(),
            DbConnectionMetadata {
                engine,
                host,
                port: optional_toml_integer(table, "port", 3306, name, path)?,
                database,
                secret_arn,
                readonly: optional_toml_bool(table, "readonly", false, name, path)?,
                connect_timeout_ms: optional_toml_integer(
                    table,
                    "connect_timeout_ms",
                    3000,
                    name,
                    path,
                )?,
                statement_timeout_ms: optional_toml_integer(
                    table,
                    "statement_timeout_ms",
                    5000,
                    name,
                    path,
                )?,
                explain_timeout_ms: optional_toml_integer(
                    table,
                    "explain_timeout_ms",
                    3000,
                    name,
                    path,
                )?,
                max_connections: optional_toml_integer(table, "max_connections", 4, name, path)?,
                require_tls: optional_toml_bool(table, "require_tls", true, name, path)?,
                accept_invalid_tls_certs: optional_toml_bool(
                    table,
                    "accept_invalid_tls_certs",
                    false,
                    name,
                    path,
                )?,
                skip_tls_hostname_verification: optional_toml_bool(
                    table,
                    "skip_tls_hostname_verification",
                    false,
                    name,
                    path,
                )?,
            },
        );
    }
    Ok(registry)
}

fn optional_toml_integer(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
    default: i64,
    name: &str,
    path: &Path,
) -> Result<i64, UiValidationIssue> {
    let Some(value) = table.get(key) else {
        return Ok(default);
    };
    value.as_integer().ok_or_else(|| {
        validation_issue(
            "database_connection_invalid_field_type",
            format!("database_connections.{name}.{key} must be an integer"),
            Some(path.display().to_string()),
        )
    })
}

fn optional_toml_bool(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
    default: bool,
    name: &str,
    path: &Path,
) -> Result<bool, UiValidationIssue> {
    let Some(value) = table.get(key) else {
        return Ok(default);
    };
    value.as_bool().ok_or_else(|| {
        validation_issue(
            "database_connection_invalid_field_type",
            format!("database_connections.{name}.{key} must be a boolean"),
            Some(path.display().to_string()),
        )
    })
}

fn required_toml_string(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
    name: &str,
    path: &Path,
) -> Result<String, UiValidationIssue> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            validation_issue(
                "database_connection_missing_field",
                format!("database_connections.{name}.{key} is required"),
                Some(path.display().to_string()),
            )
        })
}

fn required_nonempty_toml_string(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
    name: &str,
    path: &Path,
) -> Result<String, UiValidationIssue> {
    let value = required_toml_string(table, key, name, path)?;
    if value.trim().is_empty() {
        return Err(validation_issue(
            "database_connection_empty_field",
            format!("database_connections.{name}.{key} must not be empty"),
            Some(path.display().to_string()),
        ));
    }
    Ok(value)
}

fn extract_tfvars_database_connections_toml(content: &str) -> Option<String> {
    let mut lines = content.lines();
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, raw_value)) = trimmed.split_once('=') else {
            continue;
        };
        if key.trim() != "database_connections_toml" {
            continue;
        }
        let value = raw_value.trim();
        if let Some(delimiter) = value
            .strip_prefix("<<-")
            .or_else(|| value.strip_prefix("<<"))
        {
            let delimiter = delimiter.trim();
            let mut snippet = String::new();
            for line in lines.by_ref() {
                if line.trim() == delimiter {
                    return Some(snippet);
                }
                snippet.push_str(line);
                snippet.push('\n');
            }
            return None;
        }
        if value.starts_with('"') {
            let parsed = format!("value = {value}").parse::<toml::Value>().ok()?;
            return parsed
                .get("value")
                .and_then(toml::Value::as_str)
                .map(str::to_owned);
        }
    }
    None
}

fn validation_issue(
    code: impl Into<String>,
    message: impl Into<String>,
    path: Option<String>,
) -> UiValidationIssue {
    UiValidationIssue {
        code: code.into(),
        message: message.into(),
        path,
    }
}

fn file_sha256(path: &Path) -> Option<String> {
    fs::read(path)
        .ok()
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
}

fn transaction_artifact_paths(catalog_path: &Path) -> (PathBuf, PathBuf) {
    let artifact_dir = catalog_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let digest = hex::encode(Sha256::digest(catalog_path.display().to_string()));
    let prefix = format!(".canopy-entitlements-transaction-{}", &digest[..16]);
    (
        artifact_dir.join(format!("{prefix}.lock")),
        artifact_dir.join(format!("{prefix}.manifest.json")),
    )
}

fn transaction_lock_status(lock_path: &Path) -> (bool, Option<String>) {
    transaction_artifact_status(lock_path)
}

fn transaction_artifact_status(path: &Path) -> (bool, Option<String>) {
    match fs::symlink_metadata(path) {
        Ok(_) => (true, None),
        Err(err) if err.kind() == io::ErrorKind::NotFound => (false, None),
        Err(err) => (false, Some(err.kind().to_string())),
    }
}

fn explain_request_from_body(
    args: &UiArgs,
    request: ExplainRequestBody,
) -> Result<catalog::ExplainRequest, UiMutationError> {
    Ok(catalog::ExplainRequest {
        sub: required_identity_sub(request.sub, args)?,
        email: trimmed_optional(request.email)
            .or_else(|| trimmed_optional(args.dev_operator_email.clone())),
        email_verified: request
            .email_verified
            .unwrap_or(args.dev_operator_email_verified),
        external_groups: request
            .external_groups
            .unwrap_or_else(|| args.dev_operator_external_groups.clone())
            .into_iter()
            .filter_map(trimmed_string)
            .collect(),
    })
}

fn dry_run_request_from_body(
    args: &UiArgs,
    request: DryRunRequestBody,
) -> Result<catalog::DryRunRequest, UiMutationError> {
    let operation = trimmed_string(request.operation).ok_or_else(|| {
        UiMutationError::bad_request("empty_dry_run_operation", "operation is required")
    })?;
    Ok(catalog::DryRunRequest {
        operation,
        sub: required_identity_sub(request.sub, args)?,
        email: trimmed_optional(request.email)
            .or_else(|| trimmed_optional(args.dev_operator_email.clone())),
        email_verified: request
            .email_verified
            .unwrap_or(args.dev_operator_email_verified),
        external_groups: request
            .external_groups
            .unwrap_or_else(|| args.dev_operator_external_groups.clone())
            .into_iter()
            .filter_map(trimmed_string)
            .collect(),
        account: trimmed_optional(request.account),
        region: trimmed_optional(request.region),
        cluster: trimmed_optional(request.cluster),
        log_group_arn: trimmed_optional(request.log_group_arn),
        os_user: trimmed_optional(request.os_user),
        instance_tags: request
            .instance_tags
            .into_iter()
            .filter_map(trimmed_string)
            .collect(),
        task_tags: request
            .task_tags
            .into_iter()
            .filter_map(trimmed_string)
            .collect(),
        container: trimmed_optional(request.container),
        scope: trimmed_optional(request.scope),
        connection: trimmed_optional(request.connection),
        environment: trimmed_optional(request.environment),
        schema: trimmed_optional(request.schema),
        table: trimmed_optional(request.table),
        action: trimmed_optional(request.action),
    })
}

fn required_identity_sub(
    request_sub: Option<String>,
    args: &UiArgs,
) -> Result<String, UiMutationError> {
    trimmed_optional(request_sub)
        .or_else(|| args.dev_operator_sub.clone())
        .and_then(trimmed_string)
        .ok_or_else(|| {
            UiMutationError::bad_request(
                "missing_operator_subject",
                "operator subject is required for explain and dry-run",
            )
        })
}

fn trimmed_optional(value: Option<String>) -> Option<String> {
    value.and_then(trimmed_string)
}

fn trimmed_string(value: String) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

impl UiPendingChanges {
    fn empty() -> Self {
        Self {
            added_bindings: Vec::new(),
            removed_bindings: Vec::new(),
            added_memberships: Vec::new(),
            removed_memberships: Vec::new(),
            added_group_mappings: Vec::new(),
            removed_group_mappings: Vec::new(),
            added_scope_resources: Vec::new(),
            removed_scope_resources: Vec::new(),
            added_accounts: Vec::new(),
            removed_accounts: Vec::new(),
            updated_accounts: Vec::new(),
            added_roles: Vec::new(),
            removed_roles: Vec::new(),
            updated_roles: Vec::new(),
            added_packages: Vec::new(),
            removed_packages: Vec::new(),
            updated_packages: Vec::new(),
            high_risk_added: 0,
            high_risk_removed: 0,
            semantic_diff: UiSemanticDiff::empty(),
        }
    }
}

impl UiSemanticDiff {
    fn empty() -> Self {
        Self {
            added: Vec::new(),
            removed: Vec::new(),
            high_risk: Vec::new(),
            error: None,
        }
    }

    fn error(error: anyhow::Error) -> Self {
        Self {
            added: Vec::new(),
            removed: Vec::new(),
            high_risk: Vec::new(),
            error: Some(format!("{error:#}")),
        }
    }
}

fn known_groups(catalog: &Catalog) -> BTreeSet<String> {
    catalog
        .bindings
        .iter()
        .map(|binding| binding.group.clone())
        .chain(
            catalog
                .memberships
                .iter()
                .map(|membership| membership.group.clone()),
        )
        .chain(
            catalog
                .group_mappings
                .iter()
                .map(|mapping| mapping.canopy_group.clone()),
        )
        .collect()
}

fn account_summaries(catalog: &Catalog) -> Vec<UiAccountSummary> {
    let scopes_by_account = catalog.scopes.iter().fold(
        BTreeMap::<&str, BTreeSet<String>>::new(),
        |mut accounts, scope| {
            for account in &scope.accounts {
                accounts
                    .entry(account.as_str())
                    .or_default()
                    .insert(scope.id.clone());
            }
            accounts
        },
    );
    let scope_by_id = catalog
        .scopes
        .iter()
        .map(|scope| (scope.id.as_str(), scope))
        .collect::<BTreeMap<_, _>>();
    let mut packages_by_account = BTreeMap::<&str, BTreeSet<String>>::new();
    let mut roles_by_account = BTreeMap::<&str, BTreeSet<String>>::new();
    for package in &catalog.packages {
        let Some(scope) = scope_by_id.get(package.scope.as_str()) else {
            continue;
        };
        for account in &scope.accounts {
            packages_by_account
                .entry(account.as_str())
                .or_default()
                .insert(package.id.clone());
            roles_by_account
                .entry(account.as_str())
                .or_default()
                .insert(package.role.clone());
        }
    }

    let mut accounts = catalog
        .accounts
        .iter()
        .map(|account| UiAccountSummary {
            id: account.id.clone(),
            account_id: account.account_id.clone(),
            name: account.name.clone(),
            scopes: map_set_values(&scopes_by_account, account.id.as_str()),
            packages: map_set_values(&packages_by_account, account.id.as_str()),
            roles: map_set_values(&roles_by_account, account.id.as_str()),
        })
        .collect::<Vec<_>>();
    accounts.sort_by(|left, right| left.id.cmp(&right.id));
    accounts
}

fn role_summaries(catalog: &Catalog) -> Vec<UiRoleSummary> {
    let scope_by_id = catalog
        .scopes
        .iter()
        .map(|scope| (scope.id.as_str(), scope))
        .collect::<BTreeMap<_, _>>();
    let mut accounts_by_role = BTreeMap::<&str, BTreeSet<String>>::new();
    let mut packages_by_role = BTreeMap::<&str, BTreeSet<String>>::new();
    for package in &catalog.packages {
        packages_by_role
            .entry(package.role.as_str())
            .or_default()
            .insert(package.id.clone());
        let Some(scope) = scope_by_id.get(package.scope.as_str()) else {
            continue;
        };
        for account in &scope.accounts {
            accounts_by_role
                .entry(package.role.as_str())
                .or_default()
                .insert(account.clone());
        }
    }

    let mut roles = catalog
        .roles
        .iter()
        .map(|role| UiRoleSummary {
            id: role.id.clone(),
            role_arn: role.role_arn.clone(),
            mode: role_mode(&role.role_arn),
            accounts: map_set_values(&accounts_by_role, role.id.as_str()),
            packages: map_set_values(&packages_by_role, role.id.as_str()),
        })
        .collect::<Vec<_>>();
    roles.sort_by(|left, right| left.id.cmp(&right.id));
    roles
}

fn map_set_values(map: &BTreeMap<&str, BTreeSet<String>>, key: &str) -> Vec<String> {
    map.get(key)
        .map(|values| values.iter().cloned().collect())
        .unwrap_or_default()
}

fn role_mode(role_arn: &str) -> &'static str {
    if role_arn == "direct" {
        "direct"
    } else if role_arn.starts_with("profile:") {
        "profile"
    } else if role_arn.contains("{account_id}") {
        "template"
    } else {
        "concrete"
    }
}

fn package_summaries(catalog: &Catalog) -> Vec<UiPackageSummary> {
    let scopes_by_id = catalog
        .scopes
        .iter()
        .map(|scope| (scope.id.as_str(), scope))
        .collect::<BTreeMap<_, _>>();
    let mut packages = catalog
        .packages
        .iter()
        .map(|package| {
            let scope = scopes_by_id.get(package.scope.as_str());
            UiPackageSummary {
                id: package.id.clone(),
                features: package.features.clone(),
                high_risk_features: high_risk_features(package),
                scope: package.scope.clone(),
                role: package.role.clone(),
                database_scope_count: scope.map_or(0, |scope| scope.database_scopes.len()),
                database_scopes: scope
                    .map(|scope| {
                        scope
                            .database_scopes
                            .iter()
                            .map(|database_scope| UiDatabaseScopeSummary {
                                name: database_scope.name.clone(),
                                connection: database_scope.connection.clone(),
                                environment: database_scope.environment.clone(),
                                allowed_schemas: database_scope.allowed_schemas.clone(),
                                allowed_tables: database_scope.allowed_tables.clone(),
                                allowed_actions: database_scope.allowed_actions.clone(),
                                max_rows: database_scope.max_rows,
                                statement_timeout_ms: database_scope.statement_timeout_ms,
                                require_explain: database_scope.require_explain,
                                max_examined_rows: database_scope.max_examined_rows,
                                allow_full_table_scan: database_scope.allow_full_table_scan,
                                allow_views: database_scope.allow_views,
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                mcp_ec2_diagnostic_scope_count: scope
                    .map_or(0, |scope| scope.mcp_ec2_diagnostic_scopes.len()),
                max_session_seconds: package.max_session_seconds,
            }
        })
        .collect::<Vec<_>>();
    packages.sort_by(|left, right| left.id.cmp(&right.id));
    packages
}

fn group_summaries(catalog: &Catalog) -> Vec<UiGroupSummary> {
    let package_by_id = catalog
        .packages
        .iter()
        .map(|package| (package.id.as_str(), package))
        .collect::<BTreeMap<_, _>>();
    let mut groups = known_groups(catalog)
        .into_iter()
        .map(|group| {
            let bound_packages = catalog
                .bindings
                .iter()
                .filter(|binding| binding.group == group)
                .filter_map(|binding| package_by_id.get(binding.package.as_str()).copied())
                .collect::<Vec<_>>();
            UiGroupSummary {
                id: group.clone(),
                member_count: catalog
                    .memberships
                    .iter()
                    .filter(|membership| membership.group == group)
                    .count(),
                external_mapping_count: catalog
                    .group_mappings
                    .iter()
                    .filter(|mapping| mapping.canopy_group == group)
                    .count(),
                members: catalog
                    .memberships
                    .iter()
                    .filter(|membership| membership.group == group)
                    .map(|membership| membership.user_id.clone())
                    .collect(),
                external_mappings: catalog
                    .group_mappings
                    .iter()
                    .filter(|mapping| mapping.canopy_group == group)
                    .map(|mapping| mapping.external_group.clone())
                    .collect(),
                package_count: bound_packages.len(),
                high_risk_package_count: bound_packages
                    .iter()
                    .filter(|package| !high_risk_features(package).is_empty())
                    .count(),
            }
        })
        .collect::<Vec<_>>();
    groups.sort_by(|left, right| left.id.cmp(&right.id));
    groups
}

fn binding_summaries(catalog: &Catalog) -> Vec<UiBindingSummary> {
    let mut bindings = catalog
        .bindings
        .iter()
        .map(|binding| UiBindingSummary {
            group: binding.group.clone(),
            package: binding.package.clone(),
        })
        .collect::<Vec<_>>();
    bindings.sort_by(|left, right| {
        left.group
            .cmp(&right.group)
            .then_with(|| left.package.cmp(&right.package))
    });
    bindings
}

fn scope_summaries(catalog: &Catalog) -> Vec<UiScopeSummary> {
    let packages_by_scope = catalog.packages.iter().fold(
        BTreeMap::<&str, Vec<String>>::new(),
        |mut scopes, package| {
            scopes
                .entry(package.scope.as_str())
                .or_default()
                .push(package.id.clone());
            scopes
        },
    );
    let mut scopes = catalog
        .scopes
        .iter()
        .map(|scope| scope_summary(scope, &packages_by_scope))
        .collect::<Vec<_>>();
    scopes.sort_by(|left, right| left.id.cmp(&right.id));
    scopes
}

fn scope_summary(
    scope: &CatalogScope,
    packages_by_scope: &BTreeMap<&str, Vec<String>>,
) -> UiScopeSummary {
    UiScopeSummary {
        id: scope.id.clone(),
        description: scope.metadata.description.clone(),
        business_scopes: scope
            .metadata
            .scopes
            .iter()
            .map(|metadata| {
                let aliases = if metadata.aliases.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", metadata.aliases.join(", "))
                };
                format!(
                    "{} / {}{}",
                    metadata.platform, metadata.environment, aliases
                )
            })
            .collect(),
        accounts: scope.accounts.clone(),
        regions: scope.regions.clone(),
        log_group_arns: scope.log_group_arns.clone(),
        clusters: scope.clusters.clone(),
        os_users: scope.os_users.clone(),
        instance_tag_selectors: tag_selector_summaries(&scope.instance_tag_selectors),
        excluded_tag_selectors: tag_selector_summaries(&scope.excluded_tag_selectors),
        task_tag_selectors: tag_selector_summaries(&scope.task_tag_selectors),
        excluded_task_tag_selectors: tag_selector_summaries(&scope.excluded_task_tag_selectors),
        excluded_container_names: scope.excluded_container_names.clone(),
        allow_broad_cluster_discovery: scope.allow_broad_cluster_discovery,
        database_scopes: scope
            .database_scopes
            .iter()
            .map(|database_scope| UiDatabaseScopeSummary {
                name: database_scope.name.clone(),
                connection: database_scope.connection.clone(),
                environment: database_scope.environment.clone(),
                allowed_schemas: database_scope.allowed_schemas.clone(),
                allowed_tables: database_scope.allowed_tables.clone(),
                allowed_actions: database_scope.allowed_actions.clone(),
                max_rows: database_scope.max_rows,
                statement_timeout_ms: database_scope.statement_timeout_ms,
                require_explain: database_scope.require_explain,
                max_examined_rows: database_scope.max_examined_rows,
                allow_full_table_scan: database_scope.allow_full_table_scan,
                allow_views: database_scope.allow_views,
            })
            .collect(),
        mcp_ec2_diagnostic_scopes: scope
            .mcp_ec2_diagnostic_scopes
            .iter()
            .map(|ec2_scope| UiMcpEc2ScopeSummary {
                id: ec2_scope.id.clone(),
                log_paths: ec2_scope
                    .allowed_log_paths
                    .iter()
                    .map(|path| path.path_pattern.clone())
                    .collect(),
                journal_units: ec2_scope
                    .allowed_journal_units
                    .iter()
                    .map(|unit| unit.unit.clone())
                    .collect(),
                http_urls: ec2_scope
                    .allowed_http_urls
                    .iter()
                    .map(|url| url.normalized_url.clone())
                    .collect(),
                tcp_targets: ec2_scope
                    .allowed_tcp_targets
                    .iter()
                    .map(|target| format!("{}:{}", target.host, target.port))
                    .collect(),
                dns_targets: ec2_scope
                    .allowed_dns_targets
                    .iter()
                    .map(|target| {
                        let records = target
                            .record_types
                            .iter()
                            .map(|record| format!("{record:?}"))
                            .collect::<Vec<_>>()
                            .join(",");
                        format!("{} [{}]", target.host, records)
                    })
                    .collect(),
                allowed_log_paths: ec2_scope
                    .allowed_log_paths
                    .iter()
                    .map(|path| UiMcpEc2LogPathSummary {
                        path_pattern: path.path_pattern.clone(),
                        canonical_safe_prefix: path.canonical_safe_prefix.clone(),
                        safe_for_mcp_output: path.safe_for_mcp_output,
                    })
                    .collect(),
                allowed_journal_units: ec2_scope
                    .allowed_journal_units
                    .iter()
                    .map(|unit| UiMcpEc2JournalUnitSummary {
                        unit: unit.unit.clone(),
                        safe_for_mcp_output: unit.safe_for_mcp_output,
                    })
                    .collect(),
                allowed_http_urls: ec2_scope
                    .allowed_http_urls
                    .iter()
                    .map(|url| UiMcpEc2HttpUrlSummary {
                        normalized_url: url.normalized_url.clone(),
                        query_policy: url.query_policy.clone(),
                        safe_for_mcp_output: url.safe_for_mcp_output,
                        private_target_ref: url.private_target_ref.clone(),
                    })
                    .collect(),
                allowed_tcp_targets: ec2_scope
                    .allowed_tcp_targets
                    .iter()
                    .map(|target| UiMcpEc2TcpTargetSummary {
                        host: target.host.clone(),
                        port: target.port,
                        private_target_ref: target.private_target_ref.clone(),
                    })
                    .collect(),
                allowed_dns_targets: ec2_scope
                    .allowed_dns_targets
                    .iter()
                    .map(|target| UiMcpEc2DnsTargetSummary {
                        host: target.host.clone(),
                        record_types: target.record_types.clone(),
                        safe_for_mcp_output: target.safe_for_mcp_output,
                        private_target_ref: target.private_target_ref.clone(),
                    })
                    .collect(),
                private_target_refs: ec2_scope.private_target_refs.clone(),
                max_lines: ec2_scope.max_lines,
                max_since_seconds: ec2_scope.max_since_seconds,
                max_timeout_seconds: ec2_scope.max_timeout_seconds,
                max_matches: ec2_scope.max_matches,
                connectivity_probe_budget_per_window: ec2_scope
                    .connectivity_probe_budget_per_window,
                budget_window_seconds: ec2_scope.budget_window_seconds,
                denylist_version: ec2_scope.denylist_version.clone(),
                allowlist_rule_id: ec2_scope.allowlist_rule_id.clone(),
                unsafe_output_count: ec2_unsafe_output_count(ec2_scope),
            })
            .collect(),
        packages: packages_by_scope
            .get(scope.id.as_str())
            .cloned()
            .unwrap_or_default(),
    }
}

fn tag_selector_summaries(selectors: &[shared::dto::entitlements::TagSelector]) -> Vec<String> {
    selectors
        .iter()
        .map(|selector| {
            let mut entries = selector.tags.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            entries
                .into_iter()
                .map(|(key, values)| format!("{key}={}", values.join("|")))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .collect()
}

fn ec2_unsafe_output_count(scope: &shared::dto::entitlements::McpEc2DiagnosticScope) -> usize {
    scope
        .allowed_log_paths
        .iter()
        .filter(|path| !path.safe_for_mcp_output)
        .count()
        + scope
            .allowed_journal_units
            .iter()
            .filter(|unit| !unit.safe_for_mcp_output)
            .count()
        + scope
            .allowed_http_urls
            .iter()
            .filter(|url| !url.safe_for_mcp_output)
            .count()
        + scope
            .allowed_dns_targets
            .iter()
            .filter(|target| !target.safe_for_mcp_output)
            .count()
}

fn feature_summaries() -> Vec<UiFeatureSummary> {
    catalog::feature_field_names()
        .iter()
        .map(|(feature, _)| UiFeatureSummary {
            id: feature,
            high_risk: catalog::is_high_risk_feature(feature),
        })
        .collect()
}

fn known_catalog_feature(feature: &str) -> bool {
    catalog::feature_field_names()
        .iter()
        .any(|(candidate, _)| *candidate == feature)
}

fn required_base_feature(feature: &str) -> Option<&'static str> {
    match feature {
        "mcp:cloudwatch" | "mcp:raw-audit-plaintext" | "mcp:ec2" | "mcp:database" => {
            Some("mcp:use")
        }
        "ecs:exec" => Some("ecs:view"),
        "ec2:instance-connect" | "ec2:start" | "ec2:stop" | "ec2:reboot" => Some("ec2:view"),
        _ => None,
    }
}

fn disabling_required_base(feature: &str, features: &[String]) -> bool {
    match feature {
        "mcp:use" => features
            .iter()
            .any(|candidate| candidate.starts_with("mcp:") && candidate != "mcp:use"),
        "ecs:view" => features.iter().any(|candidate| candidate == "ecs:exec"),
        "ec2:view" => features.iter().any(|candidate| {
            matches!(
                candidate.as_str(),
                "ec2:instance-connect" | "ec2:start" | "ec2:stop" | "ec2:reboot"
            )
        }),
        _ => false,
    }
}

fn add_feature_once(features: &mut Vec<String>, feature: &str) {
    if !features.iter().any(|candidate| candidate == feature) {
        features.push(feature.to_owned());
    }
}

fn order_catalog_features(features: &mut Vec<String>) {
    let order = catalog::feature_field_names()
        .iter()
        .enumerate()
        .map(|(index, (feature, _))| (*feature, index))
        .collect::<BTreeMap<_, _>>();
    features.sort_by(|left, right| {
        order
            .get(left.as_str())
            .copied()
            .unwrap_or(usize::MAX)
            .cmp(&order.get(right.as_str()).copied().unwrap_or(usize::MAX))
            .then_with(|| left.cmp(right))
    });
    features.dedup();
}

fn binding_set(catalog: &Catalog) -> BTreeSet<(String, String)> {
    catalog
        .bindings
        .iter()
        .map(|binding| (binding.group.clone(), binding.package.clone()))
        .collect()
}

fn pending_changes(baseline: &Catalog, draft: &Catalog) -> UiPendingChanges {
    let baseline_bindings = binding_set(baseline);
    let draft_bindings = binding_set(draft);
    let baseline_memberships = membership_set(baseline);
    let draft_memberships = membership_set(draft);
    let baseline_group_mappings = group_mapping_set(baseline);
    let draft_group_mappings = group_mapping_set(draft);
    let baseline_scope_resources = scope_resource_set(baseline);
    let draft_scope_resources = scope_resource_set(draft);
    let baseline_accounts = account_map(baseline);
    let draft_accounts = account_map(draft);
    let baseline_roles = role_map(baseline);
    let draft_roles = role_map(draft);
    let baseline_package_map = package_map(baseline);
    let draft_package_map = package_map(draft);
    let draft_packages = package_index(draft);
    let baseline_packages = package_index(baseline);
    let added_bindings = draft_bindings
        .difference(&baseline_bindings)
        .map(|(group, package)| binding_change(group, package, &draft_packages))
        .collect::<Vec<_>>();
    let removed_bindings = baseline_bindings
        .difference(&draft_bindings)
        .map(|(group, package)| binding_change(group, package, &baseline_packages))
        .collect::<Vec<_>>();
    let added_memberships = draft_memberships
        .difference(&baseline_memberships)
        .map(|(group, user_id)| UiMembershipChange {
            group: group.clone(),
            user_id: user_id.clone(),
        })
        .collect::<Vec<_>>();
    let removed_memberships = baseline_memberships
        .difference(&draft_memberships)
        .map(|(group, user_id)| UiMembershipChange {
            group: group.clone(),
            user_id: user_id.clone(),
        })
        .collect::<Vec<_>>();
    let added_group_mappings = draft_group_mappings
        .difference(&baseline_group_mappings)
        .map(|(group, external_group)| UiGroupMappingChange {
            group: group.clone(),
            external_group: external_group.clone(),
        })
        .collect::<Vec<_>>();
    let removed_group_mappings = baseline_group_mappings
        .difference(&draft_group_mappings)
        .map(|(group, external_group)| UiGroupMappingChange {
            group: group.clone(),
            external_group: external_group.clone(),
        })
        .collect::<Vec<_>>();
    let added_scope_resources = draft_scope_resources
        .difference(&baseline_scope_resources)
        .map(|(scope, field, value)| UiScopeResourceChange {
            scope: scope.clone(),
            field: field.clone(),
            value: value.clone(),
        })
        .collect::<Vec<_>>();
    let removed_scope_resources = baseline_scope_resources
        .difference(&draft_scope_resources)
        .map(|(scope, field, value)| UiScopeResourceChange {
            scope: scope.clone(),
            field: field.clone(),
            value: value.clone(),
        })
        .collect::<Vec<_>>();
    let added_accounts = draft_accounts
        .iter()
        .filter(|(id, _)| !baseline_accounts.contains_key(*id))
        .map(|(_, account)| account_change(account))
        .collect::<Vec<_>>();
    let removed_accounts = baseline_accounts
        .iter()
        .filter(|(id, _)| !draft_accounts.contains_key(*id))
        .map(|(_, account)| account_change(account))
        .collect::<Vec<_>>();
    let updated_accounts = draft_accounts
        .iter()
        .filter(|(id, account)| {
            baseline_accounts
                .get(*id)
                .is_some_and(|baseline_account| baseline_account != *account)
        })
        .map(|(_, account)| account_change(account))
        .collect::<Vec<_>>();
    let added_roles = draft_roles
        .iter()
        .filter(|(id, _)| !baseline_roles.contains_key(*id))
        .map(|(_, role)| role_change(role))
        .collect::<Vec<_>>();
    let removed_roles = baseline_roles
        .iter()
        .filter(|(id, _)| !draft_roles.contains_key(*id))
        .map(|(_, role)| role_change(role))
        .collect::<Vec<_>>();
    let updated_roles = draft_roles
        .iter()
        .filter(|(id, role)| {
            baseline_roles
                .get(*id)
                .is_some_and(|baseline_role| baseline_role != *role)
        })
        .map(|(_, role)| role_change(role))
        .collect::<Vec<_>>();
    let added_packages = draft_package_map
        .iter()
        .filter(|(id, _)| !baseline_package_map.contains_key(*id))
        .map(|(_, package)| package_change(package))
        .collect::<Vec<_>>();
    let removed_packages = baseline_package_map
        .iter()
        .filter(|(id, _)| !draft_package_map.contains_key(*id))
        .map(|(_, package)| package_change(package))
        .collect::<Vec<_>>();
    let updated_packages = draft_package_map
        .iter()
        .filter(|(id, package)| {
            baseline_package_map
                .get(*id)
                .is_some_and(|baseline_package| baseline_package != *package)
        })
        .map(|(_, package)| package_change(package))
        .collect::<Vec<_>>();
    let high_risk_added = added_bindings
        .iter()
        .filter(|change| change.high_risk)
        .count();
    let high_risk_removed = removed_bindings
        .iter()
        .filter(|change| change.high_risk)
        .count();
    let semantic_diff = semantic_diff(baseline, draft);
    UiPendingChanges {
        added_bindings,
        removed_bindings,
        added_memberships,
        removed_memberships,
        added_group_mappings,
        removed_group_mappings,
        added_scope_resources,
        removed_scope_resources,
        added_accounts,
        removed_accounts,
        updated_accounts,
        added_roles,
        removed_roles,
        updated_roles,
        added_packages,
        removed_packages,
        updated_packages,
        high_risk_added,
        high_risk_removed,
        semantic_diff,
    }
}

fn semantic_diff(baseline: &Catalog, draft: &Catalog) -> UiSemanticDiff {
    match catalog::diff_catalogs(baseline, draft, "baseline catalog", "draft catalog") {
        Ok(diff) => UiSemanticDiff {
            added: diff.added,
            removed: diff.removed,
            high_risk: diff.high_risk_changes,
            error: None,
        },
        Err(err) => UiSemanticDiff::error(err),
    }
}

fn package_index(catalog: &Catalog) -> BTreeMap<&str, &CatalogPackage> {
    catalog
        .packages
        .iter()
        .map(|package| (package.id.as_str(), package))
        .collect()
}

fn package_map(catalog: &Catalog) -> BTreeMap<String, CatalogPackage> {
    catalog
        .packages
        .iter()
        .map(|package| (package.id.clone(), package.clone()))
        .collect()
}

fn account_map(catalog: &Catalog) -> BTreeMap<String, CatalogAccount> {
    catalog
        .accounts
        .iter()
        .map(|account| (account.id.clone(), account.clone()))
        .collect()
}

fn role_map(catalog: &Catalog) -> BTreeMap<String, CatalogRole> {
    catalog
        .roles
        .iter()
        .map(|role| (role.id.clone(), role.clone()))
        .collect()
}

fn account_change(account: &CatalogAccount) -> UiAccountChange {
    UiAccountChange {
        id: account.id.clone(),
        account_id: account.account_id.clone(),
        name: account.name.clone(),
    }
}

fn role_change(role: &CatalogRole) -> UiRoleChange {
    UiRoleChange {
        id: role.id.clone(),
        role_arn: role.role_arn.clone(),
    }
}

fn package_change(package: &CatalogPackage) -> UiPackageChange {
    UiPackageChange {
        id: package.id.clone(),
        scope: package.scope.clone(),
        role: package.role.clone(),
        features: package.features.clone(),
        max_session_seconds: package.max_session_seconds,
    }
}

fn scope_resource_set(catalog: &Catalog) -> BTreeSet<(String, String, String)> {
    let mut resources = BTreeSet::new();
    for scope in &catalog.scopes {
        add_scope_resource_values(&mut resources, &scope.id, "accounts", &scope.accounts);
        add_scope_resource_values(&mut resources, &scope.id, "regions", &scope.regions);
        add_scope_resource_values(
            &mut resources,
            &scope.id,
            "log_group_arns",
            &scope.log_group_arns,
        );
        add_scope_resource_values(&mut resources, &scope.id, "clusters", &scope.clusters);
        add_scope_resource_values(&mut resources, &scope.id, "os_users", &scope.os_users);
    }
    resources
}

fn add_scope_resource_values(
    resources: &mut BTreeSet<(String, String, String)>,
    scope: &str,
    field: &str,
    values: &[String],
) {
    for value in values {
        resources.insert((scope.to_owned(), field.to_owned(), value.clone()));
    }
}

fn membership_set(catalog: &Catalog) -> BTreeSet<(String, String)> {
    catalog
        .memberships
        .iter()
        .map(|membership| (membership.group.clone(), membership.user_id.clone()))
        .collect()
}

fn group_mapping_set(catalog: &Catalog) -> BTreeSet<(String, String)> {
    catalog
        .group_mappings
        .iter()
        .map(|mapping| (mapping.canopy_group.clone(), mapping.external_group.clone()))
        .collect()
}

fn binding_change(
    group: &str,
    package: &str,
    package_by_id: &BTreeMap<&str, &CatalogPackage>,
) -> UiBindingChange {
    let features = package_by_id
        .get(package)
        .map(|package| package.features.clone())
        .unwrap_or_default();
    UiBindingChange {
        group: group.to_owned(),
        package: package.to_owned(),
        high_risk: features
            .iter()
            .any(|feature| catalog::is_high_risk_feature(feature)),
        features,
    }
}

fn high_risk_features(package: &CatalogPackage) -> Vec<String> {
    package
        .features
        .iter()
        .filter(|feature| catalog::is_high_risk_feature(feature))
        .cloned()
        .collect()
}

fn random_url_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn session_cookie_header(session: &str) -> String {
    format!(
        "{SESSION_COOKIE_NAME}={session}; Path=/; Max-Age={}; HttpOnly; SameSite=Strict",
        UI_SESSION_TTL.as_secs()
    )
}

fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie.split(';').find_map(|part| {
        let part = part.trim();
        part.strip_prefix(&format!("{SESSION_COOKIE_NAME}="))
    })
}

fn validate_session_headers(state: &UiAppState, headers: &HeaderMap) -> Result<(), UiRequestError> {
    let Some(session) = session_cookie(headers) else {
        return Err(UiRequestError {
            status: StatusCode::UNAUTHORIZED,
            code: "missing_session",
            message: "UI session cookie is required",
        });
    };
    if state.validate_session(session) {
        Ok(())
    } else {
        Err(UiRequestError {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_session",
            message: "UI session cookie is invalid or expired",
        })
    }
}

fn validate_local_host(headers: &HeaderMap) -> Result<(), UiRequestError> {
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return Err(UiRequestError {
            status: StatusCode::FORBIDDEN,
            code: "missing_host",
            message: "Host header is required",
        });
    };
    if is_local_host(host) {
        Ok(())
    } else {
        Err(UiRequestError {
            status: StatusCode::FORBIDDEN,
            code: "invalid_host",
            message: "Host header must target localhost, 127.0.0.1, or [::1]",
        })
    }
}

fn validate_local_origin(headers: &HeaderMap) -> Result<(), UiRequestError> {
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return Err(UiRequestError {
            status: StatusCode::FORBIDDEN,
            code: "missing_origin",
            message: "Origin header is required for local UI API requests",
        });
    };
    let origin_host = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"));
    if origin_host.is_some_and(is_local_host) {
        Ok(())
    } else {
        Err(UiRequestError {
            status: StatusCode::FORBIDDEN,
            code: "invalid_origin",
            message: "Origin must target localhost, 127.0.0.1, or [::1]",
        })
    }
}

fn is_local_host(host: &str) -> bool {
    let host = host.trim();
    if host == "localhost" || host == "127.0.0.1" || host == "[::1]" {
        return true;
    }
    if let Some(port) = host.strip_prefix("[::1]:") {
        return is_numeric_port(port);
    }
    let Some((name, port)) = host.rsplit_once(':') else {
        return false;
    };
    matches!(name, "localhost" | "127.0.0.1") && is_numeric_port(port)
}

fn is_numeric_port(port: &str) -> bool {
    !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
}

fn validate_bind_addr(addr: SocketAddr) -> anyhow::Result<()> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(anyhow!(
            "ui bind address '{}' is not loopback; use 127.0.0.1 or [::1]",
            addr
        ))
    }
}

fn validate_ui_file_paths(args: &UiArgs) -> anyhow::Result<()> {
    let catalog = normalized_ui_path(&args.catalog)?;
    let runtime = normalized_ui_path(&args.runtime)?;
    if catalog == runtime {
        anyhow::bail!(
            "--catalog and --runtime must point to different files: '{}'",
            args.catalog.display()
        );
    }

    if let Some(import_runtime) = args.import_runtime.as_deref() {
        let import_runtime_normalized = normalized_ui_path(import_runtime)?;
        if import_runtime_normalized == catalog {
            anyhow::bail!(
                "--import-runtime and --catalog must point to different files: '{}'",
                import_runtime.display()
            );
        }
        if import_runtime_normalized == runtime {
            anyhow::bail!(
                "--import-runtime and --runtime must point to different files: '{}'",
                import_runtime.display()
            );
        }
    }

    if let Some(operator_jwt) = args.operator_jwt.as_deref() {
        validate_operator_jwt_file_path(operator_jwt)?;
    }
    if let Some(auth_config) = args.auth_config.as_deref() {
        validate_auth_config_file_path(auth_config)?;
    }

    Ok(())
}

fn validate_operator_jwt_file_path(path: &Path) -> anyhow::Result<()> {
    validate_protected_ui_file_path(path, "--operator-jwt file").map(|_| ())
}

fn validate_auth_config_file_path(path: &Path) -> anyhow::Result<()> {
    validate_protected_ui_file_path(path, "--auth-config file").map(|_| ())
}

fn validate_protected_ui_file_path(path: &Path, label: &str) -> anyhow::Result<PathBuf> {
    let normalized = normalized_ui_path(path)?;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} '{}'", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("{label} '{}' must not be a symlink", path.display());
    }
    if !metadata.file_type().is_file() {
        anyhow::bail!("{label} '{}' must be a regular file", path.display());
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 {
            anyhow::bail!(
                "{label} '{}' must not be group/world writable",
                path.display()
            );
        }
        let current_uid = unsafe { geteuid() };
        if metadata.uid() != current_uid {
            anyhow::bail!(
                "{label} '{}' must be owned by the current effective user",
                path.display()
            );
        }
    }
    if let Some(repo_root) = current_repo_root()? {
        if normalized.starts_with(&repo_root) {
            anyhow::bail!(
                "{label} '{}' must be outside the repository working tree '{}'",
                path.display(),
                repo_root.display()
            );
        }
    }
    Ok(normalized)
}

fn current_repo_root() -> anyhow::Result<Option<PathBuf>> {
    let mut dir = normalized_ui_path(
        &std::env::current_dir()
            .context("failed to resolve current directory for operator JWT path validation")?,
    )?;
    loop {
        if dir.join(".git").exists() {
            return Ok(Some(dir));
        }
        if !dir.pop() {
            return Ok(None);
        }
    }
}

fn normalized_ui_path(path: &Path) -> anyhow::Result<PathBuf> {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return Ok(canonical);
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to resolve current directory for UI path validation")?
            .join(path)
    };
    Ok(lexically_normalized_path(&absolute))
}

fn lexically_normalized_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

pub fn bootstrap_prelude_sha256() -> &'static str {
    BOOTSTRAP_PRELUDE_SHA256
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::{header, Request};
    use base64::engine::general_purpose::STANDARD;
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    fn test_args() -> UiArgs {
        UiArgs {
            catalog: PathBuf::from("entitlements.catalog.toml"),
            runtime: PathBuf::from("entitlements.generated.toml"),
            import_runtime: None,
            deployment_mode: Some("config".to_owned()),
            tfvars: None,
            deployment_config: Some(PathBuf::from("config.toml")),
            auth_config: None,
            db_config: Some(PathBuf::from("database_connections.local.toml")),
            dev_admin_group: "admin".to_owned(),
            identity_source: "dev-claims".to_owned(),
            operator_jwt: None,
            allow_dev_identity: true,
            dev_operator_sub: Some("operator-sub".to_owned()),
            dev_operator_email: Some("operator@example.com".to_owned()),
            dev_operator_email_verified: true,
            dev_operator_external_groups: vec!["admin".to_owned()],
            bind: "127.0.0.1:0".parse().unwrap(),
        }
    }

    fn test_state(code: &str) -> UiAppState {
        UiAppState::for_test(test_args(), code, Instant::now() + BOOTSTRAP_CODE_TTL)
    }

    fn test_state_with_catalog(catalog: PathBuf) -> UiAppState {
        let mut args = test_args();
        args.catalog = catalog;
        UiAppState::for_test(args, "draft-code", Instant::now() + BOOTSTRAP_CODE_TTL)
    }

    fn test_state_with_catalog_and_args(catalog: PathBuf, mut args: UiArgs) -> UiAppState {
        args.catalog = catalog;
        UiAppState::for_test(args, "draft-code", Instant::now() + BOOTSTRAP_CODE_TTL)
    }

    fn catalog_fixture_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("canopy-ui-{name}-{}.toml", random_url_token()))
    }

    fn write_catalog_fixture(name: &str) -> (PathBuf, String) {
        let content = r#"
[[accounts]]
id = "prod"
account_id = "111"
name = "production"

[[roles]]
id = "readonly"
role_arn = "role/{account_id}/readonly"

[[scopes]]
id = "db-scope"
accounts = ["prod"]
regions = ["ap-northeast-1"]

[[scopes.database_scopes]]
name = "orders_read"
connection = "orders"
environment = "production"
allowed_schemas = ["mart"]
allowed_tables = ["orders"]
allowed_actions = ["select"]
max_rows = 100
statement_timeout_ms = 5000
require_explain = true
max_examined_rows = 10000
allow_full_table_scan = false
allow_views = false

[[packages]]
id = "analytics"
features = ["cloudwatch:search"]
scope = "db-scope"
role = "readonly"

[[packages]]
id = "mcp-database"
features = ["mcp:use", "mcp:database"]
scope = "db-scope"
role = "readonly"

[[bindings]]
group = "RD"
package = "analytics"

[[group_mappings]]
external_group = "canopy-rd"
canopy_group = "RD"

[[memberships]]
user_id = "rd@example.com"
group = "RD"
"#
        .trim_start()
        .to_owned();
        let path = catalog_fixture_path(name);
        std::fs::write(&path, &content).unwrap();
        (path, content)
    }

    fn write_catalog_fixture_with_admin_member(
        name: &str,
        admin_user_id: &str,
    ) -> (PathBuf, String) {
        write_catalog_fixture_with_group_member(name, "admin", admin_user_id)
    }

    fn write_catalog_fixture_with_group_member(
        name: &str,
        group: &str,
        user_id: &str,
    ) -> (PathBuf, String) {
        let (path, mut content) = write_catalog_fixture(name);
        content.push_str(&format!(
            r#"

[[bindings]]
group = "{group}"
package = "analytics"

[[memberships]]
user_id = "{user_id}"
group = "{group}"
"#
        ));
        std::fs::write(&path, &content).unwrap();
        (path, content)
    }

    fn write_auth_config_fixture(name: &str, admin_group: &str) -> PathBuf {
        let path = catalog_fixture_path(name);
        std::fs::write(&path, format!("admin_group = \"{admin_group}\"\n")).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn write_database_config_fixture(name: &str) -> PathBuf {
        let content = r#"
[database_connections.orders]
engine = "mysql"
host = "orders.example.internal"
port = 3306
database = "orders"
secret_arn = "orders-secret-ref"
readonly = true
require_tls = true
"#
        .trim_start();
        let path = catalog_fixture_path(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    fn write_database_config_fixture_with_database(name: &str, database: &str) -> PathBuf {
        let content = format!(
            r#"
[database_connections.orders]
engine = "mysql"
host = "orders.example.internal"
port = 3306
database = "{database}"
secret_arn = "orders-secret-ref"
readonly = true
require_tls = true
"#
        );
        let path = catalog_fixture_path(name);
        std::fs::write(&path, content.trim_start()).unwrap();
        path
    }

    fn write_unsafe_database_config_fixture(name: &str) -> PathBuf {
        let secret_ref = ["db", "-ref"].concat();
        let content = format!(
            r#"
[database_connections.orders]
engine = "mysql"
host = "orders.example.internal"
port = 3306
database = "orders"
secret_arn = "{secret_ref}"
readonly = false
require_tls = false
accept_invalid_tls_certs = true
skip_tls_hostname_verification = true
"#
        )
        .trim_start()
        .to_owned();
        let path = catalog_fixture_path(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    fn write_runtime_from_catalog_fixture(name: &str, catalog_content: &str) -> PathBuf {
        let runtime_path = catalog_fixture_path(name);
        let generated = Catalog::from_toml_str(catalog_content)
            .unwrap()
            .generate_runtime()
            .unwrap();
        std::fs::write(&runtime_path, generated.toml).unwrap();
        runtime_path
    }

    fn state_cookie() -> &'static str {
        "canopy_ui_session=session-token"
    }

    fn embedded_js_function(name: &str) -> &'static str {
        let start = APP_JS.find(name).expect("embedded function should exist");
        let rest = &APP_JS[start..];
        let end = rest[1..]
            .find("\nfunction ")
            .or_else(|| rest[1..].find("\nasync function "))
            .map(|offset| offset + 1)
            .unwrap_or(rest.len());
        &rest[..end]
    }

    fn install_session(state: &UiAppState) {
        state.store_session("session-token".to_owned());
    }

    #[test]
    fn bootstrap_prelude_hash_matches_embedded_inline_script() {
        let script_start = INDEX_HTML.find("<script>").unwrap() + "<script>".len();
        let script_end = INDEX_HTML[script_start..].find("</script>").unwrap() + script_start;
        let inline_script = &INDEX_HTML[script_start..script_end];
        let digest = Sha256::digest(inline_script.as_bytes());
        assert_eq!(
            format!("sha256-{}", STANDARD.encode(digest)),
            bootstrap_prelude_sha256()
        );
    }

    #[test]
    fn transaction_artifact_paths_are_catalog_specific() {
        let first = catalog_fixture_path("transaction-artifact-first");
        let second = catalog_fixture_path("transaction-artifact-second");
        let (first_lock, first_manifest) = transaction_artifact_paths(&first);
        let (second_lock, second_manifest) = transaction_artifact_paths(&second);

        assert_ne!(first_lock, second_lock);
        assert_ne!(first_manifest, second_manifest);
        assert!(first_lock
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(".canopy-entitlements-transaction-"));
        assert!(first_lock
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(".lock"));
        assert!(first_manifest
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(".manifest.json"));
    }

    #[tokio::test]
    async fn embedded_ui_routes_render_nonblank_with_security_headers() {
        for path in ["/", "/app.css", "/app.js"] {
            let response = router(test_state("static-route-code"))
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers().get(header::REFERRER_POLICY).unwrap(),
                "no-referrer"
            );
            let csp = response
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap()
                .to_str()
                .unwrap();
            assert!(csp.contains("default-src 'self'"));
            assert!(csp.contains(bootstrap_prelude_sha256()));
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            assert!(!body.is_empty(), "{path} should render nonblank");
        }
    }

    #[test]
    fn embedded_review_apply_assets_expose_draft_gate() {
        assert!(INDEX_HTML.contains(r#"data-view="review-apply""#));
        assert!(INDEX_HTML.contains(r#"class="review-apply-view""#));
        assert!(INDEX_HTML.contains(r#"id="review-validate-button""#));
        assert!(INDEX_HTML.contains(r#"id="review-apply-button""#));
        assert!(INDEX_HTML.contains(r#"id="apply-button""#));
        assert!(INDEX_HTML.contains(r#"id="review-change-rows""#));

        assert!(APP_JS.contains("function renderReviewApply()"));
        assert!(APP_JS.contains("function runValidation(button)"));
        assert!(APP_JS.contains("function runApply(button)"));
        assert!(APP_JS.contains("async function applyDraft()"));
        assert!(APP_JS.contains("review-validate-button"));
        assert!(APP_JS.contains("review-apply-button"));

        assert!(APP_CSS.contains(".workspace.review-mode"));
        assert!(APP_CSS.contains(".workspace.review-mode .review-strip"));
        assert!(APP_CSS.contains(".review-change-table"));
        assert!(APP_CSS.contains(".review-apply-view"));
        assert!(APP_CSS.contains(".apply-locked"));
    }

    #[test]
    fn embedded_review_apply_js_keeps_apply_state_scoped_to_each_view() {
        let overview = embedded_js_function("function renderOverview()");
        let review = embedded_js_function("function renderReviewApply()");

        assert_eq!(overview.matches("const apply = state.apply;").count(), 1);
        assert_eq!(
            overview
                .matches("const applyGate = apply?.gate || null;")
                .count(),
            0
        );
        assert_eq!(review.matches("const apply = state.apply;").count(), 1);
        assert_eq!(
            review
                .matches("const applyGate = apply?.gate || null;")
                .count(),
            1
        );
    }

    #[test]
    fn embedded_overview_assets_expose_dashboard() {
        assert!(INDEX_HTML.contains(r#"data-view="overview""#));
        assert!(INDEX_HTML.contains(r#"class="workspace overview-mode""#));
        assert!(INDEX_HTML.contains(r#"class="overview-view""#));
        assert!(INDEX_HTML.contains(r#"id="overview-status-list""#));
        assert!(INDEX_HTML.contains(r#"id="import-runtime-button""#));
        assert!(INDEX_HTML.contains(r#"id="membership-add-button""#));
        assert!(INDEX_HTML.contains(r#"id="group-mapping-add-button""#));
        assert!(INDEX_HTML.contains(r#"data-overview-target="review-apply""#));

        assert!(APP_JS.contains("function renderOverview()"));
        assert!(APP_JS.contains("function overviewStatusRow("));
        assert!(APP_JS.contains("function updateDraftMembership("));
        assert!(APP_JS.contains("function updateDraftGroupMapping("));
        assert!(APP_JS.contains("function renderIdentityWiring("));
        assert!(APP_JS.contains("function importRuntimeDraft()"));
        assert!(APP_JS.contains("function canImportRuntime("));
        assert!(APP_JS.contains("function resetDraftSelection()"));
        assert!(APP_JS.contains("/api/draft/memberships"));
        assert!(APP_JS.contains("/api/draft/group-mappings"));
        assert!(APP_JS.contains("/api/import-runtime"));
        assert!(APP_JS.contains("data-overview-target"));

        assert!(APP_CSS.contains(".workspace.overview-mode"));
        assert!(APP_CSS.contains(".overview-view"));
        assert!(APP_CSS.contains(".identity-editor"));
        assert!(APP_CSS.contains(".identity-list-row"));
        assert!(APP_CSS.contains(".overview-import-button"));
        assert!(APP_CSS.contains(".overview-status-list"));
        assert!(APP_CSS.contains(".overview-status-row"));
    }

    #[test]
    fn embedded_packages_assets_expose_feature_toggles() {
        assert!(INDEX_HTML.contains(r#"data-view="packages""#));
        assert!(INDEX_HTML.contains(r#"class="packages-view""#));
        assert!(INDEX_HTML.contains(r#"id="package-feature-toggles""#));
        assert!(INDEX_HTML.contains(r#"id="package-save-button""#));
        assert!(INDEX_HTML.contains(r#"id="package-edit-scope""#));

        assert!(APP_JS.contains("function renderPackages("));
        assert!(APP_JS.contains("function updateDraftPackage("));
        assert!(APP_JS.contains("function renderPackageEditor("));
        assert!(APP_JS.contains("function togglePackageFeature("));
        assert!(APP_JS.contains("/api/draft/packages"));
        assert!(APP_JS.contains("/api/draft/packages/features"));

        assert!(APP_CSS.contains(".workspace.package-mode"));
        assert!(APP_CSS.contains(".packages-table"));
        assert!(APP_CSS.contains(".package-editor"));
        assert!(APP_CSS.contains(".feature-toggle"));
    }

    #[test]
    fn embedded_scopes_assets_expose_scope_inspector() {
        assert!(INDEX_HTML.contains(r#"data-view="scopes""#));
        assert!(INDEX_HTML.contains(r#"class="scopes-view""#));
        assert!(INDEX_HTML.contains(r#"id="scope-detail-list""#));
        assert!(INDEX_HTML.contains(r#"id="scope-resource-field""#));
        assert!(INDEX_HTML.contains(r#"id="scope-resource-add-button""#));
        assert!(INDEX_HTML.contains(r#"id="scope-db-template""#));
        assert!(INDEX_HTML.contains(r#"id="scope-db-save-button""#));
        assert!(INDEX_HTML.contains(r#"id="scope-db-delete-button""#));
        assert!(INDEX_HTML.contains(r#"id="scope-mcp-ec2-template""#));
        assert!(INDEX_HTML.contains(r#"id="scope-mcp-ec2-save-button""#));
        assert!(INDEX_HTML.contains(r#"id="scope-mcp-ec2-delete-button""#));

        assert!(APP_JS.contains("function renderScopes("));
        assert!(APP_JS.contains("function renderScopeInspector("));
        assert!(APP_JS.contains("function updateDraftScopeResource("));
        assert!(APP_JS.contains("function updateDraftDatabaseScope("));
        assert!(APP_JS.contains("function updateDraftMcpEc2Scope("));
        assert!(APP_JS.contains("function saveDatabaseScopeDraft("));
        assert!(APP_JS.contains("function saveMcpEc2ScopeDraft("));
        assert!(APP_JS.contains("function renderScopeResourceEditor("));
        assert!(APP_JS.contains("function renderScopeDatabaseEditor("));
        assert!(APP_JS.contains("function renderScopeMcpEc2Editor("));
        assert!(APP_JS.contains("mcpEc2ScopeLine"));
        assert!(APP_JS.contains("/api/draft/scopes/resources"));
        assert!(APP_JS.contains("/api/draft/scopes/database"));
        assert!(APP_JS.contains("/api/draft/scopes/mcp-ec2"));

        assert!(APP_CSS.contains(".workspace.scope-mode"));
        assert!(APP_CSS.contains(".scopes-table"));
        assert!(APP_CSS.contains(".scope-resource-editor"));
        assert!(APP_CSS.contains(".scope-resource-list-row"));
        assert!(APP_CSS.contains(".scope-db-fieldset"));
        assert!(APP_CSS.contains(".scope-db-actions"));
        assert!(APP_CSS.contains(".scope-mcp-ec2-fieldset"));
        assert!(APP_CSS.contains(".scope-mcp-ec2-actions"));
        assert!(APP_CSS.contains(".scope-detail-block"));
    }

    #[test]
    fn embedded_accounts_roles_assets_expose_inspector() {
        assert!(INDEX_HTML.contains(r#"data-view="accounts-roles""#));
        assert!(INDEX_HTML.contains(r#"class="accounts-roles-view""#));
        assert!(INDEX_HTML.contains(r#"id="account-role-detail-list""#));
        assert!(INDEX_HTML.contains(r#"id="account-role-save-button""#));
        assert!(INDEX_HTML.contains(r#"id="account-role-edit-primary""#));

        assert!(APP_JS.contains("function renderAccountsRoles("));
        assert!(APP_JS.contains("function renderAccountRoleInspector("));
        assert!(APP_JS.contains("function updateDraftAccount("));
        assert!(APP_JS.contains("function updateDraftRole("));
        assert!(APP_JS.contains("function setElementInputValue("));
        assert!(APP_JS.contains("accountRoleDetailBlock"));
        assert!(APP_JS.contains("/api/draft/accounts"));
        assert!(APP_JS.contains("/api/draft/roles"));

        assert!(APP_CSS.contains(".workspace.account-role-mode"));
        assert!(APP_CSS.contains(".account-role-table"));
        assert!(APP_CSS.contains(".account-role-editor"));
        assert!(APP_CSS.contains(".account-role-detail-block"));
    }

    #[test]
    fn embedded_ui_assets_do_not_shadow_db_input_helper() {
        assert_eq!(APP_JS.matches("function setInputValue(").count(), 1);
        assert_eq!(APP_JS.matches("function setElementInputValue(").count(), 1);
    }

    #[test]
    fn embedded_db_connection_assets_expose_new_connection_flow() {
        assert!(INDEX_HTML.contains(r#"id="db-new-button""#));
        assert!(INDEX_HTML.contains(r#"id="db-connection-name""#));
        assert!(INDEX_HTML.contains(r#"id="db-save-button""#));

        assert!(APP_JS.contains("draftingNewDbConnection"));
        assert!(APP_JS.contains("dbConnectionDraftRequestFromForm"));
        assert!(APP_JS.contains("/api/draft/db-connections"));

        assert!(APP_CSS.contains(".db-panel-actions"));
        assert!(APP_CSS.contains(".db-save-button"));
    }

    #[tokio::test]
    async fn unknown_ui_route_returns_secured_404() {
        let response = router(test_state("missing-route-code"))
            .oneshot(
                Request::builder()
                    .uri("/does-not-exist")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get(header::REFERRER_POLICY).unwrap(),
            "no-referrer"
        );
    }

    #[tokio::test]
    async fn state_requires_session_cookie() {
        let response = router(test_state("state-code"))
            .oneshot(
                Request::builder()
                    .uri("/api/state")
                    .header(header::HOST, "127.0.0.1:8080")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::REFERRER_POLICY).unwrap(),
            "no-referrer"
        );
    }

    #[tokio::test]
    async fn session_exchange_sets_http_only_cookie_and_allows_state() {
        let app = router(test_state("exchange-code"));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/session/exchange")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"code":"exchange-code"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/"));

        let session_pair = cookie.split(';').next().unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/state")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::COOKIE, session_pair)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let state: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(state["mode"], "local-auth-shell");
        assert_eq!(state["capabilities"]["apply"], false);
        assert!(state.get("operator_jwt").is_none());
        assert!(!String::from_utf8(body.to_vec())
            .unwrap()
            .contains("secret-value"));
    }

    #[tokio::test]
    async fn state_includes_loaded_draft_matrix_summary() {
        let (catalog_path, _content) = write_catalog_fixture("state-matrix");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/state")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let state: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(state["draft"]["loaded"], true);
        assert_eq!(state["capabilities"]["draft_write"], true);
        assert_eq!(state["draft"]["groups"][0]["id"], "RD");
        assert!(state["draft"]["packages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|package| package["id"] == "mcp-database"
                && package["database_scopes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|scope| scope["name"] == "orders_read"
                        && scope["connection"] == "orders"
                        && scope["allowed_tables"]
                            .as_array()
                            .unwrap()
                            .contains(&serde_json::Value::String("orders".to_owned())))
                && package["high_risk_features"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::Value::String("mcp:database".to_owned()))));
        assert!(!String::from_utf8(body.to_vec())
            .unwrap()
            .contains("secret-value"));
        assert_eq!(
            state["changes"]["added_bindings"].as_array().unwrap().len(),
            0
        );
        assert_eq!(
            state["changes"]["semantic_diff"]["added"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            state["changes"]["semantic_diff"]["high_risk"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn state_includes_account_role_summaries() {
        let (catalog_path, _content) = write_catalog_fixture("state-accounts-roles");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/state")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let state: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let account = state["draft"]["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|account| account["id"] == "prod")
            .unwrap();
        assert_eq!(account["account_id"], "111");
        assert_eq!(account["name"], "production");
        assert!(account["scopes"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String("db-scope".to_owned())));
        assert!(account["packages"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String("mcp-database".to_owned())));
        assert!(account["roles"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String("readonly".to_owned())));

        let role = state["draft"]["roles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|role| role["id"] == "readonly")
            .unwrap();
        assert_eq!(role["mode"], "template");
        assert_eq!(role["role_arn"], "role/{account_id}/readonly");
        assert!(role["accounts"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String("prod".to_owned())));
        assert!(role["packages"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String("analytics".to_owned())));
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn state_includes_sanitized_scope_summaries() {
        let (catalog_path, content) = write_catalog_fixture("state-scopes");
        let enriched = content.replacen(
            "\n[[packages]]",
            r#"
[[scopes.instance_tag_selectors]]
[scopes.instance_tag_selectors.tags]
Environment = ["production"]

[[scopes.mcp_ec2_diagnostic_scopes]]
id = "app-diagnostics"
private_target_refs = ["service:app-api"]
max_lines = 200
max_since_seconds = 900
max_timeout_seconds = 30
max_matches = 20
connectivity_probe_budget_per_window = 4
budget_window_seconds = 60
denylist_version = "builtin-v1"
allowlist_rule_id = "app-diagnostics-v1"

[[scopes.mcp_ec2_diagnostic_scopes.allowed_log_paths]]
path_pattern = "/var/log/app/error.log"
canonical_safe_prefix = "/var/log/app/"
safe_for_mcp_output = true

[[scopes.mcp_ec2_diagnostic_scopes.allowed_http_urls]]
normalized_url = "https://10.0.1.20/health"
query_policy = "no_query"
safe_for_mcp_output = true
private_target_ref = "service:app-api"

[[scopes.mcp_ec2_diagnostic_scopes.allowed_tcp_targets]]
host = "10.0.1.20"
port = 443
private_target_ref = "service:app-api"

[[packages]]
"#,
            1,
        );
        std::fs::write(&catalog_path, enriched).unwrap();
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/state")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let state: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let scopes = state["draft"]["scopes"].as_array().unwrap();
        let scope = scopes
            .iter()
            .find(|scope| scope["id"] == "db-scope")
            .unwrap();
        assert!(scope["accounts"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String("prod".to_owned())));
        assert!(scope["instance_tag_selectors"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String(
                "Environment=production".to_owned()
            )));
        assert_eq!(scope["database_scopes"][0]["max_rows"], 100);
        assert_eq!(scope["database_scopes"][0]["require_explain"], true);
        assert_eq!(scope["database_scopes"][0]["allow_views"], false);
        assert_eq!(
            scope["mcp_ec2_diagnostic_scopes"][0]["id"],
            "app-diagnostics"
        );
        assert_eq!(
            scope["mcp_ec2_diagnostic_scopes"][0]["private_target_refs"][0],
            "service:app-api"
        );
        assert_eq!(
            scope["mcp_ec2_diagnostic_scopes"][0]["log_paths"][0],
            "/var/log/app/error.log"
        );
        assert_eq!(
            scope["mcp_ec2_diagnostic_scopes"][0]["http_urls"][0],
            "https://10.0.1.20/health"
        );
        assert_eq!(
            scope["mcp_ec2_diagnostic_scopes"][0]["tcp_targets"][0],
            "10.0.1.20:443"
        );
        assert_eq!(scope["mcp_ec2_diagnostic_scopes"][0]["max_lines"], 200);
        assert_eq!(
            scope["mcp_ec2_diagnostic_scopes"][0]["connectivity_probe_budget_per_window"],
            4
        );
        assert_eq!(
            scope["mcp_ec2_diagnostic_scopes"][0]["denylist_version"],
            "builtin-v1"
        );
        assert_eq!(
            scope["mcp_ec2_diagnostic_scopes"][0]["allowlist_rule_id"],
            "app-diagnostics-v1"
        );
        assert_eq!(
            scope["mcp_ec2_diagnostic_scopes"][0]["unsafe_output_count"],
            0
        );
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn state_includes_sanitized_database_connection_metadata() {
        let (catalog_path, _content) = write_catalog_fixture("state-db-connections");
        let db_config_path = write_unsafe_database_config_fixture("state-db-connections-config");
        let mut args = test_args();
        args.db_config = Some(db_config_path.clone());
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/state")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let state: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let connections = &state["database_connections"];
        assert_eq!(connections["configured"], true);
        assert!(connections["required"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String("orders".to_owned())));
        assert_eq!(connections["local"][0]["name"], "orders");
        assert_eq!(connections["local"][0]["engine"], "mysql");
        assert_eq!(connections["local"][0]["readonly"], false);
        assert_eq!(connections["local"][0]["require_tls"], false);
        assert_eq!(connections["local"][0]["secret_ref_configured"], true);
        assert_eq!(connections["local"][0]["safety"], "blocking");
        let issue_codes = connections["issues"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|issue| issue["code"].as_str())
            .collect::<Vec<_>>();
        assert!(issue_codes.contains(&"database_connection_not_readonly"));
        assert!(issue_codes.contains(&"database_connection_tls_disabled"));
        assert!(issue_codes.contains(&"database_connection_accepts_invalid_tls"));
        assert!(issue_codes.contains(&"database_connection_skips_tls_hostname"));
        let secret_ref = ["db", "-ref"].concat();
        assert!(!String::from_utf8(body.to_vec())
            .unwrap()
            .contains(&secret_ref));
        let _ = std::fs::remove_file(catalog_path);
        let _ = std::fs::remove_file(db_config_path);
    }

    #[tokio::test]
    async fn draft_database_connection_update_uses_memory_draft_without_writing_config() {
        let (catalog_path, catalog_content) = write_catalog_fixture("draft-db-update-catalog");
        let runtime_path =
            write_runtime_from_catalog_fixture("draft-db-update-runtime", &catalog_content);
        let db_config_path =
            write_database_config_fixture_with_database("draft-db-update-local", "orders_archive");
        let deployment_config_path = write_database_config_fixture("draft-db-update-deploy");
        let original_db_config = std::fs::read_to_string(&db_config_path).unwrap();
        let mut args = test_args();
        args.catalog = catalog_path.clone();
        args.runtime = runtime_path.clone();
        args.db_config = Some(db_config_path.clone());
        args.deployment_mode = Some("config".to_owned());
        args.deployment_config = Some(deployment_config_path.clone());
        let state = UiAppState::for_test(args, "draft-code", Instant::now() + BOOTSTRAP_CODE_TTL);
        install_session(&state);
        let existing_secret_ref = ["orders", "-secret", "-ref"].concat();

        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/db-connections")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "name": "orders",
                            "engine": "mysql",
                            "host": "orders.example.internal",
                            "port": 3306,
                            "database": "orders",
                            "readonly": true,
                            "connect_timeout_ms": 3000,
                            "statement_timeout_ms": 5000,
                            "explain_timeout_ms": 3000,
                            "max_connections": 4,
                            "require_tls": true,
                            "accept_invalid_tls_certs": false,
                            "skip_tls_hostname_verification": false
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let state_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(state_json["database_connections"]["dirty"], true);
        assert_eq!(
            state_json["database_connections"]["local"][0]["database"],
            "orders"
        );
        assert_eq!(
            state_json["database_connections"]["local"][0]["secret_ref_configured"],
            true
        );
        assert!(!String::from_utf8(body.to_vec())
            .unwrap()
            .contains(&existing_secret_ref));
        assert_eq!(
            std::fs::read_to_string(&db_config_path).unwrap(),
            original_db_config
        );

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/validate")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let validation: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(validation["valid"], true);
        assert!(!String::from_utf8(body.to_vec())
            .unwrap()
            .contains(&existing_secret_ref));

        let _ = std::fs::remove_file(catalog_path);
        let _ = std::fs::remove_file(runtime_path);
        let _ = std::fs::remove_file(db_config_path);
        let _ = std::fs::remove_file(deployment_config_path);
    }

    #[tokio::test]
    async fn draft_database_connection_update_adds_missing_required_connection() {
        let (catalog_path, _content) = write_catalog_fixture("draft-db-add-catalog");
        let mut args = test_args();
        args.db_config = None;
        args.deployment_mode = None;
        args.deployment_config = None;
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);
        let secret_ref = ["new", "-secret", "-ref"].concat();

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/db-connections")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "name": "orders",
                            "engine": "mysql",
                            "host": "orders.example.internal",
                            "port": 3306,
                            "database": "orders",
                            "secret_arn": secret_ref,
                            "readonly": true,
                            "connect_timeout_ms": 3000,
                            "statement_timeout_ms": 5000,
                            "explain_timeout_ms": 3000,
                            "max_connections": 4,
                            "require_tls": true,
                            "accept_invalid_tls_certs": false,
                            "skip_tls_hostname_verification": false
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let state_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(state_json["database_connections"]["configured"], true);
        assert_eq!(state_json["database_connections"]["dirty"], true);
        assert!(state_json["database_connections"]["missing_required"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(
            state_json["database_connections"]["local"][0]["name"],
            "orders"
        );
        assert_eq!(
            state_json["database_connections"]["local"][0]["safety"],
            "required"
        );
        assert!(!String::from_utf8(body.to_vec())
            .unwrap()
            .contains(&["new", "-secret", "-ref"].concat()));
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_database_connection_update_adds_optional_connection_draft() {
        let (catalog_path, _content) = write_catalog_fixture("draft-db-add-optional-catalog");
        let mut args = test_args();
        args.db_config = None;
        args.deployment_mode = None;
        args.deployment_config = None;
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);
        let secret_ref = ["analytics", "-secret", "-ref"].concat();

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/db-connections")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "name": "analytics",
                            "engine": "mysql",
                            "host": "analytics.example.internal",
                            "port": 3306,
                            "database": "analytics",
                            "secret_arn": secret_ref,
                            "readonly": true,
                            "connect_timeout_ms": 3000,
                            "statement_timeout_ms": 5000,
                            "explain_timeout_ms": 3000,
                            "max_connections": 4,
                            "require_tls": true,
                            "accept_invalid_tls_certs": false,
                            "skip_tls_hostname_verification": false
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let state_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(state_json["database_connections"]["configured"], true);
        assert_eq!(state_json["database_connections"]["dirty"], true);
        assert!(state_json["database_connections"]["missing_required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|connection| connection == "orders"));
        assert!(state_json["database_connections"]["local"]
            .as_array()
            .unwrap()
            .iter()
            .any(|connection| connection["name"] == "analytics"
                && connection["safety"] == "unused"
                && connection["secret_ref_configured"] == true));
        assert!(!String::from_utf8(body.to_vec())
            .unwrap()
            .contains(&secret_ref));
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_database_connection_update_rejects_unsafe_readwrite_request() {
        let (catalog_path, _content) = write_catalog_fixture("draft-db-unsafe-catalog");
        let db_config_path = write_database_config_fixture("draft-db-unsafe-local");
        let mut args = test_args();
        args.db_config = Some(db_config_path.clone());
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/db-connections")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "name": "orders",
                            "engine": "mysql",
                            "host": "orders.example.internal",
                            "port": 3306,
                            "database": "orders",
                            "readonly": false,
                            "connect_timeout_ms": 3000,
                            "statement_timeout_ms": 5000,
                            "explain_timeout_ms": 3000,
                            "max_connections": 4,
                            "require_tls": true,
                            "accept_invalid_tls_certs": false,
                            "skip_tls_hostname_verification": false
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"]["code"], "database_connection_not_readonly");
        let _ = std::fs::remove_file(catalog_path);
        let _ = std::fs::remove_file(db_config_path);
    }

    #[tokio::test]
    async fn draft_binding_update_requires_local_origin() {
        let (catalog_path, _content) = write_catalog_fixture("missing-origin");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/bindings")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"group":"RD","package":"mcp-database","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_binding_update_requires_session_cookie() {
        let (catalog_path, _content) = write_catalog_fixture("missing-session");
        let response = router(test_state_with_catalog(catalog_path.clone()))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/bindings")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"group":"RD","package":"mcp-database","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_binding_update_rejects_unknown_package() {
        let (catalog_path, _content) = write_catalog_fixture("unknown-package");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/bindings")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"group":"RD","package":"does-not-exist","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"]["code"], "unknown_package");
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_account_update_adds_account_without_writing_catalog() {
        let (catalog_path, original_content) = write_catalog_fixture("account-update");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/accounts")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"id":"qa","account_id":"222","name":"qa","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let state: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(state["draft"]["dirty"], true);
        assert_eq!(state["draft"]["revision"], 1);
        assert!(state["draft"]["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|account| account["id"] == "qa"
                && account["account_id"] == "222"
                && account["name"] == "qa"));
        assert!(state["changes"]["added_accounts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["id"] == "qa" && change["account_id"] == "222"));
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_content
        );
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_account_update_rejects_removing_referenced_account() {
        let (catalog_path, _content) = write_catalog_fixture("account-remove-referenced");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/accounts")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"id":"prod","account_id":"","name":"","enabled":false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"]["code"], "account_in_use");
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_account_update_requires_local_origin() {
        let (catalog_path, _content) = write_catalog_fixture("account-origin");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/accounts")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"id":"qa","account_id":"222","name":"qa","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_role_update_updates_role_without_writing_catalog() {
        let (catalog_path, original_content) = write_catalog_fixture("role-update");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/roles")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"id":"readonly","role_arn":"role/{account_id}/readonly-v2","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let state: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(state["draft"]["dirty"], true);
        assert_eq!(state["draft"]["revision"], 1);
        assert!(state["draft"]["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|role| role["id"] == "readonly"
                && role["role_arn"] == "role/{account_id}/readonly-v2"));
        assert!(state["changes"]["updated_roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["id"] == "readonly"
                && change["role_arn"] == "role/{account_id}/readonly-v2"));
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_content
        );
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_role_update_rejects_removing_referenced_role() {
        let (catalog_path, _content) = write_catalog_fixture("role-remove-referenced");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/roles")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"id":"readonly","role_arn":"","enabled":false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"]["code"], "role_in_use");
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_role_update_requires_session_cookie() {
        let (catalog_path, _content) = write_catalog_fixture("role-session");
        let response = router(test_state_with_catalog(catalog_path.clone()))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/roles")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"id":"readonly","role_arn":"role/{account_id}/readonly-v2","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_scope_resource_update_adds_region_without_writing_catalog() {
        let (catalog_path, original_content) = write_catalog_fixture("scope-resource-update");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/scopes/resources")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"scope":"db-scope","field":"regions","value":"eu-central-1","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let state: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(state["draft"]["dirty"], true);
        assert_eq!(state["draft"]["revision"], 1);
        assert!(state["draft"]["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|scope| scope["id"] == "db-scope"
                && scope["regions"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::Value::String("eu-central-1".to_owned()))));
        assert!(state["changes"]["added_scope_resources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["scope"] == "db-scope"
                && change["field"] == "regions"
                && change["value"] == "eu-central-1"));
        assert!(state["changes"]["semantic_diff"]["added"]
            .as_array()
            .unwrap()
            .iter()
            .any(|grant| grant["kind"] == "region" && grant["value"] == "eu-central-1"));
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_content
        );
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_scope_resource_update_rejects_unknown_account() {
        let (catalog_path, _content) = write_catalog_fixture("scope-resource-account");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/scopes/resources")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"scope":"db-scope","field":"accounts","value":"missing","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"]["code"], "unknown_account");
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_database_scope_update_adds_scope_without_writing_catalog() {
        let (catalog_path, original_content) = write_catalog_fixture("database-scope-add");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/scopes/database")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "scope": "db-scope",
                            "name": "customer_read",
                            "connection": "orders",
                            "environment": "production",
                            "allowed_schemas": ["mart", "audit"],
                            "allowed_tables": ["customers"],
                            "allowed_actions": ["select"],
                            "max_rows": 200,
                            "statement_timeout_ms": 4000,
                            "require_explain": true,
                            "max_examined_rows": 20000,
                            "allow_full_table_scan": false,
                            "allow_views": true,
                            "enabled": true
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let state: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(state["draft"]["dirty"], true);
        assert_eq!(state["draft"]["revision"], 1);
        let db_scope = state["draft"]["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|scope| scope["id"] == "db-scope")
            .unwrap()["database_scopes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|scope| scope["name"] == "customer_read")
            .unwrap()
            .clone();
        assert_eq!(db_scope["connection"], "orders");
        assert_eq!(db_scope["max_rows"], 200);
        assert_eq!(db_scope["allow_views"], true);
        assert!(db_scope["allowed_schemas"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String("audit".to_owned())));
        assert!(state["changes"]["semantic_diff"]["high_risk"]
            .as_array()
            .unwrap()
            .iter()
            .any(|grant| grant["kind"] == "database_scope_allow_views"
                && grant["value"] == "customer_read|true"));
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_content
        );
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_database_scope_update_removes_scope_without_writing_catalog() {
        let (catalog_path, original_content) = write_catalog_fixture("database-scope-remove");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/scopes/database")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"scope":"db-scope","name":"orders_read","connection":"","environment":"","allowed_schemas":[],"allowed_tables":[],"allowed_actions":[],"max_rows":0,"statement_timeout_ms":0,"require_explain":true,"max_examined_rows":0,"allow_full_table_scan":false,"allow_views":false,"enabled":false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let state: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(state["draft"]["dirty"], true);
        assert_eq!(state["draft"]["revision"], 1);
        let scope = state["draft"]["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|scope| scope["id"] == "db-scope")
            .unwrap();
        assert!(!scope["database_scopes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|database_scope| database_scope["name"] == "orders_read"));
        assert!(state["changes"]["semantic_diff"]["removed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|grant| grant["kind"] == "database_scope" && grant["value"] == "orders_read"));
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_content
        );
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_mcp_ec2_scope_update_adds_scope_without_writing_catalog() {
        let (catalog_path, content) = write_catalog_fixture("mcp-ec2-scope-add");
        let original_content = content.replacen(
            "\n[[group_mappings]]",
            r#"
[[scopes.mcp_ec2_diagnostic_scopes]]
id = "base-diagnostics"
private_target_refs = []
max_lines = 50
max_since_seconds = 600
max_timeout_seconds = 15
max_matches = 25
connectivity_probe_budget_per_window = 10
budget_window_seconds = 1200
denylist_version = "builtin-v1"
allowlist_rule_id = "base-diagnostics-v1"

[[scopes.mcp_ec2_diagnostic_scopes.allowed_log_paths]]
path_pattern = "/var/log/base/error.log"
canonical_safe_prefix = "/var/log/base/"
safe_for_mcp_output = true

[[packages]]
id = "mcp-ec2-diagnostics"
features = ["mcp:use", "mcp:ec2"]
scope = "db-scope"
role = "readonly"

[[bindings]]
group = "RD"
package = "mcp-ec2-diagnostics"

[[group_mappings]]
"#,
            1,
        );
        std::fs::write(&catalog_path, &original_content).unwrap();
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/scopes/mcp-ec2")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "scope": "db-scope",
                            "id": "app-diagnostics",
                            "private_target_refs": ["service:app-api"],
                            "allowed_log_paths": [{
                                "path_pattern": "/var/log/app/error.log",
                                "canonical_safe_prefix": "/var/log/app/",
                                "safe_for_mcp_output": true
                            }],
                            "allowed_journal_units": [{
                                "unit": "app.service",
                                "safe_for_mcp_output": true
                            }],
                            "allowed_http_urls": [{
                                "normalized_url": "https://example.com/health",
                                "query_policy": "no_query",
                                "safe_for_mcp_output": true
                            }],
                            "allowed_tcp_targets": [{
                                "host": "example.com",
                                "port": 443
                            }],
                            "allowed_dns_targets": [{
                                "host": "example.com",
                                "record_types": ["A", "AAAA"],
                                "safe_for_mcp_output": true
                            }],
                            "max_lines": 100,
                            "max_since_seconds": 900,
                            "max_timeout_seconds": 30,
                            "max_matches": 50,
                            "connectivity_probe_budget_per_window": 20,
                            "budget_window_seconds": 600,
                            "denylist_version": "builtin-v1",
                            "allowlist_rule_id": "app-diagnostics-v1",
                            "enabled": true
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let state: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(state["draft"]["dirty"], true);
        assert_eq!(state["draft"]["revision"], 1);
        let mcp_ec2_scope = state["draft"]["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|scope| scope["id"] == "db-scope")
            .unwrap()["mcp_ec2_diagnostic_scopes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|scope| scope["id"] == "app-diagnostics")
            .unwrap()
            .clone();
        assert_eq!(mcp_ec2_scope["private_target_refs"][0], "service:app-api");
        assert_eq!(
            mcp_ec2_scope["allowed_log_paths"][0]["path_pattern"],
            "/var/log/app/error.log"
        );
        assert_eq!(
            mcp_ec2_scope["allowed_http_urls"][0]["normalized_url"],
            "https://example.com/health"
        );
        assert_eq!(mcp_ec2_scope["allowed_tcp_targets"][0]["port"], 443);
        assert_eq!(
            mcp_ec2_scope["allowed_tcp_targets"][0]["host"],
            "example.com"
        );
        assert_eq!(
            mcp_ec2_scope["allowed_dns_targets"][0]["record_types"][1],
            "AAAA"
        );
        assert!(state["changes"]["semantic_diff"]["high_risk"]
            .as_array()
            .unwrap()
            .iter()
            .any(|grant| grant["kind"]
                .as_str()
                .is_some_and(|kind| kind.starts_with("mcp_ec2_"))
                && grant["value"]
                    .as_str()
                    .is_some_and(|value| value.contains("app-diagnostics"))));
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_content
        );
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_mcp_ec2_scope_update_removes_scope_without_writing_catalog() {
        let (catalog_path, content) = write_catalog_fixture("mcp-ec2-scope-remove");
        let enriched = content.replacen(
            "\n[[group_mappings]]",
            r#"
[[scopes.mcp_ec2_diagnostic_scopes]]
id = "base-diagnostics"
private_target_refs = []
max_lines = 50
max_since_seconds = 600
max_timeout_seconds = 15
max_matches = 25
connectivity_probe_budget_per_window = 10
budget_window_seconds = 1200
denylist_version = "builtin-v1"
allowlist_rule_id = "base-diagnostics-v1"

[[scopes.mcp_ec2_diagnostic_scopes.allowed_log_paths]]
path_pattern = "/var/log/base/error.log"
canonical_safe_prefix = "/var/log/base/"
safe_for_mcp_output = true

[[scopes.mcp_ec2_diagnostic_scopes]]
id = "app-diagnostics"
private_target_refs = ["service:app-api"]
max_lines = 100
max_since_seconds = 900
max_timeout_seconds = 30
max_matches = 50
connectivity_probe_budget_per_window = 20
budget_window_seconds = 600
denylist_version = "builtin-v1"
allowlist_rule_id = "app-diagnostics-v1"

[[scopes.mcp_ec2_diagnostic_scopes.allowed_log_paths]]
path_pattern = "/var/log/app/error.log"
canonical_safe_prefix = "/var/log/app/"
safe_for_mcp_output = true

[[packages]]
id = "mcp-ec2-diagnostics"
features = ["mcp:use", "mcp:ec2"]
scope = "db-scope"
role = "readonly"

[[bindings]]
group = "RD"
package = "mcp-ec2-diagnostics"

[[group_mappings]]
"#,
            1,
        );
        std::fs::write(&catalog_path, &enriched).unwrap();
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/scopes/mcp-ec2")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"scope":"db-scope","id":"app-diagnostics","private_target_refs":[],"allowed_log_paths":[],"allowed_journal_units":[],"allowed_http_urls":[],"allowed_tcp_targets":[],"allowed_dns_targets":[],"max_lines":1,"max_since_seconds":1,"max_timeout_seconds":1,"max_matches":1,"connectivity_probe_budget_per_window":1,"budget_window_seconds":1,"denylist_version":"remove","allowlist_rule_id":"remove","enabled":false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let state: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(state["draft"]["dirty"], true);
        assert_eq!(state["draft"]["revision"], 1);
        let scope = state["draft"]["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|scope| scope["id"] == "db-scope")
            .unwrap();
        assert!(!scope["mcp_ec2_diagnostic_scopes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|ec2_scope| ec2_scope["id"] == "app-diagnostics"));
        assert!(state["changes"]["semantic_diff"]["removed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|grant| grant["kind"] == "mcp_ec2_diagnostic_scope"
                && grant["value"] == "app-diagnostics"));
        assert_eq!(std::fs::read_to_string(&catalog_path).unwrap(), enriched);
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_mcp_ec2_scope_update_requires_session_cookie() {
        let (catalog_path, _content) = write_catalog_fixture("mcp-ec2-scope-session");
        let response = router(test_state_with_catalog(catalog_path.clone()))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/scopes/mcp-ec2")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"scope":"db-scope","id":"app-diagnostics","private_target_refs":[],"allowed_log_paths":[],"allowed_journal_units":[],"allowed_http_urls":[],"allowed_tcp_targets":[],"allowed_dns_targets":[],"max_lines":1,"max_since_seconds":1,"max_timeout_seconds":1,"max_matches":1,"connectivity_probe_budget_per_window":1,"budget_window_seconds":1,"denylist_version":"builtin-v1","allowlist_rule_id":"app-diagnostics-v1","enabled":false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_mcp_ec2_scope_update_requires_local_origin() {
        let (catalog_path, _content) = write_catalog_fixture("mcp-ec2-scope-origin");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/scopes/mcp-ec2")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"scope":"db-scope","id":"app-diagnostics","private_target_refs":[],"allowed_log_paths":[],"allowed_journal_units":[],"allowed_http_urls":[],"allowed_tcp_targets":[],"allowed_dns_targets":[],"max_lines":1,"max_since_seconds":1,"max_timeout_seconds":1,"max_matches":1,"connectivity_probe_budget_per_window":1,"budget_window_seconds":1,"denylist_version":"builtin-v1","allowlist_rule_id":"app-diagnostics-v1","enabled":false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_database_scope_update_requires_session_cookie() {
        let (catalog_path, _content) = write_catalog_fixture("database-scope-session");
        let response = router(test_state_with_catalog(catalog_path.clone()))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/scopes/database")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"scope":"db-scope","name":"customer_read","connection":"orders","environment":"production","allowed_schemas":["mart"],"allowed_tables":["customers"],"allowed_actions":["select"],"max_rows":100,"statement_timeout_ms":5000,"require_explain":true,"max_examined_rows":10000,"allow_full_table_scan":false,"allow_views":false,"enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_database_scope_update_requires_local_origin() {
        let (catalog_path, _content) = write_catalog_fixture("database-scope-origin");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/scopes/database")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"scope":"db-scope","name":"customer_read","connection":"orders","environment":"production","allowed_schemas":["mart"],"allowed_tables":["customers"],"allowed_actions":["select"],"max_rows":100,"statement_timeout_ms":5000,"require_explain":true,"max_examined_rows":10000,"allow_full_table_scan":false,"allow_views":false,"enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_database_scope_update_rejects_mixed_case_identifier() {
        let (catalog_path, _content) = write_catalog_fixture("database-scope-mixed-case");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/scopes/database")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"scope":"db-scope","name":"customer_read","connection":"orders","environment":"production","allowed_schemas":["Mart"],"allowed_tables":["customers"],"allowed_actions":["select"],"max_rows":100,"statement_timeout_ms":5000,"require_explain":true,"max_examined_rows":10000,"allow_full_table_scan":false,"allow_views":false,"enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"]["code"], "invalid_database_scope_identifier");
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_membership_update_adds_member_without_writing_catalog() {
        let (catalog_path, original_content) = write_catalog_fixture("membership-update");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/memberships")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"group":"QA","user_id":"qa@example.com","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let state: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(state["draft"]["dirty"], true);
        assert_eq!(state["draft"]["revision"], 1);
        assert!(state["draft"]["groups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|group| group["id"] == "QA"
                && group["members"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::Value::String("qa@example.com".to_owned()))));
        assert!(state["changes"]["added_memberships"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["group"] == "QA" && change["user_id"] == "qa@example.com"));
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_content
        );
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_membership_update_requires_local_origin() {
        let (catalog_path, _content) = write_catalog_fixture("membership-origin");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/memberships")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"group":"RD","user_id":"qa@example.com","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_group_mapping_update_rejects_duplicate_external_group() {
        let (catalog_path, _content) = write_catalog_fixture("mapping-duplicate");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/group-mappings")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"group":"admin","external_group":"canopy-rd","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"]["code"], "duplicate_external_group_mapping");
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_preview_requires_local_origin() {
        let (catalog_path, _content) = write_catalog_fixture("preview-origin");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/preview")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"group":"RD"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_preview_rejects_unknown_group() {
        let (catalog_path, _content) = write_catalog_fixture("preview-unknown-group");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/preview")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"group":"finance"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"]["code"], "unknown_group");
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_explain_resolves_external_group_against_memory_draft() {
        let (catalog_path, _content) = write_catalog_fixture("explain-external-group");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/explain")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"sub":"operator","email":"operator@example.com","email_verified":true,"external_groups":["canopy-rd"]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let explain: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(explain["command"], "explain");
        assert!(explain["resolved_groups"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String("RD".to_owned())));
        assert!(explain["matched_packages"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String("analytics".to_owned())));
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_explain_defaults_to_startup_operator_identity() {
        let (catalog_path, _content) = write_catalog_fixture("explain-default-identity");
        let mut args = test_args();
        args.dev_operator_sub = Some("operator".to_owned());
        args.dev_operator_email = Some("operator@example.com".to_owned());
        args.dev_operator_email_verified = true;
        args.dev_operator_external_groups = vec!["canopy-rd".to_owned()];
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/explain")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let explain: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(explain["sub"], "operator");
        assert_eq!(explain["email"], "operator@example.com");
        assert!(explain["external_groups"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String("canopy-rd".to_owned())));
        assert!(explain["resolved_groups"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String("RD".to_owned())));
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_binding_update_adds_pending_high_risk_without_writing_catalog() {
        let (catalog_path, original_content) = write_catalog_fixture("binding-update");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/bindings")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"group":"RD","package":"mcp-database","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let state: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(state["draft"]["dirty"], true);
        assert_eq!(state["draft"]["revision"], 1);
        assert_eq!(state["changes"]["high_risk_added"], 1);
        assert!(state["changes"]["semantic_diff"]["added"]
            .as_array()
            .unwrap()
            .iter()
            .any(|grant| grant["group"] == "RD"
                && grant["package"] == "mcp-database"
                && grant["kind"] == "feature"
                && grant["value"] == "mcp:database"));
        assert!(state["changes"]["semantic_diff"]["added"]
            .as_array()
            .unwrap()
            .iter()
            .any(|grant| grant["group"] == "RD"
                && grant["package"] == "mcp-database"
                && grant["kind"] == "database_scope_allowed_table"
                && grant["value"] == "orders_read|orders"));
        assert!(state["changes"]["semantic_diff"]["high_risk"]
            .as_array()
            .unwrap()
            .iter()
            .any(|grant| grant["group"] == "RD"
                && grant["package"] == "mcp-database"
                && grant["kind"] == "feature"
                && grant["value"] == "mcp:database"));
        assert!(state["draft"]["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|binding| binding["group"] == "RD" && binding["package"] == "mcp-database"));
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_content
        );
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_package_update_adds_package_without_writing_catalog() {
        let (catalog_path, original_content) = write_catalog_fixture("package-add");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/packages")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"id":"qa-database","scope":"db-scope","role":"readonly","max_session_seconds":900,"enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let state: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(state["draft"]["dirty"], true);
        assert_eq!(state["draft"]["revision"], 1);
        assert!(state["draft"]["packages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|package| package["id"] == "qa-database"
                && package["scope"] == "db-scope"
                && package["role"] == "readonly"
                && package["max_session_seconds"] == 900));
        assert!(state["changes"]["added_packages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["id"] == "qa-database" && change["max_session_seconds"] == 900));
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_content
        );
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_package_update_updates_metadata_without_writing_catalog() {
        let (catalog_path, original_content) = write_catalog_fixture("package-update");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/packages")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"id":"analytics","scope":"db-scope","role":"readonly","max_session_seconds":600,"enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let state: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(state["draft"]["dirty"], true);
        assert_eq!(state["draft"]["revision"], 1);
        assert!(state["changes"]["updated_packages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["id"] == "analytics" && change["max_session_seconds"] == 600));
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_content
        );
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_package_update_requires_local_origin() {
        let (catalog_path, _content) = write_catalog_fixture("package-origin");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/packages")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"id":"qa-database","scope":"db-scope","role":"readonly","max_session_seconds":900,"enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_package_update_requires_session_cookie() {
        let (catalog_path, _content) = write_catalog_fixture("package-session");
        let response = router(test_state_with_catalog(catalog_path.clone()))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/packages")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"id":"qa-database","scope":"db-scope","role":"readonly","max_session_seconds":900,"enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_package_update_rejects_unknown_scope() {
        let (catalog_path, _content) = write_catalog_fixture("package-unknown-scope");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/packages")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"id":"qa-database","scope":"missing","role":"readonly","max_session_seconds":null,"enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"]["code"], "unknown_scope");
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_package_update_rejects_removing_bound_package() {
        let (catalog_path, _content) = write_catalog_fixture("package-remove-bound");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/packages")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"id":"analytics","scope":"","role":"","max_session_seconds":null,"enabled":false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"]["code"], "package_in_use");
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_package_feature_update_adds_high_risk_without_writing_catalog() {
        let (catalog_path, original_content) = write_catalog_fixture("package-feature-update");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/packages/features")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"package":"analytics","feature":"mcp:database","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let state: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(state["draft"]["dirty"], true);
        assert_eq!(state["draft"]["revision"], 1);
        let package = state["draft"]["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|package| package["id"] == "analytics")
            .unwrap();
        assert!(package["features"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String("mcp:use".to_owned())));
        assert!(package["features"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String("mcp:database".to_owned())));
        assert!(state["changes"]["semantic_diff"]["high_risk"]
            .as_array()
            .unwrap()
            .iter()
            .any(|grant| grant["package"] == "analytics"
                && grant["kind"] == "feature"
                && grant["value"] == "mcp:database"));
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_content
        );
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_package_feature_update_rejects_unknown_feature() {
        let (catalog_path, original_content) = write_catalog_fixture("package-feature-unknown");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/packages/features")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"package":"analytics","feature":"not:a-feature","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"]["code"], "unknown_catalog_feature");
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_content
        );
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_package_feature_update_rejects_disabling_required_base() {
        let (catalog_path, original_content) = write_catalog_fixture("package-feature-base");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/packages/features")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"package":"mcp-database","feature":"mcp:use","enabled":false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"]["code"], "required_base_feature");
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_content
        );
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_dry_run_mcp_database_uses_updated_memory_draft_without_writing_catalog() {
        let (catalog_path, original_content) = write_catalog_fixture("dry-run-memory-draft");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let app = router(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/bindings")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"group":"RD","package":"mcp-database","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/dry-run")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"operation":"mcp-database","sub":"operator","external_groups":["canopy-rd"],"scope":"orders_read","connection":"orders","environment":"production","schema":"mart","table":"orders","action":"select"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let dry_run: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(dry_run["command"], "dry-run");
        assert_eq!(dry_run["operation"], "mcp-database");
        assert_eq!(dry_run["allow"], true);
        assert_eq!(dry_run["matched_rule"], "catalog-rd-mcp-database");
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_content
        );
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_dry_run_defaults_to_startup_operator_identity() {
        let (catalog_path, original_content) = write_catalog_fixture("dry-run-default-identity");
        let mut args = test_args();
        args.dev_operator_sub = Some("operator".to_owned());
        args.dev_operator_email = Some("operator@example.com".to_owned());
        args.dev_operator_email_verified = true;
        args.dev_operator_external_groups = vec!["canopy-rd".to_owned()];
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);
        let app = router(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/bindings")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"group":"RD","package":"mcp-database","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/dry-run")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"operation":"mcp-database","scope":"orders_read","connection":"orders","environment":"production","schema":"mart","table":"orders","action":"select"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let dry_run: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(dry_run["allow"], true);
        assert!(dry_run["resolved_groups"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String("RD".to_owned())));
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_content
        );
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_dry_run_mcp_database_rejects_noncanonical_schema_before_db_execution() {
        let (catalog_path, _content) = write_catalog_fixture("dry-run-uppercase-schema");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/dry-run")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"operation":"mcp-database","sub":"operator","external_groups":["canopy-rd"],"scope":"orders_read","connection":"orders","environment":"production","schema":"Mart","table":"orders","action":"select"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"]["code"], "draft_dry_run_failed");
        assert!(error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--schema must be a lowercase ASCII SQL identifier"));
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_validate_uses_temp_runtime_and_does_not_write_formal_runtime() {
        let (catalog_path, catalog_content) = write_catalog_fixture("validate-clean-catalog");
        let runtime_path =
            write_runtime_from_catalog_fixture("validate-clean-runtime", &catalog_content);
        let db_config_path = write_database_config_fixture("validate-clean-db");
        let deployment_config_path = write_database_config_fixture("validate-clean-deploy");
        let original_runtime = std::fs::read_to_string(&runtime_path).unwrap();
        let mut args = test_args();
        args.runtime = runtime_path.clone();
        args.db_config = Some(db_config_path.clone());
        args.deployment_mode = Some("config".to_owned());
        args.deployment_config = Some(deployment_config_path.clone());
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/validate")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let validation: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(validation["command"], "validate");
        assert_eq!(validation["valid"], true);
        assert_eq!(
            validation["generated"]["runtime_path"],
            runtime_path.display().to_string()
        );
        assert_eq!(validation["generated"]["runtime_drift"], false);
        assert_eq!(validation["generated"]["temp_runtime_removed"], true);
        assert_eq!(validation["deployment"]["checked"], true);
        assert!(validation["database_connections"]["required"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String("orders".to_owned())));
        assert!(!String::from_utf8(body.to_vec())
            .unwrap()
            .contains("orders-secret-ref"));
        assert_eq!(
            std::fs::read_to_string(&runtime_path).unwrap(),
            original_runtime
        );
        let _ = std::fs::remove_file(catalog_path);
        let _ = std::fs::remove_file(runtime_path);
        let _ = std::fs::remove_file(db_config_path);
        let _ = std::fs::remove_file(deployment_config_path);
    }

    #[tokio::test]
    async fn draft_validate_blocks_missing_db_config_without_writing_runtime() {
        let (catalog_path, _catalog_content) = write_catalog_fixture("validate-missing-db-catalog");
        let runtime_path = catalog_fixture_path("validate-missing-db-runtime");
        let mut args = test_args();
        args.runtime = runtime_path.clone();
        args.db_config = None;
        args.deployment_mode = None;
        args.deployment_config = None;
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/validate")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let validation: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(validation["valid"], false);
        let issue_codes = validation["blocking_errors"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|issue| issue["code"].as_str())
            .collect::<Vec<_>>();
        assert!(issue_codes.contains(&"missing_db_config"));
        assert!(issue_codes.contains(&"missing_deployment_mode"));
        assert!(!runtime_path.exists());
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn draft_validate_blocks_deployment_connection_drift() {
        let (catalog_path, catalog_content) = write_catalog_fixture("validate-drift-catalog");
        let runtime_path =
            write_runtime_from_catalog_fixture("validate-drift-runtime", &catalog_content);
        let db_config_path = write_database_config_fixture("validate-drift-db");
        let deployment_config_path =
            write_database_config_fixture_with_database("validate-drift-deploy", "orders_archive");
        let mut args = test_args();
        args.runtime = runtime_path.clone();
        args.db_config = Some(db_config_path.clone());
        args.deployment_mode = Some("config".to_owned());
        args.deployment_config = Some(deployment_config_path.clone());
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/validate")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let validation: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(validation["valid"], false);
        assert!(validation["blocking_errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["code"] == "database_connection_deploy_drift"));
        let _ = std::fs::remove_file(catalog_path);
        let _ = std::fs::remove_file(runtime_path);
        let _ = std::fs::remove_file(db_config_path);
        let _ = std::fs::remove_file(deployment_config_path);
    }

    #[tokio::test]
    async fn draft_validate_requires_local_origin() {
        let (catalog_path, _content) = write_catalog_fixture("validate-origin");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/validate")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn apply_requires_session_cookie() {
        let (catalog_path, _content) = write_catalog_fixture("apply-session");
        let state = test_state_with_catalog(catalog_path.clone());

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apply")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn apply_requires_local_origin() {
        let (catalog_path, _content) = write_catalog_fixture("apply-origin");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apply")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn apply_blocks_invalid_validation_without_writing_files() {
        let (catalog_path, original_catalog) = write_catalog_fixture("apply-invalid-catalog");
        let runtime_path = catalog_fixture_path("apply-invalid-runtime");
        let mut args = test_args();
        args.runtime = runtime_path.clone();
        args.db_config = None;
        args.deployment_mode = None;
        args.deployment_config = None;
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apply")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let apply: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(apply["command"], "apply");
        assert_eq!(apply["applied"], false);
        assert_eq!(apply["status"], "blocked");
        assert_eq!(apply["gate"]["reason_code"], "validation_blocked");
        assert_eq!(apply["validation"]["valid"], false);
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_catalog
        );
        assert!(!runtime_path.exists());
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn apply_rejects_dev_identity_without_writing_catalog_or_runtime() {
        let (catalog_path, catalog_content) = write_catalog_fixture("apply-dev-catalog");
        let runtime_path =
            write_runtime_from_catalog_fixture("apply-dev-runtime", &catalog_content);
        let db_config_path = write_database_config_fixture("apply-dev-db");
        let deployment_config_path = write_database_config_fixture("apply-dev-deploy");
        let original_catalog = std::fs::read_to_string(&catalog_path).unwrap();
        let original_runtime = std::fs::read_to_string(&runtime_path).unwrap();
        let original_db_config = std::fs::read_to_string(&db_config_path).unwrap();
        let mut args = test_args();
        args.runtime = runtime_path.clone();
        args.db_config = Some(db_config_path.clone());
        args.deployment_mode = Some("config".to_owned());
        args.deployment_config = Some(deployment_config_path.clone());
        args.allow_dev_identity = true;
        args.identity_source = "dev-claims".to_owned();
        args.dev_operator_external_groups = vec!["canopy-admin".to_owned()];
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apply")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let apply: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(apply["command"], "apply");
        assert_eq!(apply["applied"], false);
        assert_eq!(apply["status"], "locked");
        assert_eq!(apply["gate"]["reason_code"], "dev_identity_apply_disabled");
        assert_eq!(apply["gate"]["can_apply"], false);
        assert_eq!(apply["validation"]["valid"], true);
        assert_eq!(apply["transaction"]["state"], "not_started");
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_catalog
        );
        assert_eq!(
            std::fs::read_to_string(&runtime_path).unwrap(),
            original_runtime
        );
        assert_eq!(
            std::fs::read_to_string(&db_config_path).unwrap(),
            original_db_config
        );
        let _ = std::fs::remove_file(catalog_path);
        let _ = std::fs::remove_file(runtime_path);
        let _ = std::fs::remove_file(db_config_path);
        let _ = std::fs::remove_file(deployment_config_path);
    }

    #[tokio::test]
    async fn apply_rejects_non_admin_operator_against_baseline_catalog() {
        let (catalog_path, catalog_content) = write_catalog_fixture("apply-non-admin-catalog");
        let runtime_path =
            write_runtime_from_catalog_fixture("apply-non-admin-runtime", &catalog_content);
        let db_config_path = write_database_config_fixture("apply-non-admin-db");
        let deployment_config_path = write_database_config_fixture("apply-non-admin-deploy");
        let original_catalog = std::fs::read_to_string(&catalog_path).unwrap();
        let original_runtime = std::fs::read_to_string(&runtime_path).unwrap();
        let original_db_config = std::fs::read_to_string(&db_config_path).unwrap();
        let mut args = test_args();
        args.runtime = runtime_path.clone();
        args.db_config = Some(db_config_path.clone());
        args.deployment_mode = Some("config".to_owned());
        args.deployment_config = Some(deployment_config_path.clone());
        args.identity_source = "os-allowlist".to_owned();
        args.allow_dev_identity = false;
        args.dev_operator_sub = Some("operator".to_owned());
        args.dev_operator_external_groups = vec!["canopy-rd".to_owned()];
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apply")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let apply: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(apply["applied"], false);
        assert_eq!(apply["gate"]["state"], "admin_blocked");
        assert_eq!(apply["gate"]["reason_code"], "non_admin_identity");
        assert_eq!(apply["validation"]["valid"], true);
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_catalog
        );
        assert_eq!(
            std::fs::read_to_string(&runtime_path).unwrap(),
            original_runtime
        );
        assert_eq!(
            std::fs::read_to_string(&db_config_path).unwrap(),
            original_db_config
        );
        let _ = std::fs::remove_file(catalog_path);
        let _ = std::fs::remove_file(runtime_path);
        let _ = std::fs::remove_file(db_config_path);
        let _ = std::fs::remove_file(deployment_config_path);
    }

    #[tokio::test]
    async fn apply_admin_gate_ignores_draft_self_grant() {
        let (catalog_path, catalog_content) =
            write_catalog_fixture_with_admin_member("apply-self-grant-catalog", "other-admin");
        let runtime_path =
            write_runtime_from_catalog_fixture("apply-self-grant-runtime", &catalog_content);
        let db_config_path = write_database_config_fixture("apply-self-grant-db");
        let deployment_config_path = write_database_config_fixture("apply-self-grant-deploy");
        let original_catalog = std::fs::read_to_string(&catalog_path).unwrap();
        let original_runtime = std::fs::read_to_string(&runtime_path).unwrap();
        let original_db_config = std::fs::read_to_string(&db_config_path).unwrap();
        let mut args = test_args();
        args.runtime = runtime_path.clone();
        args.db_config = Some(db_config_path.clone());
        args.deployment_mode = Some("config".to_owned());
        args.deployment_config = Some(deployment_config_path.clone());
        args.identity_source = "os-allowlist".to_owned();
        args.allow_dev_identity = false;
        args.dev_operator_sub = Some("operator".to_owned());
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);
        let app = router(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/memberships")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"group":"admin","user_id":"operator","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apply")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let apply: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(apply["applied"], false);
        assert_eq!(apply["gate"]["state"], "admin_blocked");
        assert_eq!(apply["gate"]["reason_code"], "non_admin_identity");
        assert_eq!(apply["validation"]["valid"], true);
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_catalog
        );
        assert_eq!(
            std::fs::read_to_string(&runtime_path).unwrap(),
            original_runtime
        );
        assert_eq!(
            std::fs::read_to_string(&db_config_path).unwrap(),
            original_db_config
        );
        let _ = std::fs::remove_file(catalog_path);
        let _ = std::fs::remove_file(runtime_path);
        let _ = std::fs::remove_file(db_config_path);
        let _ = std::fs::remove_file(deployment_config_path);
    }

    #[tokio::test]
    async fn apply_baseline_admin_reaches_authorization_transaction_lock() {
        let (catalog_path, catalog_content) =
            write_catalog_fixture_with_admin_member("apply-admin-catalog", "operator");
        let runtime_path =
            write_runtime_from_catalog_fixture("apply-admin-runtime", &catalog_content);
        let db_config_path = write_database_config_fixture("apply-admin-db");
        let deployment_config_path = write_database_config_fixture("apply-admin-deploy");
        let original_catalog = std::fs::read_to_string(&catalog_path).unwrap();
        let original_runtime = std::fs::read_to_string(&runtime_path).unwrap();
        let original_db_config = std::fs::read_to_string(&db_config_path).unwrap();
        let mut args = test_args();
        args.runtime = runtime_path.clone();
        args.db_config = Some(db_config_path.clone());
        args.deployment_mode = Some("config".to_owned());
        args.deployment_config = Some(deployment_config_path.clone());
        args.identity_source = "os-allowlist".to_owned();
        args.allow_dev_identity = false;
        args.dev_operator_sub = Some("operator".to_owned());
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apply")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let apply: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(apply["applied"], false);
        assert_eq!(apply["gate"]["state"], "admin_ready");
        assert_eq!(
            apply["gate"]["reason_code"],
            "apply_transaction_unavailable"
        );
        assert_eq!(apply["validation"]["valid"], true);
        assert_eq!(apply["transaction"]["state"], "not_started");
        assert_eq!(apply["transaction"]["lock_exists"], false);
        assert_eq!(apply["transaction"]["manifest_exists"], false);
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_catalog
        );
        assert_eq!(
            std::fs::read_to_string(&runtime_path).unwrap(),
            original_runtime
        );
        assert_eq!(
            std::fs::read_to_string(&db_config_path).unwrap(),
            original_db_config
        );
        let _ = std::fs::remove_file(catalog_path);
        let _ = std::fs::remove_file(runtime_path);
        let _ = std::fs::remove_file(db_config_path);
        let _ = std::fs::remove_file(deployment_config_path);
    }

    #[tokio::test]
    async fn apply_uses_auth_config_admin_group_against_baseline_catalog() {
        let (catalog_path, catalog_content) = write_catalog_fixture_with_group_member(
            "apply-auth-config-admin-catalog",
            "ops-admin",
            "operator",
        );
        let runtime_path =
            write_runtime_from_catalog_fixture("apply-auth-config-admin-runtime", &catalog_content);
        let db_config_path = write_database_config_fixture("apply-auth-config-admin-db");
        let deployment_config_path =
            write_database_config_fixture("apply-auth-config-admin-deploy");
        let auth_config_path =
            write_auth_config_fixture("apply-auth-config-admin-auth", "ops-admin");
        let original_catalog = std::fs::read_to_string(&catalog_path).unwrap();
        let original_runtime = std::fs::read_to_string(&runtime_path).unwrap();
        let original_db_config = std::fs::read_to_string(&db_config_path).unwrap();
        let mut args = test_args();
        args.runtime = runtime_path.clone();
        args.db_config = Some(db_config_path.clone());
        args.deployment_mode = Some("config".to_owned());
        args.deployment_config = Some(deployment_config_path.clone());
        args.auth_config = Some(auth_config_path.clone());
        args.identity_source = "os-allowlist".to_owned();
        args.allow_dev_identity = false;
        args.dev_admin_group = "admin".to_owned();
        args.dev_operator_sub = Some("operator".to_owned());
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apply")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let apply: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(apply["applied"], false);
        assert_eq!(apply["gate"]["state"], "admin_ready");
        assert_eq!(apply["gate"]["admin_group"], "ops-admin");
        assert_eq!(
            apply["gate"]["reason_code"],
            "apply_transaction_unavailable"
        );
        assert_eq!(apply["validation"]["valid"], true);
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_catalog
        );
        assert_eq!(
            std::fs::read_to_string(&runtime_path).unwrap(),
            original_runtime
        );
        assert_eq!(
            std::fs::read_to_string(&db_config_path).unwrap(),
            original_db_config
        );
        let _ = std::fs::remove_file(catalog_path);
        let _ = std::fs::remove_file(runtime_path);
        let _ = std::fs::remove_file(db_config_path);
        let _ = std::fs::remove_file(deployment_config_path);
        let _ = std::fs::remove_file(auth_config_path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn apply_rejects_auth_config_that_becomes_group_writable() {
        let (catalog_path, catalog_content) = write_catalog_fixture_with_group_member(
            "apply-auth-config-writable-catalog",
            "ops-admin",
            "operator",
        );
        let runtime_path = write_runtime_from_catalog_fixture(
            "apply-auth-config-writable-runtime",
            &catalog_content,
        );
        let db_config_path = write_database_config_fixture("apply-auth-config-writable-db");
        let deployment_config_path =
            write_database_config_fixture("apply-auth-config-writable-deploy");
        let auth_config_path =
            write_auth_config_fixture("apply-auth-config-writable-auth", "ops-admin");
        let original_catalog = std::fs::read_to_string(&catalog_path).unwrap();
        let original_runtime = std::fs::read_to_string(&runtime_path).unwrap();
        let original_db_config = std::fs::read_to_string(&db_config_path).unwrap();
        let mut args = test_args();
        args.runtime = runtime_path.clone();
        args.db_config = Some(db_config_path.clone());
        args.deployment_mode = Some("config".to_owned());
        args.deployment_config = Some(deployment_config_path.clone());
        args.auth_config = Some(auth_config_path.clone());
        args.identity_source = "os-allowlist".to_owned();
        args.allow_dev_identity = false;
        args.dev_operator_sub = Some("operator".to_owned());
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);
        std::fs::set_permissions(&auth_config_path, std::fs::Permissions::from_mode(0o620))
            .unwrap();

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apply")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let apply: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(apply["applied"], false);
        assert_eq!(apply["gate"]["state"], "admin_blocked");
        assert_eq!(
            apply["gate"]["reason_code"],
            "canonical_auth_config_invalid"
        );
        assert!(apply["gate"]["message"]
            .as_str()
            .unwrap()
            .contains("must not be group/world writable"));
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_catalog
        );
        assert_eq!(
            std::fs::read_to_string(&runtime_path).unwrap(),
            original_runtime
        );
        assert_eq!(
            std::fs::read_to_string(&db_config_path).unwrap(),
            original_db_config
        );
        let _ = std::fs::remove_file(catalog_path);
        let _ = std::fs::remove_file(runtime_path);
        let _ = std::fs::remove_file(db_config_path);
        let _ = std::fs::remove_file(deployment_config_path);
        let _ = std::fs::remove_file(auth_config_path);
    }

    #[tokio::test]
    async fn apply_blocks_existing_transaction_lock_without_writing_files() {
        let (catalog_path, catalog_content) =
            write_catalog_fixture_with_admin_member("apply-lock-catalog", "operator");
        let runtime_path =
            write_runtime_from_catalog_fixture("apply-lock-runtime", &catalog_content);
        let db_config_path = write_database_config_fixture("apply-lock-db");
        let deployment_config_path = write_database_config_fixture("apply-lock-deploy");
        let original_catalog = std::fs::read_to_string(&catalog_path).unwrap();
        let original_runtime = std::fs::read_to_string(&runtime_path).unwrap();
        let original_db_config = std::fs::read_to_string(&db_config_path).unwrap();
        let (lock_path, _manifest_path) = transaction_artifact_paths(&catalog_path);
        let mut args = test_args();
        args.runtime = runtime_path.clone();
        args.db_config = Some(db_config_path.clone());
        args.deployment_mode = Some("config".to_owned());
        args.deployment_config = Some(deployment_config_path.clone());
        args.identity_source = "os-allowlist".to_owned();
        args.allow_dev_identity = false;
        args.dev_operator_sub = Some("operator".to_owned());
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);
        std::fs::write(&lock_path, "pending transaction").unwrap();

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apply")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let apply: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(apply["status"], "blocked");
        assert_eq!(apply["applied"], false);
        assert_eq!(apply["validation"]["valid"], true);
        assert_eq!(apply["gate"]["state"], "transaction_blocked");
        assert_eq!(apply["gate"]["reason_code"], "transaction_lock_exists");
        assert_eq!(apply["transaction"]["state"], "lock_blocked");
        assert_eq!(apply["transaction"]["lock_exists"], true);
        assert_eq!(
            apply["transaction"]["lock_path"],
            lock_path.display().to_string()
        );
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_catalog
        );
        assert_eq!(
            std::fs::read_to_string(&runtime_path).unwrap(),
            original_runtime
        );
        assert_eq!(
            std::fs::read_to_string(&db_config_path).unwrap(),
            original_db_config
        );
        let _ = std::fs::remove_file(lock_path);
        let _ = std::fs::remove_file(catalog_path);
        let _ = std::fs::remove_file(runtime_path);
        let _ = std::fs::remove_file(db_config_path);
        let _ = std::fs::remove_file(deployment_config_path);
    }

    #[tokio::test]
    async fn apply_blocks_existing_transaction_manifest_without_writing_files() {
        let (catalog_path, catalog_content) =
            write_catalog_fixture_with_admin_member("apply-manifest-catalog", "operator");
        let runtime_path =
            write_runtime_from_catalog_fixture("apply-manifest-runtime", &catalog_content);
        let db_config_path = write_database_config_fixture("apply-manifest-db");
        let deployment_config_path = write_database_config_fixture("apply-manifest-deploy");
        let original_catalog = std::fs::read_to_string(&catalog_path).unwrap();
        let original_runtime = std::fs::read_to_string(&runtime_path).unwrap();
        let original_db_config = std::fs::read_to_string(&db_config_path).unwrap();
        let (_lock_path, manifest_path) = transaction_artifact_paths(&catalog_path);
        let mut args = test_args();
        args.runtime = runtime_path.clone();
        args.db_config = Some(db_config_path.clone());
        args.deployment_mode = Some("config".to_owned());
        args.deployment_config = Some(deployment_config_path.clone());
        args.identity_source = "os-allowlist".to_owned();
        args.allow_dev_identity = false;
        args.dev_operator_sub = Some("operator".to_owned());
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);
        std::fs::write(&manifest_path, r#"{"state":"incomplete"}"#).unwrap();

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apply")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let apply: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(apply["status"], "blocked");
        assert_eq!(apply["applied"], false);
        assert_eq!(apply["validation"]["valid"], true);
        assert_eq!(apply["gate"]["state"], "transaction_blocked");
        assert_eq!(apply["gate"]["reason_code"], "transaction_manifest_exists");
        assert_eq!(apply["transaction"]["state"], "manifest_blocked");
        assert_eq!(apply["transaction"]["manifest_exists"], true);
        assert_eq!(
            apply["transaction"]["manifest_path"],
            manifest_path.display().to_string()
        );
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_catalog
        );
        assert_eq!(
            std::fs::read_to_string(&runtime_path).unwrap(),
            original_runtime
        );
        assert_eq!(
            std::fs::read_to_string(&db_config_path).unwrap(),
            original_db_config
        );
        let _ = std::fs::remove_file(manifest_path);
        let _ = std::fs::remove_file(catalog_path);
        let _ = std::fs::remove_file(runtime_path);
        let _ = std::fs::remove_file(db_config_path);
        let _ = std::fs::remove_file(deployment_config_path);
    }

    #[tokio::test]
    async fn apply_blocks_catalog_baseline_digest_mismatch_without_writing_files() {
        let (catalog_path, catalog_content) =
            write_catalog_fixture_with_admin_member("apply-catalog-mismatch-catalog", "operator");
        let runtime_path =
            write_runtime_from_catalog_fixture("apply-catalog-mismatch-runtime", &catalog_content);
        let db_config_path = write_database_config_fixture("apply-catalog-mismatch-db");
        let deployment_config_path = write_database_config_fixture("apply-catalog-mismatch-deploy");
        let original_runtime = std::fs::read_to_string(&runtime_path).unwrap();
        let original_db_config = std::fs::read_to_string(&db_config_path).unwrap();
        let external_catalog = format!("{catalog_content}\n# external update after UI startup\n");
        let mut args = test_args();
        args.runtime = runtime_path.clone();
        args.db_config = Some(db_config_path.clone());
        args.deployment_mode = Some("config".to_owned());
        args.deployment_config = Some(deployment_config_path.clone());
        args.identity_source = "os-allowlist".to_owned();
        args.allow_dev_identity = false;
        args.dev_operator_sub = Some("operator".to_owned());
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);
        std::fs::write(&catalog_path, &external_catalog).unwrap();

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apply")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let apply: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(apply["status"], "blocked");
        assert_eq!(apply["applied"], false);
        assert_eq!(apply["validation"]["valid"], true);
        assert_eq!(apply["gate"]["state"], "transaction_blocked");
        assert_eq!(apply["gate"]["reason_code"], "baseline_digest_mismatch");
        assert_eq!(apply["transaction"]["state"], "baseline_mismatch");
        assert_eq!(
            apply["transaction"]["baseline_mismatches"][0]["artifact"],
            "catalog"
        );
        assert_eq!(
            apply["transaction"]["baseline_mismatches"][0]["reason_code"],
            "baseline_digest_mismatch"
        );
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            external_catalog
        );
        assert_eq!(
            std::fs::read_to_string(&runtime_path).unwrap(),
            original_runtime
        );
        assert_eq!(
            std::fs::read_to_string(&db_config_path).unwrap(),
            original_db_config
        );
        let _ = std::fs::remove_file(catalog_path);
        let _ = std::fs::remove_file(runtime_path);
        let _ = std::fs::remove_file(db_config_path);
        let _ = std::fs::remove_file(deployment_config_path);
    }

    #[tokio::test]
    async fn apply_blocks_runtime_baseline_digest_mismatch_without_writing_files() {
        let (catalog_path, catalog_content) =
            write_catalog_fixture_with_admin_member("apply-runtime-mismatch-catalog", "operator");
        let runtime_path =
            write_runtime_from_catalog_fixture("apply-runtime-mismatch-runtime", &catalog_content);
        let db_config_path = write_database_config_fixture("apply-runtime-mismatch-db");
        let deployment_config_path = write_database_config_fixture("apply-runtime-mismatch-deploy");
        let original_catalog = std::fs::read_to_string(&catalog_path).unwrap();
        let original_db_config = std::fs::read_to_string(&db_config_path).unwrap();
        let external_runtime = format!(
            "{}\n# external update after UI startup\n",
            std::fs::read_to_string(&runtime_path).unwrap()
        );
        let mut args = test_args();
        args.runtime = runtime_path.clone();
        args.db_config = Some(db_config_path.clone());
        args.deployment_mode = Some("config".to_owned());
        args.deployment_config = Some(deployment_config_path.clone());
        args.identity_source = "os-allowlist".to_owned();
        args.allow_dev_identity = false;
        args.dev_operator_sub = Some("operator".to_owned());
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);
        std::fs::write(&runtime_path, &external_runtime).unwrap();

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apply")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let apply: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(apply["status"], "blocked");
        assert_eq!(apply["applied"], false);
        assert_eq!(apply["validation"]["valid"], true);
        assert_eq!(apply["gate"]["state"], "transaction_blocked");
        assert_eq!(apply["gate"]["reason_code"], "baseline_digest_mismatch");
        assert_eq!(apply["transaction"]["state"], "baseline_mismatch");
        assert_eq!(
            apply["transaction"]["baseline_mismatches"][0]["artifact"],
            "runtime"
        );
        assert_eq!(
            apply["transaction"]["baseline_mismatches"][0]["reason_code"],
            "baseline_digest_mismatch"
        );
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_catalog
        );
        assert_eq!(
            std::fs::read_to_string(&runtime_path).unwrap(),
            external_runtime
        );
        assert_eq!(
            std::fs::read_to_string(&db_config_path).unwrap(),
            original_db_config
        );
        let _ = std::fs::remove_file(catalog_path);
        let _ = std::fs::remove_file(runtime_path);
        let _ = std::fs::remove_file(db_config_path);
        let _ = std::fs::remove_file(deployment_config_path);
    }

    #[tokio::test]
    async fn apply_blocks_db_config_baseline_digest_mismatch_without_writing_files() {
        let (catalog_path, catalog_content) =
            write_catalog_fixture_with_admin_member("apply-db-mismatch-catalog", "operator");
        let runtime_path =
            write_runtime_from_catalog_fixture("apply-db-mismatch-runtime", &catalog_content);
        let db_config_path = write_database_config_fixture("apply-db-mismatch-db");
        let deployment_config_path = write_database_config_fixture("apply-db-mismatch-deploy");
        let original_catalog = std::fs::read_to_string(&catalog_path).unwrap();
        let original_runtime = std::fs::read_to_string(&runtime_path).unwrap();
        let external_db_config = r#"
[database_connections.orders]
engine = "mysql"
host = "orders.example.internal"
port = 3306
database = "orders"
secret_arn = "orders-secret-ref-updated"
readonly = true
require_tls = true
"#
        .trim_start()
        .to_owned();
        let mut args = test_args();
        args.runtime = runtime_path.clone();
        args.db_config = Some(db_config_path.clone());
        args.deployment_mode = Some("config".to_owned());
        args.deployment_config = Some(deployment_config_path.clone());
        args.identity_source = "os-allowlist".to_owned();
        args.allow_dev_identity = false;
        args.dev_operator_sub = Some("operator".to_owned());
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);
        std::fs::write(&db_config_path, &external_db_config).unwrap();

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/apply")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let apply: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(apply["status"], "blocked");
        assert_eq!(apply["applied"], false);
        assert_eq!(apply["validation"]["valid"], true);
        assert_eq!(apply["gate"]["state"], "transaction_blocked");
        assert_eq!(apply["gate"]["reason_code"], "baseline_digest_mismatch");
        assert_eq!(apply["transaction"]["state"], "baseline_mismatch");
        assert_eq!(
            apply["transaction"]["baseline_mismatches"][0]["artifact"],
            "db_config"
        );
        assert_eq!(
            apply["transaction"]["baseline_mismatches"][0]["reason_code"],
            "baseline_digest_mismatch"
        );
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_catalog
        );
        assert_eq!(
            std::fs::read_to_string(&runtime_path).unwrap(),
            original_runtime
        );
        assert_eq!(
            std::fs::read_to_string(&db_config_path).unwrap(),
            external_db_config
        );
        let _ = std::fs::remove_file(catalog_path);
        let _ = std::fs::remove_file(runtime_path);
        let _ = std::fs::remove_file(db_config_path);
        let _ = std::fs::remove_file(deployment_config_path);
    }

    #[tokio::test]
    async fn import_runtime_rejects_unconfigured_import_source() {
        let (catalog_path, _content) = write_catalog_fixture("import-unconfigured");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/import-runtime")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"]["code"], "import_runtime_unconfigured");
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn import_runtime_requires_local_origin() {
        let (catalog_path, _content) = write_catalog_fixture("import-origin");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/import-runtime")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn import_runtime_updates_memory_draft_without_writing_catalog() {
        let (source_catalog_path, source_catalog) = write_catalog_fixture("import-source-catalog");
        let runtime_path =
            write_runtime_from_catalog_fixture("import-source-runtime", &source_catalog);
        let catalog_path = catalog_fixture_path("import-target-catalog");
        let runtime_output_path = catalog_fixture_path("import-generated-runtime");
        let mut args = test_args();
        args.catalog = catalog_path.clone();
        args.runtime = runtime_output_path.clone();
        args.import_runtime = Some(runtime_path.clone());
        let state = test_state_with_catalog_and_args(catalog_path.clone(), args);
        install_session(&state);

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/import-runtime")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let state: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(state["draft"]["loaded"], true);
        assert_eq!(state["draft"]["dirty"], true);
        assert_eq!(state["draft"]["revision"], 1);
        assert_eq!(state["capabilities"]["draft_write"], true);
        assert_eq!(state["capabilities"]["import_runtime"], true);
        assert!(state["draft"]["groups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|group| group["id"] == "RD"));
        assert!(state["draft"]["packages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|package| package["features"]
                .as_array()
                .unwrap()
                .contains(&serde_json::Value::String("cloudwatch:search".to_owned()))));
        assert!(!catalog_path.exists());
        assert!(!runtime_output_path.exists());
        let _ = std::fs::remove_file(source_catalog_path);
        let _ = std::fs::remove_file(runtime_path);
    }

    #[test]
    fn ui_file_path_validation_rejects_catalog_runtime_and_import_collisions() {
        let mut args = test_args();
        args.catalog = PathBuf::from("same.toml");
        args.runtime = PathBuf::from("./same.toml");
        let err = validate_ui_file_paths(&args).unwrap_err().to_string();
        assert!(err.contains("--catalog and --runtime"));

        let mut args = test_args();
        args.catalog = PathBuf::from("catalog.toml");
        args.runtime = PathBuf::from("generated.toml");
        args.import_runtime = Some(PathBuf::from("./generated.toml"));
        let err = validate_ui_file_paths(&args).unwrap_err().to_string();
        assert!(err.contains("--import-runtime and --runtime"));

        let mut args = test_args();
        args.catalog = PathBuf::from("catalog.toml");
        args.runtime = PathBuf::from("generated.toml");
        args.import_runtime = Some(PathBuf::from("./catalog.toml"));
        let err = validate_ui_file_paths(&args).unwrap_err().to_string();
        assert!(err.contains("--import-runtime and --catalog"));
    }

    #[test]
    fn operator_jwt_validation_accepts_private_file_outside_repo() {
        let path = catalog_fixture_path("operator-jwt-safe");
        std::fs::write(&path, "header.payload.signature").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut args = test_args();
        args.operator_jwt = Some(path.clone());

        validate_ui_file_paths(&args).unwrap();

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn operator_jwt_validation_rejects_repo_worktree_path() {
        let path = std::env::current_dir()
            .unwrap()
            .join(format!(".canopy-test-operator-{}.jwt", random_url_token()));
        std::fs::write(&path, "header.payload.signature").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut args = test_args();
        args.operator_jwt = Some(path.clone());

        let err = validate_ui_file_paths(&args).unwrap_err().to_string();
        assert!(err.contains("outside the repository working tree"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn auth_config_validation_rejects_repo_worktree_path() {
        let path = std::env::current_dir()
            .unwrap()
            .join(format!(".canopy-test-auth-{}.toml", random_url_token()));
        std::fs::write(&path, "admin_group = \"admin\"\n").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut args = test_args();
        args.auth_config = Some(path.clone());

        let err = validate_ui_file_paths(&args).unwrap_err().to_string();
        assert!(err.contains("--auth-config file"));
        assert!(err.contains("outside the repository working tree"));

        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn operator_jwt_validation_rejects_group_or_world_writable_file() {
        let path = catalog_fixture_path("operator-jwt-writable");
        std::fs::write(&path, "header.payload.signature").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o620)).unwrap();
        let mut args = test_args();
        args.operator_jwt = Some(path.clone());

        let err = validate_ui_file_paths(&args).unwrap_err().to_string();
        assert!(err.contains("must not be group/world writable"));

        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn operator_jwt_validation_rejects_symlink() {
        let target = catalog_fixture_path("operator-jwt-target");
        let link = catalog_fixture_path("operator-jwt-link");
        std::fs::write(&target, "header.payload.signature").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let mut args = test_args();
        args.operator_jwt = Some(link.clone());

        let err = validate_ui_file_paths(&args).unwrap_err().to_string();
        assert!(err.contains("must not be a symlink"));

        let _ = std::fs::remove_file(link);
        let _ = std::fs::remove_file(target);
    }

    #[test]
    fn tfvars_database_connections_toml_heredoc_extracts_connections() {
        let snippet = r#"
locals {
}
database_connections_toml = <<-TOML
[database_connections.orders]
engine = "mysql"
host = "orders.example.internal"
database = "orders"
secret_arn = "orders-secret-ref"
readonly = true
TOML
"#;
        let toml = extract_tfvars_database_connections_toml(snippet).unwrap();
        let path = PathBuf::from("terraform.tfvars");
        let registry = parse_connection_registry(&toml, &path).unwrap();
        assert!(registry.contains_key("orders"));
    }

    #[test]
    fn database_connection_parser_rejects_mistyped_tls_bool() {
        let content = r#"
[database_connections.orders]
engine = "mysql"
host = "orders.example.internal"
database = "orders"
secret_arn = "orders-secret-ref"
readonly = true
require_tls = "true"
"#;
        let path = PathBuf::from("database_connections.local.toml");
        let issue = parse_connection_registry(content, &path).unwrap_err();
        assert_eq!(issue.code, "database_connection_invalid_field_type");
        assert!(issue.message.contains("require_tls must be a boolean"));
    }

    #[tokio::test]
    async fn draft_preview_uses_updated_memory_draft_without_writing_catalog() {
        let (catalog_path, original_content) = write_catalog_fixture("preview-memory-draft");
        let state = test_state_with_catalog(catalog_path.clone());
        install_session(&state);
        let app = router(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/draft/bindings")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"group":"RD","package":"mcp-database","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/preview")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::COOKIE, state_cookie())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"group":"RD"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let preview: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(preview["command"], "preview");
        assert_eq!(preview["group"], "RD");
        assert!(preview["packages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|package| {
                package["package"] == "mcp-database"
                    && package["high_risk_features"]
                        .as_array()
                        .unwrap()
                        .contains(&serde_json::Value::String("mcp:database".to_owned()))
            }));
        assert_eq!(
            std::fs::read_to_string(&catalog_path).unwrap(),
            original_content
        );
        let _ = std::fs::remove_file(catalog_path);
    }

    #[tokio::test]
    async fn exchange_rejects_query_code_and_invalidates_bootstrap() {
        let app = router(test_state("single-use-code"));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/session/exchange?code=single-use-code")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"code":"single-use-code"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/session/exchange")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"code":"single-use-code"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn failed_exchange_invalidates_bootstrap_code() {
        let app = router(test_state("right-code"));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/session/exchange")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"code":"wrong-code"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/session/exchange")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"code":"right-code"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn malformed_exchange_request_invalidates_bootstrap_code() {
        let app = router(test_state("json-code"));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/session/exchange")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{not-json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/session/exchange")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"code":"json-code"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn exchange_rejects_nonlocal_origin() {
        let response = router(test_state("origin-code"))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/session/exchange")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "https://example.com")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"code":"origin-code"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn local_host_validation_rejects_suffix_hosts() {
        assert!(is_local_host("127.0.0.1:8080"));
        assert!(is_local_host("localhost:8080"));
        assert!(is_local_host("[::1]:8080"));
        assert!(!is_local_host("127.0.0.1:8080.evil"));
        assert!(!is_local_host("localhost.evil"));
        assert!(!is_local_host("[::1]:8080.evil"));
        assert!(!is_local_host("127.0.0.1:"));
    }

    #[test]
    fn rejects_non_loopback_bind_addresses() {
        let err = validate_bind_addr("0.0.0.0:8080".parse().unwrap())
            .unwrap_err()
            .to_string();
        assert!(err.contains("not loopback"));
        validate_bind_addr("127.0.0.1:0".parse().unwrap()).unwrap();
    }

    #[test]
    fn expired_bootstrap_code_is_rejected() {
        let state = UiAppState::for_test(test_args(), "expired-code", Instant::now());
        std::thread::sleep(Duration::from_millis(1));
        assert!(!state.claim_bootstrap_code("expired-code"));
    }
}
