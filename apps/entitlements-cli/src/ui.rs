use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::{self, Write};
use std::net::SocketAddr;
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

use crate::catalog::{self, Catalog, CatalogBinding, CatalogPackage};

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
        .route("/api/draft/bindings", put(put_draft_binding))
        .fallback(not_found)
        .with_state(state)
}

#[derive(Clone, Debug)]
struct UiAppState {
    args: Arc<UiArgs>,
    bootstrap: Arc<Mutex<BootstrapState>>,
    sessions: Arc<Mutex<HashMap<String, SessionRecord>>>,
    draft: Arc<Mutex<DraftState>>,
}

impl UiAppState {
    fn new(args: UiArgs, code: String, expires_at: Instant) -> Self {
        let draft = DraftState::load(&args.catalog);
        Self {
            args: Arc::new(args),
            bootstrap: Arc::new(Mutex::new(BootstrapState {
                code: Some(code),
                expires_at,
            })),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            draft: Arc::new(Mutex::new(draft)),
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
}

#[derive(Debug, Serialize)]
struct UiCapabilities {
    state: bool,
    preview: bool,
    explain: bool,
    dry_run: bool,
    draft_write: bool,
    validate: bool,
    apply: bool,
}

#[derive(Debug, Serialize)]
struct UiDraftResponse {
    loaded: bool,
    status: &'static str,
    revision: u64,
    dirty: bool,
    groups: Vec<UiGroupSummary>,
    packages: Vec<UiPackageSummary>,
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
struct UiDatabaseScopeSummary {
    name: String,
    connection: String,
    environment: String,
    allowed_schemas: Vec<String>,
    allowed_tables: Vec<String>,
    allowed_actions: Vec<String>,
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
    high_risk_added: usize,
    high_risk_removed: usize,
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

    fn sanitized_state(&self) -> UiStateResponse {
        let args = self.args.as_ref();
        let (draft, changes) = self
            .draft
            .lock()
            .expect("draft mutex should not be poisoned")
            .summarize();
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
            identity: UiIdentityState {
                source: args.identity_source.clone(),
                dev_identity_allowed: args.allow_dev_identity,
                dev_admin_group: args.dev_admin_group.clone(),
                operator_sub_configured: args.dev_operator_sub.is_some(),
                operator_email_configured: args.dev_operator_email.is_some(),
                operator_external_group_count: args.dev_operator_external_groups.len(),
                operator_jwt_configured: args.operator_jwt.is_some(),
            },
            capabilities: UiCapabilities {
                state: true,
                preview: draft_write,
                explain: draft_write,
                dry_run: draft_write,
                draft_write,
                validate: false,
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
            self.revision = self.revision.saturating_add(1);
            self.dirty = self
                .baseline
                .as_ref()
                .is_some_and(|baseline| binding_set(baseline) != binding_set(draft));
        }
        Ok(())
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

    fn summarize(&self) -> (UiDraftResponse, UiPendingChanges) {
        let Some(draft) = self.draft.as_ref() else {
            return (
                UiDraftResponse {
                    loaded: false,
                    status: "unavailable",
                    revision: self.revision,
                    dirty: self.dirty,
                    groups: Vec::new(),
                    packages: Vec::new(),
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
                packages: package_summaries(draft),
                bindings: binding_summaries(draft),
                selected_group,
                error: None,
            },
            changes,
        )
    }
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
            high_risk_added: 0,
            high_risk_removed: 0,
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
    let high_risk_added = added_bindings
        .iter()
        .filter(|change| change.high_risk)
        .count();
    let high_risk_removed = removed_bindings
        .iter()
        .filter(|change| change.high_risk)
        .count();
    UiPendingChanges {
        added_bindings,
        removed_bindings,
        high_risk_added,
        high_risk_removed,
    }
}

fn package_index(catalog: &Catalog) -> BTreeMap<&str, &CatalogPackage> {
    catalog
        .packages
        .iter()
        .map(|package| (package.id.as_str(), package))
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

    fn state_cookie() -> &'static str {
        "canopy_ui_session=session-token"
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
        let _ = std::fs::remove_file(catalog_path);
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
