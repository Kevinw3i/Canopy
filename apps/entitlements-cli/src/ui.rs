use std::collections::HashMap;
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
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;

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
        .fallback(not_found)
        .with_state(state)
}

#[derive(Clone, Debug)]
struct UiAppState {
    args: Arc<UiArgs>,
    bootstrap: Arc<Mutex<BootstrapState>>,
    sessions: Arc<Mutex<HashMap<String, SessionRecord>>>,
}

impl UiAppState {
    fn new(args: UiArgs, code: String, expires_at: Instant) -> Self {
        Self {
            args: Arc::new(args),
            bootstrap: Arc::new(Mutex::new(BootstrapState {
                code: Some(code),
                expires_at,
            })),
            sessions: Arc::new(Mutex::new(HashMap::new())),
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

#[derive(Debug, Deserialize)]
struct ExchangeRequest {
    code: String,
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
    draft_write: bool,
    validate: bool,
    apply: bool,
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
    let Some(session) = session_cookie(&headers) else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "missing_session",
            "UI session cookie is required",
        );
    };
    if !state.validate_session(session) {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_session",
            "UI session cookie is invalid or expired",
        );
    }
    json_response(StatusCode::OK, &state.sanitized_state())
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

    fn sanitized_state(&self) -> UiStateResponse {
        let args = self.args.as_ref();
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
                draft_write: false,
                validate: false,
                apply: false,
            },
        }
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
            message: "Origin header is required for session exchange",
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
