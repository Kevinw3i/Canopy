use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{anyhow, Context};
use axum::body::Body;
use axum::http::{header, HeaderValue, Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use serde::Serialize;
use tokio::net::TcpListener;

const INDEX_HTML: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/ui/index.html"));
const APP_CSS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/ui/app.css"));
const APP_JS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/ui/app.js"));
const BOOTSTRAP_PRELUDE_SHA256: &str = "sha256-ID/LmcrKIAtlemN0u3a1GF6TD9U4TLcWC/92XwkXD/g=";
const CONTENT_SECURITY_POLICY: &str =
    "default-src 'self'; script-src 'self' 'sha256-ID/LmcrKIAtlemN0u3a1GF6TD9U4TLcWC/92XwkXD/g='; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

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
        url: format!("http://{addr}/"),
        catalog: args.catalog.display().to_string(),
        runtime: args.runtime.display().to_string(),
        mode: "static-shell",
    };
    writeln!(
        stdout,
        "serving Entitlement Catalog UI at {} ({})",
        status.url, status.mode
    )?;
    runtime.block_on(async move { serve_listener(listener).await })
}

async fn serve_listener(listener: TcpListener) -> anyhow::Result<()> {
    axum::serve(listener, router())
        .await
        .context("UI server failed")
}

pub fn router() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/index.html", get(index))
        .route("/app.css", get(app_css))
        .route("/app.js", get(app_js))
        .route("/healthz", get(healthz))
        .fallback(not_found)
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
    use axum::http::Request;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

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
            let response = router()
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
        let response = router()
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

    #[test]
    fn rejects_non_loopback_bind_addresses() {
        let err = validate_bind_addr("0.0.0.0:8080".parse().unwrap())
            .unwrap_err()
            .to_string();
        assert!(err.contains("not loopback"));
        validate_bind_addr("127.0.0.1:0".parse().unwrap()).unwrap();
    }
}
