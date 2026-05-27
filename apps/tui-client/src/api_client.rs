use anyhow::Result;
use reqwest::{
    header::{HeaderMap, HeaderValue, USER_AGENT},
    RequestBuilder, StatusCode,
};
use serde::de::DeserializeOwned;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::auth::SessionTokens;
use shared::dto::auth::*;
use shared::dto::cloudwatch::*;
use shared::dto::ec2::*;
use shared::dto::ecs::*;
use shared::dto::entitlements::UserEntitlements;
use shared::errors::ApiError;
use shared::headers;

pub type ApiResult<T> = std::result::Result<T, ApiClientError>;

#[derive(Debug, Default)]
struct SessionState {
    tokens: Option<SessionTokens>,
    generation: u64,
}

#[derive(Debug, Clone)]
struct SessionSnapshot {
    access_token: Option<String>,
    refresh_token: Option<String>,
    generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthBehavior {
    TreatUnauthorizedAsExpired,
    ReturnUnauthorizedAsApiError,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiClientError {
    #[error("session expired")]
    TokenExpired,
    #[error("[{status}] {code}: {message}")]
    Api {
        status: u16,
        code: String,
        message: String,
    },
    #[error(transparent)]
    Transport(#[from] reqwest::Error),
    #[error("failed to persist auth session: {message}")]
    SessionStore { message: String },
}

/// HTTP client for the control-plane API
#[derive(Clone)]
pub struct ApiClient {
    base_url: String,
    client: reqwest::Client,
    session: Arc<Mutex<SessionState>>,
    session_store_path: Arc<Mutex<Option<PathBuf>>>,
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

impl ApiClient {
    pub fn new(base_url: &str) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static(concat!("canopy-tui/", env!("CARGO_PKG_VERSION"))),
        );
        headers.insert(
            headers::CANOPY_TUI_VERSION,
            HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
        );

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .default_headers(headers)
                .build()?,
            session: Arc::new(Mutex::new(SessionState::default())),
            session_store_path: Arc::new(Mutex::new(Some(crate::auth::token_path()))),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    pub fn tui_version() -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    pub fn user_agent() -> &'static str {
        concat!("canopy-tui/", env!("CARGO_PKG_VERSION"))
    }

    pub fn set_token(&self, token: String) {
        self.set_session(SessionTokens::new(token, None));
    }

    pub fn set_session(&self, session: SessionTokens) {
        self.replace_session(Some(session));
    }

    pub fn set_session_store_path(&self, path: PathBuf) {
        *self.session_store_path_guard() = Some(path);
    }

    pub fn apply_token_response(&self, resp: TokenResponse) -> SessionTokens {
        let mut state = self.session_guard();
        let refresh_token = resp.refresh_token.or_else(|| {
            state
                .tokens
                .as_ref()
                .and_then(|session| session.refresh_token.clone())
        });
        let session = SessionTokens::new(resp.access_token, refresh_token);
        state.tokens = Some(session.clone());
        state.generation = state.generation.wrapping_add(1);
        session
    }

    pub fn clear_token(&self) {
        self.replace_session(None);
    }

    pub fn has_token(&self) -> bool {
        self.session_guard()
            .tokens
            .as_ref()
            .is_some_and(|session| !session.access_token.is_empty())
    }

    pub fn get_token(&self) -> Option<String> {
        self.session_guard()
            .tokens
            .as_ref()
            .map(|session| session.access_token.clone())
    }

    pub fn get_refresh_token(&self) -> Option<String> {
        self.session_guard()
            .tokens
            .as_ref()
            .and_then(|session| session.refresh_token.clone())
    }

    fn session_guard(&self) -> MutexGuard<'_, SessionState> {
        self.session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn session_store_path_guard(&self) -> MutexGuard<'_, Option<PathBuf>> {
        self.session_store_path
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn replace_session(&self, tokens: Option<SessionTokens>) {
        let mut state = self.session_guard();
        state.tokens = tokens;
        state.generation = state.generation.wrapping_add(1);
    }

    fn session_snapshot(&self) -> SessionSnapshot {
        let state = self.session_guard();
        SessionSnapshot {
            access_token: state
                .tokens
                .as_ref()
                .map(|session| session.access_token.clone()),
            refresh_token: state
                .tokens
                .as_ref()
                .and_then(|session| session.refresh_token.clone()),
            generation: state.generation,
        }
    }

    fn refresh_preempted_result(&self) -> ApiResult<()> {
        if self.has_token() {
            Ok(())
        } else {
            Err(ApiClientError::TokenExpired)
        }
    }

    fn auth_header(&self) -> Option<String> {
        self.get_token().map(|t| format!("Bearer {}", t))
    }

    async fn decode_response<T: DeserializeOwned>(
        resp: reqwest::Response,
        auth_behavior: AuthBehavior,
    ) -> ApiResult<T> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp.json().await?);
        }

        if auth_behavior == AuthBehavior::TreatUnauthorizedAsExpired
            && status == StatusCode::UNAUTHORIZED
        {
            return Err(ApiClientError::TokenExpired);
        }

        let status_code = status.as_u16();
        let err: ApiError = resp.json().await?;
        Err(ApiClientError::Api {
            status: status_code,
            code: err.code,
            message: err.message,
        })
    }

    fn with_auth(&self, mut req: RequestBuilder) -> RequestBuilder {
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }
        req
    }

    async fn refresh_access_token_if_stale(
        &self,
        stale_snapshot: SessionSnapshot,
    ) -> ApiResult<()> {
        let _refresh_guard = self.refresh_lock.lock().await;
        let current = self.session_snapshot();
        if current.generation != stale_snapshot.generation
            || current.access_token != stale_snapshot.access_token
        {
            return self.refresh_preempted_result();
        }

        let refresh_token = current
            .refresh_token
            .clone()
            .ok_or(ApiClientError::TokenExpired)?;

        let resp = self
            .client
            .post(format!("{}/auth/refresh", self.base_url))
            .json(&RefreshTokenRequest { refresh_token })
            .send()
            .await?;

        let token_resp = match Self::decode_response::<TokenResponse>(
            resp,
            AuthBehavior::ReturnUnauthorizedAsApiError,
        )
        .await
        {
            Ok(resp) => resp,
            Err(ApiClientError::Transport(err)) => return Err(ApiClientError::Transport(err)),
            Err(ApiClientError::Api {
                status,
                code,
                message,
            }) if status >= 500 => {
                return Err(ApiClientError::Api {
                    status,
                    code,
                    message,
                });
            }
            Err(_) => return Err(ApiClientError::TokenExpired),
        };

        let session = SessionTokens::new(
            token_resp.access_token,
            token_resp.refresh_token.or(current.refresh_token),
        );
        let path = self.session_store_path_guard().clone();
        let mut state = self.session_guard();
        if state.generation != stale_snapshot.generation
            || state
                .tokens
                .as_ref()
                .map(|session| session.access_token.clone())
                != stale_snapshot.access_token
        {
            drop(state);
            return self.refresh_preempted_result();
        }
        if let Some(path) = path {
            crate::auth::save_session_to_path(&path, &session).map_err(|err| {
                ApiClientError::SessionStore {
                    message: err.to_string(),
                }
            })?;
        }
        state.tokens = Some(session);
        state.generation = state.generation.wrapping_add(1);
        tracing::info!("refreshed auth session and persisted updated token");
        Ok(())
    }

    async fn send_authenticated<T, F>(&self, build_request: F) -> ApiResult<T>
    where
        T: DeserializeOwned,
        F: Fn() -> RequestBuilder,
    {
        let snapshot = self.session_snapshot();
        let resp = self.with_auth(build_request()).send().await?;
        match Self::decode_response(resp, AuthBehavior::TreatUnauthorizedAsExpired).await {
            Err(ApiClientError::TokenExpired) => {
                self.refresh_access_token_if_stale(snapshot).await?;
                let resp = self.with_auth(build_request()).send().await?;
                Self::decode_response(resp, AuthBehavior::TreatUnauthorizedAsExpired).await
            }
            other => other,
        }
    }

    // ── Auth ────────────────────────────────────────────

    pub async fn dev_login(&self, username: &str) -> ApiResult<DevLoginResponse> {
        let resp = self
            .client
            .post(format!("{}/auth/dev-login", self.base_url))
            .json(&DevLoginRequest {
                username: username.into(),
            })
            .send()
            .await?;

        Self::decode_response(resp, AuthBehavior::ReturnUnauthorizedAsApiError).await
    }

    pub async fn pkce_start(
        &self,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> ApiResult<PkceAuthResponse> {
        let resp = self
            .client
            .post(format!("{}/auth/pkce/start", self.base_url))
            .json(&PkceAuthRequest {
                code_verifier: code_verifier.into(),
                redirect_uri: redirect_uri.into(),
            })
            .send()
            .await?;

        Self::decode_response(resp, AuthBehavior::ReturnUnauthorizedAsApiError).await
    }

    pub async fn pkce_exchange(
        &self,
        code: &str,
        code_verifier: &str,
        state: &str,
        redirect_uri: &str,
    ) -> ApiResult<TokenResponse> {
        let resp = self
            .client
            .post(format!("{}/auth/pkce/exchange", self.base_url))
            .json(&TokenExchangeRequest {
                code: code.into(),
                code_verifier: code_verifier.into(),
                state: state.into(),
                redirect_uri: redirect_uri.into(),
            })
            .send()
            .await?;

        Self::decode_response(resp, AuthBehavior::ReturnUnauthorizedAsApiError).await
    }

    pub async fn device_code_start(&self) -> ApiResult<DeviceCodeResponse> {
        let resp = self
            .client
            .post(format!("{}/auth/device-code/start", self.base_url))
            .json(&DeviceCodeRequest {
                client_id: "canopy-tui".into(),
            })
            .send()
            .await?;

        Self::decode_response(resp, AuthBehavior::ReturnUnauthorizedAsApiError).await
    }

    pub async fn device_code_poll(&self, device_code: &str) -> ApiResult<DeviceCodePollResponse> {
        let resp = self
            .client
            .post(format!("{}/auth/device-code/poll", self.base_url))
            .json(&DeviceCodePollRequest {
                device_code: device_code.into(),
                client_id: "canopy-tui".into(),
            })
            .send()
            .await?;

        Self::decode_response(resp, AuthBehavior::ReturnUnauthorizedAsApiError).await
    }

    // ── Entitlements ────────────────────────────────────

    pub async fn get_entitlements(&self) -> ApiResult<UserEntitlements> {
        self.send_authenticated(|| {
            self.client
                .get(format!("{}/api/entitlements", self.base_url))
        })
        .await
    }

    pub async fn mfa_status(&self) -> ApiResult<MfaStatusResponse> {
        self.send_authenticated(|| {
            self.client
                .get(format!("{}/api/auth/mfa/status", self.base_url))
        })
        .await
    }

    pub async fn start_totp_enrollment(
        &self,
        request: &TotpEnrollStartRequest,
    ) -> ApiResult<TotpEnrollStartResponse> {
        self.send_authenticated(|| {
            self.client
                .post(format!("{}/api/auth/mfa/totp/start", self.base_url))
                .json(request)
        })
        .await
    }

    pub async fn confirm_totp_enrollment(
        &self,
        request: &TotpEnrollConfirmRequest,
    ) -> ApiResult<TotpEnrollConfirmResponse> {
        self.send_authenticated(|| {
            self.client
                .post(format!("{}/api/auth/mfa/totp/confirm", self.base_url))
                .json(request)
        })
        .await
    }

    // ── EC2 ─────────────────────────────────────────────

    pub async fn list_ec2(&self, request: &Ec2ListRequest) -> ApiResult<Ec2ListResponse> {
        self.send_authenticated(|| {
            self.client
                .post(format!("{}/api/ec2/list", self.base_url))
                .json(request)
        })
        .await
    }

    pub async fn connect(&self, request: &ConnectRequest) -> ApiResult<ConnectResponse> {
        self.send_authenticated(|| {
            self.client
                .post(format!("{}/api/ec2/connect", self.base_url))
                .json(request)
        })
        .await
    }

    pub async fn power_ec2(&self, request: &Ec2PowerRequest) -> ApiResult<Ec2PowerResponse> {
        self.send_authenticated(|| {
            self.client
                .post(format!("{}/api/ec2/power", self.base_url))
                .json(request)
        })
        .await
    }

    // ── ECS ─────────────────────────────────────────────

    pub async fn list_ecs_tasks(&self, request: &EcsTasksRequest) -> ApiResult<EcsTasksResponse> {
        self.send_authenticated(|| {
            self.client
                .post(format!("{}/api/ecs/tasks", self.base_url))
                .json(request)
        })
        .await
    }

    pub async fn ecs_exec(&self, request: &EcsExecRequest) -> ApiResult<EcsExecResponse> {
        self.send_authenticated(|| {
            self.client
                .post(format!("{}/api/ecs/exec", self.base_url))
                .json(request)
        })
        .await
    }

    // ── CloudWatch ──────────────────────────────────────

    pub async fn list_log_groups(
        &self,
        request: &LogGroupsRequest,
    ) -> ApiResult<LogGroupsResponse> {
        self.send_authenticated(|| {
            self.client
                .post(format!("{}/api/cloudwatch/log-groups", self.base_url))
                .json(request)
        })
        .await
    }

    pub async fn filter_log_events(
        &self,
        request: &FilterLogEventsRequest,
    ) -> ApiResult<FilterLogEventsResponse> {
        self.send_authenticated(|| {
            self.client
                .post(format!("{}/api/cloudwatch/filter-events", self.base_url))
                .json(request)
        })
        .await
    }

    pub async fn start_insights_query(
        &self,
        request: &StartInsightsQueryRequest,
    ) -> ApiResult<StartInsightsQueryResponse> {
        self.send_authenticated(|| {
            self.client
                .post(format!("{}/api/cloudwatch/insights/start", self.base_url))
                .json(request)
        })
        .await
    }

    pub async fn get_query_results(
        &self,
        request: &GetQueryResultsRequest,
    ) -> ApiResult<GetQueryResultsResponse> {
        self.send_authenticated(|| {
            self.client
                .post(format!("{}/api/cloudwatch/insights/results", self.base_url))
                .json(request)
        })
        .await
    }
}

/// Generate a random RFC 7636 code verifier (43–128 unreserved characters).
pub fn generate_code_verifier() -> String {
    // Use two UUIDs to get enough entropy (64 hex chars)
    let a = uuid::Uuid::new_v4().as_simple().to_string();
    let b = uuid::Uuid::new_v4().as_simple().to_string();
    format!("{}{}", a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_strips_trailing_slash() {
        let client = ApiClient::new("http://localhost:8443/").unwrap();
        assert_eq!(client.base_url, "http://localhost:8443");
    }

    #[test]
    fn test_token_lifecycle() {
        let client = ApiClient::new("http://localhost:8443").unwrap();
        assert!(!client.has_token());
        assert!(client.get_token().is_none());
        assert!(client.auth_header().is_none());

        client.set_token("my-jwt".into());
        assert!(client.has_token());
        assert_eq!(client.get_token().as_deref(), Some("my-jwt"));
        assert_eq!(client.auth_header().as_deref(), Some("Bearer my-jwt"));

        client.clear_token();
        assert!(!client.has_token());
        assert!(client.auth_header().is_none());
    }

    #[test]
    fn session_mutations_bump_generation() {
        let client = ApiClient::new("http://localhost:8443").unwrap();
        let initial = client.session_snapshot().generation;

        client.set_token("first".into());
        let after_set = client.session_snapshot().generation;
        client.clear_token();
        let after_clear = client.session_snapshot().generation;

        assert!(after_set > initial);
        assert!(after_clear > after_set);
    }

    #[test]
    fn poisoned_session_mutex_does_not_panic_subsequent_calls() {
        let client = ApiClient::new("http://localhost:8443").unwrap();
        let session = Arc::clone(&client.session);
        let _ = std::thread::spawn(move || {
            let _guard = session.lock().unwrap();
            panic!("poison session mutex for test");
        })
        .join();

        client.set_token("after-poison".into());

        assert!(client.has_token());
        assert_eq!(client.get_token().as_deref(), Some("after-poison"));
    }

    #[test]
    fn test_code_verifier_length_and_uniqueness() {
        let v1 = generate_code_verifier();
        let v2 = generate_code_verifier();
        // 64 hex chars (two UUIDs)
        assert_eq!(v1.len(), 64);
        // Each call should produce a different verifier
        assert_ne!(v1, v2);
    }

    #[test]
    fn test_code_verifier_is_hex() {
        let v = generate_code_verifier();
        assert!(v.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
