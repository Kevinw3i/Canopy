use anyhow::Result;
use reqwest::{
    header::{HeaderMap, HeaderValue, USER_AGENT},
    StatusCode,
};
use serde::de::DeserializeOwned;
use shared::dto::auth::*;
use shared::dto::cloudwatch::*;
use shared::dto::ec2::*;
use shared::dto::entitlements::UserEntitlements;
use shared::errors::ApiError;
use shared::headers;

pub type ApiResult<T> = std::result::Result<T, ApiClientError>;

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
}

/// HTTP client for the control-plane API
#[derive(Clone)]
pub struct ApiClient {
    base_url: String,
    client: reqwest::Client,
    token: Option<String>,
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
            token: None,
        })
    }

    pub fn tui_version() -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    pub fn user_agent() -> &'static str {
        concat!("canopy-tui/", env!("CARGO_PKG_VERSION"))
    }

    pub fn set_token(&mut self, token: String) {
        self.token = Some(token);
    }

    pub fn clear_token(&mut self) {
        self.token = None;
    }

    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    pub fn get_token(&self) -> Option<String> {
        self.token.clone()
    }

    fn auth_header(&self) -> Option<String> {
        self.token.as_ref().map(|t| format!("Bearer {}", t))
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
        let mut req = self
            .client
            .get(format!("{}/api/entitlements", self.base_url));

        if let Some(ref auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        let resp = req.send().await?;
        Self::decode_response(resp, AuthBehavior::TreatUnauthorizedAsExpired).await
    }

    // ── EC2 ─────────────────────────────────────────────

    pub async fn list_ec2(&self, request: &Ec2ListRequest) -> ApiResult<Ec2ListResponse> {
        let mut req = self
            .client
            .post(format!("{}/api/ec2/list", self.base_url))
            .json(request);

        if let Some(ref auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        let resp = req.send().await?;
        Self::decode_response(resp, AuthBehavior::TreatUnauthorizedAsExpired).await
    }

    pub async fn connect(&self, request: &ConnectRequest) -> ApiResult<ConnectResponse> {
        let mut req = self
            .client
            .post(format!("{}/api/ec2/connect", self.base_url))
            .json(request);

        if let Some(ref auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        let resp = req.send().await?;
        Self::decode_response(resp, AuthBehavior::TreatUnauthorizedAsExpired).await
    }

    // ── CloudWatch ──────────────────────────────────────

    pub async fn list_log_groups(
        &self,
        request: &LogGroupsRequest,
    ) -> ApiResult<LogGroupsResponse> {
        let mut req = self
            .client
            .post(format!("{}/api/cloudwatch/log-groups", self.base_url))
            .json(request);

        if let Some(ref auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        let resp = req.send().await?;
        Self::decode_response(resp, AuthBehavior::TreatUnauthorizedAsExpired).await
    }

    pub async fn filter_log_events(
        &self,
        request: &FilterLogEventsRequest,
    ) -> ApiResult<FilterLogEventsResponse> {
        let mut req = self
            .client
            .post(format!("{}/api/cloudwatch/filter-events", self.base_url))
            .json(request);

        if let Some(ref auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        let resp = req.send().await?;
        Self::decode_response(resp, AuthBehavior::TreatUnauthorizedAsExpired).await
    }

    pub async fn start_insights_query(
        &self,
        request: &StartInsightsQueryRequest,
    ) -> ApiResult<StartInsightsQueryResponse> {
        let mut req = self
            .client
            .post(format!("{}/api/cloudwatch/insights/start", self.base_url))
            .json(request);

        if let Some(ref auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        let resp = req.send().await?;
        Self::decode_response(resp, AuthBehavior::TreatUnauthorizedAsExpired).await
    }

    pub async fn get_query_results(
        &self,
        request: &GetQueryResultsRequest,
    ) -> ApiResult<GetQueryResultsResponse> {
        let mut req = self
            .client
            .post(format!("{}/api/cloudwatch/insights/results", self.base_url))
            .json(request);

        if let Some(ref auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        let resp = req.send().await?;
        Self::decode_response(resp, AuthBehavior::TreatUnauthorizedAsExpired).await
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
        let mut client = ApiClient::new("http://localhost:8443").unwrap();
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
