use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashMap;
use tokio::sync::{OnceCell, RwLock};

use crate::config::OidcConfig;

/// Endpoints discovered from the OIDC provider's .well-known configuration
#[derive(Debug, Clone, Deserialize)]
struct DiscoveryDocument {
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    userinfo_endpoint: Option<String>,
    #[serde(default)]
    device_authorization_endpoint: Option<String>,
    #[serde(default)]
    jwks_uri: Option<String>,
}

/// A single JSON Web Key from the JWKS endpoint
#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    alg: Option<String>,
    #[serde(rename = "use")]
    use_: Option<String>,
    // RSA fields
    n: Option<String>,
    e: Option<String>,
    // EC fields
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

/// JWKS response
#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

/// Resolved OIDC endpoints — either from config overrides or discovery.
#[derive(Debug, Clone)]
pub struct OidcEndpoints {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub device_authorization_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
}

/// OIDC client that handles communication with the identity provider.
pub struct OidcClient {
    config: OidcConfig,
    http: reqwest::Client,
    endpoints: OnceCell<OidcEndpoints>,
    /// Cached JWKS keys, keyed by `kid`
    jwks_cache: RwLock<HashMap<String, Jwk>>,
}

/// Standard OIDC token response
#[derive(Debug, Deserialize)]
pub struct OidcTokenResponse {
    pub access_token: String,
    #[allow(dead_code)]
    pub token_type: String,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// Claims we extract from the OIDC id_token
#[derive(Debug, Deserialize)]
pub struct IdTokenClaims {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    // Standard OIDC validation claims
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    pub aud: Option<serde_json::Value>, // can be string or array
    #[serde(default)]
    pub exp: Option<u64>,
    #[serde(default)]
    pub acr: Option<String>,
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default)]
    pub auth_time: Option<u64>,
}

/// OIDC device authorization response
#[derive(Debug, Deserialize)]
pub struct DeviceAuthResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    #[serde(default = "default_expires_in")]
    pub expires_in: u64,
    #[serde(default = "default_interval")]
    pub interval: u64,
}

fn default_expires_in() -> u64 {
    600
}
fn default_interval() -> u64 {
    5
}

/// OIDC token error (e.g. authorization_pending during device code polling)
#[derive(Debug, Deserialize)]
pub struct OidcTokenError {
    pub error: String,
    #[serde(default)]
    pub error_description: Option<String>,
}

/// Result of a device-code poll against the OIDC provider.
pub enum DevicePollResult {
    /// User hasn't completed auth yet.
    Pending,
    /// RFC 8628: server requests that the client increase its poll interval
    /// by 5 seconds.
    SlowDown,
    /// User completed auth — tokens are available.
    Complete(OidcTokenResponse),
}

impl OidcClient {
    pub fn new(config: OidcConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
            endpoints: OnceCell::new(),
            jwks_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Resolve endpoints. If all required endpoints are configured, skips
    /// discovery entirely. Otherwise discovers from issuer and applies
    /// any partial overrides on top.
    pub async fn endpoints(&self) -> anyhow::Result<&OidcEndpoints> {
        self.endpoints
            .get_or_try_init(|| async {
                // If all required endpoints are explicitly configured,
                // skip discovery (works with providers that don't expose
                // .well-known or locked-down networks).
                if let (Some(authz), Some(token)) = (
                    &self.config.authorization_endpoint,
                    &self.config.token_endpoint,
                ) {
                    // JWKS URI is required for id_token validation. If not
                    // explicitly provided, fall through to discovery so we
                    // can still fetch JWKS from the issuer's .well-known.
                    if self.config.jwks_uri.is_some() {
                        tracing::info!("Using explicitly configured OIDC endpoints (no discovery)");
                        return Ok(OidcEndpoints {
                            authorization_endpoint: authz.clone(),
                            token_endpoint: token.clone(),
                            userinfo_endpoint: self.config.userinfo_endpoint.clone(),
                            device_authorization_endpoint: self
                                .config
                                .device_authorization_endpoint
                                .clone(),
                            jwks_uri: self.config.jwks_uri.clone(),
                        });
                    }
                    tracing::warn!(
                        "authorization_endpoint and token_endpoint are set but jwks_uri is \
                         missing — falling back to issuer discovery for JWKS"
                    );
                }

                // Auto-discover from issuer
                let discovery_url = format!(
                    "{}/.well-known/openid-configuration",
                    self.config.issuer_url.trim_end_matches('/')
                );
                tracing::info!(url = %discovery_url, "Discovering OIDC endpoints");

                let doc: DiscoveryDocument =
                    self.http.get(&discovery_url).send().await?.json().await?;

                Ok(OidcEndpoints {
                    authorization_endpoint: self
                        .config
                        .authorization_endpoint
                        .clone()
                        .unwrap_or(doc.authorization_endpoint),
                    token_endpoint: self
                        .config
                        .token_endpoint
                        .clone()
                        .unwrap_or(doc.token_endpoint),
                    userinfo_endpoint: self
                        .config
                        .userinfo_endpoint
                        .clone()
                        .or(doc.userinfo_endpoint),
                    device_authorization_endpoint: self
                        .config
                        .device_authorization_endpoint
                        .clone()
                        .or(doc.device_authorization_endpoint),
                    jwks_uri: self.config.jwks_uri.clone().or(doc.jwks_uri),
                })
            })
            .await
    }

    /// Fetch and cache the JWKS keys from the provider.
    async fn refresh_jwks(&self) -> anyhow::Result<()> {
        let ep = self.endpoints().await?;
        let jwks_uri = ep
            .jwks_uri
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No jwks_uri available — JWKS verification disabled"))?;

        let resp: JwksResponse = self.http.get(jwks_uri).send().await?.json().await?;
        let mut cache = self.jwks_cache.write().await;
        cache.clear();
        for key in resp.keys {
            if let Some(ref kid) = key.kid {
                cache.insert(kid.clone(), key);
            }
        }
        tracing::info!(keys = cache.len(), "JWKS cache refreshed");
        Ok(())
    }

    /// Get a JWK by kid, refreshing the cache if not found.
    async fn get_jwk(&self, kid: &str) -> anyhow::Result<Jwk> {
        // Check cache first
        {
            let cache = self.jwks_cache.read().await;
            if let Some(key) = cache.get(kid) {
                return Ok(key.clone());
            }
        }
        // Cache miss — refresh and retry
        self.refresh_jwks().await?;
        let cache = self.jwks_cache.read().await;
        cache
            .get(kid)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("JWK with kid '{}' not found in JWKS", kid))
    }

    /// Build a DecodingKey from a JWK.
    fn decoding_key_from_jwk(jwk: &Jwk) -> anyhow::Result<(DecodingKey, Algorithm)> {
        match jwk.kty.as_str() {
            "RSA" => {
                let n = jwk
                    .n
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("RSA JWK missing 'n'"))?;
                let e = jwk
                    .e
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("RSA JWK missing 'e'"))?;
                let key = DecodingKey::from_rsa_components(n, e)?;
                let alg = match jwk.alg.as_deref() {
                    Some("RS384") => Algorithm::RS384,
                    Some("RS512") => Algorithm::RS512,
                    Some("PS256") => Algorithm::PS256,
                    Some("PS384") => Algorithm::PS384,
                    Some("PS512") => Algorithm::PS512,
                    _ => Algorithm::RS256, // default for RSA
                };
                Ok((key, alg))
            }
            "EC" => {
                let x = jwk
                    .x
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("EC JWK missing 'x'"))?;
                let y = jwk
                    .y
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("EC JWK missing 'y'"))?;
                let key = DecodingKey::from_ec_components(x, y)?;
                let alg = match jwk.crv.as_deref() {
                    Some("P-384") => Algorithm::ES384,
                    _ => Algorithm::ES256,
                };
                Ok((key, alg))
            }
            other => anyhow::bail!("Unsupported JWK key type: {}", other),
        }
    }

    /// Exchange an authorization code for tokens (PKCE flow).
    pub async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> anyhow::Result<OidcTokenResponse> {
        let ep = self.endpoints().await?;

        let mut params = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", code_verifier),
            ("redirect_uri", redirect_uri),
            ("client_id", &self.config.client_id),
        ];
        let secret_val;
        if let Some(ref secret) = self.config.client_secret {
            secret_val = secret.clone();
            params.push(("client_secret", &secret_val));
        }

        let resp = self
            .http
            .post(&ep.token_endpoint)
            .form(&params)
            .send()
            .await?;

        if !resp.status().is_success() {
            let err: OidcTokenError = resp.json().await.unwrap_or(OidcTokenError {
                error: "unknown".into(),
                error_description: Some("Token exchange failed".into()),
            });
            anyhow::bail!(
                "OIDC token exchange failed: {} — {}",
                err.error,
                err.error_description.unwrap_or_default()
            );
        }

        Ok(resp.json().await?)
    }

    /// Decode and validate an id_token.
    ///
    /// When JWKS is available (from discovery), verifies the JWT signature
    /// cryptographically. When JWKS is not available (explicit endpoint
    /// config without discovery), falls back to claims-only validation.
    ///
    /// Always validates issuer, audience, and expiry.
    pub async fn decode_and_validate_id_token(
        &self,
        id_token: &str,
    ) -> anyhow::Result<IdTokenClaims> {
        // Always verify the JWT signature cryptographically via JWKS.
        // If no jwks_uri is available (explicit endpoint config without
        // discovery), fail closed — unsigned tokens are never accepted.
        let claims = self.decode_with_jwks(id_token).await.map_err(|e| {
            anyhow::anyhow!(
                "id_token signature verification failed: {}. \
                 Ensure the OIDC provider's jwks_uri is reachable \
                 (use auto-discovery or configure jwks_uri explicitly).",
                e
            )
        })?;

        // Validate issuer
        if let Some(ref iss) = claims.iss {
            let expected_issuer = self.config.issuer_url.trim_end_matches('/');
            let actual_issuer = iss.trim_end_matches('/');
            if actual_issuer != expected_issuer {
                anyhow::bail!(
                    "id_token issuer mismatch: expected '{}', got '{}'",
                    expected_issuer,
                    actual_issuer
                );
            }
        } else {
            anyhow::bail!("id_token missing required 'iss' claim");
        }

        // Validate audience (must contain our client_id)
        match &claims.aud {
            Some(aud) => {
                let aud_matches = match aud {
                    serde_json::Value::String(s) => s == &self.config.client_id,
                    serde_json::Value::Array(arr) => arr
                        .iter()
                        .any(|v| v.as_str() == Some(&self.config.client_id)),
                    _ => false,
                };
                if !aud_matches {
                    anyhow::bail!(
                        "id_token audience does not contain client_id '{}'",
                        self.config.client_id
                    );
                }
            }
            None => anyhow::bail!("id_token missing required 'aud' claim"),
        }

        // Validate expiry
        match claims.exp {
            Some(exp) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if now > exp + 300 {
                    anyhow::bail!("id_token has expired (exp={}, now={})", exp, now);
                }
            }
            None => anyhow::bail!("id_token missing required 'exp' claim"),
        }

        self.validate_mfa_claims(&claims)?;

        Ok(claims)
    }

    fn validate_mfa_claims(&self, claims: &IdTokenClaims) -> anyhow::Result<()> {
        if !self.config.required_acr_values.is_empty() {
            match claims.acr.as_deref() {
                Some(acr)
                    if self
                        .config
                        .required_acr_values
                        .iter()
                        .any(|required| required == acr) => {}
                Some(acr) => {
                    anyhow::bail!("id_token acr '{}' does not match required values", acr);
                }
                None => anyhow::bail!("id_token missing required 'acr' claim"),
            }
        }

        for required in &self.config.required_amr_values {
            if !claims.amr.iter().any(|amr| amr == required) {
                anyhow::bail!(
                    "id_token amr does not contain required value '{}'",
                    required
                );
            }
        }

        if let Some(max_age) = self.config.max_age_seconds {
            let auth_time = claims
                .auth_time
                .ok_or_else(|| anyhow::anyhow!("id_token missing required 'auth_time' claim"))?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let latest_allowed = auth_time.saturating_add(max_age).saturating_add(300);
            if now > latest_allowed {
                anyhow::bail!("id_token auth_time is older than configured max_age_seconds");
            }
        }

        Ok(())
    }

    /// Verify an id_token using JWKS keys.
    async fn decode_with_jwks(&self, id_token: &str) -> anyhow::Result<IdTokenClaims> {
        // Extract kid from JWT header
        let header = jsonwebtoken::decode_header(id_token)?;
        let kid = header
            .kid
            .ok_or_else(|| anyhow::anyhow!("id_token JWT header missing 'kid'"))?;

        // Fetch the matching JWK
        let jwk = self.get_jwk(&kid).await?;
        let (decoding_key, alg) = Self::decoding_key_from_jwk(&jwk)?;

        // Decode and verify signature
        let mut validation = Validation::new(alg);
        // We validate iss/aud/exp ourselves for better error messages
        validation.validate_aud = false;
        validation.validate_exp = false;

        let token_data = decode::<IdTokenClaims>(id_token, &decoding_key, &validation)?;
        Ok(token_data.claims)
    }

    /// Decode an id_token payload without signature verification.
    fn decode_unverified(&self, id_token: &str) -> anyhow::Result<IdTokenClaims> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let parts: Vec<&str> = id_token.split('.').collect();
        if parts.len() != 3 {
            anyhow::bail!("Invalid JWT format in id_token");
        }

        let payload = URL_SAFE_NO_PAD.decode(parts[1])?;
        let claims: IdTokenClaims = serde_json::from_slice(&payload)?;
        Ok(claims)
    }

    /// Start the device authorization flow.
    pub async fn device_authorize(&self) -> anyhow::Result<DeviceAuthResponse> {
        let ep = self.endpoints().await?;
        let device_ep = ep
            .device_authorization_endpoint
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("OIDC provider has no device_authorization_endpoint"))?;

        let mut params: Vec<(&'static str, String)> = vec![
            ("client_id", self.config.client_id.clone()),
            ("scope", self.config.scopes.join(" ")),
        ];
        if let Some(ref secret) = self.config.client_secret {
            params.push(("client_secret", secret.clone()));
        }
        if !self.config.acr_values.is_empty() {
            params.push(("acr_values", self.config.acr_values.join(" ")));
        }
        if let Some(prompt) = self.config.prompt.as_ref() {
            params.push(("prompt", prompt.clone()));
        }
        if let Some(max_age) = self.config.max_age_seconds {
            params.push(("max_age", max_age.to_string()));
        }

        let resp = self.http.post(device_ep).form(&params).send().await?;
        if !resp.status().is_success() {
            let err: OidcTokenError = resp.json().await.unwrap_or(OidcTokenError {
                error: "unknown".into(),
                error_description: Some("Device authorization failed".into()),
            });
            anyhow::bail!(
                "OIDC device authorization failed: {} — {}",
                err.error,
                err.error_description.unwrap_or_default()
            );
        }

        Ok(resp.json().await?)
    }

    /// Poll for device code completion. Returns Ok(Some(tokens)) on success,
    /// Ok(None) if still pending, or Err on terminal failure.
    pub async fn device_poll(&self, device_code: &str) -> anyhow::Result<DevicePollResult> {
        let ep = self.endpoints().await?;

        let mut params = vec![
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code),
            ("client_id", self.config.client_id.as_str()),
        ];
        let secret_val;
        if let Some(ref secret) = self.config.client_secret {
            secret_val = secret.clone();
            params.push(("client_secret", &secret_val));
        }

        let resp = self
            .http
            .post(&ep.token_endpoint)
            .form(&params)
            .send()
            .await?;

        if resp.status().is_success() {
            let tokens: OidcTokenResponse = resp.json().await?;
            return Ok(DevicePollResult::Complete(tokens));
        }

        let err: OidcTokenError = resp.json().await.unwrap_or(OidcTokenError {
            error: "unknown".into(),
            error_description: None,
        });

        match err.error.as_str() {
            "authorization_pending" => Ok(DevicePollResult::Pending),
            "slow_down" => Ok(DevicePollResult::SlowDown),
            "expired_token" => anyhow::bail!("Device code expired"),
            "access_denied" => anyhow::bail!("Authentication denied by user"),
            _ => anyhow::bail!(
                "OIDC device poll error: {} — {}",
                err.error,
                err.error_description.unwrap_or_default()
            ),
        }
    }

    /// Refresh an access token using a refresh_token.
    pub async fn refresh_token(&self, refresh_token: &str) -> anyhow::Result<OidcTokenResponse> {
        let ep = self.endpoints().await?;

        let mut params = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", self.config.client_id.as_str()),
        ];
        let secret_val;
        if let Some(ref secret) = self.config.client_secret {
            secret_val = secret.clone();
            params.push(("client_secret", &secret_val));
        }

        let resp = self
            .http
            .post(&ep.token_endpoint)
            .form(&params)
            .send()
            .await?;

        if !resp.status().is_success() {
            let err: OidcTokenError = resp.json().await.unwrap_or(OidcTokenError {
                error: "unknown".into(),
                error_description: Some("Token refresh failed".into()),
            });
            anyhow::bail!(
                "OIDC refresh failed: {} — {}",
                err.error,
                err.error_description.unwrap_or_default()
            );
        }

        Ok(resp.json().await?)
    }

    pub fn client_id(&self) -> &str {
        &self.config.client_id
    }

    pub fn scopes(&self) -> &[String] {
        &self.config.scopes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header as JwtHeader};
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::traits::PublicKeyParts;
    use std::sync::LazyLock;

    // ── Test RSA key pair (dynamically generated to avoid secret scanning) ──

    struct TestKeyPair {
        pem: Vec<u8>,
        n: String,
        e: String,
    }

    static TEST_KEY_PAIR: LazyLock<TestKeyPair> = LazyLock::new(|| {
        let mut rng = rand::thread_rng();
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pem_doc = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let public_key = private_key.to_public_key();

        // base64url-encode n and e (no padding) for JWK
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        TestKeyPair {
            pem: pem_doc.as_bytes().to_vec(),
            n,
            e,
        }
    });

    fn test_rsa_pem() -> &'static [u8] {
        &TEST_KEY_PAIR.pem
    }
    fn test_n() -> &'static str {
        &TEST_KEY_PAIR.n
    }
    fn test_e() -> &'static str {
        &TEST_KEY_PAIR.e
    }

    const TEST_KID: &str = "test-key-1";
    const TEST_ISSUER: &str = "https://test-issuer.example.com";
    const TEST_CLIENT_ID: &str = "test-client-id";

    fn test_config() -> crate::config::OidcConfig {
        crate::config::OidcConfig {
            issuer_url: TEST_ISSUER.into(),
            client_id: TEST_CLIENT_ID.into(),
            client_secret: None,
            scopes: vec!["openid".into()],
            acr_values: vec![],
            prompt: None,
            max_age_seconds: None,
            required_acr_values: vec![],
            required_amr_values: vec![],
            authorization_endpoint: None,
            token_endpoint: None,
            device_authorization_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: None,
        }
    }

    fn test_client() -> OidcClient {
        OidcClient::new(test_config())
    }

    /// Create a client with the test RSA key pre-populated in JWKS cache.
    async fn client_with_cached_jwks_config(config: crate::config::OidcConfig) -> OidcClient {
        let client = OidcClient::new(config);
        let jwk = Jwk {
            kid: Some(TEST_KID.into()),
            kty: "RSA".into(),
            alg: Some("RS256".into()),
            use_: Some("sig".into()),
            n: Some(test_n().into()),
            e: Some(test_e().into()),
            crv: None,
            x: None,
            y: None,
        };
        client.jwks_cache.write().await.insert(TEST_KID.into(), jwk);
        client
    }

    async fn client_with_cached_jwks() -> OidcClient {
        client_with_cached_jwks_config(test_config()).await
    }

    /// Sign a JWT with the test RSA key, including kid in the header.
    fn sign_test_jwt(claims: &serde_json::Value) -> String {
        let header = JwtHeader {
            alg: Algorithm::RS256,
            kid: Some(TEST_KID.into()),
            ..Default::default()
        };
        let key = EncodingKey::from_rsa_pem(test_rsa_pem()).unwrap();
        encode(&header, claims, &key).unwrap()
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    // ═══════════════════════════════════════════════════════════════════
    // decoding_key_from_jwk
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn decoding_key_rsa_defaults_to_rs256() {
        let jwk = Jwk {
            kid: Some("k1".into()),
            kty: "RSA".into(),
            alg: None,
            use_: Some("sig".into()),
            n: Some(test_n().into()),
            e: Some(test_e().into()),
            crv: None,
            x: None,
            y: None,
        };
        let (_, alg) = OidcClient::decoding_key_from_jwk(&jwk).unwrap();
        assert_eq!(alg, Algorithm::RS256);
    }

    #[test]
    fn decoding_key_rsa_respects_explicit_alg() {
        for (alg_str, expected) in [
            ("RS384", Algorithm::RS384),
            ("RS512", Algorithm::RS512),
            ("PS256", Algorithm::PS256),
            ("PS384", Algorithm::PS384),
            ("PS512", Algorithm::PS512),
        ] {
            let jwk = Jwk {
                kid: None,
                kty: "RSA".into(),
                alg: Some(alg_str.into()),
                use_: None,
                n: Some(test_n().into()),
                e: Some(test_e().into()),
                crv: None,
                x: None,
                y: None,
            };
            let (_, alg) = OidcClient::decoding_key_from_jwk(&jwk).unwrap();
            assert_eq!(alg, expected, "mismatch for {alg_str}");
        }
    }

    #[test]
    fn decoding_key_unsupported_kty_errors() {
        let jwk = Jwk {
            kid: None,
            kty: "OKP".into(),
            alg: None,
            use_: None,
            n: None,
            e: None,
            crv: None,
            x: None,
            y: None,
        };
        let result = OidcClient::decoding_key_from_jwk(&jwk);
        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("Unsupported JWK key type: OKP"));
    }

    #[test]
    fn decoding_key_rsa_missing_n_errors() {
        let jwk = Jwk {
            kid: None,
            kty: "RSA".into(),
            alg: None,
            use_: None,
            n: None,
            e: Some(test_e().into()),
            crv: None,
            x: None,
            y: None,
        };
        let result = OidcClient::decoding_key_from_jwk(&jwk);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("missing 'n'"));
    }

    #[test]
    fn decoding_key_rsa_missing_e_errors() {
        let jwk = Jwk {
            kid: None,
            kty: "RSA".into(),
            alg: None,
            use_: None,
            n: Some(test_n().into()),
            e: None,
            crv: None,
            x: None,
            y: None,
        };
        let result = OidcClient::decoding_key_from_jwk(&jwk);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("missing 'e'"));
    }

    #[test]
    fn decoding_key_ec_missing_x_errors() {
        let jwk = Jwk {
            kid: None,
            kty: "EC".into(),
            alg: None,
            use_: None,
            n: None,
            e: None,
            crv: Some("P-256".into()),
            x: None,
            y: Some("y-coord".into()),
        };
        let result = OidcClient::decoding_key_from_jwk(&jwk);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("missing 'x'"));
    }

    #[test]
    fn decoding_key_ec_missing_y_errors() {
        let jwk = Jwk {
            kid: None,
            kty: "EC".into(),
            alg: None,
            use_: None,
            n: None,
            e: None,
            crv: Some("P-256".into()),
            x: Some("x-coord".into()),
            y: None,
        };
        let result = OidcClient::decoding_key_from_jwk(&jwk);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("missing 'y'"));
    }

    // ═══════════════════════════════════════════════════════════════════
    // decode_unverified
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn decode_unverified_valid_jwt() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let client = test_client();
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        let payload_json = serde_json::json!({
            "sub": "user-1",
            "email": "test@example.com",
            "iss": "https://issuer.com",
        });
        let payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload_json).unwrap().as_bytes());
        let jwt = format!("{header}.{payload}.fake-sig");

        let claims = client.decode_unverified(&jwt).unwrap();
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.email.as_deref(), Some("test@example.com"));
        assert_eq!(claims.iss.as_deref(), Some("https://issuer.com"));
    }

    #[test]
    fn decode_unverified_rejects_non_three_parts() {
        let client = test_client();
        assert!(client.decode_unverified("only.two").is_err());
        assert!(client.decode_unverified("one").is_err());
        assert!(client.decode_unverified("").is_err());
    }

    #[test]
    fn decode_unverified_rejects_invalid_base64_payload() {
        let client = test_client();
        assert!(client
            .decode_unverified("valid.!!!not-base64!!!.sig")
            .is_err());
    }

    // ═══════════════════════════════════════════════════════════════════
    // Endpoint resolution
    // ═══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn endpoints_all_explicit_skips_discovery() {
        let config = crate::config::OidcConfig {
            issuer_url: "https://issuer.example.com".into(),
            client_id: "cid".into(),
            client_secret: None,
            scopes: vec!["openid".into()],
            acr_values: vec![],
            prompt: None,
            max_age_seconds: None,
            required_acr_values: vec![],
            required_amr_values: vec![],
            authorization_endpoint: Some("https://auth.example.com/authorize".into()),
            token_endpoint: Some("https://auth.example.com/token".into()),
            device_authorization_endpoint: Some("https://auth.example.com/device".into()),
            userinfo_endpoint: Some("https://auth.example.com/userinfo".into()),
            jwks_uri: Some("https://auth.example.com/jwks".into()),
        };
        let client = OidcClient::new(config);
        let ep = client.endpoints().await.unwrap();
        assert_eq!(
            ep.authorization_endpoint,
            "https://auth.example.com/authorize"
        );
        assert_eq!(ep.token_endpoint, "https://auth.example.com/token");
        assert_eq!(
            ep.device_authorization_endpoint.as_deref(),
            Some("https://auth.example.com/device")
        );
        assert_eq!(
            ep.userinfo_endpoint.as_deref(),
            Some("https://auth.example.com/userinfo")
        );
        assert_eq!(
            ep.jwks_uri.as_deref(),
            Some("https://auth.example.com/jwks")
        );
    }

    #[tokio::test]
    async fn endpoints_cached_after_first_resolve() {
        let config = crate::config::OidcConfig {
            issuer_url: "https://issuer.example.com".into(),
            client_id: "cid".into(),
            client_secret: None,
            scopes: vec![],
            acr_values: vec![],
            prompt: None,
            max_age_seconds: None,
            required_acr_values: vec![],
            required_amr_values: vec![],
            authorization_endpoint: Some("https://a/authorize".into()),
            token_endpoint: Some("https://a/token".into()),
            device_authorization_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: Some("https://a/jwks".into()),
        };
        let client = OidcClient::new(config);
        let ep1 = client.endpoints().await.unwrap();
        let ep2 = client.endpoints().await.unwrap();
        // Same reference from OnceCell
        assert!(std::ptr::eq(ep1, ep2));
    }

    #[tokio::test]
    async fn endpoints_partial_config_without_jwks_falls_through() {
        // authorization_endpoint + token_endpoint set, but NO jwks_uri
        // → should fall through to discovery (which will fail since the
        // issuer URL is fake, but we just test that it attempts discovery)
        let config = crate::config::OidcConfig {
            issuer_url: "https://nonexistent.invalid".into(),
            client_id: "cid".into(),
            client_secret: None,
            scopes: vec![],
            acr_values: vec![],
            prompt: None,
            max_age_seconds: None,
            required_acr_values: vec![],
            required_amr_values: vec![],
            authorization_endpoint: Some("https://a/authorize".into()),
            token_endpoint: Some("https://a/token".into()),
            device_authorization_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: None, // missing → triggers discovery
        };
        let client = OidcClient::new(config);
        // Discovery will fail because the URL is fake — that's expected
        let result = client.endpoints().await;
        assert!(result.is_err());
    }

    // ═══════════════════════════════════════════════════════════════════
    // Serde — response types
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn serde_discovery_document_full() {
        let doc: DiscoveryDocument = serde_json::from_value(serde_json::json!({
            "authorization_endpoint": "https://a/authorize",
            "token_endpoint": "https://a/token",
            "userinfo_endpoint": "https://a/userinfo",
            "device_authorization_endpoint": "https://a/device",
            "jwks_uri": "https://a/jwks"
        }))
        .unwrap();
        assert_eq!(doc.authorization_endpoint, "https://a/authorize");
        assert_eq!(doc.jwks_uri.as_deref(), Some("https://a/jwks"));
    }

    #[test]
    fn serde_discovery_document_minimal() {
        let doc: DiscoveryDocument = serde_json::from_value(serde_json::json!({
            "authorization_endpoint": "https://a/authorize",
            "token_endpoint": "https://a/token"
        }))
        .unwrap();
        assert!(doc.userinfo_endpoint.is_none());
        assert!(doc.device_authorization_endpoint.is_none());
        assert!(doc.jwks_uri.is_none());
    }

    #[test]
    fn serde_oidc_token_response_full() {
        let resp: OidcTokenResponse = serde_json::from_value(serde_json::json!({
            "access_token": "at-123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": "id-tok",
            "refresh_token": "ref-tok"
        }))
        .unwrap();
        assert_eq!(resp.access_token, "at-123");
        assert_eq!(resp.expires_in, Some(3600));
        assert_eq!(resp.id_token.as_deref(), Some("id-tok"));
        assert_eq!(resp.refresh_token.as_deref(), Some("ref-tok"));
    }

    #[test]
    fn serde_oidc_token_response_minimal() {
        let resp: OidcTokenResponse = serde_json::from_value(serde_json::json!({
            "access_token": "at",
            "token_type": "Bearer"
        }))
        .unwrap();
        assert!(resp.expires_in.is_none());
        assert!(resp.id_token.is_none());
        assert!(resp.refresh_token.is_none());
    }

    #[test]
    fn serde_device_auth_response_defaults() {
        let resp: DeviceAuthResponse = serde_json::from_value(serde_json::json!({
            "device_code": "dc",
            "user_code": "UC-1234",
            "verification_uri": "https://device.example.com"
        }))
        .unwrap();
        assert_eq!(resp.expires_in, 600); // default_expires_in
        assert_eq!(resp.interval, 5); // default_interval
        assert!(resp.verification_uri_complete.is_none());
    }

    #[tokio::test]
    async fn device_authorize_includes_mfa_controls() {
        use axum::{
            extract::{Form, State},
            routing::post,
            Router,
        };
        use std::sync::{Arc, Mutex};

        type CapturedForm = Arc<Mutex<Option<HashMap<String, String>>>>;

        async fn capture_device_form(
            State(captured): State<CapturedForm>,
            Form(form): Form<HashMap<String, String>>,
        ) -> impl axum::response::IntoResponse {
            *captured.lock().unwrap() = Some(form);
            axum::Json(serde_json::json!({
                "device_code": "dc",
                "user_code": "UC-1234",
                "verification_uri": "https://device.example.com",
                "expires_in": 600,
                "interval": 5
            }))
        }

        let captured: CapturedForm = Arc::new(Mutex::new(None));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/device", post(capture_device_form))
            .with_state(captured.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut config = test_config();
        config.authorization_endpoint = Some(format!("http://{addr}/authorize"));
        config.token_endpoint = Some(format!("http://{addr}/token"));
        config.device_authorization_endpoint = Some(format!("http://{addr}/device"));
        config.jwks_uri = Some(format!("http://{addr}/jwks"));
        config.client_secret = Some("secret".into());
        config.acr_values = vec!["urn:mfa".into(), "urn:webauthn".into()];
        config.prompt = Some("login".into());
        config.max_age_seconds = Some(300);

        let client = OidcClient::new(config);
        let resp = client.device_authorize().await.unwrap();
        assert_eq!(resp.device_code, "dc");

        let form = captured.lock().unwrap().clone().unwrap();
        assert_eq!(
            form.get("client_id").map(String::as_str),
            Some(TEST_CLIENT_ID)
        );
        assert_eq!(form.get("scope").map(String::as_str), Some("openid"));
        assert_eq!(
            form.get("client_secret").map(String::as_str),
            Some("secret")
        );
        assert_eq!(
            form.get("acr_values").map(String::as_str),
            Some("urn:mfa urn:webauthn")
        );
        assert_eq!(form.get("prompt").map(String::as_str), Some("login"));
        assert_eq!(form.get("max_age").map(String::as_str), Some("300"));
    }

    #[test]
    fn serde_oidc_token_error() {
        let err: OidcTokenError = serde_json::from_value(serde_json::json!({
            "error": "authorization_pending",
            "error_description": "User hasn't approved yet"
        }))
        .unwrap();
        assert_eq!(err.error, "authorization_pending");
        assert_eq!(
            err.error_description.as_deref(),
            Some("User hasn't approved yet")
        );
    }

    #[test]
    fn serde_oidc_token_error_no_description() {
        let err: OidcTokenError = serde_json::from_value(serde_json::json!({
            "error": "access_denied"
        }))
        .unwrap();
        assert_eq!(err.error, "access_denied");
        assert!(err.error_description.is_none());
    }

    #[test]
    fn serde_id_token_claims_full() {
        let claims: IdTokenClaims = serde_json::from_value(serde_json::json!({
            "sub": "user-123",
            "email": "user@corp.com",
            "email_verified": true,
            "name": "Test User",
            "preferred_username": "tuser",
            "iss": "https://issuer.com",
            "aud": "client-1",
            "exp": 1700000000_u64,
            "acr": "urn:mfa",
            "amr": ["pwd", "mfa"],
            "auth_time": 1699999900_u64
        }))
        .unwrap();
        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.email.as_deref(), Some("user@corp.com"));
        assert_eq!(claims.email_verified, Some(true));
        assert_eq!(claims.name.as_deref(), Some("Test User"));
        assert_eq!(claims.exp, Some(1700000000));
        assert_eq!(claims.acr.as_deref(), Some("urn:mfa"));
        assert_eq!(claims.amr, vec!["pwd", "mfa"]);
        assert_eq!(claims.auth_time, Some(1699999900));
    }

    #[test]
    fn serde_id_token_claims_aud_as_array() {
        let claims: IdTokenClaims = serde_json::from_value(serde_json::json!({
            "sub": "u",
            "aud": ["client-1", "client-2"]
        }))
        .unwrap();
        assert!(claims.aud.unwrap().is_array());
    }

    #[test]
    fn serde_id_token_claims_minimal() {
        let claims: IdTokenClaims =
            serde_json::from_value(serde_json::json!({"sub": "u"})).unwrap();
        assert_eq!(claims.sub, "u");
        assert!(claims.email.is_none());
        assert!(claims.iss.is_none());
        assert!(claims.aud.is_none());
        assert!(claims.exp.is_none());
        assert!(claims.acr.is_none());
        assert!(claims.amr.is_empty());
        assert!(claims.auth_time.is_none());
    }

    // ═══════════════════════════════════════════════════════════════════
    // decode_and_validate_id_token — claims validation
    // ═══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn validate_id_token_valid() {
        let client = client_with_cached_jwks().await;
        let token = sign_test_jwt(&serde_json::json!({
            "sub": "user-valid",
            "email": "valid@corp.com",
            "email_verified": true,
            "name": "Valid User",
            "iss": TEST_ISSUER,
            "aud": TEST_CLIENT_ID,
            "exp": now_secs() + 3600,
        }));
        let claims = client.decode_and_validate_id_token(&token).await.unwrap();
        assert_eq!(claims.sub, "user-valid");
        assert_eq!(claims.email.as_deref(), Some("valid@corp.com"));
        assert_eq!(claims.email_verified, Some(true));
    }

    #[tokio::test]
    async fn validate_id_token_missing_iss() {
        let client = client_with_cached_jwks().await;
        let token = sign_test_jwt(&serde_json::json!({
            "sub": "u",
            "aud": TEST_CLIENT_ID,
            "exp": now_secs() + 3600,
        }));
        let err = client
            .decode_and_validate_id_token(&token)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("missing required 'iss'"));
    }

    #[tokio::test]
    async fn validate_id_token_wrong_issuer() {
        let client = client_with_cached_jwks().await;
        let token = sign_test_jwt(&serde_json::json!({
            "sub": "u",
            "iss": "https://evil-issuer.com",
            "aud": TEST_CLIENT_ID,
            "exp": now_secs() + 3600,
        }));
        let err = client
            .decode_and_validate_id_token(&token)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("issuer mismatch"));
    }

    #[tokio::test]
    async fn validate_id_token_issuer_trailing_slash_normalized() {
        let client = client_with_cached_jwks().await;
        let token = sign_test_jwt(&serde_json::json!({
            "sub": "u",
            "iss": format!("{}/", TEST_ISSUER),
            "aud": TEST_CLIENT_ID,
            "exp": now_secs() + 3600,
        }));
        // Trailing slash should be normalized — validation passes
        assert!(client.decode_and_validate_id_token(&token).await.is_ok());
    }

    #[tokio::test]
    async fn validate_id_token_missing_aud() {
        let client = client_with_cached_jwks().await;
        let token = sign_test_jwt(&serde_json::json!({
            "sub": "u",
            "iss": TEST_ISSUER,
            "exp": now_secs() + 3600,
        }));
        let err = client
            .decode_and_validate_id_token(&token)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("missing required 'aud'"));
    }

    #[tokio::test]
    async fn validate_id_token_wrong_aud_string() {
        let client = client_with_cached_jwks().await;
        let token = sign_test_jwt(&serde_json::json!({
            "sub": "u",
            "iss": TEST_ISSUER,
            "aud": "wrong-client-id",
            "exp": now_secs() + 3600,
        }));
        let err = client
            .decode_and_validate_id_token(&token)
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("audience does not contain client_id"));
    }

    #[tokio::test]
    async fn validate_id_token_aud_array_matching() {
        let client = client_with_cached_jwks().await;
        let token = sign_test_jwt(&serde_json::json!({
            "sub": "u",
            "iss": TEST_ISSUER,
            "aud": ["other-client", TEST_CLIENT_ID, "third"],
            "exp": now_secs() + 3600,
        }));
        assert!(client.decode_and_validate_id_token(&token).await.is_ok());
    }

    #[tokio::test]
    async fn validate_id_token_aud_array_no_match() {
        let client = client_with_cached_jwks().await;
        let token = sign_test_jwt(&serde_json::json!({
            "sub": "u",
            "iss": TEST_ISSUER,
            "aud": ["other-1", "other-2"],
            "exp": now_secs() + 3600,
        }));
        let err = client
            .decode_and_validate_id_token(&token)
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("audience does not contain client_id"));
    }

    #[tokio::test]
    async fn validate_id_token_expired() {
        let client = client_with_cached_jwks().await;
        let token = sign_test_jwt(&serde_json::json!({
            "sub": "u",
            "iss": TEST_ISSUER,
            "aud": TEST_CLIENT_ID,
            "exp": 946684800_u64, // 2000-01-01 — well past 300s leeway
        }));
        let err = client
            .decode_and_validate_id_token(&token)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[tokio::test]
    async fn validate_id_token_requires_configured_acr() {
        let mut config = test_config();
        config.required_acr_values = vec!["urn:mfa".into()];
        let client = client_with_cached_jwks_config(config).await;
        let token = sign_test_jwt(&serde_json::json!({
            "sub": "u",
            "iss": TEST_ISSUER,
            "aud": TEST_CLIENT_ID,
            "exp": now_secs() + 3600,
            "acr": "urn:pwd",
        }));
        let err = client
            .decode_and_validate_id_token(&token)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("acr"));

        let token = sign_test_jwt(&serde_json::json!({
            "sub": "u",
            "iss": TEST_ISSUER,
            "aud": TEST_CLIENT_ID,
            "exp": now_secs() + 3600,
            "acr": "urn:mfa",
        }));
        assert!(client.decode_and_validate_id_token(&token).await.is_ok());
    }

    #[tokio::test]
    async fn validate_id_token_requires_configured_amr_values() {
        let mut config = test_config();
        config.required_amr_values = vec!["mfa".into(), "pwd".into()];
        let client = client_with_cached_jwks_config(config).await;
        let token = sign_test_jwt(&serde_json::json!({
            "sub": "u",
            "iss": TEST_ISSUER,
            "aud": TEST_CLIENT_ID,
            "exp": now_secs() + 3600,
            "amr": ["pwd"],
        }));
        let err = client
            .decode_and_validate_id_token(&token)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("amr"));

        let token = sign_test_jwt(&serde_json::json!({
            "sub": "u",
            "iss": TEST_ISSUER,
            "aud": TEST_CLIENT_ID,
            "exp": now_secs() + 3600,
            "amr": ["pwd", "mfa"],
        }));
        assert!(client.decode_and_validate_id_token(&token).await.is_ok());
    }

    #[tokio::test]
    async fn validate_id_token_enforces_configured_max_age() {
        let mut config = test_config();
        config.max_age_seconds = Some(60);
        let client = client_with_cached_jwks_config(config).await;
        let token = sign_test_jwt(&serde_json::json!({
            "sub": "u",
            "iss": TEST_ISSUER,
            "aud": TEST_CLIENT_ID,
            "exp": now_secs() + 3600,
            "auth_time": now_secs() - 600,
        }));
        let err = client
            .decode_and_validate_id_token(&token)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("auth_time"));

        let token = sign_test_jwt(&serde_json::json!({
            "sub": "u",
            "iss": TEST_ISSUER,
            "aud": TEST_CLIENT_ID,
            "exp": now_secs() + 3600,
            "auth_time": now_secs(),
        }));
        assert!(client.decode_and_validate_id_token(&token).await.is_ok());
    }

    #[tokio::test]
    async fn validate_id_token_missing_kid_in_header() {
        let client = client_with_cached_jwks().await;
        let header = JwtHeader {
            alg: Algorithm::RS256,
            kid: None,
            ..Default::default()
        };
        let claims = serde_json::json!({
            "sub": "u",
            "iss": TEST_ISSUER,
            "aud": TEST_CLIENT_ID,
            "exp": now_secs() + 3600,
        });
        let key = EncodingKey::from_rsa_pem(test_rsa_pem()).unwrap();
        let token = encode(&header, &claims, &key).unwrap();
        let err = client
            .decode_and_validate_id_token(&token)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("kid"));
    }

    #[tokio::test]
    async fn validate_id_token_unknown_kid() {
        // Key is in cache under TEST_KID, but token has a different kid
        let client = client_with_cached_jwks().await;
        let header = JwtHeader {
            alg: Algorithm::RS256,
            kid: Some("unknown-kid".into()),
            ..Default::default()
        };
        let claims = serde_json::json!({
            "sub": "u",
            "iss": TEST_ISSUER,
            "aud": TEST_CLIENT_ID,
            "exp": now_secs() + 3600,
        });
        let key = EncodingKey::from_rsa_pem(test_rsa_pem()).unwrap();
        let token = encode(&header, &claims, &key).unwrap();
        // get_jwk will miss cache, try refresh_jwks (which fails without
        // endpoints), so we expect an error
        let err = client
            .decode_and_validate_id_token(&token)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
    }

    // ═══════════════════════════════════════════════════════════════════
    // Accessors
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn client_id_accessor() {
        let client = test_client();
        assert_eq!(client.client_id(), TEST_CLIENT_ID);
    }

    #[test]
    fn scopes_accessor() {
        let client = test_client();
        assert_eq!(client.scopes(), &["openid".to_string()]);
    }
}
