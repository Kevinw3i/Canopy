use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shared::dto::auth::*;

use crate::config::AppConfig;
use crate::services::oidc::{IdTokenClaims, OidcClient, OidcEndpoints};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub name: String,
    pub groups: Vec<String>,
    pub exp: usize,
    pub iat: usize,
    /// Whether the email was verified by the IdP. Only verified emails
    /// are used for entitlement membership matching.
    #[serde(default)]
    pub email_verified: bool,
}

pub struct AuthService {
    config: AppConfig,
}

impl AuthService {
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }

    /// Issue a JWT for the given identity
    pub fn issue_token(&self, identity: &UserIdentity) -> anyhow::Result<TokenResponse> {
        self.issue_token_with_refresh(identity, None)
    }

    /// Issue a JWT with an optional OIDC refresh_token passed through.
    pub fn issue_token_with_refresh(
        &self,
        identity: &UserIdentity,
        oidc_refresh_token: Option<String>,
    ) -> anyhow::Result<TokenResponse> {
        let now = Utc::now().timestamp() as usize;
        let exp = now + self.config.jwt.expiry_seconds as usize;

        let claims = Claims {
            sub: identity.user_id.clone(),
            email: identity.email.clone(),
            name: identity.display_name.clone(),
            groups: identity.groups.clone(),
            exp,
            iat: now,
            email_verified: identity.email_verified,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.jwt.secret.as_bytes()),
        )?;

        Ok(TokenResponse {
            access_token: token,
            token_type: "Bearer".into(),
            expires_in: self.config.jwt.expiry_seconds,
            refresh_token: oidc_refresh_token,
        })
    }

    /// Validate a JWT and return claims
    pub fn validate_token(&self, token: &str) -> anyhow::Result<Claims> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.config.jwt.secret.as_bytes()),
            &Validation::default(),
        )?;
        Ok(token_data.claims)
    }

    /// Dev-mode login: creates a token for a local dev user
    pub fn dev_login(&self, req: &DevLoginRequest) -> anyhow::Result<DevLoginResponse> {
        if !self.config.dev_mode {
            anyhow::bail!("Dev login is only available in dev mode");
        }

        let identity = UserIdentity {
            user_id: req.username.clone(),
            email: format!("{}@dev.local", req.username),
            display_name: req.username.clone(),
            groups: vec!["platform-engineering".into()],
            email_verified: true, // dev mode — always trusted
        };

        let token_response = self.issue_token(&identity)?;

        Ok(DevLoginResponse {
            access_token: token_response.access_token,
            expires_in: token_response.expires_in,
            identity,
        })
    }

    /// Verify a PKCE state parameter. Returns true if the HMAC is valid.
    pub fn verify_pkce_state(&self, state: &str) -> bool {
        use hmac::{Hmac, Mac};

        let parts: Vec<&str> = state.splitn(2, '.').collect();
        if parts.len() != 2 {
            return false;
        }
        let nonce = parts[0];
        let provided_sig = parts[1];

        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.config.jwt.secret.as_bytes()).expect("valid key");
        mac.update(nonce.as_bytes());
        let expected_sig = hex::encode(mac.finalize().into_bytes());

        expected_sig == provided_sig
    }

    /// Build PKCE authorization URL using discovered or configured endpoints.
    pub fn build_pkce_auth_url(
        &self,
        req: &PkceAuthRequest,
        endpoints: &OidcEndpoints,
    ) -> PkceAuthResponse {
        use hmac::{Hmac, Mac};

        // HMAC-sign a random nonce so the server can verify state without
        // storing session data. Format: "{nonce}.{hmac_hex}"
        let nonce = uuid::Uuid::new_v4().to_string();
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.config.jwt.secret.as_bytes()).expect("valid key");
        mac.update(nonce.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());
        let state = format!("{}.{}", nonce, sig);

        // RFC 7636: code_challenge = BASE64URL(SHA256(code_verifier))
        let digest = Sha256::digest(req.code_verifier.as_bytes());
        let code_challenge = URL_SAFE_NO_PAD.encode(digest);

        let mut url = reqwest::Url::parse(&endpoints.authorization_endpoint)
            .expect("authorization_endpoint must be a valid URL");
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.oidc.client_id)
            .append_pair("redirect_uri", &req.redirect_uri)
            .append_pair("scope", &self.config.oidc.scopes.join(" "))
            .append_pair("state", &state)
            .append_pair("code_challenge", &code_challenge)
            .append_pair("code_challenge_method", "S256");
        let authorize_url = url.to_string();

        PkceAuthResponse {
            authorize_url,
            state,
        }
    }

    /// Build a UserIdentity from OIDC ID token claims + entitlement groups.
    pub fn identity_from_oidc_claims(claims: &IdTokenClaims, groups: Vec<String>) -> UserIdentity {
        UserIdentity {
            user_id: claims.sub.clone(),
            email: claims
                .email
                .clone()
                .unwrap_or_else(|| format!("{}@unknown", claims.sub)),
            display_name: claims
                .name
                .clone()
                .or_else(|| claims.preferred_username.clone())
                .unwrap_or_else(|| claims.sub.clone()),
            groups,
            email_verified: claims.email_verified.unwrap_or(false),
        }
    }

    /// Exchange an OIDC code for an internal token.
    /// Calls the OIDC provider, extracts identity from the id_token,
    /// looks up groups from the entitlement store, and issues an internal JWT.
    pub async fn exchange_oidc_code(
        &self,
        oidc_client: &OidcClient,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
        entitlement_store: &crate::models::entitlements::EntitlementStore,
    ) -> anyhow::Result<TokenResponse> {
        let oidc_resp = oidc_client
            .exchange_code(code, code_verifier, redirect_uri)
            .await?;

        let id_token = oidc_resp
            .id_token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("OIDC provider did not return an id_token"))?;

        let oidc_claims = oidc_client.decode_and_validate_id_token(id_token).await?;

        // Look up groups from entitlement store
        let display_name = oidc_claims
            .name
            .clone()
            .or_else(|| oidc_claims.preferred_username.clone())
            .unwrap_or_else(|| oidc_claims.sub.clone());
        let email = oidc_claims
            .email
            .clone()
            .unwrap_or_else(|| format!("{}@unknown", oidc_claims.sub));

        let email_verified = oidc_claims.email_verified.unwrap_or(false);
        let ent =
            entitlement_store.evaluate(&oidc_claims.sub, &email, &display_name, email_verified);

        let identity = Self::identity_from_oidc_claims(&oidc_claims, ent.groups);

        self.issue_token_with_refresh(&identity, oidc_resp.refresh_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, AwsConfig, JwtConfig, OidcConfig};
    use std::collections::HashMap;

    fn test_config(dev_mode: bool) -> AppConfig {
        AppConfig {
            bind_address: "127.0.0.1:8443".into(),
            oidc: OidcConfig {
                issuer_url: "https://example.com".into(),
                client_id: "test-client".into(),
                client_secret: None,
                scopes: vec!["openid".into()],
                authorization_endpoint: None,
                token_endpoint: None,
                device_authorization_endpoint: None,
                userinfo_endpoint: None,
                jwks_uri: None,
            },
            jwt: JwtConfig {
                secret: "test-secret-at-least-32-chars-long!!".into(),
                expiry_seconds: 3600,
            },
            aws: AwsConfig {
                default_region: Some("us-east-1".into()),
                session_duration_seconds: Some(3600),
                sts_external_id: Some("canopy".into()),
            },
            database_connections: HashMap::new(),
            dev_mode,
            mock_aws_data: None,
            entitlements_file: None,
            audit_log: None,
            cors_allowed_origins: vec![],
        }
    }

    fn test_identity() -> UserIdentity {
        UserIdentity {
            user_id: "alice".into(),
            email: "alice@example.com".into(),
            display_name: "Alice".into(),
            groups: vec!["engineers".into()],
            email_verified: true,
        }
    }

    #[test]
    fn test_issue_and_validate_token() {
        let svc = AuthService::new(test_config(false));
        let resp = svc.issue_token(&test_identity()).unwrap();
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, 3600);

        let claims = svc.validate_token(&resp.access_token).unwrap();
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.email, "alice@example.com");
        assert_eq!(claims.groups, vec!["engineers"]);
        assert!(claims.email_verified);
    }

    #[test]
    fn test_validate_rejects_tampered_token() {
        let svc = AuthService::new(test_config(false));
        let resp = svc.issue_token(&test_identity()).unwrap();
        let tampered = format!("{}x", resp.access_token);
        assert!(svc.validate_token(&tampered).is_err());
    }

    #[test]
    fn test_validate_rejects_wrong_secret() {
        let svc = AuthService::new(test_config(false));
        let resp = svc.issue_token(&test_identity()).unwrap();

        let mut other_config = test_config(false);
        other_config.jwt.secret = "completely-different-secret-value!!".into();
        let other_svc = AuthService::new(other_config);
        assert!(other_svc.validate_token(&resp.access_token).is_err());
    }

    #[test]
    fn test_validate_rejects_expired_token() {
        // Forge claims manually with exp in the past
        let claims = Claims {
            sub: "alice".into(),
            email: "alice@example.com".into(),
            name: "Alice".into(),
            groups: vec![],
            exp: 0, // epoch — definitely expired
            iat: 0,
            email_verified: false,
        };
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(b"test-secret-at-least-32-chars-long!!"),
        )
        .unwrap();
        let svc = AuthService::new(test_config(false));
        assert!(svc.validate_token(&token).is_err());
    }

    #[test]
    fn test_issue_token_with_refresh() {
        let svc = AuthService::new(test_config(false));
        let resp = svc
            .issue_token_with_refresh(&test_identity(), Some("refresh-tok".into()))
            .unwrap();
        assert_eq!(resp.refresh_token.as_deref(), Some("refresh-tok"));
    }

    #[test]
    fn test_dev_login_succeeds_in_dev_mode() {
        let svc = AuthService::new(test_config(true));
        let req = DevLoginRequest {
            username: "dev-admin".into(),
        };
        let resp = svc.dev_login(&req).unwrap();
        assert_eq!(resp.identity.user_id, "dev-admin");
        assert_eq!(resp.identity.email, "dev-admin@dev.local");
        assert_eq!(resp.identity.groups, vec!["platform-engineering"]);
        assert!(resp.identity.email_verified);
        // Token should be valid
        assert!(svc.validate_token(&resp.access_token).is_ok());
    }

    #[test]
    fn test_dev_login_rejected_in_prod_mode() {
        let svc = AuthService::new(test_config(false));
        let req = DevLoginRequest {
            username: "hacker".into(),
        };
        assert!(svc.dev_login(&req).is_err());
    }

    #[test]
    fn test_pkce_state_roundtrip() {
        let svc = AuthService::new(test_config(false));
        let endpoints = OidcEndpoints {
            authorization_endpoint: "https://example.com/auth".into(),
            token_endpoint: "https://example.com/token".into(),
            device_authorization_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: Some("https://example.com/jwks".into()),
        };
        let req = PkceAuthRequest {
            code_verifier: "test-verifier".into(),
            redirect_uri: "http://localhost:9876/callback".into(),
        };
        let resp = svc.build_pkce_auth_url(&req, &endpoints);

        // State should be verifiable
        assert!(svc.verify_pkce_state(&resp.state));
    }

    #[test]
    fn test_pkce_state_rejects_tampered() {
        let svc = AuthService::new(test_config(false));
        assert!(!svc.verify_pkce_state("fake-nonce.0000bad0000"));
        assert!(!svc.verify_pkce_state("no-dot-here"));
        assert!(!svc.verify_pkce_state(""));
    }

    #[test]
    fn test_identity_from_oidc_claims() {
        let claims = IdTokenClaims {
            sub: "sub-123".into(),
            email: Some("alice@corp.com".into()),
            email_verified: Some(true),
            name: Some("Alice Smith".into()),
            preferred_username: None,
            iss: None,
            aud: None,
            exp: None,
        };
        let id = AuthService::identity_from_oidc_claims(&claims, vec!["ops".into()]);
        assert_eq!(id.user_id, "sub-123");
        assert_eq!(id.email, "alice@corp.com");
        assert_eq!(id.display_name, "Alice Smith");
        assert!(id.email_verified);
    }

    #[test]
    fn test_identity_from_oidc_claims_fallbacks() {
        let claims = IdTokenClaims {
            sub: "sub-456".into(),
            email: None,
            email_verified: None,
            name: None,
            preferred_username: Some("bob".into()),
            iss: None,
            aud: None,
            exp: None,
        };
        let id = AuthService::identity_from_oidc_claims(&claims, vec![]);
        assert_eq!(id.email, "sub-456@unknown");
        assert_eq!(id.display_name, "bob");
        assert!(!id.email_verified);
    }
}
