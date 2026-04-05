pub mod audit;
pub mod auth;
pub mod cloudwatch;
pub mod ec2;
pub mod entitlements;
pub mod oidc;

use crate::config::AppConfig;
use crate::models::entitlements::EntitlementStore;
use aws_config::SdkConfig;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Tracks who started a Logs Insights query and which log groups were approved.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QueryAuthorization {
    pub user_id: String,
    pub log_group_names: Vec<String>,
}

/// Encode query authorization into a signed token that can survive restarts.
/// Format: `{aws_query_id}.{base64url(json)}.{hmac_hex}`
pub fn sign_query_token(aws_query_id: &str, auth: &QueryAuthorization, secret: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let payload = serde_json::to_string(auth).unwrap_or_default();
    let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());

    let msg = format!("{}.{}", aws_query_id, encoded);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC key length");
    mac.update(msg.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());

    format!("{}.{}", msg, sig)
}

/// Verify and extract authorization from a signed query token.
pub fn verify_query_token(token: &str, secret: &str) -> Option<(String, QueryAuthorization)> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let parts: Vec<&str> = token.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return None;
    }
    let sig_hex = parts[0];
    let msg = parts[1]; // "{aws_query_id}.{encoded_payload}"

    // Verify HMAC
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(msg.as_bytes());
    let expected_sig = hex::encode(mac.finalize().into_bytes());
    if sig_hex != expected_sig {
        return None;
    }

    // Split msg into aws_query_id and encoded payload
    let dot_pos = msg.find('.')?;
    let aws_query_id = &msg[..dot_pos];
    let encoded = &msg[dot_pos + 1..];

    let payload_bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let auth: QueryAuthorization = serde_json::from_slice(&payload_bytes).ok()?;

    Some((aws_query_id.to_string(), auth))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_token_roundtrip() {
        let auth = QueryAuthorization {
            user_id: "alice".into(),
            log_group_names: vec!["/app/web".into(), "/app/api".into()],
        };
        let token = sign_query_token("query-abc-123", &auth, "my-secret");
        let (id, decoded) = verify_query_token(&token, "my-secret").unwrap();
        assert_eq!(id, "query-abc-123");
        assert_eq!(decoded.user_id, "alice");
        assert_eq!(decoded.log_group_names, vec!["/app/web", "/app/api"]);
    }

    #[test]
    fn test_query_token_rejects_wrong_secret() {
        let auth = QueryAuthorization {
            user_id: "alice".into(),
            log_group_names: vec![],
        };
        let token = sign_query_token("q1", &auth, "secret-a");
        assert!(verify_query_token(&token, "secret-b").is_none());
    }

    #[test]
    fn test_query_token_rejects_tampered_payload() {
        let auth = QueryAuthorization {
            user_id: "alice".into(),
            log_group_names: vec!["/app/x".into()],
        };
        let token = sign_query_token("q1", &auth, "secret");
        // Tamper with the query ID portion (before first dot)
        let tampered = token.replacen("q1", "q2", 1);
        assert!(verify_query_token(&tampered, "secret").is_none());
    }

    #[test]
    fn test_query_token_rejects_malformed() {
        assert!(verify_query_token("", "secret").is_none());
        assert!(verify_query_token("no-dots-at-all", "secret").is_none());
        assert!(verify_query_token("one.two", "secret").is_none());
    }
}

/// Shared application state passed to all handlers
pub struct AppState {
    pub config: AppConfig,
    pub entitlement_store: Arc<RwLock<EntitlementStore>>,
    pub audit_service: audit::AuditService,
    pub oidc_client: oidc::OidcClient,
    pub base_aws_config: SdkConfig,
    /// Set to true after startup preflight checks (OIDC discovery + STS identity) succeed.
    pub ready: std::sync::atomic::AtomicBool,
}

impl AppState {
    pub async fn new(config: AppConfig) -> anyhow::Result<Self> {
        let entitlement_store = if let Some(ref path) = config.entitlements_file {
            // Explicit entitlements file always takes priority (dev or production)
            EntitlementStore::load_from_file(std::path::Path::new(path))?
        } else if config.dev_mode {
            EntitlementStore::dev_defaults()
        } else {
            anyhow::bail!(
                "entitlements_file is required in production mode. \
                 Set dev_mode = true or provide an entitlements config path."
            );
        };

        let oidc_client = oidc::OidcClient::new(config.oidc.clone());

        // Load the base AWS SDK config (uses ambient credentials: env vars,
        // instance profile, ~/.aws/credentials, etc.).
        let base_aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(
                config
                    .aws
                    .default_region
                    .clone()
                    .unwrap_or_else(|| "us-east-1".to_string()),
            ))
            .load()
            .await;

        let audit_service = if let Some(ref log_path) = config.audit_log {
            audit::AuditService::with_file(log_path)?
        } else {
            audit::AuditService::new()
        };

        Ok(Self {
            config,
            entitlement_store: Arc::new(RwLock::new(entitlement_store)),
            audit_service,
            oidc_client,
            base_aws_config,
            ready: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Run startup preflight: verify OIDC discovery and STS identity.
    /// Retries with exponential backoff (up to ~30s total).
    /// Sets `ready` to true on success.
    pub async fn run_preflight(&self) -> anyhow::Result<()> {
        let max_attempts = 3u32;
        let mut last_err = None;

        for attempt in 0..max_attempts {
            if attempt > 0 {
                let delay = std::time::Duration::from_secs(2u64.pow(attempt.min(4)));
                tracing::warn!(
                    "Preflight attempt {} failed, retrying in {:?}...",
                    attempt,
                    delay
                );
                tokio::time::sleep(delay).await;
            }

            let step_timeout = std::time::Duration::from_secs(10);

            // 1. OIDC discovery (bounded by timeout)
            tracing::info!(
                "Preflight (attempt {}): verifying OIDC discovery...",
                attempt + 1
            );
            match tokio::time::timeout(step_timeout, self.oidc_client.endpoints()).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    last_err = Some(format!("OIDC discovery: {e}"));
                    continue;
                }
                Err(_) => {
                    last_err = Some("OIDC discovery timed out".into());
                    continue;
                }
            }
            tracing::info!("Preflight: OIDC discovery OK");

            // 2. STS GetCallerIdentity (bounded by timeout)
            tracing::info!("Preflight: verifying STS identity...");
            let sts = aws_sdk_sts::Client::new(&self.base_aws_config);
            match tokio::time::timeout(step_timeout, sts.get_caller_identity().send()).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    last_err = Some(format!("STS GetCallerIdentity: {e}"));
                    continue;
                }
                Err(_) => {
                    last_err = Some("STS GetCallerIdentity timed out".into());
                    continue;
                }
            }
            tracing::info!("Preflight: STS identity OK");

            self.ready.store(true, std::sync::atomic::Ordering::Release);
            return Ok(());
        }

        Err(anyhow::anyhow!(
            "Preflight failed after {} attempts: {}",
            max_attempts,
            last_err.unwrap_or_default()
        ))
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(std::sync::atomic::Ordering::Acquire)
    }
}
