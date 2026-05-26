use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    #[serde(default = "default_bind")]
    pub bind_address: String,

    pub oidc: OidcConfig,
    pub jwt: JwtConfig,
    pub aws: AwsConfig,

    #[serde(default)]
    pub dev_mode: bool,

    /// When true, EC2/CloudWatch API calls return mock data instead of
    /// hitting real AWS. Defaults to the value of `dev_mode` if omitted.
    /// Set to `false` while keeping `dev_mode = true` to use dev-login
    /// auth with real AWS data.
    #[serde(default)]
    pub mock_aws_data: Option<bool>,

    /// Path to the entitlements config file (rules + memberships).
    /// Production mode requires either this or `entitlements_database_url`.
    #[serde(default)]
    pub entitlements_file: Option<String>,

    /// SQLite entitlement database URL. Supported forms:
    /// `sqlite:///absolute/path.db` or `sqlite://relative/path.db`.
    /// Mutually exclusive with `entitlements_file`.
    #[serde(default)]
    pub entitlements_database_url: Option<String>,

    /// Path to the audit log file (JSON-lines). If set, all audit events
    /// are appended here in addition to structured tracing output.
    #[serde(default)]
    pub audit_log: Option<String>,

    /// Allowed CORS origins. If empty and dev_mode is true, all origins are
    /// allowed. In production, list the exact origins that need access
    /// (e.g. ["http://localhost:9876"]).
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
}

fn default_bind() -> String {
    "127.0.0.1:8443".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,

    // Optional endpoint overrides — if omitted, discovered from issuer_url
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
}

fn default_scopes() -> Vec<String> {
    vec!["openid".into(), "profile".into(), "email".into()]
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    #[serde(default = "default_expiry")]
    pub expiry_seconds: u64,
}

fn default_expiry() -> u64 {
    3600
}

#[derive(Debug, Clone, Deserialize)]
pub struct AwsConfig {
    #[serde(default)]
    pub default_region: Option<String>,
    #[serde(default)]
    pub session_duration_seconds: Option<i32>,
    /// STS ExternalId for AssumeRole calls. Must match the Condition in the
    /// target role's trust policy. Defaults to "canopy".
    #[serde(default = "default_sts_external_id")]
    pub sts_external_id: Option<String>,
}

fn default_sts_external_id() -> Option<String> {
    Some("canopy".into())
}

impl AppConfig {
    pub fn load() -> anyhow::Result<Self> {
        // Try config file first, fall back to env-based defaults
        let config_path = std::env::var("CONFIG_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("config.toml"));

        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            let config: AppConfig = toml::from_str(&content)?;
            Ok(config)
        } else if std::env::var("DEV_MODE")
            .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
            .unwrap_or(false)
        {
            Ok(Self::dev_defaults())
        } else {
            anyhow::bail!(
                "No config.toml found and DEV_MODE not set. \
                 Set CONFIG_PATH or DEV_MODE=1"
            );
        }
    }

    fn dev_defaults() -> Self {
        Self {
            bind_address: "127.0.0.1:8443".into(),
            oidc: OidcConfig {
                issuer_url: "https://accounts.google.com".into(),
                client_id: "dev-client-id".into(),
                client_secret: None,
                scopes: default_scopes(),
                authorization_endpoint: None,
                token_endpoint: None,
                device_authorization_endpoint: None,
                userinfo_endpoint: None,
                jwks_uri: None,
            },
            jwt: JwtConfig {
                secret: "dev-secret-change-in-production".into(),
                expiry_seconds: default_expiry(),
            },
            aws: AwsConfig {
                default_region: Some("us-east-1".into()),
                session_duration_seconds: Some(3600),
                sts_external_id: default_sts_external_id(),
            },
            dev_mode: true,
            mock_aws_data: None,
            entitlements_file: None,
            entitlements_database_url: None,
            audit_log: None,
            cors_allowed_origins: vec![],
        }
    }

    /// Whether to use mock AWS data. Defaults to `dev_mode` value if not set.
    pub fn use_mock_aws(&self) -> bool {
        self.mock_aws_data.unwrap_or(self.dev_mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_toml() {
        let toml = r#"
            [oidc]
            issuer_url = "https://example.com"
            client_id = "my-id"

            [jwt]
            secret = "my-secret"

            [aws]
        "#;
        let config: AppConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.bind_address, "127.0.0.1:8443"); // default
        assert!(!config.dev_mode); // default false
        assert_eq!(config.jwt.expiry_seconds, 3600); // default
        assert_eq!(config.oidc.scopes, vec!["openid", "profile", "email"]); // default
        assert_eq!(
            config.aws.sts_external_id.as_deref(),
            Some("canopy") // default
        );
    }

    #[test]
    fn test_parse_full_toml() {
        let toml = r#"
            bind_address = "0.0.0.0:9090"
            dev_mode = true
            mock_aws_data = false
            entitlements_database_url = "sqlite:///var/lib/canopy/entitlements.db"
            audit_log = "/tmp/audit.jsonl"
            cors_allowed_origins = ["http://localhost:3000"]

            [oidc]
            issuer_url = "https://auth.example.com"
            client_id = "cid"
            client_secret = "csecret"
            scopes = ["openid"]

            [jwt]
            secret = "s3cret"
            expiry_seconds = 7200

            [aws]
            default_region = "eu-west-1"
            session_duration_seconds = 1800
            sts_external_id = "custom-id"
        "#;
        let config: AppConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.bind_address, "0.0.0.0:9090");
        assert!(config.dev_mode);
        assert_eq!(config.mock_aws_data, Some(false));
        assert_eq!(config.entitlements_file, None);
        assert_eq!(
            config.entitlements_database_url.as_deref(),
            Some("sqlite:///var/lib/canopy/entitlements.db")
        );
        assert_eq!(config.jwt.expiry_seconds, 7200);
        assert_eq!(config.oidc.client_secret.as_deref(), Some("csecret"));
        assert_eq!(config.aws.default_region.as_deref(), Some("eu-west-1"));
        assert_eq!(config.aws.sts_external_id.as_deref(), Some("custom-id"));
        assert_eq!(config.cors_allowed_origins, vec!["http://localhost:3000"]);
    }

    #[test]
    fn test_use_mock_aws_follows_dev_mode_by_default() {
        let mut config: AppConfig = toml::from_str(
            r#"
            [oidc]
            issuer_url = "x"
            client_id = "x"
            [jwt]
            secret = "x"
            [aws]
        "#,
        )
        .unwrap();

        config.dev_mode = true;
        config.mock_aws_data = None;
        assert!(config.use_mock_aws());

        config.dev_mode = false;
        assert!(!config.use_mock_aws());
    }

    #[test]
    fn test_use_mock_aws_explicit_override() {
        let mut config: AppConfig = toml::from_str(
            r#"
            dev_mode = true
            mock_aws_data = false
            [oidc]
            issuer_url = "x"
            client_id = "x"
            [jwt]
            secret = "x"
            [aws]
        "#,
        )
        .unwrap();
        // dev_mode=true but mock_aws_data=false → use real AWS
        assert!(!config.use_mock_aws());

        config.mock_aws_data = Some(true);
        config.dev_mode = false;
        assert!(config.use_mock_aws());
    }

    #[test]
    fn test_parse_fails_on_missing_required_fields() {
        // jwt.secret is required
        let toml = r#"
            [oidc]
            issuer_url = "x"
            client_id = "x"
            [jwt]
            [aws]
        "#;
        assert!(toml::from_str::<AppConfig>(toml).is_err());
    }
}
