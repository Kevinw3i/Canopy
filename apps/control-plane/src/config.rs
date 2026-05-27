use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    #[serde(default = "default_bind")]
    pub bind_address: String,

    pub oidc: OidcConfig,
    pub jwt: JwtConfig,
    pub aws: AwsConfig,

    #[serde(default)]
    pub database_connections: HashMap<String, DatabaseConnectionConfig>,

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

    /// SQLite local MFA factor database URL. Supported forms:
    /// `sqlite:///absolute/path.db` or `sqlite://relative/path.db`.
    /// If omitted, local MFA enrollment remains disabled. Local WebAuthn
    /// fields are reserved but not currently exposed as an available factor.
    #[serde(default)]
    pub mfa_database_url: Option<String>,

    /// Base64-encoded 32-byte key used to encrypt local MFA secrets before
    /// they are written to `mfa_database_url`.
    #[serde(default)]
    pub mfa_secret_key: Option<String>,

    /// Path to the audit log file (JSON-lines). If set, all audit events
    /// are appended here in addition to structured tracing output.
    #[serde(default)]
    pub audit_log: Option<String>,

    /// Optional remote audit exports. These are additive sinks; the local
    /// structured tracing and `audit_log` behavior remain unchanged.
    #[serde(default)]
    pub audit_export: AuditExportConfig,

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
    /// Optional OIDC auth request controls for provider-enforced MFA.
    #[serde(default)]
    pub acr_values: Vec<String>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub max_age_seconds: Option<u64>,
    /// Optional id_token claim requirements for app-side MFA enforcement.
    #[serde(default)]
    pub required_acr_values: Vec<String>,
    #[serde(default)]
    pub required_amr_values: Vec<String>,

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

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConnectionConfig {
    pub engine: DatabaseEngine,
    pub host: String,
    #[serde(default = "default_mysql_port")]
    pub port: u16,
    pub database: String,
    pub secret_arn: String,
    #[serde(default)]
    pub readonly: bool,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_statement_timeout_ms")]
    pub statement_timeout_ms: u64,
    #[serde(default = "default_explain_timeout_ms")]
    pub explain_timeout_ms: u64,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// Whether to require TLS for the MySQL connection. Defaults to true.
    /// `mysql_async` ships with `ssl_opts = None`, so without this Canopy
    /// would silently send Secrets-Manager-sourced credentials in cleartext.
    #[serde(default = "default_require_tls")]
    pub require_tls: bool,
    /// Explicit opt-in to accept self-signed or otherwise invalid TLS certs.
    /// Only intended for local development; production deployments must keep
    /// this `false` and rely on the trust store.
    #[serde(default)]
    pub accept_invalid_tls_certs: bool,
    /// Explicit opt-in to skip TLS hostname (SAN/CN) validation. Only intended
    /// for local development where the cert subject does not match the host
    /// the control-plane connects to.
    #[serde(default)]
    pub skip_tls_hostname_verification: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseEngine {
    Mysql,
}

fn default_mysql_port() -> u16 {
    3306
}

fn default_connect_timeout_ms() -> u64 {
    3000
}

fn default_statement_timeout_ms() -> u64 {
    5000
}

fn default_explain_timeout_ms() -> u64 {
    3000
}

fn default_max_connections() -> u32 {
    4
}

fn default_require_tls() -> bool {
    true
}

fn default_sts_external_id() -> Option<String> {
    Some("canopy".into())
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditExportConfig {
    #[serde(default = "default_audit_export_queue_size")]
    pub queue_size: usize,
    #[serde(default)]
    pub cloudwatch_logs: Option<AuditCloudWatchLogsExportConfig>,
    #[serde(default)]
    pub s3: Option<AuditS3ExportConfig>,
}

impl Default for AuditExportConfig {
    fn default() -> Self {
        Self {
            queue_size: default_audit_export_queue_size(),
            cloudwatch_logs: None,
            s3: None,
        }
    }
}

impl AuditExportConfig {
    pub fn is_enabled(&self) -> bool {
        self.cloudwatch_logs.is_some() || self.s3.is_some()
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.queue_size == 0 {
            anyhow::bail!("audit_export.queue_size must be greater than zero");
        }

        if let Some(config) = &self.cloudwatch_logs {
            if config.log_group_name.trim().is_empty() {
                anyhow::bail!("audit_export.cloudwatch_logs.log_group_name must not be empty");
            }
            if config.log_stream_name.trim().is_empty() {
                anyhow::bail!("audit_export.cloudwatch_logs.log_stream_name must not be empty");
            }
        }

        if let Some(config) = &self.s3 {
            if config.bucket.trim().is_empty() {
                anyhow::bail!("audit_export.s3.bucket must not be empty");
            }
        }

        Ok(())
    }
}

fn default_audit_export_queue_size() -> usize {
    1024
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditCloudWatchLogsExportConfig {
    pub log_group_name: String,
    #[serde(default = "default_audit_cloudwatch_log_stream_name")]
    pub log_stream_name: String,
    #[serde(default = "default_true")]
    pub create_log_stream: bool,
}

fn default_audit_cloudwatch_log_stream_name() -> String {
    "canopy-audit".into()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditS3ExportConfig {
    pub bucket: String,
    #[serde(default)]
    pub prefix: String,
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
            config.validate()?;
            Ok(config)
        } else if std::env::var("DEV_MODE")
            .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
            .unwrap_or(false)
        {
            let config = Self::dev_defaults();
            config.validate()?;
            Ok(config)
        } else {
            anyhow::bail!(
                "No config.toml found and DEV_MODE not set. \
                 Set CONFIG_PATH or DEV_MODE=1"
            );
        }
    }

    /// Refuse to boot the production-mode control-plane with database
    /// connections that opt out of TLS or weaken its verification. Outside
    /// `dev_mode = true`, any of `require_tls = false`,
    /// `accept_invalid_tls_certs = true`, or `skip_tls_hostname_verification
    /// = true` would silently expose Secrets-Manager-sourced credentials and
    /// query payloads on the network. Failing fast here removes the single
    /// `config.toml` mistake from the threat model entirely.
    pub fn validate_database_tls(&self) -> anyhow::Result<()> {
        // The `database` field is enforced lowercase regardless of dev_mode
        // because the SQL validator compares against it case-sensitively. A
        // mixed-case default schema would let a `MyApp` database silently
        // satisfy an entitlement granting `allowed_schemas = ["myapp"]` on
        // case-sensitive MySQL hosts.
        for (name, db) in &self.database_connections {
            if db.database.chars().any(|c| c.is_ascii_uppercase()) {
                anyhow::bail!(
                    "database_connections.{name}.database '{database}' must be lowercase ASCII; \
                     mixed-case default schemas can silently match entitlement scopes on \
                     case-sensitive MySQL hosts.",
                    database = db.database
                );
            }
        }
        if self.dev_mode {
            return Ok(());
        }
        for (name, db) in &self.database_connections {
            if !db.require_tls {
                anyhow::bail!(
                    "database_connections.{name}.require_tls must be true outside dev_mode; \
                     refusing to start with plaintext MySQL credentials"
                );
            }
            if db.accept_invalid_tls_certs {
                anyhow::bail!(
                    "database_connections.{name}.accept_invalid_tls_certs must be false \
                     outside dev_mode; refusing to disable TLS cert verification in production"
                );
            }
            if db.skip_tls_hostname_verification {
                anyhow::bail!(
                    "database_connections.{name}.skip_tls_hostname_verification must be false \
                     outside dev_mode; refusing to skip hostname verification in production"
                );
            }
        }
        Ok(())
    }

    fn dev_defaults() -> Self {
        Self {
            bind_address: "127.0.0.1:8443".into(),
            oidc: OidcConfig {
                issuer_url: "https://accounts.google.com".into(),
                client_id: "dev-client-id".into(),
                client_secret: None,
                scopes: default_scopes(),
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
            database_connections: HashMap::new(),
            dev_mode: true,
            mock_aws_data: None,
            entitlements_file: None,
            entitlements_database_url: None,
            mfa_database_url: None,
            mfa_secret_key: None,
            audit_log: None,
            audit_export: AuditExportConfig::default(),
            cors_allowed_origins: vec![],
        }
    }

    /// Whether to use mock AWS data. Defaults to `dev_mode` value if not set.
    pub fn use_mock_aws(&self) -> bool {
        self.mock_aws_data.unwrap_or(self.dev_mode)
    }

    fn validate(&self) -> anyhow::Result<()> {
        self.validate_database_tls()?;
        self.audit_export.validate()?;
        validate_optional_32_byte_base64_key("mfa_secret_key", self.mfa_secret_key.as_deref())?;
        Ok(())
    }
}

fn validate_optional_32_byte_base64_key(name: &str, value: Option<&str>) -> anyhow::Result<()> {
    let Some(value) = value else {
        return Ok(());
    };

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let decoded = STANDARD
        .decode(value)
        .map_err(|_| anyhow::anyhow!("{name} must be base64 encoded"))?;
    if decoded.len() != 32 {
        anyhow::bail!("{name} must decode to exactly 32 bytes");
    }

    Ok(())
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
        assert!(config.database_connections.is_empty());
        assert_eq!(config.audit_export.queue_size, 1024);
        assert!(!config.audit_export.is_enabled());
        assert_eq!(config.mfa_database_url, None);
        assert_eq!(config.mfa_secret_key, None);
        config.validate().unwrap();
    }

    #[test]
    fn test_parse_full_toml() {
        let toml = r#"
            bind_address = "0.0.0.0:9090"
            dev_mode = true
            mock_aws_data = false
            entitlements_database_url = "sqlite:///var/lib/canopy/entitlements.db"
            mfa_database_url = "sqlite:///var/lib/canopy/mfa.db"
            mfa_secret_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            audit_log = "/tmp/audit.jsonl"
            cors_allowed_origins = ["http://localhost:3000"]

            [audit_export]
            queue_size = 2048

            [audit_export.cloudwatch_logs]
            log_group_name = "/aws/canopy/audit"
            log_stream_name = "control-plane"
            create_log_stream = true

            [audit_export.s3]
            bucket = "canopy-audit"
            prefix = "prod/"

            [oidc]
            issuer_url = "https://auth.example.com"
            client_id = "cid"
            client_secret = "csecret"
            scopes = ["openid"]
            acr_values = ["urn:mfa"]
            prompt = "login"
            max_age_seconds = 300
            required_acr_values = ["urn:mfa"]
            required_amr_values = ["mfa"]

            [jwt]
            secret = "s3cret"
            expiry_seconds = 7200

            [aws]
            default_region = "eu-west-1"
            session_duration_seconds = 1800
            sts_external_id = "custom-id"

            [database_connections.orders_prod]
            engine = "mysql"
            host = "orders-prod.example.internal"
            port = 3306
            database = "orders"
            secret_arn = "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:canopy/db/orders-prod"
            readonly = true
            connect_timeout_ms = 3000
            statement_timeout_ms = 5000
            explain_timeout_ms = 3000
            max_connections = 4
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
        assert_eq!(
            config.mfa_database_url.as_deref(),
            Some("sqlite:///var/lib/canopy/mfa.db")
        );
        assert_eq!(
            config.mfa_secret_key.as_deref(),
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        );
        assert_eq!(config.audit_log.as_deref(), Some("/tmp/audit.jsonl"));
        assert_eq!(config.audit_export.queue_size, 2048);
        let cw = config.audit_export.cloudwatch_logs.as_ref().unwrap();
        assert_eq!(cw.log_group_name, "/aws/canopy/audit");
        assert_eq!(cw.log_stream_name, "control-plane");
        assert!(cw.create_log_stream);
        let s3 = config.audit_export.s3.as_ref().unwrap();
        assert_eq!(s3.bucket, "canopy-audit");
        assert_eq!(s3.prefix, "prod/");
        assert_eq!(config.jwt.expiry_seconds, 7200);
        assert_eq!(config.oidc.client_secret.as_deref(), Some("csecret"));
        assert_eq!(config.oidc.acr_values, vec!["urn:mfa"]);
        assert_eq!(config.oidc.prompt.as_deref(), Some("login"));
        assert_eq!(config.oidc.max_age_seconds, Some(300));
        assert_eq!(config.oidc.required_acr_values, vec!["urn:mfa"]);
        assert_eq!(config.oidc.required_amr_values, vec!["mfa"]);
        assert_eq!(config.aws.default_region.as_deref(), Some("eu-west-1"));
        assert_eq!(config.aws.sts_external_id.as_deref(), Some("custom-id"));
        assert_eq!(config.cors_allowed_origins, vec!["http://localhost:3000"]);
        let db = config.database_connections.get("orders_prod").unwrap();
        assert_eq!(db.engine, DatabaseEngine::Mysql);
        assert_eq!(db.host, "orders-prod.example.internal");
        assert_eq!(db.port, 3306);
        assert!(db.readonly);
        config.validate().unwrap();
    }

    #[test]
    fn test_validation_rejects_invalid_mfa_secret_key() {
        let config: AppConfig = toml::from_str(
            r#"
            mfa_secret_key = "not-base64"
            [oidc]
            issuer_url = "x"
            client_id = "x"
            [jwt]
            secret = "x"
            [aws]
        "#,
        )
        .unwrap();

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_audit_export_validation_rejects_invalid_sink_config() {
        let zero_queue: AuditExportConfig = toml::from_str("queue_size = 0").unwrap();
        assert!(zero_queue.validate().is_err());

        let empty_log_group: AuditExportConfig = toml::from_str(
            r#"
            [cloudwatch_logs]
            log_group_name = " "
        "#,
        )
        .unwrap();
        assert!(empty_log_group.validate().is_err());

        let empty_bucket: AuditExportConfig = toml::from_str(
            r#"
            [s3]
            bucket = ""
        "#,
        )
        .unwrap();
        assert!(empty_bucket.validate().is_err());
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
    fn production_mode_rejects_database_with_tls_disabled() {
        // The TLS opt-out flags are intentionally narrow escape hatches for
        // local development. In production (dev_mode = false) any of them
        // must abort startup so a single config typo cannot expose
        // Secrets-Manager-sourced credentials in cleartext.
        let mut config = AppConfig::dev_defaults();
        config.dev_mode = false;
        config.database_connections.insert(
            "orders".into(),
            DatabaseConnectionConfig {
                engine: DatabaseEngine::Mysql,
                host: "orders.example.internal".into(),
                port: 3306,
                database: "orders".into(),
                secret_arn: "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:canopy"
                    .into(),
                readonly: true,
                connect_timeout_ms: 3000,
                statement_timeout_ms: 5000,
                explain_timeout_ms: 3000,
                max_connections: 4,
                require_tls: false,
                accept_invalid_tls_certs: false,
                skip_tls_hostname_verification: false,
            },
        );
        let err = config.validate_database_tls().unwrap_err().to_string();
        assert!(
            err.contains("require_tls must be true"),
            "expected require_tls error, got: {err}"
        );
    }

    #[test]
    fn production_mode_rejects_database_with_invalid_cert_acceptance() {
        let mut config = AppConfig::dev_defaults();
        config.dev_mode = false;
        config.database_connections.insert(
            "orders".into(),
            DatabaseConnectionConfig {
                engine: DatabaseEngine::Mysql,
                host: "orders.example.internal".into(),
                port: 3306,
                database: "orders".into(),
                secret_arn: "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:canopy"
                    .into(),
                readonly: true,
                connect_timeout_ms: 3000,
                statement_timeout_ms: 5000,
                explain_timeout_ms: 3000,
                max_connections: 4,
                require_tls: true,
                accept_invalid_tls_certs: true,
                skip_tls_hostname_verification: false,
            },
        );
        let err = config.validate_database_tls().unwrap_err().to_string();
        assert!(err.contains("accept_invalid_tls_certs"));
    }

    #[test]
    fn database_with_uppercase_database_name_is_rejected_in_any_mode() {
        // A mixed-case `database` field would become the default schema at
        // SQL validation time and conflate with a lowercase entitlement grant
        // on case-sensitive MySQL hosts. The load-time check rejects this
        // regardless of dev_mode because the same misconfiguration is
        // dangerous in either environment.
        for dev_mode in [true, false] {
            let mut config = AppConfig::dev_defaults();
            config.dev_mode = dev_mode;
            config.database_connections.insert(
                "orders".into(),
                DatabaseConnectionConfig {
                    engine: DatabaseEngine::Mysql,
                    host: "orders.example.internal".into(),
                    port: 3306,
                    database: "Orders".into(),
                    secret_arn: "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:canopy"
                        .into(),
                    readonly: true,
                    connect_timeout_ms: 3000,
                    statement_timeout_ms: 5000,
                    explain_timeout_ms: 3000,
                    max_connections: 4,
                    require_tls: true,
                    accept_invalid_tls_certs: false,
                    skip_tls_hostname_verification: false,
                },
            );
            let err = config.validate_database_tls().unwrap_err().to_string();
            assert!(
                err.contains("lowercase ASCII"),
                "expected uppercase database rejection (dev_mode={dev_mode}), got: {err}"
            );
        }
    }

    #[test]
    fn dev_mode_allows_tls_opt_outs_for_local_development() {
        let mut config = AppConfig::dev_defaults();
        config.dev_mode = true;
        config.database_connections.insert(
            "orders".into(),
            DatabaseConnectionConfig {
                engine: DatabaseEngine::Mysql,
                host: "127.0.0.1".into(),
                port: 3306,
                database: "orders".into(),
                secret_arn: "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:dev".into(),
                readonly: true,
                connect_timeout_ms: 3000,
                statement_timeout_ms: 5000,
                explain_timeout_ms: 3000,
                max_connections: 4,
                require_tls: false,
                accept_invalid_tls_certs: true,
                skip_tls_hostname_verification: true,
            },
        );
        // dev_mode permits the dangerous flags so engineers can run against
        // a local sandbox MySQL without TLS.
        assert!(config.validate_database_tls().is_ok());
    }

    #[test]
    fn database_connection_defaults_to_tls_required_without_cert_overrides() {
        // `mysql_async` ships with `ssl_opts = None`, so Canopy must opt-in
        // to TLS explicitly. This test locks in `require_tls = true` as the
        // default and ensures the dangerous override flags default to `false`.
        // A regression here would silently re-enable plaintext database
        // connections.
        let toml = r#"
            [oidc]
            issuer_url = "x"
            client_id = "x"
            [jwt]
            secret = "x"
            [aws]
            [database_connections.orders_prod]
            engine = "mysql"
            host = "orders.example.internal"
            database = "orders"
            secret_arn = "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:canopy/db/orders"
        "#;
        let config: AppConfig = toml::from_str(toml).unwrap();
        let db = config.database_connections.get("orders_prod").unwrap();
        assert!(db.require_tls, "require_tls must default to true");
        assert!(
            !db.accept_invalid_tls_certs,
            "accept_invalid_tls_certs must default to false"
        );
        assert!(
            !db.skip_tls_hostname_verification,
            "skip_tls_hostname_verification must default to false"
        );
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
