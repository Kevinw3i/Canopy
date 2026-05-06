use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub control_plane_url: String,
    #[serde(default)]
    pub dev_mode: bool,
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval_secs: u64,
    #[serde(default = "default_scrollback")]
    pub live_tail_scrollback: usize,
    #[serde(default = "default_callback_port")]
    pub pkce_callback_port: u16,
    /// Feature flag for the live-tail beta.  Defaults to false (hidden) in
    /// production; automatically set to true when `dev_mode` is enabled.
    #[serde(default)]
    pub enable_live_tail: bool,
    /// Show public IP on the dashboard (requires outbound call to checkip.amazonaws.com).
    #[serde(default)]
    pub show_public_ip: bool,
    /// Automatically check for and apply updates on startup (at most once per hour).
    #[serde(default = "default_auto_update")]
    pub auto_update: bool,
    /// GitHub repo owner for update checks (default: "Kevinw3i").
    #[serde(default = "default_update_repo_owner")]
    pub update_repo_owner: String,
    /// GitHub repo name for update checks (default: "Canopy").
    #[serde(default = "default_update_repo_name")]
    pub update_repo_name: String,
    /// Optional self-service password change URL, typically the Cognito hosted UI.
    #[serde(default)]
    pub change_password_url: Option<String>,
}

fn default_auto_update() -> bool {
    false
}

fn default_update_repo_owner() -> String {
    option_env!("CANOPY_UPDATE_REPO_OWNER")
        .unwrap_or("Kevinw3i")
        .into()
}

fn default_update_repo_name() -> String {
    option_env!("CANOPY_UPDATE_REPO_NAME")
        .unwrap_or("Canopy")
        .into()
}

fn default_callback_port() -> u16 {
    9876
}

fn default_refresh_interval() -> u64 {
    30
}

fn default_scrollback() -> usize {
    10_000
}

impl ClientConfig {
    pub fn load() -> anyhow::Result<Self> {
        Self::load_from_path(Self::dev_mode_env_enabled(), Self::config_path())
    }

    fn load_from_path(dev_mode_env_enabled: bool, config_path: PathBuf) -> anyhow::Result<Self> {
        if dev_mode_env_enabled {
            if config_path.exists() {
                tracing::warn!(
                    path = %config_path.display(),
                    "DEV_MODE=1 is set; ignoring on-disk TUI config"
                );
            }
            return Ok(Self::dev_defaults());
        }

        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            let config: ClientConfig = toml::from_str(&content)?;
            Ok(config)
        } else {
            anyhow::bail!(
                "No config file found at {:?}.\n\
                 Create a config file or set DEV_MODE=1 for development.\n\
                 See README.md for production configuration instructions.",
                config_path
            );
        }
    }

    fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("canopy")
            .join("config.toml")
    }

    fn dev_mode_env_enabled() -> bool {
        Self::dev_mode_value_enabled(std::env::var("DEV_MODE").ok().as_deref())
    }

    fn dev_mode_value_enabled(value: Option<&str>) -> bool {
        value
            .map(|v| matches!(v, "1" | "true" | "yes"))
            .unwrap_or(false)
    }

    fn dev_defaults() -> Self {
        Self {
            control_plane_url: "http://localhost:8443".into(),
            dev_mode: true,
            refresh_interval_secs: default_refresh_interval(),
            live_tail_scrollback: default_scrollback(),
            pkce_callback_port: default_callback_port(),
            enable_live_tail: true,
            show_public_ip: false,
            auto_update: false,
            update_repo_owner: default_update_repo_owner(),
            update_repo_name: default_update_repo_name(),
            change_password_url: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct RemoveDirOnDrop(PathBuf);

    impl Drop for RemoveDirOnDrop {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_parse_minimal_toml() {
        let toml_str = r#"control_plane_url = "https://canopy.internal""#;
        let config: ClientConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.control_plane_url, "https://canopy.internal");
        assert!(!config.dev_mode);
        assert_eq!(config.refresh_interval_secs, 30);
        assert_eq!(config.live_tail_scrollback, 10_000);
        assert_eq!(config.pkce_callback_port, 9876);
        assert!(!config.enable_live_tail);
        assert!(!config.auto_update);
        assert!(config.change_password_url.is_none());
    }

    #[test]
    fn test_parse_full_toml() {
        let toml_str = r#"
            control_plane_url = "http://localhost:9999"
            dev_mode = true
            refresh_interval_secs = 60
            live_tail_scrollback = 5000
            pkce_callback_port = 1234
            enable_live_tail = true
            show_public_ip = true
            auto_update = true
            update_repo_owner = "MyOrg"
            update_repo_name = "MyRepo"
            change_password_url = "https://auth.example.com/forgotPassword"
        "#;
        let config: ClientConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.control_plane_url, "http://localhost:9999");
        assert!(config.dev_mode);
        assert_eq!(config.refresh_interval_secs, 60);
        assert_eq!(config.live_tail_scrollback, 5000);
        assert_eq!(config.pkce_callback_port, 1234);
        assert!(config.enable_live_tail);
        assert!(config.show_public_ip);
        assert!(config.auto_update);
        assert_eq!(config.update_repo_owner, "MyOrg");
        assert_eq!(config.update_repo_name, "MyRepo");
        assert_eq!(
            config.change_password_url.as_deref(),
            Some("https://auth.example.com/forgotPassword")
        );
    }

    #[test]
    fn test_parse_fails_without_url() {
        let toml_str = r#"dev_mode = true"#;
        assert!(toml::from_str::<ClientConfig>(toml_str).is_err());
    }

    #[test]
    fn test_dev_mode_value_enabled() {
        assert!(ClientConfig::dev_mode_value_enabled(Some("1")));
        assert!(ClientConfig::dev_mode_value_enabled(Some("true")));
        assert!(ClientConfig::dev_mode_value_enabled(Some("yes")));
        assert!(!ClientConfig::dev_mode_value_enabled(None));
        assert!(!ClientConfig::dev_mode_value_enabled(Some("0")));
        assert!(!ClientConfig::dev_mode_value_enabled(Some("false")));
    }

    #[test]
    fn test_load_ignores_config_when_dev_mode_env_enabled() {
        let dir = std::env::temp_dir().join(format!(
            "canopy-tui-config-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _cleanup = RemoveDirOnDrop(dir.clone());
        let path = dir.join("config.toml");

        fs::create_dir_all(&dir).unwrap();
        fs::write(&path, "not valid toml").unwrap();

        let config = ClientConfig::load_from_path(true, path.clone()).unwrap();
        assert_eq!(config.control_plane_url, "http://localhost:8443");
        assert!(config.dev_mode);
    }
}
