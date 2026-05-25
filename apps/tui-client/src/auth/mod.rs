pub mod device_code;
pub mod pkce;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Persisted auth session. `refresh_token` is optional so dev-mode and
/// legacy token-only sessions remain valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTokens {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

impl SessionTokens {
    pub fn new(access_token: String, refresh_token: Option<String>) -> Self {
        Self {
            access_token,
            refresh_token,
        }
    }
}

/// Token storage — persists auth token between sessions.
pub fn save_token(token: &str) -> anyhow::Result<()> {
    save_session(&SessionTokens::new(token.to_string(), None))
}

pub fn save_session(session: &SessionTokens) -> anyhow::Result<()> {
    save_session_to_path(&token_path(), session)
}

pub(crate) fn save_session_to_path(path: &Path, session: &SessionTokens) -> anyhow::Result<()> {
    let contents = serde_json::to_string(session)?;
    write_token_file(path, &contents)
}

fn write_token_file(path: &Path, contents: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let temp_path = token_temp_path(parent, path);

    // Write the new token into a private temp file first, then atomically
    // rename it over the old token. This avoids exposing refresh tokens through
    // a pre-existing token file that had overly broad permissions.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temp_path)?;
        let result = (|| -> anyhow::Result<()> {
            file.write_all(contents.as_bytes())?;
            file.sync_all()?;
            std::fs::rename(&temp_path, path)?;
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp_path);
        }
        result?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&temp_path, contents)?;
        std::fs::rename(&temp_path, path)?;
    }
    Ok(())
}

fn token_temp_path(parent: &Path, path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("token");
    parent.join(format!(".{name}.tmp.{}", uuid::Uuid::new_v4()))
}

pub fn load_token() -> Option<String> {
    load_session().map(|session| session.access_token)
}

pub fn load_session() -> Option<SessionTokens> {
    load_session_from_path(&token_path())
}

pub(crate) fn load_session_from_path(path: &Path) -> Option<SessionTokens> {
    // Reject tokens from files with insecure permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                eprintln!(
                    "WARNING: Token file {} has insecure permissions {:o} (expected 600). \
                     Refusing to load. Fix with: chmod 600 {}",
                    path.display(),
                    mode,
                    path.display()
                );
                return None;
            }
        }
    }

    let contents = std::fs::read_to_string(path).ok()?;
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return None;
    }

    match serde_json::from_str::<SessionTokens>(trimmed) {
        Ok(session) if !session.access_token.is_empty() => Some(session),
        Ok(_) => None,
        Err(_) if trimmed.starts_with('{') || trimmed.starts_with('[') => None,
        Err(_) => Some(SessionTokens::new(trimmed.to_string(), None)),
    }
}

pub fn clear_token() -> anyhow::Result<()> {
    clear_session_at_path(&token_path())
}

pub(crate) fn clear_session_at_path(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            sync_parent_dir(path)?;
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        let dir = std::fs::File::open(parent)?;
        dir.sync_all()?;
    }
    Ok(())
}

pub(crate) fn token_path() -> std::path::PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("canopy")
        .join("token")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_token_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("canopy-auth-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn session_tokens_roundtrip_with_refresh_token() {
        let path = temp_token_path("token");
        let session = SessionTokens::new("access".into(), Some("refresh".into()));

        save_session_to_path(&path, &session).unwrap();
        assert_eq!(load_session_from_path(&path), Some(session));

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn session_tokens_serializes_without_refresh_field_when_none() {
        let session = SessionTokens::new("access".into(), None);

        let value = serde_json::to_value(&session).unwrap();

        assert_eq!(value["access_token"], "access");
        assert!(
            value.get("refresh_token").is_none(),
            "refresh_token must be omitted, not serialized as null"
        );
    }

    #[test]
    fn session_tokens_deserialize_requires_access_token() {
        let err = serde_json::from_value::<SessionTokens>(serde_json::json!({
            "refresh_token": "refresh"
        }))
        .unwrap_err();

        assert!(
            err.to_string().contains("access_token"),
            "expected missing access_token error, got {err}"
        );
    }

    #[test]
    fn legacy_raw_token_file_still_loads_as_access_token_only() {
        let path = temp_token_path("token");
        write_token_file(&path, "legacy-access").unwrap();

        assert_eq!(
            load_session_from_path(&path),
            Some(SessionTokens::new("legacy-access".into(), None))
        );

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn saving_session_replaces_insecure_existing_file_without_reusing_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_token_path("token");
        std::fs::write(&path, "old-token").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let session = SessionTokens::new("access".into(), Some("refresh".into()));
        save_session_to_path(&path, &session).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(load_session_from_path(&path), Some(session));

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn save_session_creates_parent_directory_when_missing() {
        let dir = std::env::temp_dir().join(format!("canopy-auth-test-{}", uuid::Uuid::new_v4()));
        let path = dir.join("nested").join("token");
        let session = SessionTokens::new("access".into(), Some("refresh".into()));

        save_session_to_path(&path, &session).unwrap();

        assert_eq!(load_session_from_path(&path), Some(session));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn concurrent_saves_leave_one_complete_token_with_no_leftover_tmp_files() {
        use std::sync::Arc;

        let path = Arc::new(temp_token_path("token"));
        let parent = path.parent().unwrap().to_path_buf();
        let first = SessionTokens::new("access-one".into(), Some("refresh-one".into()));
        let second = SessionTokens::new("access-two".into(), Some("refresh-two".into()));

        let first_thread = {
            let path = Arc::clone(&path);
            let first = first.clone();
            std::thread::spawn(move || save_session_to_path(&path, &first))
        };
        let second_thread = {
            let path = Arc::clone(&path);
            let second = second.clone();
            std::thread::spawn(move || save_session_to_path(&path, &second))
        };

        first_thread.join().unwrap().unwrap();
        second_thread.join().unwrap().unwrap();

        let loaded = load_session_from_path(&path).unwrap();
        assert!(
            loaded == first || loaded == second,
            "final token must be one complete writer output, got {loaded:?}"
        );
        let leftovers: Vec<_> = std::fs::read_dir(&parent)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".token.tmp."))
            .collect();
        assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");

        let _ = std::fs::remove_dir_all(parent);
    }

    #[test]
    fn corrupted_json_session_does_not_fall_back_to_raw_token() {
        let path = temp_token_path("token");
        write_token_file(&path, "{not-json").unwrap();

        assert_eq!(load_session_from_path(&path), None);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn load_session_rejects_empty_whitespace_and_missing_access_json() {
        let path = temp_token_path("token");

        write_token_file(&path, "").unwrap();
        assert_eq!(load_session_from_path(&path), None);

        write_token_file(&path, "   \n\t  ").unwrap();
        assert_eq!(load_session_from_path(&path), None);

        write_token_file(&path, r#"{"refresh_token":"refresh"}"#).unwrap();
        assert_eq!(load_session_from_path(&path), None);

        write_token_file(&path, r#"{"access_token":""}"#).unwrap();
        assert_eq!(load_session_from_path(&path), None);

        write_token_file(&path, r#"[{"access_token":"access"}]"#).unwrap();
        assert_eq!(load_session_from_path(&path), None);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn load_session_tolerates_trailing_whitespace_and_unknown_fields() {
        let path = temp_token_path("token");
        write_token_file(
            &path,
            r#"{"access_token":"access","refresh_token":"refresh","future":true}
              "#,
        )
        .unwrap();

        assert_eq!(
            load_session_from_path(&path),
            Some(SessionTokens::new("access".into(), Some("refresh".into())))
        );

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn load_session_returns_none_for_non_existent_file() {
        let path = temp_token_path("token");
        let parent = path.parent().unwrap().to_path_buf();

        assert_eq!(load_session_from_path(&path), None);

        let _ = std::fs::remove_dir_all(parent);
    }

    #[test]
    fn clear_session_at_path_accepts_missing_file() {
        let path = temp_token_path("token");

        clear_session_at_path(&path).unwrap();

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn clear_session_at_path_removes_existing_file() {
        let path = temp_token_path("token");
        write_token_file(&path, "legacy-access").unwrap();

        clear_session_at_path(&path).unwrap();

        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn clear_session_at_path_propagates_permission_denied() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_token_path("token");
        let parent = path.parent().unwrap().to_path_buf();
        write_token_file(&path, "legacy-access").unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500)).unwrap();

        let result = clear_session_at_path(&path);

        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            result.is_err(),
            "unlink without parent write permission must fail"
        );
        let _ = std::fs::remove_dir_all(parent);
    }
}
