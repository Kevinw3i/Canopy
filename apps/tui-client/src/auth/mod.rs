pub mod device_code;
pub mod pkce;
pub mod webauthn;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Persisted auth session. `refresh_token` is optional so dev-mode,
/// access-token-only, and legacy raw-token sessions remain valid.
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

/// Token storage - persists auth session between TUI runs.
pub fn save_token(token: &str) -> anyhow::Result<()> {
    save_session(&SessionTokens::new(token.to_string(), None))
}

pub(crate) fn save_token_to_path(path: &Path, token: &str) -> anyhow::Result<()> {
    save_session_to_path(path, &SessionTokens::new(token.to_string(), None))
}

pub fn save_session(session: &SessionTokens) -> anyhow::Result<()> {
    save_session_to_path(&token_path(), session)
}

pub(crate) fn save_session_to_path(path: &Path, session: &SessionTokens) -> anyhow::Result<()> {
    let contents = serde_json::to_string(session)?;
    write_token_file(path, &contents)
}

/// Write `contents` to `path`, creating any missing parent directories.
///
/// On Unix this uses a private 0600 temp file plus atomic rename so a
/// freshly rotated token is never written through a pre-existing file with
/// broader permissions.
fn write_token_file(path: &Path, contents: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let tmp_path = token_temp_path(parent, path)?;

        let write_result: anyhow::Result<()> = (|| {
            let mut tmp = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&tmp_path)?;
            tmp.write_all(contents.as_bytes())?;
            tmp.sync_all()?;
            Ok(())
        })();
        if let Err(err) = write_result {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err);
        }

        if let Err(err) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err.into());
        }

        match std::fs::File::open(parent).and_then(|dir| dir.sync_all()) {
            Ok(()) => {}
            Err(err) => match err.kind() {
                std::io::ErrorKind::Unsupported | std::io::ErrorKind::InvalidInput => {}
                _ => {
                    tracing::warn!(
                        error = %err,
                        parent = ?parent,
                        "Token rename succeeded but parent directory fsync failed; \
                         a power loss before background fs flush could roll back \
                         the new token. Returning Ok because the in-memory rename \
                         completed.",
                    );
                }
            },
        }
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)?;
    }

    Ok(())
}

fn token_temp_path(parent: &Path, path: &Path) -> anyhow::Result<PathBuf> {
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("token path has no filename component"))?;
    let nonce = uuid::Uuid::new_v4().as_simple().to_string();
    Ok(parent.join(format!(
        ".{}.tmp.{}.{}",
        file_name.to_string_lossy(),
        std::process::id(),
        nonce
    )))
}

pub fn load_token() -> Option<String> {
    load_session().map(|session| session.access_token)
}

pub(crate) fn load_token_from_path(path: &Path) -> Option<String> {
    load_session_from_path(path).map(|session| session.access_token)
}

pub fn load_session() -> Option<SessionTokens> {
    load_session_from_path(&token_path())
}

pub(crate) fn load_session_from_path(path: &Path) -> Option<SessionTokens> {
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
    clear_token_at_path(&token_path())
}

pub(crate) fn clear_session_at_path(path: &Path) -> anyhow::Result<()> {
    clear_token_at_path(path)
}

/// Delete the token file at `path`. Missing files are OK, but every other
/// remove error is propagated. On Unix, a successful unlink also syncs the
/// parent directory unless the filesystem does not support directory fsync.
pub(crate) fn clear_token_at_path(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            #[cfg(unix)]
            {
                if let Some(parent) = path.parent() {
                    match std::fs::File::open(parent).and_then(|dir| dir.sync_all()) {
                        Ok(()) => {}
                        Err(err) => match err.kind() {
                            std::io::ErrorKind::Unsupported | std::io::ErrorKind::InvalidInput => {}
                            _ => {
                                tracing::warn!(
                                    error = %err,
                                    parent = ?parent,
                                    "Token unlink succeeded but parent directory fsync failed; \
                                     treating clear as failed because the unlink may not be \
                                     crash-durable.",
                                );
                                return Err(anyhow::Error::new(err)
                                    .context("parent directory fsync failed after token unlink"));
                            }
                        },
                    }
                }
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Resolve the canonical token path under the user's data directory.
pub(crate) fn token_path() -> std::path::PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("canopy")
        .join("token")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_token_path() -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().expect("create tempdir");
        let path = dir.path().join("canopy").join("token");
        (dir, path)
    }

    #[test]
    fn save_token_roundtrips_as_access_only_session() {
        let (_dir, path) = temp_token_path();

        save_token_to_path(&path, "tok-abc123").expect("save succeeds");

        assert_eq!(load_token_from_path(&path).as_deref(), Some("tok-abc123"));
        assert_eq!(
            load_session_from_path(&path),
            Some(SessionTokens::new("tok-abc123".into(), None))
        );
    }

    #[test]
    fn session_tokens_roundtrip_with_refresh_token() {
        let (_dir, path) = temp_token_path();
        let session = SessionTokens::new("access".into(), Some("refresh".into()));

        save_session_to_path(&path, &session).unwrap();

        assert_eq!(load_session_from_path(&path), Some(session));
    }

    #[test]
    fn session_tokens_serializes_without_refresh_field_when_none() {
        let session = SessionTokens::new("access".into(), None);

        let value = serde_json::to_value(&session).unwrap();

        assert_eq!(value["access_token"], "access");
        assert!(value.get("refresh_token").is_none());
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
        let (_dir, path) = temp_token_path();
        write_token_file(&path, "legacy-access").unwrap();

        assert_eq!(
            load_session_from_path(&path),
            Some(SessionTokens::new("legacy-access".into(), None))
        );
    }

    #[test]
    fn save_session_creates_parent_directory_when_missing() {
        let (_dir, path) = temp_token_path();
        assert!(!path.parent().unwrap().exists());
        let session = SessionTokens::new("access".into(), Some("refresh".into()));

        save_session_to_path(&path, &session).unwrap();

        assert_eq!(load_session_from_path(&path), Some(session));
        assert!(path.parent().unwrap().is_dir());
    }

    #[test]
    fn corrupted_json_session_does_not_fall_back_to_raw_token() {
        let (_dir, path) = temp_token_path();
        write_token_file(&path, "{not-json").unwrap();

        assert_eq!(load_session_from_path(&path), None);
    }

    #[test]
    fn load_session_rejects_empty_whitespace_and_missing_access_json() {
        let (_dir, path) = temp_token_path();

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
    }

    #[test]
    fn load_session_tolerates_trailing_whitespace_and_unknown_fields() {
        let (_dir, path) = temp_token_path();
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
    }

    #[test]
    fn load_session_returns_none_for_non_existent_file() {
        let (_dir, path) = temp_token_path();

        assert_eq!(load_session_from_path(&path), None);
    }

    #[test]
    fn clear_session_at_path_accepts_missing_file() {
        let (_dir, path) = temp_token_path();

        clear_session_at_path(&path).unwrap();
    }

    #[test]
    fn clear_session_at_path_removes_existing_file() {
        let (_dir, path) = temp_token_path();
        write_token_file(&path, "legacy-access").unwrap();

        clear_session_at_path(&path).unwrap();

        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn saving_session_replaces_insecure_existing_file_without_reusing_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let (_dir, path) = temp_token_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "old-token").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let session = SessionTokens::new("access".into(), Some("refresh".into()));
        save_session_to_path(&path, &session).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(load_session_from_path(&path), Some(session));
    }

    #[cfg(unix)]
    #[test]
    fn save_session_does_not_open_existing_loose_file_for_write() {
        use std::os::unix::fs::PermissionsExt;

        let (_dir, path) = temp_token_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "stale-from-loose-file").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let session = SessionTokens::new("fresh-after-rename".into(), None);
        let result = save_session_to_path(&path, &session);

        if path.exists() {
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }

        if std::env::var_os("USER").as_deref() != Some(std::ffi::OsStr::new("root")) {
            result.expect("atomic rename must succeed even if the old file was unreadable");
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            assert_eq!(load_session_from_path(&path), Some(session));
        }
    }

    #[cfg(unix)]
    #[test]
    fn load_session_refuses_group_or_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;

        let (_dir, path) = temp_token_path();
        write_token_file(&path, r#"{"access_token":"tok"}"#).unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o604)).unwrap();
        assert_eq!(load_session_from_path(&path), None);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(load_session_from_path(&path), None);
    }

    #[cfg(unix)]
    #[test]
    fn save_session_leaves_no_temp_file_litter_on_success() {
        let (_dir, path) = temp_token_path();
        save_session_to_path(&path, &SessionTokens::new("tok".into(), None)).unwrap();

        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".token.tmp."))
            .collect();
        assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");
    }

    #[test]
    fn concurrent_saves_leave_one_complete_session_with_no_leftover_tmp_files() {
        use std::sync::Arc;

        let (_dir, path) = temp_token_path();
        let path = Arc::new(path);
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
    }

    #[cfg(unix)]
    #[test]
    fn clear_session_at_path_propagates_permission_denied() {
        use std::os::unix::fs::PermissionsExt;

        let (dir, path) = temp_token_path();
        write_token_file(&path, "legacy-access").unwrap();
        let parent = path.parent().unwrap();
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o000)).unwrap();

        let result = clear_session_at_path(&path);

        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = dir;

        if std::env::var_os("USER").as_deref() != Some(std::ffi::OsStr::new("root")) {
            assert!(
                result.is_err(),
                "unlink without parent write permission must fail"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn save_session_errors_when_parent_directory_cannot_be_created() {
        use std::os::unix::fs::PermissionsExt;

        let (dir, path) = temp_token_path();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();

        let result = save_session_to_path(&path, &SessionTokens::new("tok".into(), None));

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        if result.is_ok() {
            assert!(
                path.exists(),
                "if save succeeded it must have created the file"
            );
        } else {
            assert!(result.is_err(), "save should error when parent unwritable");
        }
    }

    #[test]
    fn load_session_returns_none_for_non_utf8_file_contents() {
        let (_dir, path) = temp_token_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, [0xFF, 0xFE, 0xFD, 0xFC]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        assert_eq!(load_session_from_path(&path), None);
    }
}
