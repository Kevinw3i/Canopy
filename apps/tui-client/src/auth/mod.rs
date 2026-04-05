pub mod device_code;
pub mod pkce;

/// Token storage — persists auth token between sessions
pub fn save_token(token: &str) -> anyhow::Result<()> {
    let path = token_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Create file with restricted permissions from the start to avoid a
    // race window where the token is world-readable.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(token.as_bytes())?;

        // Force permissions to 0600 even if the file already existed with
        // broader permissions from a previous build or manual edit.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, token)?;
    }
    Ok(())
}

pub fn load_token() -> Option<String> {
    let path = token_path();

    // Reject tokens from files with insecure permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(&path) {
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

    std::fs::read_to_string(path).ok().filter(|t| !t.is_empty())
}

pub fn clear_token() -> anyhow::Result<()> {
    let path = token_path();
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn token_path() -> std::path::PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("canopy")
        .join("token")
}
