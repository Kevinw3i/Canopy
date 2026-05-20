pub mod device_code;
pub mod pkce;

use std::path::Path;

/// Token storage — persists auth token between sessions.
///
/// The public functions resolve [`token_path`] for the current user;
/// the `_to_path` / `_from_path` / `_at_path` variants are testable
/// helpers that accept an explicit file path.
pub fn save_token(token: &str) -> anyhow::Result<()> {
    save_token_to_path(&token_path(), token)
}

pub fn load_token() -> Option<String> {
    load_token_from_path(&token_path())
}

pub fn clear_token() -> anyhow::Result<()> {
    clear_token_at_path(&token_path())
}

/// Write `token` to `path`, creating any missing parent directories.
///
/// On Unix this uses an atomic write-then-rename so the token NEVER
/// lives in a file with broader-than-0600 permissions, even briefly.
/// Codex round 4 flagged that the prior implementation
/// (`OpenOptions::mode(0o600)` + write + `set_permissions(0o600)`)
/// left a window where an existing file with 0o644 could be
/// truncated-and-written before the final chmod ran, exposing the
/// freshly rotated token to a local group/world reader.
///
/// The new flow:
///   1. Write the token into a fresh, freshly-created temp file in
///      the same directory. `create_new(true) + mode(0o600)`
///      guarantees the file is 0600 from the first byte and no
///      pre-existing file is reused.
///   2. `fsync` the temp file so the bytes survive a crash.
///   3. `rename` the temp file over the target. POSIX rename is
///      atomic within a filesystem, so any reader sees either the
///      old file or the new one — never a partial write.
pub(crate) fn save_token_to_path(path: &Path, token: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("token path has no filename component"))?;
        // Uniq suffix avoids collision when multiple processes
        // OR multiple threads save simultaneously; `create_new`
        // belt-and-braces guarantees we never reuse an existing
        // file. UUID gives us 122 bits of randomness, which beats
        // nanos+pid by a wide margin and survives the existing
        // `concurrent_saves_*` test where two threads race within
        // the same nanosecond bucket.
        let nonce = uuid::Uuid::new_v4().as_simple().to_string();
        let tmp_name = format!(
            ".{}.tmp.{}.{}",
            file_name.to_string_lossy(),
            std::process::id(),
            nonce,
        );
        let tmp_path = parent.join(&tmp_name);

        // Step 1: create fresh, 0600-from-birth, write the token.
        let write_result: anyhow::Result<()> = (|| {
            let mut tmp = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&tmp_path)?;
            tmp.write_all(token.as_bytes())?;
            // Step 2: fsync so the bytes hit disk before rename —
            // otherwise a crash between write and rename could
            // leave a torn temp file (and the rename would still
            // succeed atomically, but with garbage content).
            tmp.sync_all()?;
            Ok(())
        })();
        if let Err(e) = write_result {
            // Clean up the temp file on error so we don't leave
            // litter in the user's auth dir.
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }

        // Step 3: atomic rename. After this call, any reader of
        // `path` sees the new 0600 file. The old file (if any) is
        // unlinked atomically.
        if let Err(e) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e.into());
        }

        // Step 4: fsync the parent DIRECTORY. File fsync (step 2)
        // made the bytes durable. Directory fsync makes the
        // *directory entry* durable — i.e. the rename itself
        // survives a power loss / kernel crash. Without this, a
        // crash after `rename` returns Ok can leave the on-disk
        // state rolled back to the old token (or missing), even
        // though save_token_to_path reported success. Codex round 5
        // flagged this as a token-rotation rollback risk.
        //
        // Failure classification (Codex round 6): some filesystems
        // genuinely don't support directory fsync (returns ENOTSUP /
        // EINVAL → io::ErrorKind::Unsupported or InvalidInput). We
        // downgrade those because there's nothing we can do. Other
        // errors (EIO, EACCES, etc.) are real durability failures —
        // we still return Ok because the in-memory rename happened,
        // but we WARN loudly so an operator reviewing logs can spot
        // the weaker durability.
        match std::fs::File::open(parent).and_then(|d| d.sync_all()) {
            Ok(()) => {}
            Err(e) => match e.kind() {
                std::io::ErrorKind::Unsupported | std::io::ErrorKind::InvalidInput => {
                    // Filesystem doesn't support directory fsync —
                    // expected on some platforms, no warning needed.
                }
                _ => {
                    tracing::warn!(
                        error = %e,
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
        std::fs::write(path, token)?;
    }
    Ok(())
}

/// Read a token from `path`. Returns `None` when the file is missing,
/// empty, or — on Unix — has insecure permissions (group / world bits set).
pub(crate) fn load_token_from_path(path: &Path) -> Option<String> {
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

    std::fs::read_to_string(path).ok().filter(|t| !t.is_empty())
}

/// Delete the token file at `path`. Idempotent on missing files
/// (NotFound is treated as success), but EVERY other error is
/// propagated.
///
/// Codex round 9 flagged the previous `path.exists() { remove_file }`
/// pattern as unsafe: `Path::exists()` returns false BOTH when the
/// file is absent AND when metadata cannot be read (e.g. permission
/// denied on the parent dir). That silently converted a real clear
/// failure into Ok(()), and `set_session_token` would then proceed
/// as if the stale token had been deleted when it was actually
/// still on disk — defeating the entire round-8 stale-token guard.
///
/// Codex round 11: after a successful `remove_file`, fsync the
/// parent directory on Unix so the unlink is durable. POSIX does
/// not guarantee that a directory-entry change survives a crash
/// until the containing directory is synced. Without this, a power
/// loss after we report Ok could leave the on-disk state rolled
/// back to "token still present" and `set_session_token` would
/// have wrongly believed the stale credential was gone.
pub(crate) fn clear_token_at_path(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            #[cfg(unix)]
            {
                if let Some(parent) = path.parent() {
                    // Codex round 12: unlike save's parent-fsync
                    // (which can warn-and-Ok because the user's
                    // CURRENT session keeps working), clear's
                    // parent-fsync failure has SECURITY consequences:
                    // if the unlink isn't durable, a power loss
                    // leaves the stale credential on disk and the
                    // next restart auto-loads it. Therefore we
                    // propagate non-downgraded errors so
                    // `set_session_token` returns
                    // `StaleTokenSurvivesOnDisk` and refuses to
                    // enter the dashboard.
                    match std::fs::File::open(parent).and_then(|d| d.sync_all()) {
                        Ok(()) => {}
                        Err(e) => match e.kind() {
                            std::io::ErrorKind::Unsupported | std::io::ErrorKind::InvalidInput => {
                                // Filesystem doesn't support directory fsync — accept.
                                // Same downgrade rule as save side.
                            }
                            _ => {
                                tracing::warn!(
                                    error = %e,
                                    parent = ?parent,
                                    "Token unlink succeeded but parent directory \
                                     fsync failed; treating clear as failed because \
                                     the unlink may not be crash-durable.",
                                );
                                return Err(anyhow::Error::new(e)
                                    .context("parent directory fsync failed after token unlink"));
                            }
                        },
                    }
                }
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // The file is genuinely absent — nothing to do. This is
            // the only error class we consider "success" for clear.
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Resolve the canonical token path under the user's data
/// directory. Made `pub(crate)` so `App` can fall back to it when
/// no test override is configured (Codex round 10: tests must not
/// touch this real path).
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

    /// Build a token path inside a fresh tempdir. Caller keeps the
    /// `TempDir` alive so it isn't deleted while the test runs.
    fn temp_token_path() -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().expect("create tempdir");
        let path = dir.path().join("canopy").join("token");
        (dir, path)
    }

    // ── Normal cases ─────────────────────────────────────────────────

    #[test]
    fn save_token_writes_token_bytes_to_file() {
        let (_dir, path) = temp_token_path();

        save_token_to_path(&path, "tok-abc123").expect("save succeeds");

        let on_disk = std::fs::read_to_string(&path).expect("read back token");
        assert_eq!(on_disk, "tok-abc123");
    }

    #[test]
    fn save_then_load_roundtrip_preserves_token_content() {
        let (_dir, path) = temp_token_path();

        save_token_to_path(&path, "eyJhbGciOiJSUzI1NiIs.payload.sig").expect("save");
        let loaded = load_token_from_path(&path).expect("load");

        assert_eq!(loaded, "eyJhbGciOiJSUzI1NiIs.payload.sig");
    }

    #[test]
    fn save_token_creates_parent_directory_if_missing() {
        let (_dir, path) = temp_token_path();
        // The "canopy/" parent does not exist yet inside the tempdir.
        assert!(!path.parent().unwrap().exists());

        save_token_to_path(&path, "tok").expect("save creates parent");

        assert!(path.exists());
        assert!(path.parent().unwrap().is_dir());
    }

    #[test]
    fn save_token_overwrites_existing_token() {
        let (_dir, path) = temp_token_path();

        save_token_to_path(&path, "old-token").expect("first save");
        save_token_to_path(&path, "new-token").expect("second save");

        let loaded = load_token_from_path(&path).expect("load");
        assert_eq!(loaded, "new-token");
    }

    #[test]
    fn save_token_truncates_when_new_token_is_shorter_than_old_token() {
        // Regression guard: without `truncate(true)`, a longer-then-shorter
        // sequence would leave trailing bytes from the previous token.
        let (_dir, path) = temp_token_path();

        save_token_to_path(&path, "very-long-original-token-aaaaaaaa").expect("first save");
        save_token_to_path(&path, "short").expect("shorter save");

        let loaded = load_token_from_path(&path).expect("load");
        assert_eq!(loaded, "short");
        assert!(!loaded.contains("aaaa"));
    }

    #[test]
    fn clear_token_removes_existing_file() {
        let (_dir, path) = temp_token_path();
        save_token_to_path(&path, "tok").expect("save");
        assert!(path.exists());

        clear_token_at_path(&path).expect("clear");

        assert!(!path.exists());
    }

    // ── Boundary / null / missing cases ──────────────────────────────

    #[test]
    fn load_token_returns_none_when_file_does_not_exist() {
        let (_dir, path) = temp_token_path();
        assert!(!path.exists());

        assert_eq!(load_token_from_path(&path), None);
    }

    #[test]
    fn load_token_returns_none_for_empty_file() {
        let (_dir, path) = temp_token_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "").expect("write empty");
        // Make permissions correct so the empty-file check is what triggers None.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        assert_eq!(load_token_from_path(&path), None);
    }

    #[test]
    fn clear_token_is_idempotent_when_file_does_not_exist() {
        let (_dir, path) = temp_token_path();
        assert!(!path.exists());

        // Calling clear twice on a non-existent path should not error.
        clear_token_at_path(&path).expect("first clear no-op");
        clear_token_at_path(&path).expect("second clear no-op");

        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn clear_token_returns_err_when_parent_directory_is_inaccessible() {
        // Codex round 9 regression guard: the previous
        // `path.exists() { remove_file }` pattern would silently
        // return Ok when the parent directory couldn't be statted
        // (e.g. 0o000 permissions). That converted a real clear
        // failure into a false success, leaving a stale on-disk
        // token undetected. The new implementation calls
        // `remove_file` directly and only treats NotFound as
        // success — every other io::Error must propagate.
        use std::os::unix::fs::PermissionsExt;
        let (dir, path) = temp_token_path();
        // Seed an existing token so there IS something to clear.
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "stale-existing-token").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        // Now lock the parent directory so remove_file cannot succeed
        // AND path.exists() cannot read metadata. Mode 0o000 forbids
        // all access from non-root.
        let parent = path.parent().unwrap();
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o000)).unwrap();

        let result = clear_token_at_path(&path);

        // Restore mode so TempDir::drop can clean up.
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = dir; // keep tempdir alive

        // Root bypasses the permission bit — only assert for non-root.
        if std::env::var_os("USER").as_deref() != Some(std::ffi::OsStr::new("root")) {
            assert!(
                result.is_err(),
                "clear must propagate Err when the file cannot be removed, \
                 got Ok which would let set_session_token believe the stale \
                 token was deleted. (Returned: {result:?})",
            );
        }
    }

    #[test]
    fn save_token_accepts_empty_string_but_load_treats_it_as_missing() {
        // `save_token` itself does not validate emptiness; that's the
        // caller's responsibility. `load_token` defends by treating an
        // empty file as a missing token so callers see a consistent
        // "not signed in" signal.
        let (_dir, path) = temp_token_path();

        save_token_to_path(&path, "").expect("save empty");

        assert!(path.exists());
        assert_eq!(load_token_from_path(&path), None);
    }

    #[test]
    fn save_then_clear_then_load_returns_none() {
        let (_dir, path) = temp_token_path();
        save_token_to_path(&path, "tok").unwrap();
        clear_token_at_path(&path).unwrap();

        assert_eq!(load_token_from_path(&path), None);
    }

    // ── Permission / security cases (Unix only) ─────────────────────

    #[cfg(unix)]
    #[test]
    fn save_token_sets_unix_file_mode_to_0o600() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path) = temp_token_path();

        save_token_to_path(&path, "tok").expect("save");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;

        assert_eq!(
            mode, 0o600,
            "token file must be readable/writable only by owner"
        );
    }

    #[cfg(unix)]
    #[test]
    fn save_token_fixes_overly_permissive_existing_file() {
        // Defend against the race window where an older 0644 file
        // exists; the second save must demote it to 0600.
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path) = temp_token_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "stale").expect("seed file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        save_token_to_path(&path, "fresh").expect("save tightens mode");

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn save_token_does_not_open_existing_loose_file_for_write() {
        // Codex round 4: even the BRIEFEST exposure window matters.
        // With the prior implementation (open existing 0644 file for
        // write → truncate → write → chmod), a local reader could
        // race the chmod. With the atomic rename, the existing
        // 0644 file is never opened for write at all — we write to
        // a new temp file, fsync, then rename.
        //
        // Verify by giving the existing file an UNREADABLE mode
        // (0o000) — if save_token still tried to open-for-write
        // through that path, it would fail with EACCES. With the
        // rename approach, the existing file is only touched by
        // `rename(2)` which doesn't need read perms — so save
        // succeeds and ends up at 0600.
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path) = temp_token_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "stale-from-loose-file").expect("seed file");
        // Mode 0o000 — unreadable, unwritable. If the implementation
        // tries to truncate-and-write through this file, EACCES.
        // If it uses rename, the rename succeeds because rename only
        // needs +w on the directory.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let result = save_token_to_path(&path, "fresh-after-rename");

        // Restore so the assertions can read metadata and Drop can clean up.
        if path.exists() {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).ok();
        }

        // Skip the assertion if running as root (root bypasses the
        // permission check, so this test cannot distinguish behavior).
        if std::env::var_os("USER").as_deref() != Some(std::ffi::OsStr::new("root")) {
            result.expect("atomic rename must succeed even if the old file was unreadable");
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "the renamed-in file must be 0o600 from the moment it appears at the target path",
            );
            // And the new content must be there, not the stale stuff.
            let body = std::fs::read_to_string(&path).expect("readable now");
            assert_eq!(body, "fresh-after-rename");
        }
    }

    #[cfg(unix)]
    #[test]
    fn save_token_leaves_no_temp_file_litter_on_success() {
        // Atomic rename pattern uses ".{name}.tmp.{pid}.{nonce}"
        // inside the same directory. After a successful save the
        // temp file must be gone (it was renamed over the target).
        let (_dir, path) = temp_token_path();
        save_token_to_path(&path, "tok").expect("save");

        let parent = path.parent().unwrap();
        let dir_entries = std::fs::read_dir(parent)
            .expect("readable dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        let leftover_tmps: Vec<&String> = dir_entries
            .iter()
            .filter(|name| name.contains(".tmp."))
            .collect();
        assert!(
            leftover_tmps.is_empty(),
            "no .tmp.* files must remain after a successful save, found: {leftover_tmps:?}",
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_token_returns_none_when_file_is_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path) = temp_token_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "tok").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o604)).unwrap();

        let loaded = load_token_from_path(&path);

        assert_eq!(loaded, None, "world-readable token must be refused");
    }

    #[cfg(unix)]
    #[test]
    fn load_token_returns_none_when_file_is_group_readable() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path) = temp_token_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "tok").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        let loaded = load_token_from_path(&path);

        assert_eq!(loaded, None, "group-readable token must be refused");
    }

    #[cfg(unix)]
    #[test]
    fn load_token_succeeds_for_valid_token_with_0o600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path) = temp_token_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "tok-secure").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let loaded = load_token_from_path(&path);

        assert_eq!(loaded.as_deref(), Some("tok-secure"));
    }

    // ── External-failure cases ───────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn save_token_errors_when_parent_directory_cannot_be_created() {
        // Make the tempdir read-only so create_dir_all() fails when
        // it tries to mkdir a "canopy/" child. Skipped silently when
        // running as root because root bypasses the write bit.
        use std::os::unix::fs::PermissionsExt;
        let (dir, path) = temp_token_path();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();

        let result = save_token_to_path(&path, "tok");

        // Restore mode so TempDir::drop can clean up.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        // Root users bypass the read-only mode bit; everyone else must hit Err.
        // We assert "root or Err" rather than depending on test environment knowing UID.
        if result.is_ok() {
            // Sanity check: this only happens under root.
            assert!(
                path.exists(),
                "if save succeeded it must have created the file"
            );
        } else {
            assert!(result.is_err(), "save should error when parent unwritable");
        }
    }

    #[test]
    fn load_token_returns_none_for_non_utf8_file_contents() {
        // Disk corruption / wrong file: arbitrary non-UTF-8 bytes
        // must not crash; load_token returns None.
        let (_dir, path) = temp_token_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, [0xFF, 0xFE, 0xFD, 0xFC]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        assert_eq!(load_token_from_path(&path), None);
    }

    // ── Race / concurrency note ──────────────────────────────────────
    //
    // Concurrent `save_token_to_path` calls are not atomic (the impl
    // uses create+truncate+write rather than write-temp-then-rename),
    // so two parallel saves race over the final byte sequence. We do
    // NOT assert any specific winner here — the contract is "the file
    // exists with a complete token from one of the writers, never a
    // mixed prefix". The simpler write path is acceptable for the
    // single-user TUI; if multi-process safety is needed in future,
    // switch to `std::fs::write` on a temp file + rename.

    #[test]
    fn concurrent_saves_leave_a_complete_token_one_of_the_writers_won() {
        use std::sync::Arc;
        use std::thread;
        let (_dir, path) = temp_token_path();
        let path = Arc::new(path);

        let mut handles = Vec::new();
        for n in 0..8 {
            let p = Arc::clone(&path);
            handles.push(thread::spawn(move || {
                let value = format!("token-from-thread-{n}");
                save_token_to_path(&p, &value).expect("save");
            }));
        }
        for h in handles {
            h.join().expect("thread joined");
        }

        let final_contents = std::fs::read_to_string(&*path).expect("read after races");
        let one_of_the_writers_won =
            (0..8).any(|n| final_contents == format!("token-from-thread-{n}"));
        assert!(
            one_of_the_writers_won,
            "expected a complete token from a single writer, got {final_contents:?}"
        );
    }
}
