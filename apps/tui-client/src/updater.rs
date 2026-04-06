use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const TAG_PREFIX: &str = "tui-v";
const CHECK_INTERVAL_SECS: i64 = 600; // 10 minutes

// ---------------------------------------------------------------------------
// Persistent state
// ---------------------------------------------------------------------------

/// Stored at `~/.config/canopy/update_state_{hash}.toml` to throttle API checks.
/// The file is namespaced by repo owner/name so multiple configurations
/// (e.g. upstream + fork) do not interfere with each other.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateState {
    pub last_check: Option<String>,
    /// Version that was downloaded and is pending a restart to activate.
    pub pending_version: Option<String>,
    /// Version that is available but could not be auto-applied (e.g. non-writable
    /// install). Persisted so the manual-update banner survives throttled restarts.
    pub available_version: Option<String>,
    /// Version we last attempted to apply. Prevents re-downloading the same
    /// release when `CARGO_PKG_VERSION` was not bumped to match the tag.
    pub last_attempted_version: Option<String>,
}

impl UpdateState {
    pub fn load(repo_owner: &str, repo_name: &str) -> Self {
        let path = Self::state_path(repo_owner, repo_name);
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, repo_owner: &str, repo_name: &str) -> Result<()> {
        let path = Self::state_path(repo_owner, repo_name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, toml::to_string_pretty(self)?)?;
        Ok(())
    }

    fn state_path(repo_owner: &str, repo_name: &str) -> PathBuf {
        // Namespace by repo to avoid cross-contamination between upstream/forks
        let key = format!("{}/{}", repo_owner, repo_name);
        let hash = simple_hash(&key);
        config_dir()
            .join("canopy")
            .join(format!("update_state_{}.toml", hash))
    }

    /// Returns `true` when at least `CHECK_INTERVAL_SECS` have elapsed.
    pub fn should_check(&self) -> bool {
        let Some(ref last) = self.last_check else {
            return true;
        };
        chrono::DateTime::parse_from_rfc3339(last)
            .map(|dt| {
                let elapsed = chrono::Utc::now().signed_duration_since(dt);
                elapsed.num_seconds() >= CHECK_INTERVAL_SECS
            })
            .unwrap_or(true)
    }

    pub fn record_check(&mut self) {
        self.last_check = Some(chrono::Utc::now().to_rfc3339());
    }
}

fn config_dir() -> PathBuf {
    #[cfg(test)]
    {
        if let Some(path) = TEST_CONFIG_DIR.with(|slot| slot.borrow().clone()) {
            return path;
        }
    }

    dirs::config_dir().unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
thread_local! {
    static TEST_CONFIG_DIR: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

/// Stable 8-char hex hash for namespacing state files.
fn simple_hash(s: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325; // FNV-1a offset basis
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3); // FNV prime
    }
    format!("{:016x}", h)
}

// ---------------------------------------------------------------------------
// Update result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct UpdateResult {
    pub new_version: String,
    pub updated: bool,
    pub message: String,
}

// ---------------------------------------------------------------------------
// GitHub API types (minimal)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    #[serde(default)]
    prerelease: bool,
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

// ---------------------------------------------------------------------------
// Platform detection
// ---------------------------------------------------------------------------

/// Maps the current platform to the CI matrix suffix in `release-tui.yml`.
fn platform_asset_suffix() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Some("darwin-arm64"),
        ("macos", "x86_64") => Some("darwin-amd64"),
        ("linux", "x86_64") => Some("linux-amd64"),
        ("linux", "aarch64") => Some("linux-arm64"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

/// Background update check + apply.
///
/// `repo_owner` and `repo_name` come from `ClientConfig` so forks can
/// point at their own GitHub repo.
pub async fn check_and_apply(repo_owner: &str, repo_name: &str) -> Result<Option<UpdateResult>> {
    let current_version = semver::Version::parse(env!("CARGO_PKG_VERSION"))?;
    let mut state = UpdateState::load(repo_owner, repo_name);

    // Throttle: skip network call if checked recently
    if !state.should_check() {
        // Re-surface banner if a previous download is pending restart
        if let Some(ref pending) = state.pending_version {
            // If we already attempted this version and CARGO_PKG_VERSION still
            // hasn't caught up, the user already restarted — stop prompting.
            if state.last_attempted_version.as_deref() == Some(pending.as_str())
                && semver::Version::parse(pending)
                    .map(|v| v > current_version)
                    .unwrap_or(false)
            {
                state.pending_version = None;
                state.save(repo_owner, repo_name).ok();
            } else if semver::Version::parse(pending)
                .map(|v| v > current_version)
                .unwrap_or(false)
            {
                return Ok(Some(UpdateResult {
                    new_version: pending.clone(),
                    updated: false,
                    message: format!("v{} 已就緒，重啟即可套用", pending),
                }));
            } else {
                // Running version caught up — clear stale pending
                state.pending_version = None;
                state.save(repo_owner, repo_name).ok();
            }
        }
        // Re-surface manual-update notice for non-writable installs
        if let Some(ref available) = state.available_version {
            if semver::Version::parse(available)
                .map(|v| v > current_version)
                .unwrap_or(false)
            {
                return Ok(Some(UpdateResult {
                    new_version: available.clone(),
                    updated: false,
                    message: format!("v{} 可用，請手動下載更新", available),
                }));
            }
            state.available_version = None;
            state.save(repo_owner, repo_name).ok();
        }
        return Ok(None);
    }

    // Run the actual check, always recording last_check afterwards
    let result = do_check_and_apply(&current_version, &mut state, repo_owner, repo_name).await;

    // Always persist last_check regardless of success/failure so we
    // respect the throttle interval even when the check fails.
    state.record_check();
    state.save(repo_owner, repo_name).ok();

    result
}

/// Inner implementation separated so the caller can always persist state.
async fn do_check_and_apply(
    current_version: &semver::Version,
    state: &mut UpdateState,
    repo_owner: &str,
    repo_name: &str,
) -> Result<Option<UpdateResult>> {
    // Fetch releases from GitHub (per_page=100 to handle repos with many prereleases)
    let client = reqwest::Client::builder()
        .user_agent("canopy-tui-updater")
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let releases: Vec<GitHubRelease> = client
        .get(format!(
            "https://api.github.com/repos/{}/{}/releases",
            repo_owner, repo_name
        ))
        .query(&[("per_page", "100")])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    // Find the latest stable tui-v* release.
    // Skip prereleases by checking both the GitHub prerelease flag AND the
    // semver pre-release suffix (alpha/beta/rc).
    let latest = releases
        .iter()
        .filter(|r| !r.prerelease)
        .filter_map(|r| {
            r.tag_name
                .strip_prefix(TAG_PREFIX)
                .and_then(|v| semver::Version::parse(v).ok())
                .filter(|v| v.pre.is_empty())
                .map(|v| (v, r))
        })
        .max_by(|(a, _), (b, _)| a.cmp(b));

    let Some((latest_version, release)) = latest else {
        return Ok(None);
    };

    if latest_version <= *current_version {
        state.pending_version = None;
        state.available_version = None;
        state.last_attempted_version = None;
        return Ok(None);
    }

    let version_str = latest_version.to_string();

    // Guard against re-download loops: if we already attempted this exact
    // version and the running binary still reports an older CARGO_PKG_VERSION
    // (e.g. the tag was cut without bumping Cargo.toml), don't download again.
    if state.last_attempted_version.as_deref() == Some(version_str.as_str()) {
        tracing::debug!("Already attempted v{}, skipping re-download", version_str);

        // If pending_version is set, the binary was replaced but CARGO_PKG_VERSION
        // wasn't bumped. Since we're running now, the user already restarted —
        // clear the pending state to stop the endless "restart to apply" prompt.
        if state.pending_version.is_some() {
            state.pending_version = None;
        }

        // Re-surface manual-update notice for non-writable installs
        if state.available_version.is_some() {
            return Ok(Some(UpdateResult {
                new_version: version_str.clone(),
                updated: false,
                message: format!("v{} 可用，請手動下載更新", version_str),
            }));
        }
        return Ok(None);
    }

    // Find platform-appropriate asset
    let Some(suffix) = platform_asset_suffix() else {
        tracing::warn!("No update asset available for this platform");
        return Ok(None);
    };

    let asset_name = format!("canopy-{}.tar.gz", suffix);
    let Some(asset) = release.assets.iter().find(|a| a.name == asset_name) else {
        tracing::warn!("Release {} missing asset {}", release.tag_name, asset_name);
        return Ok(None);
    };

    // Probe whether we can actually write to the binary's directory
    let current_exe = std::env::current_exe()?;
    let probe = current_exe.with_extension(format!("probe_{}", std::process::id()));
    let can_replace = std::fs::File::create(&probe)
        .map(|_| {
            std::fs::remove_file(&probe).ok();
            true
        })
        .unwrap_or(false);

    if !can_replace {
        tracing::info!(
            "Cannot write next to {}, skipping download",
            current_exe.display()
        );
        // Persist so the notice survives throttled restarts
        state.available_version = Some(version_str.clone());
        return Ok(Some(UpdateResult {
            new_version: version_str.clone(),
            updated: false,
            message: format!("v{} 可用，請手動下載更新", version_str),
        }));
    }

    // Download tarball
    tracing::info!("Downloading update: {}", asset.browser_download_url);
    let bytes = client
        .get(&asset.browser_download_url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    // Verify SHA256 checksum if the .sha256 asset is available
    let sha_asset_name = format!("{}.sha256", asset_name);
    if let Some(sha_asset) = release.assets.iter().find(|a| a.name == sha_asset_name) {
        let sha_text = client
            .get(&sha_asset.browser_download_url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        // Format: "<hex>  <filename>" or "<hex> <filename>"
        let expected_hex = sha_text.split_whitespace().next().unwrap_or("");
        let actual_hex = {
            use sha2::Digest;
            let hash = sha2::Sha256::digest(&bytes);
            format!("{:x}", hash)
        };
        if !expected_hex.eq_ignore_ascii_case(&actual_hex) {
            anyhow::bail!(
                "SHA256 mismatch for {}: expected {}, got {}",
                asset_name,
                expected_hex,
                actual_hex
            );
        }
        tracing::debug!("SHA256 verified for {}", asset_name);
    } else {
        anyhow::bail!(
            "Release {} missing .sha256 checksum asset, refusing to apply unverified update",
            asset_name
        );
    }

    // Extract the `canopy` binary from the tarball.
    // Stage next to the target binary (same filesystem) to ensure rename works.
    let sibling_tmp = current_exe.with_extension(format!("update_tmp_{}", std::process::id()));
    let fallback_tmp_dir =
        std::env::temp_dir().join(format!("canopy-update-{}", std::process::id()));

    let tmp_bin = if std::fs::File::create(&sibling_tmp).is_ok() {
        std::fs::remove_file(&sibling_tmp).ok();
        sibling_tmp
    } else {
        std::fs::create_dir_all(&fallback_tmp_dir)?;
        fallback_tmp_dir.join("canopy")
    };

    let gz = flate2::read::GzDecoder::new(&bytes[..]);
    let mut archive = tar::Archive::new(gz);

    let mut found = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        if path.file_name().and_then(|n| n.to_str()) == Some("canopy") {
            let mut out = std::fs::File::create(&tmp_bin)?;
            std::io::copy(&mut entry, &mut out)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&tmp_bin, std::fs::Permissions::from_mode(0o755))?;
            }

            found = true;
            break;
        }
    }

    if !found {
        cleanup_tmp(&tmp_bin, &fallback_tmp_dir);
        anyhow::bail!("Binary 'canopy' not found in tarball {}", asset_name);
    }

    // Try to replace the current binary
    match replace_binary(&tmp_bin, &current_exe) {
        Ok(()) => {
            cleanup_tmp(&tmp_bin, &fallback_tmp_dir);

            state.pending_version = Some(version_str.clone());
            state.available_version = None;
            state.last_attempted_version = Some(version_str.clone());
            tracing::info!("Updated to v{}", version_str);

            Ok(Some(UpdateResult {
                new_version: version_str.clone(),
                updated: true,
                message: format!("已更新至 v{}，重啟即可套用", version_str),
            }))
        }
        Err(e) => {
            tracing::warn!("Cannot replace binary at {}: {}", current_exe.display(), e);
            cleanup_tmp(&tmp_bin, &fallback_tmp_dir);

            // Do NOT set last_attempted_version on failure — a transient error
            // (e.g. file lock) should be retried on the next check.
            state.available_version = Some(version_str.clone());

            Ok(Some(UpdateResult {
                new_version: version_str.clone(),
                updated: false,
                message: format!("v{} 可用，請手動下載更新", version_str),
            }))
        }
    }
}

/// Try atomic rename first; fall back to copy if cross-device (EXDEV = 18).
fn replace_binary(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    match std::fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(18) => {
            // EXDEV (cross-device link): copy contents then remove source
            std::fs::copy(src, dst)?;
            std::fs::remove_file(src).ok();
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Best-effort cleanup of temp files.
fn cleanup_tmp(tmp_bin: &std::path::Path, fallback_dir: &std::path::Path) {
    std::fs::remove_file(tmp_bin).ok();
    std::fs::remove_dir_all(fallback_dir).ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestConfigDirGuard {
        previous: Option<PathBuf>,
    }

    impl TestConfigDirGuard {
        fn set(path: PathBuf) -> Self {
            let previous = TEST_CONFIG_DIR.with(|slot| slot.replace(Some(path)));
            Self { previous }
        }
    }

    impl Drop for TestConfigDirGuard {
        fn drop(&mut self) {
            TEST_CONFIG_DIR.with(|slot| {
                slot.replace(self.previous.take());
            });
        }
    }

    // ── should_check throttle ───────────────────────────

    #[test]
    fn test_should_check_no_previous() {
        let state = UpdateState::default();
        assert!(state.should_check());
    }

    #[test]
    fn test_should_check_recent_is_throttled() {
        let state = UpdateState {
            last_check: Some(chrono::Utc::now().to_rfc3339()),
            ..Default::default()
        };
        assert!(!state.should_check());
    }

    #[test]
    fn test_should_check_old_timestamp_allows() {
        let old = chrono::Utc::now() - chrono::Duration::seconds(CHECK_INTERVAL_SECS + 1);
        let state = UpdateState {
            last_check: Some(old.to_rfc3339()),
            ..Default::default()
        };
        assert!(state.should_check());
    }

    #[test]
    fn test_should_check_malformed_timestamp_allows() {
        let state = UpdateState {
            last_check: Some("not-a-date".into()),
            ..Default::default()
        };
        assert!(state.should_check());
    }

    // ── record_check ────────────────────────────────────

    #[test]
    fn test_record_check_sets_timestamp() {
        let mut state = UpdateState::default();
        assert!(state.last_check.is_none());
        state.record_check();
        assert!(state.last_check.is_some());
        // Freshly recorded → should NOT check again
        assert!(!state.should_check());
    }

    // ── simple_hash ─────────────────────────────────────

    #[test]
    fn test_simple_hash_deterministic() {
        let a = simple_hash("Kevinw3i/Canopy");
        let b = simple_hash("Kevinw3i/Canopy");
        assert_eq!(a, b);
        assert_eq!(a.len(), 16); // 8 bytes as hex
    }

    #[test]
    fn test_simple_hash_differs_for_different_input() {
        assert_ne!(simple_hash("a/b"), simple_hash("c/d"));
    }

    // ── platform_asset_suffix ───────────────────────────

    #[test]
    fn test_platform_asset_suffix_returns_some() {
        // We're running tests on a known platform, so this should succeed
        let suffix = platform_asset_suffix();
        assert!(suffix.is_some());
        let s = suffix.unwrap();
        assert!(
            s == "darwin-arm64" || s == "darwin-amd64" || s == "linux-amd64" || s == "linux-arm64"
        );
    }

    // ── state persistence ───────────────────────────────

    #[test]
    fn test_state_save_and_load() {
        let tmp = std::env::temp_dir().join(format!("canopy-state-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let _guard = TestConfigDirGuard::set(tmp.clone());

        let owner = "test-owner";
        let repo = &format!("test-repo-{}", std::process::id());

        let path = UpdateState::state_path(owner, repo);
        assert!(path.starts_with(tmp.join("canopy")));

        let mut state = UpdateState {
            pending_version: Some("1.2.3".into()),
            ..Default::default()
        };
        state.record_check();
        state.save(owner, repo).unwrap();

        let loaded = UpdateState::load(owner, repo);
        assert_eq!(loaded.pending_version.as_deref(), Some("1.2.3"));
        assert!(loaded.last_check.is_some());

        // Cleanup
        std::fs::remove_dir_all(&tmp).ok();
    }

    // ── replace_binary ──────────────────────────────────

    #[test]
    fn test_replace_binary_same_device() {
        let dir = std::env::temp_dir().join(format!("canopy-replace-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let src = dir.join("src_bin");
        let dst = dir.join("dst_bin");
        std::fs::write(&src, b"new-content").unwrap();
        std::fs::write(&dst, b"old-content").unwrap();

        replace_binary(&src, &dst).unwrap();
        assert_eq!(std::fs::read_to_string(&dst).unwrap(), "new-content");

        std::fs::remove_dir_all(&dir).ok();
    }
}
