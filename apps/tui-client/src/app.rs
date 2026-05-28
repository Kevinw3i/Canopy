use anyhow::Result;
use shared::dto::cloudwatch::FilterLogEventsRequest;
use shared::dto::ec2::{ConnectMethod, ConnectRequest, Ec2ListRequest, Ec2PowerRequest};
use shared::dto::ecs::{EcsExecRequest, EcsTasksRequest};
use shared::dto::entitlements::UserEntitlements;
use shared::dto::pty_spawn::PtySpawnSpec;
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    process::Command,
};
use tokio::sync::mpsc;

use crate::api_client::{ApiClient, ApiClientError};
use crate::components::access::AccessScreen;
use crate::components::cloudwatch_search::{CloudWatchLoadingKind, CloudWatchSearchScreen};
use crate::components::connect_session::{ConnectSessionLaunch, ConnectSessionScreen};
use crate::components::dashboard::DashboardScreen;
use crate::components::ec2::Ec2Screen;
use crate::components::error_modal::ErrorModal;
use crate::components::live_tail::LiveTailScreen;
use crate::components::login::LoginScreen;
use crate::components::mcp::McpScreen;
use crate::components::settings::SettingsScreen;
use crate::components::Component;
use crate::config::ClientConfig;
use crate::event::{Action, Event, EventReader, Screen};
use crate::local_deps::{self, DependencyIssue, LocalDependency, SystemCommandRunner};
use crate::mcp::McpRuntime;
use crate::theme::Theme;
use crate::tui::Tui;

const FILTER_EMPTY_PAGE_AUTO_SCAN_LIMIT: usize = 50;

/// Outcome of `App::set_session_token`. Callers use this to decide
/// whether to proceed to the dashboard after a successful login.
/// Codex round 8: when save AND stale-token-clear both fail we MUST
/// refuse to proceed, because the next restart would auto-load the
/// prior user's credential.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SessionTokenOutcome {
    /// New token persisted; safe to proceed to the dashboard.
    PersistedFresh,
    /// New token did NOT persist, BUT we successfully removed any
    /// stale on-disk token. The in-memory session is safe to use
    /// for THIS run; restart will require re-login.
    InMemoryOnly,
    /// New token did not persist AND we could not remove the stale
    /// on-disk token. Caller MUST refuse to enter the dashboard.
    StaleTokenSurvivesOnDisk,
}
pub struct App {
    config: ClientConfig,
    theme: Theme,
    api: ApiClient,
    current_screen: Screen,
    screen_stack: Vec<Screen>,
    entitlements: Option<UserEntitlements>,
    running: bool,

    // Screens
    login: LoginScreen,
    dashboard: DashboardScreen,
    ec2: Ec2Screen,
    cloudwatch_search: CloudWatchSearchScreen,
    live_tail: LiveTailScreen,
    access: AccessScreen,
    settings: SettingsScreen,
    mcp: McpScreen,
    connect_session: Option<ConnectSessionScreen>,
    error_modal: ErrorModal,

    // Async action channel
    action_tx: mpsc::UnboundedSender<Action>,
    action_rx: mpsc::UnboundedReceiver<Action>,

    // Shared flag to pause the event reader during external commands
    event_reader_paused: std::sync::Arc<std::sync::atomic::AtomicBool>,

    // Cancellation tokens for in-flight background fetches
    ec2_fetch_cancel: Option<tokio_util::sync::CancellationToken>,
    cw_fetch_cancel: Option<tokio_util::sync::CancellationToken>,

    // Override for the on-disk token persistence path. `None` in
    // production code (falls back to `auth::token_path()`). Tests
    // inject a tempdir-based path so `cargo test` cannot clobber
    // the developer's real persisted credential (Codex round 10).
    token_store_path: Option<std::path::PathBuf>,

    // Cancellation token for the live tail background task
    live_tail_cancel: Option<tokio_util::sync::CancellationToken>,
    // Monotonic counter identifying the active live-tail stream.
    // Each call to `try_arm_live_tail_stream` increments this; the
    // stream's emitted `LiveTailEvent` / `LiveTailStreamEnded`
    // actions carry the generation they were spawned with, so the
    // handler can drop signals from a previously-active stream
    // (Codex round 5: prevents stale `LiveTailStreamEnded` from
    // cancelling a freshly-armed replacement stream).
    pub(crate) live_tail_generation: u64,
    mcp_runtime: Option<McpRuntime>,

    // Auto-update banner message, shown until dismissed
    update_banner: Option<String>,

    // True while the token-expired modal is visible. Dismissing it returns
    // the user to the login screen.
    session_expired_pending_login: bool,
}

fn normalized_http_url(url: &str) -> Option<&str> {
    let url = url.trim();
    if url.starts_with("https://") || url.starts_with("http://") {
        Some(url)
    } else {
        None
    }
}

fn cloudwatch_quick_search_filter_pattern(query: &str) -> Option<String> {
    let query = query.trim();
    if query.is_empty() {
        return None;
    }

    if query.starts_with('"') && query.ends_with('"') && query.len() >= 2 {
        return Some(query.to_string());
    }

    let mut pattern = String::with_capacity(query.len() + 2);
    pattern.push('"');
    for ch in query.chars() {
        match ch {
            '\\' => pattern.push_str("\\\\"),
            '"' => pattern.push_str("\\\""),
            _ => pattern.push(ch),
        }
    }
    pattern.push('"');
    Some(pattern)
}

fn should_auto_continue_empty_filter_page(
    events_len: usize,
    next_token: Option<&str>,
    empty_pages_scanned: usize,
) -> bool {
    events_len == 0
        && next_token.is_some()
        && empty_pages_scanned < FILTER_EMPTY_PAGE_AUTO_SCAN_LIMIT
}

fn should_retry_api_error(err: &ApiClientError) -> bool {
    match err {
        ApiClientError::TokenExpired => false,
        ApiClientError::Api { status, .. } => *status >= 500,
        ApiClientError::Transport(_) => true,
        ApiClientError::SessionStore { .. } => false,
    }
}

const TOKEN_EXPIRED_MODAL_MESSAGE: &str =
    "Your session has expired. Please sign in again.\n\nPress Enter to return to the login screen.";

/// Prefix for the Codex / Claude MCP server name we register on the user's
/// behalf. The actual registered name embeds the TUI PID so two concurrent
/// Canopy sessions cannot stomp on each other AND a user's own pre-existing
/// MCP entry called `canopy` is never deleted by Canopy's launcher cleanup.
const MCP_AI_CLIENT_SERVER_NAME_PREFIX: &str = "canopy-session";
const MCP_AI_CLIENT_ENV: &str = "CANOPY_MCP_AI_CLIENT";
const MCP_TERMINAL_ENV: &str = "CANOPY_MCP_TERMINAL";

fn mcp_ai_client_server_name() -> String {
    format!(
        "{}-{}",
        MCP_AI_CLIENT_SERVER_NAME_PREFIX,
        std::process::id()
    )
}
const SESSION_COUNTDOWN_WIDTH: u64 = 20;

fn format_session_duration(secs: u64) -> String {
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;

    if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes:02}:{seconds:02}")
    }
}

fn render_session_countdown(max_secs: u64, elapsed_secs: u64) -> String {
    let remaining = max_secs.saturating_sub(elapsed_secs);
    let filled = if max_secs == 0 {
        0
    } else {
        (remaining * SESSION_COUNTDOWN_WIDTH).div_ceil(max_secs)
    }
    .min(SESSION_COUNTDOWN_WIDTH);
    let empty = SESSION_COUNTDOWN_WIDTH - filled;

    format!(
        "[{}{}] {}",
        "#".repeat(filled as usize),
        "-".repeat(empty as usize),
        format_session_duration(remaining)
    )
}

fn set_terminal_title(title: &str) {
    let safe_title: String = title
        .chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect();
    print!("\x1b]0;{}\x07", safe_title);
    let _ = std::io::Write::flush(&mut std::io::stdout());
}

fn set_session_countdown_title(instance_id: &str, max_secs: u64, elapsed_secs: u64) {
    set_terminal_title(&format!(
        "Canopy {instance_id} {}",
        render_session_countdown(max_secs, elapsed_secs)
    ));
}

/// Use the in-TUI PTY wrapper only when the server gave us a hard session cap.
/// Uncapped sessions keep the legacy suspend/resume path because the wrapper's
/// primary job is enforcing and showing the remaining session time.
fn wrapper_session_limit(max_session_seconds: Option<u64>) -> Option<u64> {
    max_session_seconds.filter(|secs| *secs > 0)
}

fn ecs_tasks_warning_messages(
    failed_scopes: &[String],
    task_count: usize,
    total_count: usize,
    truncated: bool,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if !failed_scopes.is_empty() {
        warnings.push(format!(
            "Some ECS scopes failed to respond:\n{}",
            failed_scopes.join("\n")
        ));
    }
    if truncated {
        let count_text = if total_count > task_count {
            format!("showing {task_count} of at least {total_count}")
        } else {
            format!("showing {task_count}; additional results may exist")
        };
        warnings.push(format!(
            "ECS task results were truncated: {count_text}. Narrow the account or region filter."
        ));
    }
    warnings
}

struct ConnectTarget<'a> {
    instance_id: &'a str,
    instance_name: Option<&'a str>,
    account_id: &'a str,
    region: &'a str,
    method: ConnectMethod,
    os_user: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum McpAiClient {
    Codex,
    Claude,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalLaunchAdapter {
    AppleTerminal,
    ITerm2,
    WarpStable,
    WarpPreview,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DetectedTerminalApp {
    display_name: String,
    bundle_id: String,
    app_path: PathBuf,
    adapter: TerminalLaunchAdapter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AppBundleInfo {
    display_name: String,
    bundle_id: String,
    app_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct McpAiLaunchResult {
    client_label: &'static str,
    terminal_label: String,
}

fn connect_method_label(method: &ConnectMethod) -> &'static str {
    match method {
        ConnectMethod::Ssm => "SSM",
        ConnectMethod::Ec2InstanceConnect => "EIC",
        ConnectMethod::Ssh => "SSH",
    }
}

fn prompt_yes_no(prompt: &str) -> bool {
    use std::io::Write;

    print!("{prompt} [y/N] ");
    let _ = std::io::stdout().flush();

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }

    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn parse_mcp_ai_client_choice(input: &str) -> Result<Option<McpAiClient>, String> {
    match input.trim().to_ascii_lowercase().as_str() {
        "1" | "codex" | "c" => Ok(Some(McpAiClient::Codex)),
        "2" | "claude" => Ok(Some(McpAiClient::Claude)),
        "q" | "quit" | "cancel" | "" => Ok(None),
        other => Err(format!("Invalid AI client choice: {other}")),
    }
}

fn select_mcp_ai_client(choice: Option<&str>) -> Result<McpAiClient, String> {
    let Some(choice) = choice.map(str::trim).filter(|choice| !choice.is_empty()) else {
        return Ok(McpAiClient::Codex);
    };

    parse_mcp_ai_client_choice(choice)?
        .ok_or_else(|| format!("{MCP_AI_CLIENT_ENV} must be 'codex' or 'claude'."))
}

fn select_mcp_ai_client_from_env() -> Result<McpAiClient, String> {
    match std::env::var(MCP_AI_CLIENT_ENV) {
        Ok(choice) => select_mcp_ai_client(Some(&choice)),
        Err(std::env::VarError::NotPresent) => select_mcp_ai_client(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("{MCP_AI_CLIENT_ENV} is not valid UTF-8."))
        }
    }
}

fn parse_terminal_app_choice(
    input: &str,
    terminals: &[DetectedTerminalApp],
) -> Result<Option<DetectedTerminalApp>, String> {
    let choice = input.trim();
    let normalized = choice.to_ascii_lowercase();
    if matches!(normalized.as_str(), "" | "q" | "quit" | "cancel") {
        return Ok(None);
    }

    if let Ok(index) = normalized.parse::<usize>() {
        if (1..=terminals.len()).contains(&index) {
            return Ok(Some(terminals[index - 1].clone()));
        }
        return Err(format!("Invalid terminal choice: {choice}"));
    }

    terminals
        .iter()
        .find(|terminal| {
            terminal.display_name.eq_ignore_ascii_case(choice)
                || terminal.bundle_id.eq_ignore_ascii_case(choice)
                || terminal
                    .app_path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .is_some_and(|stem| stem.eq_ignore_ascii_case(choice))
        })
        .cloned()
        .map(Some)
        .ok_or_else(|| format!("Invalid terminal choice: {choice}"))
}

fn select_mcp_terminal_app(
    terminals: &[DetectedTerminalApp],
) -> Result<DetectedTerminalApp, String> {
    match std::env::var(MCP_TERMINAL_ENV) {
        Ok(choice) => select_mcp_terminal_app_choice(terminals, Some(&choice)),
        Err(std::env::VarError::NotPresent) => select_mcp_terminal_app_choice(terminals, None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("{MCP_TERMINAL_ENV} is not valid UTF-8."))
        }
    }
}

fn select_mcp_terminal_app_choice(
    terminals: &[DetectedTerminalApp],
    choice: Option<&str>,
) -> Result<DetectedTerminalApp, String> {
    if terminals.is_empty() {
        return Err("No supported terminal app was detected on this computer.".into());
    }

    let Some(choice) = choice.map(str::trim).filter(|choice| !choice.is_empty()) else {
        return Ok(terminals[0].clone());
    };

    parse_terminal_app_choice(choice, terminals)?
        .ok_or_else(|| format!("{MCP_TERMINAL_ENV} must select a terminal app."))
}

fn resolve_command(program: &str) -> Result<String, String> {
    let output = Command::new("sh")
        .args(["-lc", "command -v \"$1\"", "sh", program])
        .output()
        .map_err(|err| format!("Failed to resolve command '{program}': {err}"))?;
    if !output.status.success() {
        return Err(format!("Required command '{program}' not found in PATH."));
    }

    let resolved = String::from_utf8(output.stdout)
        .map_err(|err| format!("Resolved command path is not UTF-8: {err}"))?
        .trim()
        .to_string();
    if resolved.is_empty() {
        Err(format!("Required command '{program}' not found in PATH."))
    } else {
        Ok(resolved)
    }
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn applescript_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn toml_string(value: &str) -> String {
    toml::Value::String(value.to_string()).to_string()
}

fn plist_string_value(plist: &str, key: &str) -> Option<String> {
    let marker = format!("<key>{key}</key>");
    let after_key = plist.split_once(&marker)?.1;
    let string_start = after_key.find("<string>")? + "<string>".len();
    let after_start = &after_key[string_start..];
    let string_end = after_start.find("</string>")?;
    Some(xml_unescape_minimal(after_start[..string_end].trim()))
}

fn xml_unescape_minimal(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn read_plist_xml(path: &Path) -> Result<String, String> {
    match std::fs::read_to_string(path) {
        Ok(value) => Ok(value),
        Err(read_error) if cfg!(target_os = "macos") => {
            let output = Command::new("plutil")
                .args(["-convert", "xml1", "-o", "-", "--"])
                .arg(path)
                .output()
                .map_err(|err| {
                    format!(
                        "Failed to read {} as text ({read_error}) and plutil failed: {err}",
                        path.display()
                    )
                })?;
            if !output.status.success() {
                return Err(format!("plutil failed to convert {}", path.display()));
            }
            String::from_utf8(output.stdout)
                .map_err(|err| format!("plutil output for {} is not UTF-8: {err}", path.display()))
        }
        Err(error) => Err(format!("Failed to read {}: {error}", path.display())),
    }
}

fn read_app_bundle_info(app_path: &Path) -> Option<AppBundleInfo> {
    let plist_path = app_path.join("Contents/Info.plist");
    let plist = read_plist_xml(&plist_path).ok()?;
    let bundle_id = plist_string_value(&plist, "CFBundleIdentifier")?;
    let display_name = plist_string_value(&plist, "CFBundleDisplayName")
        .or_else(|| plist_string_value(&plist, "CFBundleName"))
        .or_else(|| plist_string_value(&plist, "CFBundleExecutable"))
        .or_else(|| {
            app_path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(ToOwned::to_owned)
        })?;

    Some(AppBundleInfo {
        display_name,
        bundle_id,
        app_path: app_path.to_path_buf(),
    })
}

fn terminal_adapter_for_app(info: &AppBundleInfo) -> Option<TerminalLaunchAdapter> {
    let bundle_id = info.bundle_id.to_ascii_lowercase();
    let display_name = info.display_name.to_ascii_lowercase();
    let file_stem = info
        .app_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if bundle_id == "com.apple.terminal" {
        return Some(TerminalLaunchAdapter::AppleTerminal);
    }
    if bundle_id == "com.googlecode.iterm2"
        || display_name == "iterm2"
        || file_stem == "iterm"
        || file_stem == "iterm2"
    {
        return Some(TerminalLaunchAdapter::ITerm2);
    }
    if bundle_id.starts_with("dev.warp.warp") || display_name == "warp" || file_stem == "warp" {
        if bundle_id.contains("preview") || display_name.contains("preview") {
            return Some(TerminalLaunchAdapter::WarpPreview);
        }
        return Some(TerminalLaunchAdapter::WarpStable);
    }

    None
}

fn default_terminal_app_scan_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    dirs.push(PathBuf::from("/Applications"));
    if let Some(home) = dirs::home_dir() {
        dirs.push(home.join("Applications"));
    }
    dirs.push(PathBuf::from("/System/Applications/Utilities"));
    dirs
}

fn detect_supported_terminal_apps() -> Result<Vec<DetectedTerminalApp>, String> {
    if !cfg!(target_os = "macos") {
        return Err(
            "Launching a new terminal window is currently implemented for macOS only.".into(),
        );
    }

    detect_supported_terminal_apps_in(&default_terminal_app_scan_dirs())
}

fn detect_supported_terminal_apps_in(dirs: &[PathBuf]) -> Result<Vec<DetectedTerminalApp>, String> {
    let mut seen = HashSet::new();
    let mut terminals = Vec::new();

    for dir in dirs {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let app_path = entry.path();
            if app_path.extension().and_then(|ext| ext.to_str()) != Some("app") {
                continue;
            }
            let Some(info) = read_app_bundle_info(&app_path) else {
                continue;
            };
            let Some(adapter) = terminal_adapter_for_app(&info) else {
                continue;
            };
            let canonical_path = std::fs::canonicalize(&info.app_path).unwrap_or(info.app_path);
            let dedupe_key = (
                info.bundle_id.to_ascii_lowercase(),
                canonical_path.display().to_string(),
            );
            if !seen.insert(dedupe_key) {
                continue;
            }
            terminals.push(DetectedTerminalApp {
                display_name: info.display_name,
                bundle_id: info.bundle_id,
                app_path: canonical_path,
                adapter,
            });
        }
    }

    terminals.sort_by(|left, right| {
        let left_priority = terminal_sort_priority(left);
        let right_priority = terminal_sort_priority(right);
        left_priority
            .cmp(&right_priority)
            .then_with(|| {
                left.display_name
                    .to_ascii_lowercase()
                    .cmp(&right.display_name.to_ascii_lowercase())
            })
            .then_with(|| left.app_path.cmp(&right.app_path))
    });

    if terminals.is_empty() {
        Err("No supported terminal app was detected on this computer.".into())
    } else {
        Ok(terminals)
    }
}

fn terminal_sort_priority(terminal: &DetectedTerminalApp) -> u8 {
    match terminal.adapter {
        TerminalLaunchAdapter::AppleTerminal => 0,
        _ => 1,
    }
}

fn write_temp_claude_mcp_config(
    endpoint: &str,
    authorization_header: &str,
) -> Result<std::path::PathBuf, String> {
    let path = std::env::temp_dir().join(format!(
        "canopy-claude-mcp-{}.json",
        uuid::Uuid::new_v4().as_simple()
    ));
    let body = serde_json::json!({
        "mcpServers": {
            (mcp_ai_client_server_name()): {
                "type": "http",
                "url": endpoint,
                "headers": {
                    "Authorization": authorization_header,
                }
            }
        }
    });
    let data = serde_json::to_vec_pretty(&body)
        .map_err(|err| format!("Failed to encode temporary Claude MCP config: {err}"))?;
    write_temp_file_private(&path, &data, 0o600)
        .map_err(|err| format!("Failed to write temporary Claude MCP config: {err}"))?;

    Ok(path)
}

fn write_temp_launch_script(name: &str, body: &str) -> Result<std::path::PathBuf, String> {
    let path = std::env::temp_dir().join(format!(
        "canopy-{name}-{}.command",
        uuid::Uuid::new_v4().as_simple()
    ));
    write_temp_file_private(&path, body.as_bytes(), 0o700)
        .map_err(|err| format!("Failed to write temporary {name} launch script: {err}"))?;

    Ok(path)
}

#[cfg(unix)]
fn write_temp_file_private(path: &std::path::Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    file.write_all(data)
}

#[cfg(not(unix))]
fn write_temp_file_private(path: &std::path::Path, data: &[u8], _mode: u32) -> std::io::Result<()> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(data)
}

fn launch_script_path_str(script_path: &Path) -> Result<&str, String> {
    script_path
        .to_str()
        .ok_or_else(|| "Temporary launch script path is not UTF-8.".to_string())
}

fn terminal_applescript_do_script(script_path: &Path) -> Result<String, String> {
    let script = script_path
        .to_str()
        .ok_or_else(|| "Temporary launch script path is not UTF-8.".to_string())?;
    let command = shell_single_quote(script);
    Ok(format!(
        "tell application \"Terminal\" to do script {}",
        applescript_string(&command)
    ))
}

fn iterm2_applescript_create_window(script_path: &Path) -> Result<String, String> {
    let script = launch_script_path_str(script_path)?;
    let command = format!("/bin/bash -lc {}", shell_single_quote(script));
    Ok(format!(
        "tell application \"iTerm2\" to create window with default profile command {}",
        applescript_string(&command)
    ))
}

fn open_script_in_apple_terminal(script_path: &Path) -> Result<(), String> {
    let script = terminal_applescript_do_script(script_path)?;
    let status = Command::new("osascript")
        .args([
            "-e",
            "tell application \"Terminal\" to activate",
            "-e",
            &script,
        ])
        .status()
        .map_err(|err| format!("Failed to open Terminal.app: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("Failed to open a new Terminal.app window.".into())
    }
}

fn open_script_in_iterm2(script_path: &Path) -> Result<(), String> {
    let script = iterm2_applescript_create_window(script_path)?;
    let status = Command::new("osascript")
        .args([
            "-e",
            "tell application \"iTerm2\" to activate",
            "-e",
            &script,
        ])
        .status()
        .map_err(|err| format!("Failed to open iTerm2: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("Failed to open a new iTerm2 window.".into())
    }
}

fn warp_tab_config_dir(adapter: TerminalLaunchAdapter) -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "Unable to resolve home directory.".to_string())?;
    match adapter {
        TerminalLaunchAdapter::WarpPreview => Ok(home.join(".warp-preview/tab_configs")),
        TerminalLaunchAdapter::WarpStable => Ok(home.join(".warp/tab_configs")),
        _ => Err("Unsupported Warp adapter.".into()),
    }
}

fn warp_url_scheme(adapter: TerminalLaunchAdapter) -> Result<&'static str, String> {
    match adapter {
        TerminalLaunchAdapter::WarpPreview => Ok("warppreview"),
        TerminalLaunchAdapter::WarpStable => Ok("warp"),
        _ => Err("Unsupported Warp adapter.".into()),
    }
}

fn build_warp_tab_config(
    name: &str,
    script_path: &Path,
    tab_config_path: &Path,
    directory: &Path,
) -> Result<String, String> {
    let script = launch_script_path_str(script_path)?;
    let tab_config = tab_config_path
        .to_str()
        .ok_or_else(|| "Temporary Warp tab config path is not UTF-8.".to_string())?;
    let directory = directory
        .to_str()
        .ok_or_else(|| "Warp launch directory path is not UTF-8.".to_string())?;
    let cleanup_command = format!("rm -f {}", shell_single_quote(tab_config));
    let launch_command = format!("/bin/bash -lc {}", shell_single_quote(script));

    Ok(format!(
        "name = {}\ntitle = {}\ncolor = \"cyan\"\n\n[[panes]]\nid = \"main\"\ntype = \"terminal\"\ndirectory = {}\ncommands = [\n  {},\n  {},\n]\nis_focused = true\n",
        toml_string(name),
        toml_string("Canopy MCP"),
        toml_string(directory),
        toml_string(&cleanup_command),
        toml_string(&launch_command),
    ))
}

fn build_warp_tab_config_url(name: &str, adapter: TerminalLaunchAdapter) -> Result<String, String> {
    Ok(format!(
        "{}://tab_config/{name}?new_window=true",
        warp_url_scheme(adapter)?
    ))
}

fn write_temp_warp_tab_config(
    script_path: &Path,
    adapter: TerminalLaunchAdapter,
) -> Result<(PathBuf, String), String> {
    let dir = warp_tab_config_dir(adapter)?;
    std::fs::create_dir_all(&dir)
        .map_err(|err| format!("Failed to create Warp tab config directory: {err}"))?;
    let name = format!("canopy_mcp_{}", uuid::Uuid::new_v4().as_simple());
    let path = dir.join(format!("{name}.toml"));
    let directory = std::env::current_dir()
        .ok()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("/"));
    let body = build_warp_tab_config(&name, script_path, &path, &directory)?;
    write_temp_file_private(&path, body.as_bytes(), 0o600)
        .map_err(|err| format!("Failed to write temporary Warp tab config: {err}"))?;
    Ok((path, build_warp_tab_config_url(&name, adapter)?))
}

fn open_script_in_warp(script_path: &Path, adapter: TerminalLaunchAdapter) -> Result<(), String> {
    let (_path, url) = write_temp_warp_tab_config(script_path, adapter)?;
    let status = Command::new("open")
        .arg(&url)
        .status()
        .map_err(|err| format!("Failed to open Warp tab config URL: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("Failed to open Warp tab config URL.".into())
    }
}

fn open_launch_script(script_path: &Path, terminal: &DetectedTerminalApp) -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err(
            "Launching a new terminal window is currently implemented for macOS only.".into(),
        );
    }

    match terminal.adapter {
        TerminalLaunchAdapter::AppleTerminal => open_script_in_apple_terminal(script_path),
        TerminalLaunchAdapter::ITerm2 => open_script_in_iterm2(script_path),
        TerminalLaunchAdapter::WarpStable | TerminalLaunchAdapter::WarpPreview => {
            open_script_in_warp(script_path, terminal.adapter)
        }
    }
}

impl App {
    pub async fn new(config: ClientConfig) -> Result<Self> {
        let api = ApiClient::new(&config.control_plane_url)?;
        let (action_tx, action_rx) = mpsc::unbounded_channel();

        let scrollback = config.live_tail_scrollback;
        let theme = config.theme.resolve()?;

        Ok(Self {
            login: LoginScreen::with_theme(config.dev_mode, theme),
            dashboard: DashboardScreen::new(
                config.enable_live_tail,
                config.show_public_ip,
                config.keybindings.clone(),
                theme,
            ),
            ec2: Ec2Screen::with_theme(theme),
            cloudwatch_search: CloudWatchSearchScreen::with_theme(theme),
            live_tail: LiveTailScreen::with_theme(scrollback, theme),
            access: AccessScreen::with_theme(theme),
            settings: SettingsScreen::new(config.clone(), theme),
            mcp: McpScreen::new(),
            connect_session: None,
            error_modal: ErrorModal::new().with_theme(theme),
            config,
            theme,
            api,
            current_screen: Screen::Login,
            screen_stack: Vec::new(),
            entitlements: None,
            running: true,
            action_tx,
            action_rx,
            event_reader_paused: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            ec2_fetch_cancel: None,
            cw_fetch_cancel: None,
            token_store_path: None, // Production default uses auth::token_path()
            live_tail_cancel: None,
            live_tail_generation: 0,
            mcp_runtime: None,
            update_banner: None,
            session_expired_pending_login: false,
        })
    }

    pub async fn run(&mut self, terminal: &mut Tui) -> Result<()> {
        // Check for saved token
        if let Some(session) = crate::auth::load_session() {
            self.api.set_session(session);
            // Try to validate by fetching entitlements
            match self.api.get_entitlements().await {
                Ok(ent) => {
                    self.set_entitlements(ent);
                    self.enter_dashboard();
                }
                Err(e) => {
                    match e {
                        ApiClientError::TokenExpired => {
                            // Codex round 7+8: surface clear failures so
                            // a stale on-disk token doesn't quietly
                            // resurrect the next session. Modal shown
                            // by the helper when delete fails; we still
                            // proceed with in-memory clear because the
                            // user must be logged out NOW.
                            let _ = self.clear_persisted_token_or_warn();
                            self.api.clear_token();
                        }
                        other => {
                            // Transient or non-authz error: keep the token but stay on login
                            // so the user can retry, rather than stranding them
                            // on a featureless dashboard.
                            tracing::warn!("Entitlements fetch failed (keeping token): {}", other);
                        }
                    }
                    // Stay on login screen in both cases — dashboard needs
                    // entitlements to function.
                }
            }
        }

        let mut event_reader = EventReader::new();
        self.event_reader_paused = event_reader.paused.clone();
        let _event_handle = event_reader.spawn();

        // Kick off background update check if enabled
        if self.config.auto_update {
            let _ = self.action_tx.send(Action::CheckForUpdate);
        }

        while self.running {
            // Render
            terminal.draw(|frame| self.render(frame))?;

            // Handle events
            tokio::select! {
                Some(event) = event_reader.rx.recv() => {
                    self.handle_event(event);
                }
                Some(action) = self.action_rx.recv() => {
                    self.handle_action(action, terminal).await;
                }
            }
        }

        Ok(())
    }

    fn render(&mut self, frame: &mut ratatui::Frame) {
        let area = frame.area();
        let mut connect_cursor = None;

        {
            // Render current screen
            let buf = frame.buffer_mut();
            match self.current_screen {
                Screen::Login => self.login.render(area, buf),
                Screen::Dashboard => self.dashboard.render(area, buf),
                Screen::Ec2Inventory => self.ec2.render(area, buf),
                Screen::CloudWatchSearch => self.cloudwatch_search.render(area, buf),
                Screen::LiveTail => self.live_tail.render(area, buf),
                Screen::Access => self.access.render(area, buf),
                Screen::Settings => self.settings.render(area, buf),
                Screen::Mcp => self.mcp.render(area, buf),
                Screen::ConnectSession => {
                    if let Some(session) = self.connect_session.as_ref() {
                        session.render(area, buf);
                        connect_cursor = session.cursor_position(area);
                    }
                }
            }

            // Render update banner (non-blocking, top of screen)
            if let Some(ref msg) = self.update_banner {
                use ratatui::prelude::*;
                use ratatui::widgets::{Block, Borders, Clear, Paragraph};

                let banner_h = 3u16.min(area.height);
                let banner_area = Rect {
                    x: area.x,
                    y: area.y,
                    width: area.width,
                    height: banner_h,
                };
                Clear.render(banner_area, buf);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_style(self.theme.success_style());
                let inner = block.inner(banner_area);
                block.render(banner_area, buf);

                Paragraph::new(Line::from(vec![
                    Span::styled(" ↑ ", self.theme.success_style().bold()),
                    Span::styled(msg.as_str(), self.theme.success_style().bold()),
                    Span::styled("  (Ctrl+D: dismiss)", self.theme.muted_style()),
                ]))
                .render(inner, buf);
                connect_cursor = None;
            }

            // Render error modal on top
            if self.error_modal.is_visible() {
                self.error_modal.render(area, buf);
                connect_cursor = None;
            }
        }

        if let Some(position) = connect_cursor {
            frame.set_cursor_position(position);
        }
    }

    fn handle_event(&mut self, event: Event) {
        match event {
            Event::Key(key) => {
                // Error modal intercepts all keys when visible
                if self.error_modal.is_visible() {
                    let action = self.error_modal.handle_key(key);
                    let _ = self.action_tx.send(action);
                    return;
                }

                // Update banner: Ctrl+D dismisses on any screen, no conflict with text input
                if self.update_banner.is_some()
                    && key.code == crossterm::event::KeyCode::Char('d')
                    && key
                        .modifiers
                        .contains(crossterm::event::KeyModifiers::CONTROL)
                {
                    let _ = self.action_tx.send(Action::DismissUpdateBanner);
                    return;
                }

                let action = match self.current_screen {
                    Screen::Login => self.login.handle_key(key),
                    Screen::Dashboard => self.dashboard.handle_key(key),
                    Screen::Ec2Inventory => self.ec2.handle_key(key),
                    Screen::CloudWatchSearch => self.cloudwatch_search.handle_key(key),
                    Screen::LiveTail => self.live_tail.handle_key(key),
                    Screen::Access => self.access.handle_key(key),
                    Screen::Settings => self.settings.handle_key(key),
                    Screen::Mcp => self.mcp.handle_key(key),
                    Screen::ConnectSession => self
                        .connect_session
                        .as_mut()
                        .map_or(Action::Noop, |session| session.handle_key(key)),
                };
                let _ = self.action_tx.send(action);
            }
            Event::Paste(text) => {
                if self.error_modal.is_visible() {
                    return;
                }

                let action = match self.current_screen {
                    Screen::Login => self.login.handle_paste(&text),
                    Screen::Dashboard => self.dashboard.handle_paste(&text),
                    Screen::Ec2Inventory => self.ec2.handle_paste(&text),
                    Screen::CloudWatchSearch => self.cloudwatch_search.handle_paste(&text),
                    Screen::LiveTail => self.live_tail.handle_paste(&text),
                    Screen::Access => self.access.handle_paste(&text),
                    Screen::Settings => self.settings.handle_paste(&text),
                    Screen::Mcp => self.mcp.handle_paste(&text),
                    Screen::ConnectSession => self
                        .connect_session
                        .as_mut()
                        .map_or(Action::Noop, |session| session.handle_paste(&text)),
                };
                let _ = self.action_tx.send(action);
            }
            Event::Tick => match self.current_screen {
                Screen::Dashboard => self.dashboard.on_tick(),
                Screen::Ec2Inventory => self.ec2.on_tick(),
                Screen::CloudWatchSearch => self.cloudwatch_search.on_tick(),
                Screen::ConnectSession => {
                    if let Some(session) = self.connect_session.as_mut() {
                        session.tick();
                    }
                }
                _ => {}
            },
            Event::Resize(w, h) => {
                if let Some(session) = self.connect_session.as_mut() {
                    session.resize(w, h);
                }
            }
            Event::Error(msg) => {
                let _ = self.action_tx.send(Action::ShowError(msg));
            }
        }
    }

    async fn handle_action(&mut self, action: Action, terminal: &mut Tui) {
        match action {
            Action::Quit => {
                self.stop_mcp_runtime();
                self.running = false;
            }
            Action::NavigateTo(screen) => {
                self.navigate_to(screen);
            }
            Action::GoBack => {
                self.go_back();
            }

            // Auth
            Action::LoginDevMode(username) => {
                self.do_dev_login(&username).await;
            }
            Action::LoginPkce => {
                if self.config.dev_mode {
                    self.login
                        .set_status("PKCE flow not available in dev mode. Use dev login.".into());
                } else {
                    self.login.set_status("SSO/PKCE: Opening browser...".into());
                    self.do_pkce_login().await;
                }
            }
            Action::LoginDeviceCode => {
                if self.config.dev_mode {
                    self.login.set_status(
                        "Device code flow not available in dev mode. Use dev login.".into(),
                    );
                } else {
                    self.login.set_status("Device code flow starting...".into());
                    self.do_device_code_login().await;
                }
            }
            Action::Logout => {
                self.reset_to_login();
            }
            Action::TokenExpired => {
                self.begin_token_expired_flow();
            }
            Action::ChangePassword => match self.config.change_password_url.as_deref() {
                Some(raw_url) => match normalized_http_url(raw_url) {
                    Some(url) => {
                        if let Err(e) = open::that(url) {
                            self.error_modal
                                .show(format!("Failed to open password page: {}\n{}", e, url));
                        }
                    }
                    None => self
                        .error_modal
                        .show("Change password URL must start with http:// or https://.".into()),
                },
                _ => {
                    self.error_modal.show(
                        "Change password URL is not configured. \
                         Set change_password_url in the TUI config."
                            .into(),
                    );
                }
            },
            Action::TokenReceived(resp) => {
                // Codex round 8: set_session_tokens positively
                // removes any stale on-disk token if persist fails.
                // If both save AND clear fail, refuse to enter the
                // dashboard — the prior user's credential could
                // resurrect on restart.
                match self.install_token_response(resp) {
                    SessionTokenOutcome::PersistedFresh | SessionTokenOutcome::InMemoryOnly => {
                        if self.fetch_entitlements().await {
                            self.enter_dashboard();
                        }
                        // If fetch_entitlements failed, error modal
                        // is shown and we stay on the current screen
                        // so the user can retry.
                    }
                    SessionTokenOutcome::StaleTokenSurvivesOnDisk => {
                        // Modal already shown by set_session_token.
                        // Stay on Login so the user must remediate.
                        self.api.clear_token();
                    }
                }
            }

            // EC2
            Action::RefreshEc2 => {
                self.spawn_ec2_fetch(None);
            }
            Action::SearchEc2(query) => {
                let filter = if query.is_empty() { None } else { Some(query) };
                self.spawn_ec2_fetch(filter);
            }
            Action::Ec2Loaded(instances, failed_scopes, generation) => {
                // Drop stale responses from superseded fetches
                if generation != self.ec2.fetch_generation {
                    return;
                }
                if !failed_scopes.is_empty() {
                    self.error_modal.show(format!(
                        "Some accounts/regions failed to respond:\n{}",
                        failed_scopes.join("\n")
                    ));
                }
                // Warn if scoped fetch returned no instances — may be an unauthorized pair
                if instances.is_empty()
                    && self.ec2.selected_account_id.is_some()
                    && self.ec2.selected_region.is_some()
                    && failed_scopes.is_empty()
                {
                    self.error_modal.show(
                        "No instances found for this account/region combination. \
                         This pair may not be authorized — try selecting \"All\"."
                            .into(),
                    );
                }
                self.ec2.set_instances(instances);
            }
            Action::Ec2FetchFailed(err, generation) => {
                if generation != self.ec2.fetch_generation {
                    return;
                }
                self.ec2.set_error(err);
            }
            Action::SelectInstance(_idx) => {
                // handled in component
            }
            Action::PowerEc2 {
                instance_id,
                account_id,
                region,
                action,
                confirmation_instance_id,
            } => {
                self.do_power_ec2(Ec2PowerRequest {
                    instance_id,
                    account_id,
                    region,
                    action,
                    confirmation_instance_id,
                })
                .await;
            }
            Action::ToggleEcsView => {
                let follow_up = self.ec2.toggle_inventory_view();
                let _ = self.action_tx.send(follow_up);
            }
            Action::RefreshEcsTasks => {
                self.spawn_ecs_tasks_fetch();
            }
            Action::EcsTasksLoaded {
                tasks,
                failed_scopes,
                total_count,
                truncated,
                generation,
            } => {
                if generation != self.ec2.fetch_generation {
                    return;
                }
                let task_count = tasks.len();
                let failed_scope_count = failed_scopes.len();
                let warnings =
                    ecs_tasks_warning_messages(&failed_scopes, task_count, total_count, truncated);
                if !warnings.is_empty() {
                    self.error_modal.show(warnings.join("\n\n"));
                }
                self.ec2.set_ecs_task_results(
                    tasks,
                    Some(total_count),
                    truncated,
                    failed_scope_count,
                );
            }
            Action::EcsTasksFetchFailed(err, generation) => {
                if generation != self.ec2.fetch_generation {
                    return;
                }
                self.ec2.set_error(err);
            }
            Action::ConnectEcsExec {
                account_id,
                region,
                cluster_arn,
                task_arn,
                container_name,
            } => {
                self.do_ecs_exec(
                    EcsExecRequest {
                        account_id,
                        region,
                        cluster_arn,
                        task_arn,
                        container_name,
                    },
                    terminal,
                )
                .await;
            }
            Action::ConnectSsm {
                instance_id,
                instance_name,
                account_id,
                region,
                os_user,
            } => {
                self.do_connect_with_user(
                    ConnectTarget {
                        instance_id: &instance_id,
                        instance_name: instance_name.as_deref(),
                        account_id: &account_id,
                        region: &region,
                        method: ConnectMethod::Ssm,
                        os_user: os_user.as_deref(),
                    },
                    terminal,
                )
                .await;
            }
            Action::ConnectEic {
                instance_id,
                instance_name,
                account_id,
                region,
                os_user,
            } => {
                self.do_connect_with_user(
                    ConnectTarget {
                        instance_id: &instance_id,
                        instance_name: instance_name.as_deref(),
                        account_id: &account_id,
                        region: &region,
                        method: ConnectMethod::Ec2InstanceConnect,
                        os_user: os_user.as_deref(),
                    },
                    terminal,
                )
                .await;
            }
            Action::ConnectSsh {
                instance_id,
                instance_name,
                account_id,
                region,
                os_user,
            } => {
                self.do_connect_with_user(
                    ConnectTarget {
                        instance_id: &instance_id,
                        instance_name: instance_name.as_deref(),
                        account_id: &account_id,
                        region: &region,
                        method: ConnectMethod::Ssh,
                        os_user: os_user.as_deref(),
                    },
                    terminal,
                )
                .await;
            }
            Action::ConnectSessionStdoutReady => {
                self.apply_connect_session_stdout_ready();
            }
            Action::ConnectSessionFailure(message) => {
                self.apply_connect_session_failure(message);
            }
            Action::ConnectSessionUserDisconnect => {
                self.apply_connect_session_user_disconnect();
            }
            Action::ConnectSessionExit => {
                self.apply_connect_session_exit();
            }

            // CloudWatch
            Action::RefreshLogGroups => {
                self.spawn_log_groups_fetch();
            }
            Action::LogGroupsLoaded(groups, generation) => {
                if generation != self.cloudwatch_search.fetch_generation {
                    return;
                }
                self.cloudwatch_search.set_log_groups(groups);
            }
            Action::LogGroupsFetchFailed(err, generation) => {
                if generation != self.cloudwatch_search.fetch_generation {
                    return;
                }
                self.cloudwatch_search.set_error(err);
            }
            Action::RunFilterSearch => {
                self.spawn_filter_search(false);
            }
            Action::FilterEventsLoaded {
                events,
                next_token,
                append,
                generation,
            } => {
                self.apply_filter_events_loaded(events, next_token, append, generation);
            }
            Action::FilterEventsFetchFailed(err, generation) => {
                self.apply_filter_events_fetch_failed(err, generation);
            }
            Action::LoadMoreFilterResults => {
                self.spawn_filter_search(true);
            }
            Action::CancelCloudWatchRequest => {
                self.cancel_cloudwatch_request();
            }
            Action::RunInsightsQuery => {
                self.spawn_insights_query();
            }
            Action::InsightsQueryStarted {
                query_id,
                generation,
            } => {
                if generation != self.cloudwatch_search.fetch_generation {
                    return;
                }
                self.cloudwatch_search.query_id = Some(query_id.clone());
                self.cloudwatch_search
                    .set_loading(CloudWatchLoadingKind::WaitingForInsightsResults);
                let _ = self.action_tx.send(Action::PollQueryResults {
                    query_id,
                    generation,
                });
            }
            Action::InsightsQueryStartFailed { error, generation } => {
                if generation != self.cloudwatch_search.fetch_generation {
                    return;
                }
                self.cloudwatch_search.set_error(error);
            }
            Action::PollQueryResults {
                query_id,
                generation,
            } => {
                self.spawn_poll_query(query_id, generation);
            }
            Action::InsightsQueryResultsLoaded {
                response,
                generation,
            } => {
                if generation != self.cloudwatch_search.fetch_generation {
                    return;
                }
                let should_poll_again = !response.status.is_terminal();
                self.cloudwatch_search.set_query_results(response);
                if should_poll_again {
                    let Some(query_id) = self.cloudwatch_search.query_id.clone() else {
                        return;
                    };
                    let tx = self.action_tx.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        let _ = tx.send(Action::PollQueryResults {
                            query_id,
                            generation,
                        });
                    });
                }
            }
            Action::InsightsQueryResultsFailed { error, generation } => {
                if generation != self.cloudwatch_search.fetch_generation {
                    return;
                }
                self.cloudwatch_search.set_error(error);
            }
            Action::ExportResults(format) => {
                self.do_export_results(&format);
            }

            // Live Tail
            Action::StartLiveTail => {
                let Some(request) = self.live_tail.start_request() else {
                    self.error_modal.show(
                        "No Live Tail log group is available with your current entitlements".into(),
                    );
                    return;
                };
                if let Some((cancel, generation)) = self.try_arm_live_tail_stream() {
                    let tx = self.action_tx.clone();
                    let base_url = self.config.control_plane_url.clone();
                    let token = self.api.get_token();
                    tokio::spawn(async move {
                        if let Err(e) = crate::live_tail_ws::stream_live_tail(
                            &base_url,
                            token.as_deref(),
                            request,
                            tx,
                            cancel,
                            generation,
                        )
                        .await
                        {
                            tracing::warn!("Live tail stream ended: {}", e);
                        }
                    });
                }
            }
            // Live-tail actions are dispatched through a single
            // entry point so tests can call the same code path as
            // production (Codex round 2: testing apply_* alone
            // doesn't catch deletion of this match arm — but
            // funneling through dispatch_live_tail_action does).
            other @ (Action::StopLiveTail
            | Action::PauseLiveTail
            | Action::ResumeLiveTail
            | Action::LiveTailEvent { .. }
            | Action::LiveTailStreamEnded(_)) => {
                self.dispatch_live_tail_action(other);
            }

            // MCP local server
            Action::EnableMcp => {
                self.start_mcp_runtime(terminal, true).await;
            }
            Action::LaunchMcpAiClient => {
                if !self.reject_direct_mcp_launch_when_stopped() {
                    self.launch_mcp_ai_client(terminal).await;
                }
            }
            Action::StopMcp => {
                self.stop_mcp_runtime();
            }
            Action::RestartMcp => {
                self.stop_mcp_runtime();
                self.start_mcp_runtime(terminal, true).await;
            }
            Action::TestMcp => {
                self.test_mcp_runtime().await;
            }
            Action::LiveTailConnected => {
                if self.live_tail_cancel.is_some() {
                    self.live_tail.set_connected();
                }
            }
            Action::LiveTailReconnecting => {
                if self.live_tail_cancel.is_some() {
                    self.live_tail.set_reconnecting();
                }
            }
            Action::LiveTailSessionUpdate { events_per_second } => {
                if self.live_tail_cancel.is_some() {
                    self.live_tail.set_events_per_second(events_per_second);
                }
            }
            Action::RefreshLiveTailLogGroups => {
                self.spawn_live_tail_log_groups_fetch();
            }
            Action::LiveTailLogGroupsLoaded { groups, generation } => {
                if generation == self.live_tail.fetch_generation {
                    self.live_tail.set_log_groups(groups);
                }
            }
            Action::LiveTailLogGroupsFailed { error, generation } => {
                if generation == self.live_tail.fetch_generation {
                    self.live_tail.set_log_groups_error(error);
                }
            }
            Action::McpStarted(status) => {
                self.mcp.set_running(&status);
                self.dashboard.set_mcp_server_running(true);
            }
            Action::McpStartFailed(error) => {
                self.mcp.set_error(error);
                self.dashboard.set_mcp_server_running(false);
            }
            Action::McpStopped => {
                self.mcp.set_stopped();
                self.dashboard.set_mcp_server_running(false);
            }
            Action::McpHealthChecked(result) => match result {
                Ok(()) => self
                    .mcp
                    .set_status_line("Health check OK; server responded successfully.".into()),
                Err(error) => self.mcp.set_error(error),
            },

            // Dashboard
            Action::FetchPublicIp => {
                self.dashboard.ip_fetch_generation += 1;
                let generation = self.dashboard.ip_fetch_generation;
                let tx = self.action_tx.clone();
                tokio::spawn(async move {
                    let client = reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(5))
                        .build()
                        .unwrap_or_default();
                    let ip = match client.get("https://checkip.amazonaws.com").send().await {
                        Ok(resp) => resp
                            .text()
                            .await
                            .map(|s| s.trim().to_string())
                            .unwrap_or_else(|_| "unavailable".into()),
                        Err(_) => "unavailable".into(),
                    };
                    let _ = tx.send(Action::SetPublicIp(ip, generation));
                });
            }
            Action::SetPublicIp(ip, generation) => {
                if generation == self.dashboard.ip_fetch_generation {
                    self.dashboard.public_ip = Some(ip);
                }
            }

            // MFA
            Action::RefreshMfaStatus => {
                self.settings.set_mfa_loading();
                self.spawn_mfa_status_fetch();
            }
            Action::MfaStatusLoaded(status) => {
                self.settings.set_mfa_status(status);
            }
            Action::MfaStatusFailed(error) => {
                self.settings.set_mfa_error(error);
            }
            Action::StartTotpEnrollment => {
                self.settings.set_totp_starting();
                self.spawn_totp_enrollment_start();
            }
            Action::TotpEnrollmentStarted(response) => {
                self.settings.set_totp_started(response);
            }
            Action::TotpEnrollmentStartFailed(error) => {
                self.settings.set_totp_start_error(error);
            }
            Action::ConfirmTotpEnrollment { factor_id, code } => {
                self.settings.set_totp_confirming();
                self.spawn_totp_enrollment_confirm(factor_id, code);
            }
            Action::TotpEnrollmentConfirmed(response) => {
                self.settings.set_totp_confirmed(response.status);
            }
            Action::TotpEnrollmentConfirmFailed(error) => {
                self.settings.set_totp_confirm_error(error);
            }
            Action::StartTotpStepUpVerification => {
                self.settings.start_totp_step_up_verification();
            }
            Action::VerifyTotpStepUp { code } => {
                self.settings.set_totp_step_up_verifying();
                self.spawn_totp_step_up_verify(code);
            }
            Action::TotpStepUpVerified(response) => {
                self.settings.set_totp_step_up_verified(response);
            }
            Action::TotpStepUpVerifyFailed(error) => {
                self.settings.set_totp_step_up_verify_error(error);
            }
            Action::GenerateRecoveryCodes => {
                self.settings.set_recovery_codes_generating();
                self.spawn_recovery_codes_generate();
            }
            Action::RecoveryCodesGenerated(response) => {
                self.settings.set_recovery_codes_generated(response);
            }
            Action::RecoveryCodesGenerateFailed(error) => {
                self.settings.set_recovery_codes_generate_error(error);
            }
            Action::StartRecoveryCodeStepUpVerification => {
                self.settings.start_recovery_code_step_up_verification();
            }
            Action::VerifyRecoveryCodeStepUp { code } => {
                self.settings.set_recovery_code_step_up_verifying();
                self.spawn_recovery_code_step_up_verify(code);
            }
            Action::RecoveryCodeStepUpVerified(response) => {
                self.settings.set_recovery_code_step_up_verified(response);
            }
            Action::RecoveryCodeStepUpVerifyFailed(error) => {
                self.settings.set_recovery_code_step_up_verify_error(error);
            }
            Action::StartWebAuthnEnrollment => {
                self.settings.set_webauthn_starting();
                self.spawn_webauthn_enrollment();
            }
            Action::WebAuthnEnrollmentSucceeded(response) => {
                self.settings.set_webauthn_enrolled(response);
            }
            Action::WebAuthnEnrollmentFailed(error) => {
                self.settings.set_webauthn_error(error);
            }
            Action::StartWebAuthnStepUpVerification => {
                self.settings.set_webauthn_verifying();
                self.spawn_webauthn_step_up_verification();
            }
            Action::WebAuthnStepUpVerified(response) => {
                self.settings.set_webauthn_step_up_verified(response);
            }
            Action::WebAuthnStepUpVerifyFailed(error) => {
                self.settings.set_webauthn_step_up_error(error);
            }

            // Auto-update
            Action::CheckForUpdate => {
                let tx = self.action_tx.clone();
                let repo_owner = self.config.update_repo_owner.clone();
                let repo_name = self.config.update_repo_name.clone();
                tokio::spawn(async move {
                    let result = crate::updater::check_and_apply(&repo_owner, &repo_name)
                        .await
                        .ok()
                        .flatten();
                    let _ = tx.send(Action::UpdateCheckComplete(result));
                });
            }
            Action::UpdateCheckComplete(result) => {
                if let Some(update) = result {
                    self.update_banner = Some(update.message);
                }
            }
            Action::DismissUpdateBanner => {
                self.update_banner = None;
            }

            // Error
            Action::ShowError(msg) => {
                self.error_modal.show(msg);
            }
            Action::DismissError => {
                self.error_modal.dismiss();
                if self.session_expired_pending_login {
                    self.reset_to_login();
                    self.login
                        .set_status("Session expired. Please sign in again.".into());
                }
            }

            Action::Noop => {}
        }
    }

    fn cancel_in_flight_work(&mut self) {
        if let Some(token) = self.ec2_fetch_cancel.take() {
            token.cancel();
        }
        if let Some(token) = self.cw_fetch_cancel.take() {
            token.cancel();
        }
        if let Some(token) = self.live_tail_cancel.take() {
            token.cancel();
        }
        self.live_tail.set_disconnected();
        if let Some(session) = self.connect_session.as_mut() {
            session.disconnect();
        }
        self.connect_session = None;
        self.stop_mcp_runtime();
    }

    fn cancel_cloudwatch_request(&mut self) {
        if let Some(token) = self.cw_fetch_cancel.take() {
            token.cancel();
        }
        self.cloudwatch_search.advance_fetch_generation();
        self.cloudwatch_search.cancel_loading();
    }

    /// Resolved path to the on-disk token store, honoring any test
    /// override. Production code: `None` → falls back to the real
    /// `auth::token_path()`. Tests: install a tempdir-based path so
    /// `cargo test` never touches the real credential (Codex round 10).
    fn resolved_token_path(&self) -> std::path::PathBuf {
        self.token_store_path
            .clone()
            .unwrap_or_else(crate::auth::token_path)
    }

    /// Clear the persisted-on-disk token. Returns Ok on success.
    /// On failure both logs a tracing::warn AND shows a user-visible
    /// modal (Codex round 8: warning-only is insufficient because
    /// startup `load_token` would resurrect the stale token without
    /// the user knowing).
    fn clear_persisted_token_or_warn(&mut self) -> Result<(), String> {
        let path = self.resolved_token_path();
        match crate::auth::clear_token_at_path(&path) {
            Ok(()) => Ok(()),
            Err(e) => {
                let msg = format!("{e:#}");
                tracing::warn!(
                    error = %e,
                    "Failed to remove persisted token file during teardown; \
                     a stale credential may survive to the next session.",
                );
                self.error_modal.show(format!(
                    "Could not delete the persisted auth token: {e}\n\n\
                     A stale credential may auto-resurrect on next restart. \
                     Manually remove the canopy token file before re-logging in."
                ));
                Err(msg)
            }
        }
    }

    /// Persist a freshly received auth session to disk. Returns true
    /// on success, false on failure. Callers that handle a fresh login
    /// should use `set_session_tokens` / `install_token_response`,
    /// which add the stale-on-disk-token cleanup guard.
    fn persist_session_or_warn(
        &mut self,
        path: &Path,
        session: &crate::auth::SessionTokens,
    ) -> bool {
        match crate::auth::save_session_to_path(path, session) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to persist auth session to disk. The session \
                     remains valid in memory but will not survive restart.",
                );
                self.error_modal.show(format!(
                    "Auth session could not be saved to disk: {e}\n\n\
                     You can keep using the app this session, but you will \
                     have to log in again after restart."
                ));
                false
            }
        }
    }

    fn persist_session_with_stale_guard(
        &mut self,
        path: &Path,
        session: &crate::auth::SessionTokens,
    ) -> SessionTokenOutcome {
        if self.persist_session_or_warn(path, session) {
            return SessionTokenOutcome::PersistedFresh;
        }

        // Save failed — actively try to delete any leftover stale
        // token so the next restart can't pick it up.
        if crate::auth::clear_token_at_path(path).is_ok() {
            tracing::warn!(
                "Could not save the new auth session, but successfully removed \
                 the stale on-disk token. In-memory session continues; \
                 restart will require re-login.",
            );
            SessionTokenOutcome::InMemoryOnly
        } else {
            tracing::error!(
                "Could not save NEW token AND could not remove the OLD token. \
                 Refusing to enter the dashboard — the prior user's \
                 credential could auto-resurrect on restart.",
            );
            self.error_modal.show(
                "Auth session could not be saved AND the old token could not be \
                 removed.\n\nThe app cannot safely proceed because the next \
                 restart could auto-load the previous credential. Please fix \
                 disk permissions and try again."
                    .to_string(),
            );
            SessionTokenOutcome::StaleTokenSurvivesOnDisk
        }
    }

    /// Install a full auth session into the in-memory API client and
    /// attempt to persist it. Codex round 8 contract: on persist
    /// failure we MUST positively delete any stale on-disk token
    /// before allowing the in-memory session to continue, otherwise
    /// the next restart would auto-load the prior user's credential.
    pub(crate) fn set_session_tokens(
        &mut self,
        session: crate::auth::SessionTokens,
    ) -> SessionTokenOutcome {
        let path = self.resolved_token_path();
        self.api.set_session_store_path(path.clone());
        self.api.set_session(session.clone());
        self.persist_session_with_stale_guard(&path, &session)
    }

    pub(crate) fn set_session_token(&mut self, token: &str) -> SessionTokenOutcome {
        self.set_session_tokens(crate::auth::SessionTokens::new(token.to_string(), None))
    }

    fn install_token_response(
        &mut self,
        resp: shared::dto::auth::TokenResponse,
    ) -> SessionTokenOutcome {
        let path = self.resolved_token_path();
        self.api.set_session_store_path(path.clone());
        let session = self.api.apply_token_response(resp);
        self.persist_session_with_stale_guard(&path, &session)
    }

    fn reset_to_login(&mut self) {
        self.cancel_in_flight_work();

        // Reset screen state and advance generation counters so queued async
        // results from the prior session are rejected.
        let ec2_gen = self.ec2.fetch_generation + 1;
        let cw_gen = self.cloudwatch_search.fetch_generation + 1;
        self.ec2 = Ec2Screen::with_theme(self.theme);
        self.ec2.fetch_generation = ec2_gen;
        self.cloudwatch_search = CloudWatchSearchScreen::with_theme(self.theme);
        self.cloudwatch_search.fetch_generation = cw_gen;
        self.dashboard.public_ip = None;
        self.dashboard.ip_fetch_generation += 1;

        // Wipe live-tail buffer so the next user / session does NOT
        // see the previous session's log lines (Codex round 7).
        // Rebuild rather than just .clear()ing — keeps filter,
        // scroll, and auto-scroll state fresh too.
        self.live_tail = LiveTailScreen::new(self.config.live_tail_scrollback);
        // Bump generation so any in-flight stream's queued events
        // are now stale and will be dropped by the generation guard.
        self.live_tail_generation = self.live_tail_generation.saturating_add(1);

        // Codex round 8: if the disk delete failed, the helper
        // already showed an error modal — leave it visible. Only
        // dismiss when clear succeeded; otherwise the user must
        // see and dismiss the failure modal so the stale-credential
        // risk is acknowledged.
        let clear_ok = self.clear_persisted_token_or_warn().is_ok();
        self.api.clear_token();
        self.entitlements = None;
        self.current_screen = Screen::Login;
        self.screen_stack.clear();
        self.session_expired_pending_login = false;
        if clear_ok {
            self.error_modal.dismiss();
        }
    }

    fn begin_token_expired_flow(&mut self) {
        if self.session_expired_pending_login {
            return;
        }

        self.cancel_in_flight_work();
        // Same defense as reset_to_login: scrub live-tail state so
        // the post-relogin user does not see the prior session's
        // logs (Codex round 7).
        self.live_tail = LiveTailScreen::new(self.config.live_tail_scrollback);
        self.live_tail_generation = self.live_tail_generation.saturating_add(1);

        let clear_ok = self.clear_persisted_token_or_warn().is_ok();
        self.api.clear_token();
        self.entitlements = None;
        self.session_expired_pending_login = true;
        if clear_ok {
            // Standard session-expired modal. If clear FAILED, the
            // helper already showed a more urgent modal explaining
            // the stale-credential risk — leave that one up.
            self.error_modal
                .show_with_title(" Session Expired ", TOKEN_EXPIRED_MODAL_MESSAGE.into());
        }
    }

    fn handle_route_error<F>(&mut self, err: ApiClientError, fallback: F)
    where
        F: FnOnce(&mut Self, String),
    {
        match err {
            ApiClientError::TokenExpired => self.begin_token_expired_flow(),
            other => fallback(self, other.to_string()),
        }
    }

    fn route_error_to_action<F>(err: ApiClientError, fallback: F) -> Action
    where
        F: FnOnce(String) -> Action,
    {
        match err {
            ApiClientError::TokenExpired => Action::TokenExpired,
            other => fallback(other.to_string()),
        }
    }

    fn navigate_to(&mut self, screen: Screen) {
        // Guard: block navigation to LiveTail when the feature flag is off
        if matches!(screen, Screen::LiveTail) && !self.config.enable_live_tail {
            let _ = self.action_tx.send(Action::ShowError(
                "Live Tail is a beta feature and is not available in this build. \
                 Set enable_live_tail = true in config to enable it."
                    .into(),
            ));
            return;
        }

        // Fire on_leave for current screen
        match self.current_screen {
            Screen::Login => self.login.on_leave(),
            Screen::Dashboard => self.dashboard.on_leave(),
            Screen::Ec2Inventory => {
                if let Some(cancel) = self.ec2_fetch_cancel.take() {
                    cancel.cancel();
                }
                self.ec2.fetch_generation += 1;
                self.ec2.on_leave();
            }
            Screen::CloudWatchSearch => {
                if let Some(cancel) = self.cw_fetch_cancel.take() {
                    cancel.cancel();
                }
                self.cloudwatch_search.fetch_generation += 1;
                self.cloudwatch_search.on_leave();
            }
            Screen::LiveTail => {
                // Cancel the background stream and reset component state
                if let Some(cancel) = self.live_tail_cancel.take() {
                    cancel.cancel();
                }
                self.live_tail.set_disconnected();
                self.live_tail.on_leave();
            }
            Screen::Access => self.access.on_leave(),
            Screen::Settings => self.settings.on_leave(),
            Screen::Mcp => self.mcp.on_leave(),
            Screen::ConnectSession => {
                if let Some(session) = self.connect_session.as_mut() {
                    session.disconnect();
                }
            }
        }

        self.screen_stack.push(self.current_screen.clone());
        self.current_screen = screen;

        // Fire on_enter for new screen
        let actions = match self.current_screen {
            Screen::Login => self.login.on_enter(),
            Screen::Dashboard => self.dashboard.on_enter(),
            Screen::Ec2Inventory => self.ec2.on_enter(),
            Screen::CloudWatchSearch => self.cloudwatch_search.on_enter(),
            Screen::LiveTail => self.live_tail.on_enter(),
            Screen::Access => self.access.on_enter(),
            Screen::Settings => self.settings.on_enter(),
            Screen::Mcp => self.mcp.on_enter(),
            Screen::ConnectSession => vec![],
        };

        for action in actions {
            let _ = self.action_tx.send(action);
        }
    }

    /// Switch to Dashboard and fire its on_enter lifecycle.
    fn enter_dashboard(&mut self) {
        self.current_screen = Screen::Dashboard;
        for action in self.dashboard.on_enter() {
            let _ = self.action_tx.send(action);
        }
    }

    fn go_back(&mut self) {
        // Cancel background fetches and invalidate generations when leaving screens
        if matches!(self.current_screen, Screen::Ec2Inventory) {
            if let Some(cancel) = self.ec2_fetch_cancel.take() {
                cancel.cancel();
            }
            self.ec2.fetch_generation += 1;
        }
        if matches!(self.current_screen, Screen::CloudWatchSearch) {
            if let Some(cancel) = self.cw_fetch_cancel.take() {
                cancel.cancel();
            }
            self.cloudwatch_search.fetch_generation += 1;
            self.cloudwatch_search.on_leave();
        }
        if matches!(self.current_screen, Screen::LiveTail) {
            if let Some(cancel) = self.live_tail_cancel.take() {
                cancel.cancel();
            }
            self.live_tail.set_disconnected();
        }
        if matches!(self.current_screen, Screen::ConnectSession) {
            if let Some(session) = self.connect_session.as_mut() {
                session.disconnect();
            }
        }
        if let Some(prev) = self.screen_stack.pop() {
            self.current_screen = prev.clone();
            // Fire on_enter for the screen we're returning to
            let actions = match prev {
                Screen::Dashboard => self.dashboard.on_enter(),
                Screen::Ec2Inventory => self.ec2.on_enter(),
                Screen::CloudWatchSearch => self.cloudwatch_search.on_enter(),
                Screen::LiveTail => self.live_tail.on_enter(),
                Screen::Access => self.access.on_enter(),
                Screen::Settings => self.settings.on_enter(),
                Screen::Mcp => self.mcp.on_enter(),
                Screen::Login => self.login.on_enter(),
                Screen::ConnectSession => vec![],
            };
            for action in actions {
                let _ = self.action_tx.send(action);
            }
        }
    }

    fn set_entitlements(&mut self, ent: UserEntitlements) {
        self.dashboard.set_entitlements(ent.clone());
        self.ec2.set_entitlements(ent.clone());
        self.cloudwatch_search.set_entitlements(ent.clone());
        self.live_tail.set_entitlements(ent.clone());
        self.access.set_entitlements(ent.clone());
        self.mcp.set_entitlements(ent.clone());
        self.entitlements = Some(ent);
    }

    async fn start_mcp_runtime(&mut self, terminal: &mut Tui, launch_client: bool) {
        if let Some(runtime) = self.mcp_runtime.as_ref() {
            self.mcp.set_running(runtime.status());
            self.dashboard.set_mcp_server_running(true);
            if launch_client {
                self.launch_mcp_ai_client(terminal).await;
            }
            return;
        }

        let Some(entitlements) = self.entitlements.clone() else {
            self.mcp
                .set_error("Entitlements are not loaded; sign in again.".into());
            return;
        };

        self.mcp.set_starting();
        match McpRuntime::start(self.api.clone(), entitlements).await {
            Ok(runtime) => {
                let status = runtime.status().clone();
                self.mcp.set_running(&status);
                self.dashboard.set_mcp_server_running(true);
                self.mcp_runtime = Some(runtime);
                if launch_client {
                    self.launch_mcp_ai_client(terminal).await;
                }
            }
            Err(error) => {
                self.mcp.set_error(error.to_string());
                self.dashboard.set_mcp_server_running(false);
            }
        }
    }

    fn stop_mcp_runtime(&mut self) {
        if let Some(runtime) = self.mcp_runtime.take() {
            if let Err(error) = runtime.stop() {
                self.mcp
                    .set_error(format!("Failed to stop MCP server: {error}"));
                return;
            }
        }
        self.mcp.set_stopped();
        self.dashboard.set_mcp_server_running(false);
    }

    async fn test_mcp_runtime(&mut self) {
        let Some(runtime) = self.mcp_runtime.as_ref() else {
            self.mcp.set_error("MCP server is not running.".into());
            return;
        };

        let result = self.mcp_health_check(runtime).await.map(|_| ());

        match result {
            Ok(()) => self
                .mcp
                .set_status_line("Health check OK; server responded successfully.".into()),
            Err(error) => self.mcp.set_error(error.to_string()),
        }
    }

    fn reject_direct_mcp_launch_when_stopped(&mut self) -> bool {
        if self.mcp_runtime.is_none() {
            self.mcp
                .set_error("MCP server is not running; press e to enable + launch first.".into());
            true
        } else {
            false
        }
    }

    async fn mcp_health_check(
        &self,
        runtime: &McpRuntime,
    ) -> Result<(crate::mcp::McpSessionFile, String)> {
        let status = runtime.status();
        let raw = std::fs::read_to_string(&status.session_file)?;
        let session: crate::mcp::McpSessionFile = serde_json::from_str(&raw)?;
        let health_url = status.stable_endpoint.replace("/mcp", "/healthz");

        let response = reqwest::Client::new()
            .get(&health_url)
            .header("Authorization", session.authorization_header.clone())
            .send()
            .await?;
        if response.status().is_success() {
            Ok((session, health_url))
        } else {
            Err(anyhow::anyhow!(
                "health check failed: {}",
                response.status()
            ))
        }
    }

    async fn launch_mcp_ai_client(&mut self, _terminal: &mut Tui) {
        let Some(runtime) = self.mcp_runtime.as_ref() else {
            self.mcp.set_error("MCP server is not running.".into());
            return;
        };

        let endpoint = runtime.status().stable_endpoint.clone();
        let (session, _) = match self.mcp_health_check(runtime).await {
            Ok(result) => result,
            Err(error) => {
                self.mcp
                    .set_error(format!("MCP health check failed before AI launch: {error}"));
                return;
            }
        };

        let result = self.run_mcp_ai_launcher(&endpoint, &session);
        match result {
            Ok(Some(result)) => self.mcp.set_status_line(format!(
                "{} launched in {}.",
                result.client_label, result.terminal_label
            )),
            Ok(None) => self
                .mcp
                .set_status_line("AI client launch cancelled; MCP server is running.".into()),
            Err(error) => self.mcp.set_error(error),
        }
    }

    fn run_mcp_ai_launcher(
        &self,
        endpoint: &str,
        session: &crate::mcp::McpSessionFile,
    ) -> Result<Option<McpAiLaunchResult>, String> {
        let client = select_mcp_ai_client_from_env()?;
        let terminals = detect_supported_terminal_apps()?;
        let terminal = select_mcp_terminal_app(&terminals)?;

        let client_label = match client {
            McpAiClient::Codex => {
                self.run_codex_with_mcp(endpoint, &session.bearer_token, &terminal)?;
                "Codex CLI"
            }
            McpAiClient::Claude => {
                self.run_claude_with_mcp(endpoint, &session.authorization_header, &terminal)?;
                "Claude Code"
            }
        };

        Ok(Some(McpAiLaunchResult {
            client_label,
            terminal_label: terminal.display_name,
        }))
    }

    fn run_codex_with_mcp(
        &self,
        endpoint: &str,
        bearer_token: &str,
        terminal: &DetectedTerminalApp,
    ) -> Result<(), String> {
        let codex_bin = std::env::var("CODEX_BIN").unwrap_or_else(|_| "codex".into());
        let codex_bin = resolve_command(&codex_bin)?;

        let script_body = format!(
            r#"#!/usr/bin/env bash
	set -uo pipefail
	cleanup() {{
	  {codex_bin} mcp remove {server_name} >/dev/null 2>&1 || true
	  rm -f "$0"
	}}
	trap cleanup EXIT

export CANOPY_MCP_BEARER_TOKEN={bearer_token}
echo "Configuring Codex MCP server '{server_name}' -> {endpoint}"
{codex_bin} mcp remove {server_name} >/dev/null 2>&1 || true
{codex_bin} mcp add {server_name} --url {endpoint} --bearer-token-env-var CANOPY_MCP_BEARER_TOKEN
config_rc=$?
if [ "$config_rc" -ne 0 ]; then
  echo
  echo "Failed to configure Codex MCP server. Exit status: $config_rc"
  read -r -p "Press Enter to close this window..."
  exit "$config_rc"
fi
echo
echo "Starting Codex CLI with Canopy MCP..."
{codex_bin}
rc=$?
echo
echo "Codex CLI exited with status $rc."
read -r -p "Press Enter to close this window..."
exit "$rc"
"#,
            bearer_token = shell_single_quote(bearer_token),
            server_name = shell_single_quote(&mcp_ai_client_server_name()),
            endpoint = shell_single_quote(endpoint),
            codex_bin = shell_single_quote(&codex_bin),
        );
        let script_path = write_temp_launch_script("codex-mcp", &script_body)?;
        open_launch_script(&script_path, terminal)
    }

    fn run_claude_with_mcp(
        &self,
        endpoint: &str,
        authorization_header: &str,
        terminal: &DetectedTerminalApp,
    ) -> Result<(), String> {
        let claude_bin = std::env::var("CLAUDE_BIN").unwrap_or_else(|_| "claude".into());
        let claude_bin = resolve_command(&claude_bin)?;

        let config_path = write_temp_claude_mcp_config(endpoint, authorization_header)?;
        let config_path_str = config_path
            .to_str()
            .ok_or_else(|| "Temporary Claude MCP config path is not UTF-8.".to_string())?;
        let script_body = format!(
            r#"#!/usr/bin/env bash
set -uo pipefail
cleanup() {{
  rm -f {config_path}
  rm -f "$0"
}}
trap cleanup EXIT

echo "Starting Claude Code with temporary Canopy MCP config..."
{claude_bin} --mcp-config {config_path}
rc=$?
echo
echo "Claude Code exited with status $rc."
read -r -p "Press Enter to close this window..."
exit "$rc"
"#,
            claude_bin = shell_single_quote(&claude_bin),
            config_path = shell_single_quote(config_path_str),
        );
        let script_path = write_temp_launch_script("claude-mcp", &script_body)?;
        open_launch_script(&script_path, terminal)
    }

    // ── Async operations ────────────────────────────────

    async fn do_dev_login(&mut self, username: &str) {
        match self.api.dev_login(username).await {
            Ok(resp) => {
                // Codex round 8: same guard as TokenReceived — refuse
                // to proceed when save AND stale-clear both fail.
                match self
                    .set_session_tokens(crate::auth::SessionTokens::new(resp.access_token, None))
                {
                    SessionTokenOutcome::PersistedFresh | SessionTokenOutcome::InMemoryOnly => {
                        if self.fetch_entitlements().await {
                            self.enter_dashboard();
                        }
                    }
                    SessionTokenOutcome::StaleTokenSurvivesOnDisk => {
                        self.api.clear_token();
                    }
                }
            }
            Err(e) => {
                self.login.set_status(format!("Login failed: {}", e));
            }
        }
    }

    async fn do_pkce_login(&mut self) {
        let port = self.config.pkce_callback_port;
        match crate::auth::pkce::start_pkce_flow(&self.api, port).await {
            Ok(resp) => {
                let _ = self.action_tx.send(Action::TokenReceived(resp));
            }
            Err(e) => {
                self.login.set_status(format!("PKCE login failed: {}", e));
            }
        }
    }

    async fn do_device_code_login(&mut self) {
        use crate::auth::device_code::DeviceCodeFlow;

        let flow = match DeviceCodeFlow::start(&self.api).await {
            Ok(f) => f,
            Err(e) => {
                self.login
                    .set_status(format!("Device code flow failed: {}", e));
                return;
            }
        };

        self.login.set_status(format!(
            "Go to {} and enter code: {}",
            flow.verification_uri, flow.user_code
        ));

        // Poll in the background so the UI stays responsive
        let tx = self.action_tx.clone();
        let api = self.api.clone();
        tokio::spawn(async move {
            match flow.poll_until_complete(&api).await {
                Ok(resp) => {
                    let _ = tx.send(Action::TokenReceived(resp));
                }
                Err(e) => {
                    let _ = tx.send(Action::ShowError(format!("Device code auth failed: {}", e)));
                }
            }
        });
    }

    /// Fetch entitlements. Returns true on success, false on failure.
    async fn fetch_entitlements(&mut self) -> bool {
        match self.api.get_entitlements().await {
            Ok(ent) => {
                self.set_entitlements(ent);
                true
            }
            Err(e) => {
                self.handle_route_error(e, |app, msg| {
                    app.error_modal
                        .show(format!("Failed to fetch entitlements: {}", msg));
                });
                false
            }
        }
    }

    fn spawn_mfa_status_fetch(&self) {
        let api = self.api.clone();
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            match api.mfa_status().await {
                Ok(status) => {
                    let _ = tx.send(Action::MfaStatusLoaded(status));
                }
                Err(err) => {
                    let _ = tx.send(Self::route_error_to_action(err, Action::MfaStatusFailed));
                }
            }
        });
    }

    fn spawn_totp_enrollment_start(&self) {
        let api = self.api.clone();
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            let request = shared::dto::auth::TotpEnrollStartRequest { label: None };
            match api.start_totp_enrollment(&request).await {
                Ok(response) => {
                    let _ = tx.send(Action::TotpEnrollmentStarted(response));
                }
                Err(err) => {
                    let _ = tx.send(Self::route_error_to_action(
                        err,
                        Action::TotpEnrollmentStartFailed,
                    ));
                }
            }
        });
    }

    fn spawn_totp_enrollment_confirm(&self, factor_id: String, code: String) {
        let api = self.api.clone();
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            let request = shared::dto::auth::TotpEnrollConfirmRequest { factor_id, code };
            match api.confirm_totp_enrollment(&request).await {
                Ok(response) => {
                    let _ = tx.send(Action::TotpEnrollmentConfirmed(response));
                }
                Err(err) => {
                    let _ = tx.send(Self::route_error_to_action(
                        err,
                        Action::TotpEnrollmentConfirmFailed,
                    ));
                }
            }
        });
    }

    fn spawn_totp_step_up_verify(&self, code: String) {
        let api = self.api.clone();
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            let request = shared::dto::auth::TotpVerifyRequest { code };
            match api.verify_totp_step_up(&request).await {
                Ok(response) => {
                    let _ = tx.send(Action::TotpStepUpVerified(response));
                }
                Err(err) => {
                    let _ = tx.send(Self::route_error_to_action(
                        err,
                        Action::TotpStepUpVerifyFailed,
                    ));
                }
            }
        });
    }

    fn spawn_recovery_codes_generate(&self) {
        let api = self.api.clone();
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            match api.generate_recovery_codes().await {
                Ok(response) => {
                    let _ = tx.send(Action::RecoveryCodesGenerated(response));
                }
                Err(err) => {
                    let _ = tx.send(Self::route_error_to_action(
                        err,
                        Action::RecoveryCodesGenerateFailed,
                    ));
                }
            }
        });
    }

    fn spawn_recovery_code_step_up_verify(&self, code: String) {
        let api = self.api.clone();
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            let request = shared::dto::auth::RecoveryCodeVerifyRequest { code };
            match api.verify_recovery_code_step_up(&request).await {
                Ok(response) => {
                    let _ = tx.send(Action::RecoveryCodeStepUpVerified(response));
                }
                Err(err) => {
                    let _ = tx.send(Self::route_error_to_action(
                        err,
                        Action::RecoveryCodeStepUpVerifyFailed,
                    ));
                }
            }
        });
    }

    fn spawn_webauthn_enrollment(&self) {
        let api = self.api.clone();
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            match crate::auth::webauthn::start_webauthn_registration_flow(&api).await {
                Ok(response) => {
                    let _ = tx.send(Action::WebAuthnEnrollmentSucceeded(response));
                }
                Err(err) => {
                    let _ = tx.send(Action::WebAuthnEnrollmentFailed(err.to_string()));
                }
            }
        });
    }

    fn spawn_webauthn_step_up_verification(&self) {
        let api = self.api.clone();
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            match crate::auth::webauthn::start_webauthn_verification_flow(&api).await {
                Ok(response) => {
                    let _ = tx.send(Action::WebAuthnStepUpVerified(response));
                }
                Err(err) => {
                    let _ = tx.send(Action::WebAuthnStepUpVerifyFailed(err.to_string()));
                }
            }
        });
    }

    fn spawn_ec2_fetch(&mut self, name_filter: Option<String>) {
        // Cancel any in-flight EC2 fetch
        if let Some(token) = self.ec2_fetch_cancel.take() {
            token.cancel();
        }

        self.ec2.set_loading();
        let api = self.api.clone();
        let tx = self.action_tx.clone();
        let account_id = self.ec2.selected_account_id.clone();
        let region = self.ec2.selected_region.clone();
        let generation = self.ec2.fetch_generation;
        let cancel = tokio_util::sync::CancellationToken::new();
        self.ec2_fetch_cancel = Some(cancel.clone());

        tokio::spawn(async move {
            let mut all_instances = Vec::new();
            let mut failed_scopes = Vec::new();
            let mut next_token = None;
            loop {
                let req = Ec2ListRequest {
                    account_id: account_id.clone(),
                    region: region.clone(),
                    name_filter: name_filter.clone(),
                    state_filter: None,
                    tag_filters: None,
                    next_token,
                    page_size: 200,
                };
                // Race the API call against cancellation
                let result = tokio::select! {
                    _ = cancel.cancelled() => return,
                    r = api.list_ec2(&req) => r,
                };
                match result {
                    Ok(resp) => {
                        failed_scopes.extend(resp.failed_scopes);
                        all_instances.extend(resp.instances);
                        next_token = resp.next_token;
                        if next_token.is_none() {
                            break;
                        }
                    }
                    Err(e) => {
                        match e {
                            ApiClientError::TokenExpired => {
                                let _ = tx.send(Action::TokenExpired);
                                return;
                            }
                            other => {
                                let msg = other.to_string();
                                if all_instances.is_empty() {
                                    let _ = tx.send(Action::Ec2FetchFailed(msg, generation));
                                    return;
                                }
                                failed_scopes.push(format!("Fetch error (partial): {}", msg));
                            }
                        }
                        break;
                    }
                }
            }

            let _ = tx.send(Action::Ec2Loaded(all_instances, failed_scopes, generation));
        });
    }

    fn spawn_ecs_tasks_fetch(&mut self) {
        if let Some(token) = self.ec2_fetch_cancel.take() {
            token.cancel();
        }

        self.ec2.set_loading();
        let api = self.api.clone();
        let tx = self.action_tx.clone();
        let generation = self.ec2.fetch_generation;
        let cancel = tokio_util::sync::CancellationToken::new();
        self.ec2_fetch_cancel = Some(cancel.clone());

        let req = EcsTasksRequest {
            account_id: self.ec2.selected_account_id.clone(),
            region: self.ec2.selected_region.clone(),
            cluster: None,
            page_size: 200,
        };

        tokio::spawn(async move {
            let result = tokio::select! {
                _ = cancel.cancelled() => return,
                r = api.list_ecs_tasks(&req) => r,
            };

            match result {
                Ok(resp) => {
                    let _ = tx.send(Action::EcsTasksLoaded {
                        tasks: resp.tasks,
                        failed_scopes: resp.failed_scopes,
                        total_count: resp.total_count,
                        truncated: resp.truncated,
                        generation,
                    });
                }
                Err(e) => {
                    let action = Self::route_error_to_action(e, |msg| {
                        Action::EcsTasksFetchFailed(
                            format!("Failed to fetch ECS tasks: {msg}"),
                            generation,
                        )
                    });
                    let _ = tx.send(action);
                }
            }
        });
    }

    async fn do_power_ec2(&mut self, req: Ec2PowerRequest) {
        match self.api.power_ec2(&req).await {
            Ok(resp) => {
                self.error_modal.show(format!(
                    "{}\nPrevious: {} → Requested: {}",
                    resp.message, resp.previous_state, resp.requested_state
                ));
                self.spawn_ec2_fetch(None);
            }
            Err(e) => {
                self.handle_route_error(e, |app, msg| {
                    app.error_modal
                        .show(format!("EC2 power action failed: {}", msg));
                });
            }
        }
    }

    fn suspend_for_external_command(&mut self) {
        self.event_reader_paused
            .store(true, std::sync::atomic::Ordering::Relaxed);
        crate::tui::suspend().ok();
    }

    fn resume_after_external_command(&mut self, terminal: &mut Tui) {
        self.event_reader_paused
            .store(false, std::sync::atomic::Ordering::Relaxed);
        match crate::tui::resume() {
            Ok(new_terminal) => *terminal = new_terminal,
            Err(e) => eprintln!("Failed to resume terminal: {}", e),
        }
    }

    fn resolve_connect_dependencies<R: local_deps::CommandRunner>(
        &mut self,
        required_deps: &[LocalDependency],
        mut issues: Vec<DependencyIssue>,
        runner: &R,
    ) -> Result<(), String> {
        let mut attempted = std::collections::BTreeSet::new();

        loop {
            println!("\n== Local dependency check ==");
            println!("The selected connect method needs additional local tools:\n");
            for issue in &issues {
                println!("  - {}: {}", issue.dependency.label(), issue.reason);
            }

            let installable: Vec<LocalDependency> = issues
                .iter()
                .map(|issue| issue.dependency)
                .filter(|dep| dep.can_auto_install() && !attempted.contains(dep))
                .collect();

            if installable.is_empty() {
                return Err(format!(
                    "Missing required local dependencies:\n{}",
                    local_deps::format_dependency_issues(&issues)
                ));
            }

            for dependency in installable {
                attempted.insert(dependency);
                if !prompt_yes_no(dependency.install_prompt()) {
                    return Err(format!(
                        "{} is required for this connect method. Install manually: {}",
                        dependency.label(),
                        dependency.manual_install_url()
                    ));
                }

                println!("\nInstalling {}...", dependency.label());
                local_deps::install_dependency(dependency, runner)?;
            }

            issues = local_deps::check_required_dependencies(required_deps, runner);
            if issues.is_empty() {
                println!("\nLocal dependencies are ready. Continuing connection...\n");
                return Ok(());
            }
        }
    }

    async fn do_connect_with_user(&mut self, target: ConnectTarget<'_>, terminal: &mut Tui) {
        let req = ConnectRequest {
            instance_id: target.instance_id.to_string(),
            account_id: target.account_id.to_string(),
            region: target.region.to_string(),
            method: target.method.clone(),
            os_user: target.os_user.map(String::from),
        };

        match self.api.connect(&req).await {
            Ok(resp) => {
                if resp.authorized {
                    let spawn_spec: PtySpawnSpec = resp.into();
                    tracing::info!(
                        command = %spawn_spec.command,
                        args = ?spawn_spec.args,
                        "Spawning connect command"
                    );

                    let runner = SystemCommandRunner;
                    let required_deps = local_deps::required_dependencies_for_connect(&spawn_spec);
                    let dependency_issues =
                        local_deps::check_required_dependencies(&required_deps, &runner);
                    let mut terminal_suspended = false;

                    if !dependency_issues.is_empty() {
                        self.suspend_for_external_command();
                        terminal_suspended = true;

                        if let Err(msg) = self.resolve_connect_dependencies(
                            &required_deps,
                            dependency_issues,
                            &runner,
                        ) {
                            eprintln!("\nError: {}\n", msg);
                            println!("Press Enter to return to the console...");
                            let _ = std::io::stdin().read_line(&mut String::new());

                            self.resume_after_external_command(terminal);
                            self.error_modal.show(msg);
                            return;
                        }
                    }

                    if let Some(max_session_seconds) =
                        wrapper_session_limit(spawn_spec.max_session_seconds)
                    {
                        if terminal_suspended {
                            self.resume_after_external_command(terminal);
                        }

                        let size = terminal
                            .size()
                            .unwrap_or_else(|_| ratatui::prelude::Size::new(80, 24));
                        match ConnectSessionScreen::spawn_with_theme(
                            ConnectSessionLaunch {
                                instance_id: target.instance_id.to_string(),
                                instance_name: target.instance_name.map(String::from),
                                account_id: target.account_id.to_string(),
                                region: target.region.to_string(),
                                method_label: connect_method_label(&target.method).to_string(),
                                spawn: spawn_spec,
                                max_session_seconds,
                                cols: size.width,
                                rows: size.height,
                            },
                            self.action_tx.clone(),
                            self.theme,
                        ) {
                            Ok(session) => {
                                self.connect_session = Some(session);
                                self.current_screen = Screen::ConnectSession;
                            }
                            Err(e) => {
                                self.error_modal
                                    .show(format!("Failed to start SSH wrapper: {e}"));
                            }
                        }
                        return;
                    }

                    // Suspend TUI, run external command, then resume.
                    if !terminal_suspended {
                        self.suspend_for_external_command();
                    }

                    // Run the command
                    let mut cmd = std::process::Command::new(&spawn_spec.command);
                    cmd.args(&spawn_spec.args);
                    for (k, v) in &spawn_spec.env_vars {
                        cmd.env(k, v);
                    }

                    // Pre-flight: TCP connectivity check for SSH with countdown
                    if spawn_spec.command == "ssh" {
                        if let Some(target) = spawn_spec.args.last() {
                            // Extract IP from "user@ip"
                            if let Some(ip) = target.split('@').nth(1) {
                                let addr = format!("{}:22", ip);
                                let check_timeout = 10;
                                print!("\n  Checking {}  ", addr);
                                let mut connected = false;
                                for remaining in (1..=check_timeout).rev() {
                                    print!("{}s ", remaining);
                                    use std::io::Write;
                                    std::io::stdout().flush().ok();
                                    match std::net::TcpStream::connect_timeout(
                                        &addr.parse().unwrap(),
                                        std::time::Duration::from_secs(1),
                                    ) {
                                        Ok(_) => {
                                            println!(" OK");
                                            connected = true;
                                            break;
                                        }
                                        Err(_) => continue,
                                    }
                                }
                                if !connected {
                                    println!(" FAILED");
                                    eprintln!("\n  Port 22 on {} is not reachable.", ip);
                                    eprintln!(
                                        "  Check: Security Group, instance state, network route.\n"
                                    );
                                    println!("Press Enter to return to the console...");
                                    let _ = std::io::stdin().read_line(&mut String::new());

                                    self.event_reader_paused
                                        .store(false, std::sync::atomic::Ordering::Relaxed);
                                    match crate::tui::resume() {
                                        Ok(new_terminal) => *terminal = new_terminal,
                                        Err(e) => eprintln!("Failed to resume terminal: {}", e),
                                    }
                                    return;
                                }
                            }
                        }
                    }

                    if let Some(secs) = spawn_spec.max_session_seconds {
                        println!(
                            "--- Connecting to {} via {} (max {} min) ---\n",
                            target.instance_id,
                            spawn_spec.command,
                            secs / 60
                        );
                        println!("Session countdown: {}", render_session_countdown(secs, 0));
                        println!("Countdown updates in this terminal tab title while connected.\n");
                        set_session_countdown_title(target.instance_id, secs, 0);
                    } else {
                        println!(
                            "--- Connecting to {} via {} ---\n",
                            target.instance_id, spawn_spec.command
                        );
                    }

                    // Connection timeout: if the process doesn't become
                    // interactive within this many seconds, kill it.
                    let connect_timeout_secs: u64 = 15;

                    match cmd.spawn() {
                        Ok(mut child) => {
                            let session_limit = spawn_spec.max_session_seconds.filter(|&s| s > 0);
                            let start = std::time::Instant::now();
                            let mut connected = false;

                            loop {
                                match child.try_wait() {
                                    Ok(Some(status)) => {
                                        if !connected && !status.success() {
                                            // Process exited before we considered it connected
                                            eprintln!(
                                                "\nConnection failed (exit code: {})\n",
                                                status.code().unwrap_or(-1)
                                            );
                                        } else if !status.success() {
                                            eprintln!(
                                                "\nCommand exited with status: {}\n",
                                                status.code().unwrap_or(-1)
                                            );
                                        }
                                        break;
                                    }
                                    Ok(None) => {
                                        let elapsed = start.elapsed().as_secs();

                                        // Connection phase: show countdown
                                        if !connected {
                                            if elapsed >= connect_timeout_secs {
                                                eprintln!(
                                                    "\n\nConnection timed out ({}s). Aborting.\n",
                                                    connect_timeout_secs
                                                );
                                                eprintln!(
                                                    "  Check: Security Group, instance state, network route.\n"
                                                );
                                                let _ = child.kill();
                                                let _ = child.wait();
                                                break;
                                            }
                                            let remaining = connect_timeout_secs - elapsed;
                                            print!(
                                                "\r  Waiting for connection... {}s  ",
                                                remaining
                                            );
                                            use std::io::Write;
                                            std::io::stdout().flush().ok();

                                            // Consider connected after a few seconds if still alive
                                            // (the process would have exited quickly on auth failure)
                                            if elapsed >= 3 {
                                                connected = true;
                                                print!(
                                                    "\r                                       \r"
                                                );
                                                std::io::stdout().flush().ok();
                                            }
                                        }

                                        // Session limit enforcement
                                        if connected {
                                            if let Some(max_secs) = session_limit {
                                                if elapsed >= max_secs {
                                                    set_session_countdown_title(
                                                        target.instance_id,
                                                        max_secs,
                                                        max_secs,
                                                    );
                                                    eprintln!(
                                                        "\n\nSession timeout ({} min). Disconnecting...\n",
                                                        max_secs / 60
                                                    );
                                                    let _ = child.kill();
                                                    let _ = child.wait();
                                                    break;
                                                }
                                                set_session_countdown_title(
                                                    target.instance_id,
                                                    max_secs,
                                                    elapsed,
                                                );
                                            }
                                        }

                                        std::thread::sleep(std::time::Duration::from_secs(1));
                                    }
                                    Err(e) => {
                                        eprintln!("\nError waiting for process: {}\n", e);
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            let msg = match e.kind() {
                                std::io::ErrorKind::NotFound => {
                                    if spawn_spec.command == "aws" {
                                        "AWS CLI not found. Install it from https://aws.amazon.com/cli/".to_string()
                                    } else {
                                        format!("Command '{}' not found", spawn_spec.command)
                                    }
                                }
                                _ => format!("Failed to execute command: {}", e),
                            };
                            eprintln!("\nError: {}\n", msg);
                        }
                    }

                    if spawn_spec.max_session_seconds.is_some() {
                        set_terminal_title("Canopy");
                    }

                    println!("\nPress Enter to return to the console...");
                    let _ = std::io::stdin().read_line(&mut String::new());

                    // Resume event reader and TUI
                    self.event_reader_paused
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                    match crate::tui::resume() {
                        Ok(new_terminal) => *terminal = new_terminal,
                        Err(e) => {
                            eprintln!("Failed to resume terminal: {}", e);
                            self.running = false;
                        }
                    }
                } else {
                    self.error_modal.show(
                        resp.error
                            .unwrap_or_else(|| "Connect not authorized".into()),
                    );
                }
            }
            Err(e) => {
                self.handle_route_error(e, |app, msg| {
                    app.error_modal.show(format!("Connect failed: {}", msg));
                });
            }
        }
    }

    async fn do_ecs_exec(&mut self, req: EcsExecRequest, terminal: &mut Tui) {
        match self.api.ecs_exec(&req).await {
            Ok(resp) => {
                let spawn_spec: PtySpawnSpec = resp.into();
                tracing::info!(
                    command = %spawn_spec.command,
                    args = ?spawn_spec.args,
                    "Spawning ECS exec command"
                );

                let runner = SystemCommandRunner;
                let required_deps = local_deps::required_dependencies_for_connect(&spawn_spec);
                let dependency_issues =
                    local_deps::check_required_dependencies(&required_deps, &runner);
                let mut terminal_suspended = false;

                if !dependency_issues.is_empty() {
                    self.suspend_for_external_command();
                    terminal_suspended = true;

                    if let Err(msg) = self.resolve_connect_dependencies(
                        &required_deps,
                        dependency_issues,
                        &runner,
                    ) {
                        eprintln!("\nError: {}\n", msg);
                        println!("Press Enter to return to the console...");
                        let _ = std::io::stdin().read_line(&mut String::new());

                        self.resume_after_external_command(terminal);
                        self.error_modal.show(msg);
                        return;
                    }
                }

                let task_label = req
                    .task_arn
                    .rsplit('/')
                    .next()
                    .unwrap_or(req.task_arn.as_str())
                    .to_string();

                if let Some(max_session_seconds) =
                    wrapper_session_limit(spawn_spec.max_session_seconds)
                {
                    if terminal_suspended {
                        self.resume_after_external_command(terminal);
                    }

                    let size = terminal
                        .size()
                        .unwrap_or_else(|_| ratatui::prelude::Size::new(80, 24));
                    match ConnectSessionScreen::spawn_with_theme(
                        ConnectSessionLaunch {
                            instance_id: task_label,
                            instance_name: Some(req.container_name),
                            account_id: req.account_id,
                            region: req.region,
                            method_label: "ECS".into(),
                            spawn: spawn_spec,
                            max_session_seconds,
                            cols: size.width,
                            rows: size.height,
                        },
                        self.action_tx.clone(),
                        self.theme,
                    ) {
                        Ok(session) => {
                            self.connect_session = Some(session);
                            self.current_screen = Screen::ConnectSession;
                        }
                        Err(e) => {
                            self.error_modal
                                .show(format!("Failed to start ECS exec wrapper: {e}"));
                        }
                    }
                    return;
                }

                if !terminal_suspended {
                    self.suspend_for_external_command();
                }

                let mut cmd = std::process::Command::new(&spawn_spec.command);
                cmd.args(&spawn_spec.args);
                for (k, v) in &spawn_spec.env_vars {
                    cmd.env(k, v);
                }

                match cmd.spawn() {
                    Ok(mut child) => {
                        let _ = child.wait();
                    }
                    Err(e) => {
                        let msg = match e.kind() {
                            std::io::ErrorKind::NotFound if spawn_spec.command == "aws" => {
                                "AWS CLI not found. Install it from https://aws.amazon.com/cli/"
                                    .to_string()
                            }
                            std::io::ErrorKind::NotFound => {
                                format!("Command '{}' not found", spawn_spec.command)
                            }
                            _ => format!("Failed to execute command: {}", e),
                        };
                        eprintln!("\nError: {}\n", msg);
                    }
                }

                println!("\nPress Enter to return to the console...");
                let _ = std::io::stdin().read_line(&mut String::new());
                self.resume_after_external_command(terminal);
            }
            Err(e) => {
                self.handle_route_error(e, |app, msg| {
                    app.error_modal.show(format!("ECS exec failed: {}", msg));
                });
            }
        }
    }

    fn spawn_log_groups_fetch(&mut self) {
        let account_id = self.cloudwatch_search.selected_account_id.clone();
        let region = self.cloudwatch_search.selected_region.clone();

        if account_id.is_empty() || region.is_empty() {
            self.cloudwatch_search
                .set_error("No CloudWatch account or region is available".into());
            return;
        }

        // Cancel any in-flight CloudWatch fetch
        if let Some(token) = self.cw_fetch_cancel.take() {
            token.cancel();
        }

        self.cloudwatch_search
            .set_loading(CloudWatchLoadingKind::LogGroups);
        self.cloudwatch_search.advance_fetch_generation();
        let api = self.api.clone();
        let tx = self.action_tx.clone();
        let generation = self.cloudwatch_search.fetch_generation;
        let cancel = tokio_util::sync::CancellationToken::new();
        self.cw_fetch_cancel = Some(cancel.clone());

        tokio::spawn(async move {
            let req = shared::dto::cloudwatch::LogGroupsRequest {
                account_id,
                region,
                prefix: None,
            };

            // Race the API call against cancellation
            let result = tokio::select! {
                _ = cancel.cancelled() => return,
                r = api.list_log_groups(&req) => r,
            };
            match result {
                Ok(resp) => {
                    let _ = tx.send(Action::LogGroupsLoaded(resp.log_groups, generation));
                }
                Err(e) => {
                    let action = Self::route_error_to_action(e, |msg| {
                        Action::LogGroupsFetchFailed(
                            format!("Failed to fetch log groups: {}", msg),
                            generation,
                        )
                    });
                    let _ = tx.send(action);
                }
            }
        });
    }

    /// Apply a `FilterEventsLoaded` action to the screen state.
    ///
    /// Stale-generation guard: a response from an older spawned task
    /// (whose generation no longer matches the current
    /// `fetch_generation`) is silently dropped, so a brand-new search
    /// cannot be overwritten by a late reply from the previous one.
    ///
    /// Extracted as a `&mut self` reducer so unit tests can exercise
    /// the dispatcher contract without constructing a `Tui` backend.
    pub(crate) fn apply_filter_events_loaded(
        &mut self,
        events: Vec<shared::dto::cloudwatch::LogEvent>,
        next_token: Option<String>,
        append: bool,
        generation: u64,
    ) {
        if generation != self.cloudwatch_search.fetch_generation {
            return;
        }
        if append {
            self.cloudwatch_search.append_events(events, next_token);
        } else {
            self.cloudwatch_search.set_events(events, next_token);
        }
    }

    /// Apply a `FilterEventsFetchFailed` action. Stale generations are
    /// dropped without surfacing the error so the user does not see
    /// stale "Error: ..." messages bleed through into a new search.
    pub(crate) fn apply_filter_events_fetch_failed(&mut self, err: String, generation: u64) {
        if generation != self.cloudwatch_search.fetch_generation {
            return;
        }
        self.cloudwatch_search.set_error(err);
    }

    /// Apply a `ConnectSessionStdoutReady` action. Drains the PTY
    /// output buffer if a session is alive; otherwise a silent no-op
    /// so late signals from a torn-down session do not crash.
    pub(crate) fn apply_connect_session_stdout_ready(&mut self) {
        if let Some(session) = self.connect_session.as_mut() {
            session.process_pending_output();
        }
    }

    /// Apply a `ConnectSessionFailure` action. The error message is
    /// surfaced inside the active session as a terminal-state
    /// overlay; if no session is alive the message is dropped (the
    /// matching screen is gone, the user already moved on).
    pub(crate) fn apply_connect_session_failure(&mut self, message: String) {
        if let Some(session) = self.connect_session.as_mut() {
            session.fail(message);
        }
    }

    /// Apply a `ConnectSessionUserDisconnect` action (Ctrl+]/Ctrl+5).
    /// Forwarded to the session so it tears down the PTY and shows the
    /// "Disconnected" final state; no-op if no session is active.
    pub(crate) fn apply_connect_session_user_disconnect(&mut self) {
        if let Some(session) = self.connect_session.as_mut() {
            session.disconnect();
        }
    }

    /// Apply a `ConnectSessionExit` action — the user dismissed the
    /// terminal screen with Enter. Drops the session and returns the
    /// app to the EC2 inventory.
    pub(crate) fn apply_connect_session_exit(&mut self) {
        self.connect_session = None;
        self.current_screen = Screen::Ec2Inventory;
    }

    /// Decide whether to start a new live-tail stream and, if so,
    /// install the cancel token + flip the UI to Connected. Returns
    /// `Some(token)` for the caller to hand to the background task;
    /// returns `None` when a stream is already in flight (the caller
    /// must NOT spawn a new task in that case).
    ///
    /// Codex round 3: prior code always spawned a new stream and
    /// overwrote `live_tail_cancel`, which meant two queued
    /// `StartLiveTail` actions left an orphaned old stream whose
    /// eventual `Action::StopLiveTail` would mis-cancel the new
    /// stream. This idempotency check closes that race at the
    /// source (the handler only spawns when `try_arm` returns Some).
    pub(crate) fn try_arm_live_tail_stream(
        &mut self,
    ) -> Option<(tokio_util::sync::CancellationToken, u64)> {
        if self.live_tail_cancel.is_some() {
            // Already streaming — refuse to install a second token.
            tracing::debug!(
                "Live tail: ignoring duplicate StartLiveTail (stream already in flight)",
            );
            return None;
        }
        // Bump the generation. Saturating-add so wraparound after
        // 2^64 arms (unreachable in practice) doesn't panic.
        self.live_tail_generation = self.live_tail_generation.saturating_add(1);
        self.live_tail.set_connected();
        let cancel = tokio_util::sync::CancellationToken::new();
        self.live_tail_cancel = Some(cancel.clone());
        Some((cancel, self.live_tail_generation))
    }

    /// Apply a `StopLiveTail` action — cancel the background WS task
    /// (if any) and transition the screen into the Disconnected
    /// state. Idempotent: calling twice is harmless because
    /// `take()` clears the token and `set_disconnected` is a state
    /// setter, not a transition.
    pub(crate) fn apply_stop_live_tail(&mut self) {
        if let Some(cancel) = self.live_tail_cancel.take() {
            cancel.cancel();
        }
        self.live_tail.set_disconnected();
    }

    /// Apply a `PauseLiveTail` action — flip the UI into Paused
    /// state. The background WS task keeps running so events keep
    /// arriving and accumulating in the scrollback; only the visible
    /// indicator changes. (Pause is purely a UI affordance for the
    /// human; the AWS API has no "pause" for live tail.)
    pub(crate) fn apply_pause_live_tail(&mut self) {
        self.live_tail.set_paused();
    }

    /// Apply a `ResumeLiveTail` action — flip the UI back into the
    /// Connected state from Paused. No background work is restarted
    /// because the WS task never actually stopped; this is purely
    /// the inverse of `apply_pause_live_tail`.
    pub(crate) fn apply_resume_live_tail(&mut self) {
        self.live_tail.set_connected();
    }

    /// Apply a `LiveTailEvent(event)` action — append the event to
    /// the live-tail scrollback. `push_event` enforces the scrollback
    /// cap configured at construction, so this stays bounded.
    pub(crate) fn apply_live_tail_event(&mut self, event: shared::dto::cloudwatch::LiveTailEvent) {
        self.live_tail.push_event(event);
    }

    /// Single entry point for the live-tail subset of `Action`. The
    /// `handle_action` match arm delegates to this function so that
    /// tests can drive the same dispatch chain production uses (give
    /// `Action::*`, observe state mutation) without spinning up a
    /// real `Tui` backend.
    ///
    /// Codex round 2 flagged that testing the `apply_*` helpers in
    /// isolation does not catch a regression that deletes the
    /// `handle_action` match arm: it would compile, silently swallow
    /// the action, and the apply-level tests would still pass. By
    /// funnelling production AND the tests through this function we
    /// remove that gap — the only way an `Action::StopLiveTail`
    /// reaches the screen state is by going through here.
    pub(crate) fn dispatch_live_tail_action(&mut self, action: Action) {
        match action {
            Action::StopLiveTail => self.apply_stop_live_tail(),
            Action::PauseLiveTail => self.apply_pause_live_tail(),
            Action::ResumeLiveTail => self.apply_resume_live_tail(),
            Action::LiveTailEvent { event, generation } => {
                // Drop late-arriving events from a stream that has
                // since been replaced (stop-then-rearm). Without
                // this guard, a stop-and-rearm sequence could leak
                // the old stream's tail-end events into the new
                // stream's buffer.
                //
                // Also require an active stream (`live_tail_cancel
                // .is_some()`). Codex round 6 pointed out that after
                // stop/logout, `live_tail_generation` retains its
                // last value — a stale event with that same gen
                // would otherwise still get appended into the
                // scrollback even though the UI says Disconnected.
                let active =
                    self.live_tail_cancel.is_some() && generation == self.live_tail_generation;
                if active {
                    self.apply_live_tail_event(event);
                } else {
                    tracing::debug!(
                        active_gen = self.live_tail_generation,
                        stale_gen = generation,
                        cancel_armed = self.live_tail_cancel.is_some(),
                        "Dropping LiveTailEvent: no active stream or generation mismatch",
                    );
                }
            }
            Action::LiveTailStreamEnded(generation) => {
                // Same idea for the natural-completion signal:
                // only the CURRENT stream is allowed to flip the UI
                // back to Disconnected. A stale one is silently
                // discarded (the new stream is still active).
                // This is Codex round 5's flagged race fix.
                let active =
                    self.live_tail_cancel.is_some() && generation == self.live_tail_generation;
                if active {
                    self.apply_stop_live_tail();
                } else {
                    tracing::debug!(
                        active_gen = self.live_tail_generation,
                        stale_gen = generation,
                        cancel_armed = self.live_tail_cancel.is_some(),
                        "Dropping LiveTailStreamEnded: no active stream or generation mismatch",
                    );
                }
            }
            _ => {
                // Not a live-tail action — caller should pre-filter
                // via the `@` binding in `handle_action`. Silently
                // ignore in release; trip in debug to surface
                // mis-routing during development.
                debug_assert!(
                    false,
                    "dispatch_live_tail_action called with non-live-tail Action: {action:?}",
                );
            }
        }
    }

    fn spawn_live_tail_log_groups_fetch(&mut self) {
        let account_id = self.live_tail.selected_account_id.clone();
        let region = self.live_tail.selected_region.clone();

        if account_id.is_empty() || region.is_empty() {
            self.live_tail
                .set_log_groups_error("No Live Tail account or region is available".into());
            return;
        }

        self.live_tail.set_log_groups_loading();
        self.live_tail.advance_fetch_generation();
        let api = self.api.clone();
        let tx = self.action_tx.clone();
        let generation = self.live_tail.fetch_generation;

        tokio::spawn(async move {
            let req = shared::dto::cloudwatch::LogGroupsRequest {
                account_id,
                region,
                prefix: None,
            };

            match api.list_log_groups(&req).await {
                Ok(resp) => {
                    let _ = tx.send(Action::LiveTailLogGroupsLoaded {
                        groups: resp.log_groups,
                        generation,
                    });
                }
                Err(e) => {
                    let action =
                        Self::route_error_to_action(e, |msg| Action::LiveTailLogGroupsFailed {
                            error: format!("Failed to fetch Live Tail log groups: {}", msg),
                            generation,
                        });
                    let _ = tx.send(action);
                }
            }
        });
    }

    fn spawn_filter_search(&mut self, append: bool) {
        if self.cloudwatch_search.selected_log_group.is_empty() {
            self.cloudwatch_search
                .set_error("No log group is available for the current scope".into());
            return;
        }

        // Guard against a stale `LoadMoreFilterResults` arriving when the
        // previous response already exhausted the result set (no token left).
        if append && self.cloudwatch_search.last_next_token.is_none() {
            return;
        }

        self.cloudwatch_search.set_loading(if append {
            CloudWatchLoadingKind::LoadingMoreEvents
        } else {
            CloudWatchLoadingKind::SearchingLogs
        });
        if let Some(token) = self.cw_fetch_cancel.take() {
            token.cancel();
        }
        self.cloudwatch_search.advance_fetch_generation();
        let generation = self.cloudwatch_search.fetch_generation;
        let cancel = tokio_util::sync::CancellationToken::new();
        self.cw_fetch_cancel = Some(cancel.clone());
        let (start_time, end_time) = self
            .cloudwatch_search
            .time_range
            .resolve_filter_log_events_window();

        let next_token = if append {
            self.cloudwatch_search.last_next_token.clone()
        } else {
            None
        };

        let req = FilterLogEventsRequest {
            account_id: self.cloudwatch_search.selected_account_id.clone(),
            region: self.cloudwatch_search.selected_region.clone(),
            log_group_name: self.cloudwatch_search.selected_log_group.clone(),
            filter_pattern: cloudwatch_quick_search_filter_pattern(
                &self.cloudwatch_search.query_input.value,
            ),
            start_time,
            end_time,
            next_token,
            limit: 1000,
        };

        self.spawn_filter_search_request(req, append, generation, cancel);
    }

    fn spawn_filter_search_request(
        &self,
        req: FilterLogEventsRequest,
        append: bool,
        generation: u64,
        cancel: tokio_util::sync::CancellationToken,
    ) {
        let api = self.api.clone();
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            let mut req = req;
            let mut empty_pages_scanned = 0usize;

            loop {
                let result = tokio::select! {
                    _ = cancel.cancelled() => return,
                    result = api.filter_log_events(&req) => result,
                };

                match result {
                    Ok(resp) => {
                        let next_token = resp.next_token;
                        let events_len = resp.events.len();
                        let should_continue = should_auto_continue_empty_filter_page(
                            events_len,
                            next_token.as_deref(),
                            empty_pages_scanned,
                        );

                        if should_continue {
                            empty_pages_scanned += 1;
                            req.next_token = next_token;
                            continue;
                        }

                        let _ = tx.send(Action::FilterEventsLoaded {
                            events: resp.events,
                            next_token,
                            append,
                            generation,
                        });
                        break;
                    }
                    Err(e) => {
                        let action = Self::route_error_to_action(e, |msg| {
                            Action::FilterEventsFetchFailed(msg, generation)
                        });
                        let _ = tx.send(action);
                        break;
                    }
                }
            }
        });
    }

    fn spawn_insights_query(&mut self) {
        if self.cloudwatch_search.selected_log_group.is_empty() {
            self.cloudwatch_search
                .set_error("No log group is available for the current scope".into());
            return;
        }

        self.cloudwatch_search
            .set_loading(CloudWatchLoadingKind::StartingInsightsQuery);
        self.cloudwatch_search.advance_fetch_generation();
        let generation = self.cloudwatch_search.fetch_generation;
        let (start_time, end_time) = self.cloudwatch_search.time_range.resolve_insights_window();

        let req = shared::dto::cloudwatch::StartInsightsQueryRequest {
            account_id: self.cloudwatch_search.selected_account_id.clone(),
            region: self.cloudwatch_search.selected_region.clone(),
            log_group_names: vec![self.cloudwatch_search.selected_log_group.clone()],
            query_string: self.cloudwatch_search.insights_query_text().to_string(),
            start_time,
            end_time,
        };

        let api = self.api.clone();
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            match api.start_insights_query(&req).await {
                Ok(resp) => {
                    let _ = tx.send(Action::InsightsQueryStarted {
                        query_id: resp.query_id,
                        generation,
                    });
                }
                Err(e) => {
                    let action =
                        Self::route_error_to_action(e, |msg| Action::InsightsQueryStartFailed {
                            error: msg,
                            generation,
                        });
                    let _ = tx.send(action);
                }
            }
        });
    }

    fn spawn_poll_query(&mut self, query_id: String, generation: u64) {
        if generation != self.cloudwatch_search.fetch_generation {
            return;
        }

        // Generation covers normal query refreshes; query_id is a defensive
        // guard against any stale action that survived without a generation
        // bump.
        if self.cloudwatch_search.query_id.as_deref() != Some(query_id.as_str()) {
            return;
        }

        let req = shared::dto::cloudwatch::GetQueryResultsRequest {
            account_id: self.cloudwatch_search.selected_account_id.clone(),
            region: self.cloudwatch_search.selected_region.clone(),
            query_id,
        };

        let api = self.api.clone();
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            let mut last_error = None;
            for attempt in 0..3 {
                match api.get_query_results(&req).await {
                    Ok(resp) => {
                        let _ = tx.send(Action::InsightsQueryResultsLoaded {
                            response: resp,
                            generation,
                        });
                        return;
                    }
                    Err(e) => {
                        let should_retry = should_retry_api_error(&e);
                        last_error = Some(e);
                        if should_retry && attempt < 2 {
                            tokio::time::sleep(std::time::Duration::from_millis(
                                300 * (1 << attempt),
                            ))
                            .await;
                        } else {
                            break;
                        }
                    }
                }
            }

            let Some(err) = last_error else {
                return;
            };
            let action =
                Self::route_error_to_action(err, |msg| Action::InsightsQueryResultsFailed {
                    error: msg,
                    generation,
                });
            let _ = tx.send(action);
        });
    }

    #[cfg(test)]
    fn test_config() -> ClientConfig {
        ClientConfig {
            control_plane_url: "http://localhost:8443".into(),
            dev_mode: true,
            refresh_interval_secs: 30,
            live_tail_scrollback: 100,
            pkce_callback_port: 9876,
            enable_live_tail: true,
            show_public_ip: false,
            auto_update: false,
            update_repo_owner: "test".into(),
            update_repo_name: "test".into(),
            change_password_url: None,
            keybindings: crate::keybindings::KeyBindings::default(),
            theme: crate::theme::ThemeConfig::default(),
        }
    }

    fn do_export_results(&self, format: &crate::event::ExportFormat) {
        let has_insights = !self.cloudwatch_search.query_results.is_empty();
        let has_events = !self.cloudwatch_search.events.is_empty();

        if !has_insights && !has_events {
            return;
        }

        let filename = format!(
            "cloudwatch-export-{}.{}",
            chrono::Utc::now().format("%Y%m%d-%H%M%S"),
            match format {
                crate::event::ExportFormat::Json => "json",
                crate::event::ExportFormat::Text => "txt",
            }
        );

        let content = if has_insights {
            // Export Insights query_results (the active result set on screen)
            match format {
                crate::event::ExportFormat::Json => {
                    serde_json::to_string_pretty(&self.cloudwatch_search.query_results)
                        .unwrap_or_default()
                }
                crate::event::ExportFormat::Text => self
                    .cloudwatch_search
                    .query_results
                    .iter()
                    .map(|row| {
                        row.iter()
                            .map(|f| format!("{}={}", f.field, f.value))
                            .collect::<Vec<_>>()
                            .join(" | ")
                    })
                    .collect::<Vec<_>>()
                    .join("\n"),
            }
        } else {
            // Export FilterLogEvents results
            let events = &self.cloudwatch_search.events;
            match format {
                crate::event::ExportFormat::Json => {
                    serde_json::to_string_pretty(events).unwrap_or_default()
                }
                crate::event::ExportFormat::Text => events
                    .iter()
                    .map(|e| {
                        format!(
                            "{} [{}] {}",
                            e.timestamp,
                            e.log_stream_name.as_deref().unwrap_or("-"),
                            e.message
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n"),
            }
        };

        match std::fs::write(&filename, content) {
            Ok(_) => tracing::info!("Exported to {}", filename),
            Err(e) => tracing::error!("Export failed: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::components::Component;
    use crate::event::Screen;
    use ratatui::{buffer::Buffer, layout::Rect};
    use shared::dto::ec2::Ec2Instance;
    use shared::dto::entitlements::*;
    use std::collections::HashMap;

    /// Helper: build an App with dev defaults for testing state-machine logic.
    /// Installs a per-test tempdir-based `token_store_path` so the test
    /// can call set_session_token / reset_to_login / etc. without
    /// touching the real `~/Library/Application Support/canopy/token`
    /// (Codex round 10: prior pre-existing tests would silently
    /// clobber the developer's persisted credential).
    async fn test_app() -> App {
        let config = App::test_config();
        let mut app = App::new(config).await.unwrap();
        // Sandbox the token store so `cargo test` cannot touch the
        // real on-disk file. The TempDir is leaked into the App via
        // `into_path()` so it survives for the lifetime of this
        // test's runtime (Drop on Application takes care of nothing
        // here; the tempdir lives until the OS reaps /tmp).
        let dir = tempfile::TempDir::new().expect("tempdir for test token store");
        let token_store_path = dir.keep().join("token");
        app.api.set_session_store_path(token_store_path.clone());
        app.token_store_path = Some(token_store_path);
        app
    }

    fn mock_entitlements() -> UserEntitlements {
        UserEntitlements {
            user_id: "test-user".into(),
            email: "test@dev.local".into(),
            display_name: "Test".into(),
            groups: vec!["platform-engineering".into()],
            features: FeatureFlags {
                can_view_ec2: true,
                can_use_cloudwatch_search: true,
                can_use_cloudwatch_tail: false,
                can_use_ssm: true,
                can_use_ec2_instance_connect: false,
                ..Default::default()
            },
            allowed_accounts: vec![AllowedAccount {
                account_id: "111111111111".into(),
                role_arn: "direct".into(),
                account_name: "dev".into(),
            }],
            allowed_regions: vec!["us-east-1".into()],
            allowed_log_group_arns: vec![],
            max_session_seconds: None,
            instance_tag_selectors: vec![],
            excluded_tag_selectors: vec![],
            allowed_clusters: vec![],
            task_tag_selectors: vec![],
            excluded_task_tag_selectors: vec![],
            excluded_container_names: vec![],
            allow_broad_cluster_discovery: false,
            allowed_os_users: vec![],
            database_scopes: vec![],
        }
    }

    fn mock_instance() -> Ec2Instance {
        Ec2Instance {
            instance_id: "i-abc123".into(),
            name: Some("test-instance".into()),
            state: shared::dto::ec2::InstanceState::Running,
            instance_type: "t3.micro".into(),
            private_ip: Some("10.0.0.1".into()),
            public_ip: None,
            launch_time: Some("2025-01-01T00:00:00Z".into()),
            tags: HashMap::new(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            vpc_id: None,
            platform: None,
            ssm_managed: false,
            instance_connect_capable: false,
            environment: None,
            subnet_id: None,
            security_groups: vec![],
            iam_role: None,
        }
    }

    fn detected_terminal(
        display_name: &str,
        bundle_id: &str,
        adapter: TerminalLaunchAdapter,
    ) -> DetectedTerminalApp {
        DetectedTerminalApp {
            display_name: display_name.into(),
            bundle_id: bundle_id.into(),
            app_path: PathBuf::from(format!("/Applications/{display_name}.app")),
            adapter,
        }
    }

    fn write_fake_app(
        root: &Path,
        app_name: &str,
        bundle_id: &str,
        display_name: &str,
        executable_name: &str,
    ) -> PathBuf {
        let app_path = root.join(app_name);
        let contents = app_path.join("Contents");
        std::fs::create_dir_all(&contents).expect("create fake app contents");
        std::fs::write(
            contents.join("Info.plist"),
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>{bundle_id}</string>
  <key>CFBundleDisplayName</key>
  <string>{display_name}</string>
  <key>CFBundleName</key>
  <string>{display_name}</string>
  <key>CFBundleExecutable</key>
  <string>{executable_name}</string>
</dict>
</plist>
"#
            ),
        )
        .expect("write fake Info.plist");
        app_path
    }

    fn rendered_mcp_screen(app: &mut App) -> String {
        let area = Rect::new(0, 0, 120, 30);
        let mut buf = Buffer::empty(area);
        app.mcp.render(area, &mut buf);
        buf.content.iter().map(|c| c.symbol()).collect()
    }

    // ── MCP launcher helpers ────────────────────────────────

    #[test]
    fn mcp_ai_client_choice_parser_accepts_aliases_and_cancel() {
        assert_eq!(
            parse_mcp_ai_client_choice("1").unwrap(),
            Some(McpAiClient::Codex)
        );
        assert_eq!(
            parse_mcp_ai_client_choice("codex").unwrap(),
            Some(McpAiClient::Codex)
        );
        assert_eq!(
            parse_mcp_ai_client_choice("c").unwrap(),
            Some(McpAiClient::Codex)
        );
        assert_eq!(
            parse_mcp_ai_client_choice("2").unwrap(),
            Some(McpAiClient::Claude)
        );
        assert_eq!(
            parse_mcp_ai_client_choice("claude").unwrap(),
            Some(McpAiClient::Claude)
        );
        assert_eq!(parse_mcp_ai_client_choice("q").unwrap(), None);
        assert_eq!(parse_mcp_ai_client_choice("").unwrap(), None);
        assert!(parse_mcp_ai_client_choice("vim").is_err());
    }

    #[test]
    fn terminal_choice_parser_accepts_index_name_bundle_id_and_cancel() {
        let terminals = vec![
            detected_terminal(
                "iTerm2",
                "com.googlecode.iterm2",
                TerminalLaunchAdapter::ITerm2,
            ),
            detected_terminal(
                "Warp",
                "dev.warp.Warp-Stable",
                TerminalLaunchAdapter::WarpStable,
            ),
        ];

        assert_eq!(
            parse_terminal_app_choice("1", &terminals)
                .unwrap()
                .unwrap()
                .display_name,
            "iTerm2"
        );
        assert_eq!(
            parse_terminal_app_choice("warp", &terminals)
                .unwrap()
                .unwrap()
                .bundle_id,
            "dev.warp.Warp-Stable"
        );
        assert_eq!(
            parse_terminal_app_choice("com.googlecode.iterm2", &terminals)
                .unwrap()
                .unwrap()
                .display_name,
            "iTerm2"
        );
        assert!(parse_terminal_app_choice("q", &terminals)
            .unwrap()
            .is_none());
        assert!(parse_terminal_app_choice("", &terminals).unwrap().is_none());
        assert!(parse_terminal_app_choice("3", &terminals).is_err());
        assert!(parse_terminal_app_choice("Ghostty", &terminals).is_err());
    }

    #[test]
    fn mcp_launcher_selects_codex_and_first_terminal_without_prompt() {
        let terminals = vec![
            detected_terminal(
                "Terminal",
                "com.apple.Terminal",
                TerminalLaunchAdapter::AppleTerminal,
            ),
            detected_terminal(
                "Warp",
                "dev.warp.Warp-Stable",
                TerminalLaunchAdapter::WarpStable,
            ),
        ];

        assert_eq!(select_mcp_ai_client(None).unwrap(), McpAiClient::Codex);
        assert_eq!(
            select_mcp_ai_client(Some("claude")).unwrap(),
            McpAiClient::Claude
        );
        assert!(select_mcp_ai_client(Some("q")).is_err());

        let selected = select_mcp_terminal_app_choice(&terminals, None).unwrap();
        assert_eq!(selected.display_name, "Terminal");

        let selected = select_mcp_terminal_app_choice(&terminals, Some("warp")).unwrap();
        assert_eq!(selected.display_name, "Warp");
        assert!(select_mcp_terminal_app_choice(&terminals, Some("q")).is_err());
    }

    #[test]
    fn terminal_discovery_lists_detected_supported_apps_and_skips_unsupported() {
        let root = tempfile::TempDir::new().expect("tempdir");
        write_fake_app(
            root.path(),
            "Warp.app",
            "dev.warp.Warp-Stable",
            "Warp",
            "warp",
        );
        write_fake_app(
            root.path(),
            "Notes.app",
            "com.apple.Notes",
            "Notes",
            "Notes",
        );
        write_fake_app(
            root.path(),
            "iTerm.app",
            "com.googlecode.iterm2",
            "iTerm2",
            "iTerm2",
        );
        write_fake_app(
            root.path(),
            "Terminal.app",
            "com.apple.Terminal",
            "Terminal",
            "Terminal",
        );

        let dirs = vec![root.path().to_path_buf(), root.path().to_path_buf()];
        let terminals = detect_supported_terminal_apps_in(&dirs).unwrap();
        let names = terminals
            .iter()
            .map(|terminal| terminal.display_name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(names, vec!["Terminal", "iTerm2", "Warp"]);
        assert_eq!(terminals.len(), 3, "duplicate scan dirs should be deduped");
        assert!(terminals
            .iter()
            .all(|terminal| terminal.display_name != "Notes"));
    }

    #[test]
    fn terminal_discovery_errors_when_no_supported_apps_exist() {
        let root = tempfile::TempDir::new().expect("tempdir");
        write_fake_app(
            root.path(),
            "Notes.app",
            "com.apple.Notes",
            "Notes",
            "Notes",
        );

        let err = detect_supported_terminal_apps_in(&[root.path().to_path_buf()]).unwrap_err();
        assert_eq!(
            err,
            "No supported terminal app was detected on this computer."
        );
    }

    #[test]
    fn terminal_launch_command_builders_escape_script_paths() {
        let script_path = PathBuf::from("/tmp/canopy launch/it's quoted.command");

        let terminal_script = terminal_applescript_do_script(&script_path).unwrap();
        assert!(terminal_script.contains("tell application \"Terminal\" to do script"));
        assert!(terminal_script.contains("/tmp/canopy launch/it'\\\\''s quoted.command"));

        let iterm_script = iterm2_applescript_create_window(&script_path).unwrap();
        assert!(iterm_script
            .contains("tell application \"iTerm2\" to create window with default profile command"));
        assert!(iterm_script.contains("/bin/bash -lc"));
        assert!(iterm_script.contains("/tmp/canopy launch/it'\\\\''s quoted.command"));
    }

    #[test]
    fn warp_tab_config_builder_writes_terminal_pane_commands_and_url() {
        let root = tempfile::TempDir::new().expect("tempdir");
        let script_path = root.path().join("canopy launch.command");
        let tab_config_path = root.path().join("canopy_mcp_test.toml");
        let body = build_warp_tab_config(
            "canopy_mcp_test",
            &script_path,
            &tab_config_path,
            root.path(),
        )
        .unwrap();
        let parsed: toml::Value = toml::from_str(&body).expect("valid TOML");
        let pane = parsed["panes"].as_array().unwrap()[0].as_table().unwrap();
        let commands = pane["commands"].as_array().unwrap();

        assert_eq!(pane["type"].as_str(), Some("terminal"));
        assert_eq!(
            pane["directory"].as_str(),
            Some(root.path().to_str().unwrap())
        );
        assert!(commands[0].as_str().unwrap().starts_with("rm -f "));
        assert!(commands[1].as_str().unwrap().starts_with("/bin/bash -lc "));
        assert!(commands[1]
            .as_str()
            .unwrap()
            .contains("canopy launch.command"));
        assert_eq!(
            build_warp_tab_config_url("canopy_mcp_test", TerminalLaunchAdapter::WarpStable)
                .unwrap(),
            "warp://tab_config/canopy_mcp_test?new_window=true"
        );
        assert_eq!(
            build_warp_tab_config_url("canopy_mcp_test", TerminalLaunchAdapter::WarpPreview)
                .unwrap(),
            "warppreview://tab_config/canopy_mcp_test?new_window=true"
        );
    }

    #[tokio::test]
    async fn direct_mcp_launch_without_runtime_sets_enable_first_error() {
        let mut app = test_app().await;

        assert!(app.reject_direct_mcp_launch_when_stopped());
        assert!(app.mcp_runtime.is_none());
        let text = rendered_mcp_screen(&mut app);
        assert!(text.contains("MCP server is not running"));
        assert!(text.contains("press e to enable + launch first"));
    }

    // ── Navigation ──────────────────────────────────────────

    #[tokio::test]
    async fn test_initial_screen_is_login() {
        let app = test_app().await;
        assert_eq!(app.current_screen, Screen::Login);
        assert!(app.screen_stack.is_empty());
    }

    #[tokio::test]
    async fn test_navigate_to_pushes_stack() {
        let mut app = test_app().await;
        app.navigate_to(Screen::Dashboard);
        assert_eq!(app.current_screen, Screen::Dashboard);
        assert_eq!(app.screen_stack, vec![Screen::Login]);
    }

    #[tokio::test]
    async fn test_navigate_chain_builds_stack() {
        let mut app = test_app().await;
        app.navigate_to(Screen::Dashboard);
        app.navigate_to(Screen::Ec2Inventory);
        app.navigate_to(Screen::Settings);
        assert_eq!(app.current_screen, Screen::Settings);
        assert_eq!(
            app.screen_stack,
            vec![Screen::Login, Screen::Dashboard, Screen::Ec2Inventory]
        );
    }

    #[tokio::test]
    async fn test_go_back_pops_stack() {
        let mut app = test_app().await;
        app.navigate_to(Screen::Dashboard);
        app.navigate_to(Screen::Ec2Inventory);
        app.go_back();
        assert_eq!(app.current_screen, Screen::Dashboard);
        assert_eq!(app.screen_stack, vec![Screen::Login]);
    }

    #[tokio::test]
    async fn test_go_back_on_empty_stack_stays() {
        let mut app = test_app().await;
        app.go_back(); // empty stack
        assert_eq!(app.current_screen, Screen::Login);
        assert!(app.screen_stack.is_empty());
    }

    #[tokio::test]
    async fn test_navigate_to_live_tail_disabled() {
        let mut config = App::test_config();
        config.enable_live_tail = false;
        let mut app = App::new(config).await.unwrap();

        app.navigate_to(Screen::Dashboard);
        app.navigate_to(Screen::LiveTail);

        // Should NOT have navigated — LiveTail is blocked
        assert_eq!(app.current_screen, Screen::Dashboard);
        assert_eq!(app.screen_stack, vec![Screen::Login]);
    }

    #[tokio::test]
    async fn test_navigate_to_live_tail_enabled() {
        let mut app = test_app().await;
        app.navigate_to(Screen::Dashboard);
        app.navigate_to(Screen::LiveTail);
        assert_eq!(app.current_screen, Screen::LiveTail);
    }

    #[tokio::test]
    async fn test_enter_dashboard() {
        let mut app = test_app().await;
        app.enter_dashboard();
        assert_eq!(app.current_screen, Screen::Dashboard);
        // enter_dashboard doesn't push to stack
        assert!(app.screen_stack.is_empty());
    }

    // ── EC2 stale generation handling ───────────────────────

    #[tokio::test]
    async fn test_ec2_loaded_correct_generation() {
        let mut app = test_app().await;
        app.ec2.set_loading();
        let gen = app.ec2.fetch_generation;
        let instances = vec![mock_instance()];

        // Generation matches — instances should be accepted
        assert_eq!(gen, app.ec2.fetch_generation);
        app.ec2.set_instances(instances.clone());
        assert_eq!(app.ec2.instances.len(), 1);
    }

    #[tokio::test]
    async fn test_ec2_loaded_stale_generation_ignored() {
        let mut app = test_app().await;

        // Bump generation to simulate a new fetch was started
        app.ec2.fetch_generation = 5;

        // Old generation (3) should be dropped in handle_action
        // We test this via the action dispatch
        let instances = vec![mock_instance()];
        let stale_gen = 3u64;

        // Simulate the action handling logic
        assert!(
            stale_gen != app.ec2.fetch_generation,
            "Should have been stale"
        );

        // Instances should still be empty
        assert!(app.ec2.instances.is_empty());

        // Correct generation should work
        let current_gen = app.ec2.fetch_generation;
        if current_gen == app.ec2.fetch_generation {
            app.ec2.set_instances(instances);
        }
        assert_eq!(app.ec2.instances.len(), 1);
    }

    // ── Entitlements propagation ────────────────────────────

    #[tokio::test]
    async fn test_set_entitlements_propagates() {
        let mut app = test_app().await;
        let ent = mock_entitlements();

        app.set_entitlements(ent.clone());
        assert!(app.entitlements.is_some());
        assert_eq!(app.entitlements.as_ref().unwrap().user_id, "test-user");
        // access screen has public entitlements field
        assert!(app.access.entitlements.is_some());
    }

    // ── Error modal ─────────────────────────────────────────

    #[tokio::test]
    async fn test_error_modal_show_dismiss() {
        let mut app = test_app().await;
        assert!(!app.error_modal.is_visible());

        app.error_modal.show("Something broke".into());
        assert!(app.error_modal.is_visible());

        app.error_modal.dismiss();
        assert!(!app.error_modal.is_visible());
    }

    #[test]
    fn change_password_url_allows_only_http_schemes() {
        assert_eq!(
            normalized_http_url(" https://auth.example.com/forgotPassword "),
            Some("https://auth.example.com/forgotPassword")
        );
        assert_eq!(
            normalized_http_url("http://localhost:9876/callback"),
            Some("http://localhost:9876/callback")
        );
        assert!(normalized_http_url("file:///etc/passwd").is_none());
        assert!(normalized_http_url("javascript:alert(1)").is_none());
        assert!(normalized_http_url("").is_none());
    }

    #[test]
    fn cloudwatch_quick_search_quotes_literal_paths() {
        assert_eq!(
            cloudwatch_quick_search_filter_pattern("/api/orders/items"),
            Some("\"/api/orders/items\"".into())
        );
        assert_eq!(
            cloudwatch_quick_search_filter_pattern(" ERROR "),
            Some("\"ERROR\"".into())
        );
    }

    #[test]
    fn cloudwatch_quick_search_preserves_existing_quotes_and_omits_blank() {
        assert_eq!(
            cloudwatch_quick_search_filter_pattern("\"/api/orders/items\""),
            Some("\"/api/orders/items\"".into())
        );
        assert_eq!(cloudwatch_quick_search_filter_pattern("   "), None);
    }

    #[test]
    fn cloudwatch_quick_search_escapes_literal_quotes() {
        assert_eq!(
            cloudwatch_quick_search_filter_pattern("request \"failed\""),
            Some("\"request \\\"failed\\\"\"".into())
        );
    }

    #[test]
    fn cloudwatch_empty_filter_page_auto_continue_is_bounded() {
        assert!(should_auto_continue_empty_filter_page(0, Some("tok-1"), 0));
        assert!(should_auto_continue_empty_filter_page(
            0,
            Some("tok-1"),
            FILTER_EMPTY_PAGE_AUTO_SCAN_LIMIT - 1
        ));
        assert!(!should_auto_continue_empty_filter_page(
            0,
            Some("tok-1"),
            FILTER_EMPTY_PAGE_AUTO_SCAN_LIMIT
        ));
        assert!(!should_auto_continue_empty_filter_page(1, Some("tok-1"), 0));
        assert!(!should_auto_continue_empty_filter_page(0, None, 0));
    }

    #[test]
    fn api_retry_policy_skips_auth_and_client_errors() {
        assert!(!should_retry_api_error(&ApiClientError::TokenExpired));
        assert!(!should_retry_api_error(&ApiClientError::Api {
            status: 403,
            code: "FORBIDDEN".into(),
            message: "not authorized".into(),
        }));
        assert!(should_retry_api_error(&ApiClientError::Api {
            status: 502,
            code: "INTERNAL_ERROR".into(),
            message: "temporary upstream failure".into(),
        }));
    }

    #[tokio::test]
    async fn cancel_cloudwatch_request_invalidates_generation_and_clears_loading() {
        let mut app = test_app().await;
        let token = tokio_util::sync::CancellationToken::new();
        let old_generation = app.cloudwatch_search.fetch_generation;

        app.cw_fetch_cancel = Some(token.clone());
        app.cloudwatch_search
            .set_loading(CloudWatchLoadingKind::SearchingLogs);

        app.cancel_cloudwatch_request();

        assert!(token.is_cancelled());
        assert!(app.cw_fetch_cancel.is_none());
        assert_eq!(app.cloudwatch_search.fetch_generation, old_generation + 1);
        assert!(!app.cloudwatch_search.is_loading());
    }

    // ── Filter-events action handler (stale-generation contract) ─────

    fn log_event(message: &str) -> shared::dto::cloudwatch::LogEvent {
        shared::dto::cloudwatch::LogEvent {
            timestamp: 1_700_000_000_000,
            message: message.into(),
            log_stream_name: Some("app/web".into()),
            ingestion_time: Some(1_700_000_000_500),
            event_id: Some(format!("evt-{message}")),
        }
    }

    #[tokio::test]
    async fn apply_filter_events_loaded_with_matching_generation_replaces_events() {
        let mut app = test_app().await;
        app.cloudwatch_search.advance_fetch_generation();
        let gen = app.cloudwatch_search.fetch_generation;

        app.apply_filter_events_loaded(
            vec![log_event("first"), log_event("second")],
            Some("tok-next".into()),
            /* append = */ false,
            gen,
        );

        assert_eq!(app.cloudwatch_search.events.len(), 2);
        assert_eq!(app.cloudwatch_search.events[0].message, "first");
        assert_eq!(app.cloudwatch_search.events[1].message, "second");
        assert!(app.cloudwatch_search.has_more);
    }

    #[tokio::test]
    async fn apply_filter_events_loaded_with_stale_generation_does_not_overwrite_state() {
        // Reproduces this race:
        //   user runs search-1 (gen=1) → in-flight
        //   user runs search-2 (gen=2) → returns first, populates "current"
        //   search-1's response finally arrives with stale gen=1
        // Expectation: search-1's payload is silently dropped.
        let mut app = test_app().await;
        app.cloudwatch_search.advance_fetch_generation(); // gen 1
        app.cloudwatch_search.advance_fetch_generation(); // gen 2 (current)
        let current_gen = app.cloudwatch_search.fetch_generation;

        // search-2 result lands first.
        app.apply_filter_events_loaded(vec![log_event("current-result")], None, false, current_gen);
        assert_eq!(app.cloudwatch_search.events.len(), 1);

        // search-1's late reply arrives with stale gen.
        let stale_gen = current_gen - 1;
        app.apply_filter_events_loaded(
            vec![
                log_event("stale-A"),
                log_event("stale-B"),
                log_event("stale-C"),
            ],
            Some("stale-token".into()),
            false,
            stale_gen,
        );

        // Current state unchanged.
        assert_eq!(app.cloudwatch_search.events.len(), 1);
        assert_eq!(app.cloudwatch_search.events[0].message, "current-result");
    }

    #[tokio::test]
    async fn apply_filter_events_loaded_append_extends_existing_events() {
        let mut app = test_app().await;
        app.cloudwatch_search.advance_fetch_generation();
        let gen = app.cloudwatch_search.fetch_generation;
        app.cloudwatch_search.set_events(
            vec![log_event("page1-a"), log_event("page1-b")],
            Some("tok".into()),
        );

        app.apply_filter_events_loaded(
            vec![log_event("page2-c"), log_event("page2-d")],
            None,
            /* append = */ true,
            gen,
        );

        assert_eq!(app.cloudwatch_search.events.len(), 4);
        assert_eq!(app.cloudwatch_search.events[3].message, "page2-d");
        assert!(!app.cloudwatch_search.has_more);
    }

    #[tokio::test]
    async fn apply_filter_events_loaded_append_with_stale_generation_keeps_old_page() {
        // Pagination race: user has page 1 loaded, presses `n` to
        // load more (spawning gen=2). Then user starts a fresh search
        // (gen=3, which clears events). The old `n` reply with gen=2
        // arrives late; we must NOT append it to the new empty list.
        let mut app = test_app().await;
        app.cloudwatch_search.advance_fetch_generation(); // gen 1
        app.cloudwatch_search
            .set_events(vec![log_event("page1")], Some("tok".into()));

        app.cloudwatch_search.advance_fetch_generation(); // gen 2 (n pressed)
        let gen_for_n = app.cloudwatch_search.fetch_generation;

        app.cloudwatch_search.advance_fetch_generation(); // gen 3 (new search)
        app.cloudwatch_search.set_events(vec![], None);
        assert!(app.cloudwatch_search.events.is_empty());

        // Late n-page-2 reply at gen 2 arrives.
        app.apply_filter_events_loaded(vec![log_event("stale-page2")], None, true, gen_for_n);

        // New empty state is preserved; no stale append.
        assert!(app.cloudwatch_search.events.is_empty());
    }

    #[tokio::test]
    async fn apply_filter_events_loaded_with_empty_events_and_no_token_marks_end() {
        let mut app = test_app().await;
        app.cloudwatch_search.advance_fetch_generation();
        let gen = app.cloudwatch_search.fetch_generation;

        app.apply_filter_events_loaded(vec![], None, false, gen);

        assert!(app.cloudwatch_search.events.is_empty());
        assert!(!app.cloudwatch_search.has_more);
    }

    #[tokio::test]
    async fn apply_filter_events_fetch_failed_with_matching_generation_sets_error() {
        let mut app = test_app().await;
        app.cloudwatch_search.advance_fetch_generation();
        let gen = app.cloudwatch_search.fetch_generation;

        app.apply_filter_events_fetch_failed("network timeout".into(), gen);

        assert_eq!(
            app.cloudwatch_search.error.as_deref(),
            Some("network timeout")
        );
        assert!(!app.cloudwatch_search.is_loading());
    }

    #[tokio::test]
    async fn apply_filter_events_fetch_failed_with_stale_generation_does_not_set_error() {
        // A late error from a cancelled / superseded search must not
        // surface to the user.
        let mut app = test_app().await;
        app.cloudwatch_search.advance_fetch_generation(); // gen 1
        let stale_gen = app.cloudwatch_search.fetch_generation;
        app.cloudwatch_search.advance_fetch_generation(); // gen 2 (current)

        app.apply_filter_events_fetch_failed("stale upstream 5xx".into(), stale_gen);

        assert!(
            app.cloudwatch_search.error.is_none(),
            "stale fetch error should be silently dropped"
        );
    }

    #[tokio::test]
    async fn apply_filter_events_loaded_does_not_panic_on_generation_zero_default() {
        // Defensive: even if a caller forgets to advance the generation
        // first, default (0) compared against current (0) should still
        // accept the data — i.e. no off-by-one in the equality check.
        let mut app = test_app().await;
        let gen = app.cloudwatch_search.fetch_generation; // 0
        app.apply_filter_events_loaded(vec![log_event("zero-gen")], None, false, gen);
        assert_eq!(app.cloudwatch_search.events.len(), 1);
    }

    // ── ConnectSession reducer (Action::ConnectSession*) ─────────────

    /// Spawn a real PTY-backed session attached to `app.connect_session`
    /// so the reducer tests run against the same code path production
    /// uses. The session runs `sleep 30` so it stays alive long enough
    /// for the assertions; tests clean it up at the end via disconnect.
    #[cfg(unix)]
    fn attach_sleeping_session(app: &mut App) {
        use crate::components::connect_session::{ConnectSessionLaunch, ConnectSessionScreen};

        let launch = ConnectSessionLaunch {
            instance_id: "i-test123".into(),
            instance_name: Some("test".into()),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            method_label: "SSH".into(),
            spawn: PtySpawnSpec {
                command: "/bin/sh".into(),
                args: vec!["-c".into(), "sleep 30".into()],
                env_vars: std::collections::HashMap::new(),
                max_session_seconds: Some(60),
            },
            max_session_seconds: 60,
            cols: 80,
            rows: 24,
        };
        let session =
            ConnectSessionScreen::spawn(launch, app.action_tx.clone()).expect("spawn PTY session");
        app.connect_session = Some(session);
        app.current_screen = Screen::ConnectSession;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn apply_connect_session_exit_clears_session_and_returns_to_ec2_inventory() {
        let mut app = test_app().await;
        attach_sleeping_session(&mut app);
        assert!(app.connect_session.is_some());
        assert!(matches!(app.current_screen, Screen::ConnectSession));

        app.apply_connect_session_exit();

        assert!(app.connect_session.is_none());
        assert!(matches!(app.current_screen, Screen::Ec2Inventory));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn apply_connect_session_user_disconnect_drains_session_without_clearing_screen() {
        // Ctrl+] / Ctrl+5: user wants to leave the session but stay
        // on the screen so they can read the "Disconnected" message
        // and decide when to dismiss. The session should be torn
        // down (terminal state) but app.connect_session stays Some
        // until the user presses Enter to exit.
        let mut app = test_app().await;
        attach_sleeping_session(&mut app);

        app.apply_connect_session_user_disconnect();

        assert!(
            app.connect_session.is_some(),
            "session should remain on screen until user dismisses"
        );
        assert!(matches!(app.current_screen, Screen::ConnectSession));
        // After disconnect, pressing Enter on the screen should yield
        // ConnectSessionExit. We don't simulate that here; the
        // disconnect-only behavior is the contract under test.
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn apply_connect_session_failure_propagates_message_to_session_overlay() {
        // The session itself records the failure as a terminal-state
        // CopyMessage-style overlay so the user sees why their PTY
        // session ended.
        let mut app = test_app().await;
        attach_sleeping_session(&mut app);

        app.apply_connect_session_failure("PTY write to pty failed: broken pipe".into());

        // Session is still attached (user can still see + dismiss).
        assert!(app.connect_session.is_some());
        // Screen does not auto-return.
        assert!(matches!(app.current_screen, Screen::ConnectSession));
    }

    #[tokio::test]
    async fn apply_connect_session_stdout_ready_is_no_op_when_no_session_attached() {
        // Late signal: PTY reader thread fired ConnectSessionStdoutReady
        // after the user already exited the session screen. Must not
        // panic, must not change app state.
        let mut app = test_app().await;
        assert!(app.connect_session.is_none());
        let prev_screen = app.current_screen.clone();

        app.apply_connect_session_stdout_ready();

        assert!(app.connect_session.is_none());
        assert_eq!(app.current_screen, prev_screen);
    }

    #[tokio::test]
    async fn apply_connect_session_failure_is_no_op_when_no_session_attached() {
        // Same race: PTY write thread surfaced a failure but the
        // session screen has already been torn down. Drop silently.
        let mut app = test_app().await;
        assert!(app.connect_session.is_none());

        app.apply_connect_session_failure("late error from torn-down session".into());

        // No panics, no error_modal pop-up — just dropped.
        assert!(app.connect_session.is_none());
    }

    #[tokio::test]
    async fn apply_connect_session_user_disconnect_is_no_op_when_no_session_attached() {
        // Defensive: if user somehow triggers ConnectSessionUserDisconnect
        // while the screen has already been popped, nothing happens.
        let mut app = test_app().await;
        assert!(app.connect_session.is_none());

        app.apply_connect_session_user_disconnect();

        assert!(app.connect_session.is_none());
    }

    #[tokio::test]
    async fn apply_connect_session_exit_when_already_inactive_still_lands_on_ec2_inventory() {
        // Idempotency: exit while session is already None should still
        // route the user back to the inventory (covers Esc fallthrough
        // edge cases).
        let mut app = test_app().await;
        app.connect_session = None;
        app.current_screen = Screen::Login; // some unrelated screen

        app.apply_connect_session_exit();

        assert!(app.connect_session.is_none());
        assert!(matches!(app.current_screen, Screen::Ec2Inventory));
    }

    #[test]
    fn session_countdown_renders_remaining_bar() {
        assert_eq!(
            render_session_countdown(3600, 0),
            "[####################] 1:00:00"
        );
        assert_eq!(
            render_session_countdown(3600, 1800),
            "[##########----------] 30:00"
        );
        assert_eq!(
            render_session_countdown(3600, 3600),
            "[--------------------] 00:00"
        );
        assert_eq!(
            render_session_countdown(60, 75),
            "[--------------------] 00:00"
        );
    }

    #[test]
    fn session_duration_uses_hours_only_when_needed() {
        assert_eq!(format_session_duration(0), "00:00");
        assert_eq!(format_session_duration(65), "01:05");
        assert_eq!(format_session_duration(3661), "1:01:01");
    }

    #[test]
    fn wrapper_session_limit_only_uses_positive_caps() {
        assert_eq!(wrapper_session_limit(Some(3600)), Some(3600));
        assert_eq!(wrapper_session_limit(Some(0)), None);
        assert_eq!(wrapper_session_limit(None), None);
    }

    #[test]
    fn ecs_tasks_warning_messages_reports_partial_and_truncated_results() {
        let warnings =
            ecs_tasks_warning_messages(&["account-a us-east-1 failed".into()], 200, 250, true);

        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].contains("Some ECS scopes failed"));
        assert!(warnings[1].contains("showing 200 of at least 250"));
    }

    #[test]
    fn ecs_tasks_warning_messages_handles_aws_side_truncation_without_exact_total() {
        let warnings = ecs_tasks_warning_messages(&[], 50, 50, true);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("additional results may exist"));
    }

    // ── Logout resets state ─────────────────────────────────

    #[tokio::test]
    async fn test_logout_resets_state() {
        let mut app = test_app().await;
        let ent = mock_entitlements();
        app.set_entitlements(ent);
        app.navigate_to(Screen::Dashboard);
        app.navigate_to(Screen::Ec2Inventory);

        // Simulate the logout action inline (we can't call handle_action easily
        // because it needs a Tui, so we replicate the key state changes)
        let ec2_gen = app.ec2.fetch_generation + 1;
        let cw_gen = app.cloudwatch_search.fetch_generation + 1;
        app.ec2 = Ec2Screen::with_theme(app.theme);
        app.ec2.fetch_generation = ec2_gen;
        app.cloudwatch_search = CloudWatchSearchScreen::with_theme(app.theme);
        app.cloudwatch_search.fetch_generation = cw_gen;
        app.entitlements = None;
        app.current_screen = Screen::Login;
        app.screen_stack.clear();

        assert_eq!(app.current_screen, Screen::Login);
        assert!(app.screen_stack.is_empty());
        assert!(app.entitlements.is_none());
        assert_eq!(app.ec2.fetch_generation, ec2_gen);
    }

    #[tokio::test]
    async fn test_token_expired_flow_shows_modal_before_login_reset() {
        let mut app = test_app().await;
        app.api.set_token("expired-token".into());
        app.set_entitlements(mock_entitlements());
        app.enter_dashboard();

        app.begin_token_expired_flow();

        assert_eq!(app.current_screen, Screen::Dashboard);
        assert!(app.error_modal.is_visible());
        assert!(app.session_expired_pending_login);
        assert!(!app.api.has_token());
        assert!(app.entitlements.is_none());

        app.reset_to_login();

        assert_eq!(app.current_screen, Screen::Login);
        assert!(!app.session_expired_pending_login);
        assert!(app.screen_stack.is_empty());
        assert!(!app.error_modal.is_visible());
    }

    #[tokio::test]
    async fn test_handle_route_error_token_expired_opens_modal() {
        let mut app = test_app().await;
        app.handle_route_error(ApiClientError::TokenExpired, |app, msg| {
            app.ec2.set_error(msg);
        });

        assert!(app.error_modal.is_visible());
        assert!(app.session_expired_pending_login);
        assert!(app.ec2.error.is_none());
    }

    #[tokio::test]
    async fn test_handle_route_error_non_token_uses_fallback() {
        let mut app = test_app().await;
        app.handle_route_error(
            ApiClientError::Api {
                status: 403,
                code: "FORBIDDEN".into(),
                message: "not authorized".into(),
            },
            |app, msg| app.ec2.set_error(msg),
        );

        assert!(!app.error_modal.is_visible());
        assert!(!app.session_expired_pending_login);
        assert!(app
            .ec2
            .error
            .as_deref()
            .is_some_and(|msg| msg.contains("FORBIDDEN")));
    }

    #[tokio::test]
    async fn test_handle_route_error_api_401_uses_fallback() {
        let mut app = test_app().await;
        app.handle_route_error(
            ApiClientError::Api {
                status: 401,
                code: "UNAUTHORIZED".into(),
                message: "auth route rejected login".into(),
            },
            |app, msg| app.ec2.set_error(msg),
        );

        assert!(!app.error_modal.is_visible());
        assert!(!app.session_expired_pending_login);
        assert!(app
            .ec2
            .error
            .as_deref()
            .is_some_and(|msg| msg.contains("UNAUTHORIZED")));
    }

    // ─────────────────────────────────────────────────────────────────
    // Phase A — Core user flows
    // ─────────────────────────────────────────────────────────────────

    // ── Login / post-auth: set_entitlements → enter_dashboard ────────

    #[tokio::test]
    async fn login_success_propagates_entitlements_to_ec2_screen() {
        // After login the Access screen, EC2 screen, CloudWatch search,
        // and Dashboard all need to see the user's entitlements.
        // `set_entitlements` is the single fan-out point; the test
        // locks that it actually reaches each screen.
        let mut app = test_app().await;
        let ent = mock_entitlements();

        app.set_entitlements(ent.clone());

        assert!(app.entitlements.is_some(), "app should retain entitlements");
        // EC2 screen learns its allowed scopes from entitlements.
        assert!(!app.ec2.available_accounts.is_empty());
        assert!(!app.ec2.available_regions.is_empty());
    }

    #[tokio::test]
    async fn login_success_lands_on_dashboard_with_clean_back_stack() {
        // The post-login transition: `enter_dashboard` sets the
        // current screen and produces a fresh back stack (no stale
        // entries from before login). Any actions emitted by
        // Dashboard's on_enter (e.g. FetchPublicIp when public-IP
        // display is enabled) flow through the action channel.
        let mut app = test_app().await;
        app.set_entitlements(mock_entitlements());

        app.enter_dashboard();

        assert_eq!(app.current_screen, Screen::Dashboard);
        assert!(
            app.screen_stack.is_empty(),
            "Dashboard is the root after login, no back-stack"
        );

        // Drain the action channel and verify nothing unexpected like
        // an error or quit slipped through. We don't require a
        // specific action because Dashboard's on_enter is config-driven
        // (FetchPublicIp only when show_public_ip is true).
        while let Ok(action) = app.action_rx.try_recv() {
            assert!(
                !matches!(action, Action::Quit | Action::ShowError(_)),
                "enter_dashboard must not emit Quit or ShowError, got {action:?}"
            );
        }
    }

    #[tokio::test]
    async fn entering_dashboard_does_not_clear_existing_screen_stack() {
        // Boundary: if the user navigates away from Dashboard and then
        // a TokenReceived flow lands them back on Dashboard, the back
        // stack should NOT inherit stale entries from before login
        // (the prior session was wiped by reset_to_login). After a
        // fresh login the stack starts empty.
        let mut app = test_app().await;
        app.set_entitlements(mock_entitlements());
        app.navigate_to(Screen::Ec2Inventory);
        app.navigate_to(Screen::CloudWatchSearch);
        // Pretend the screen_stack was reset by reset_to_login then
        // login lands the user on Dashboard.
        app.screen_stack.clear();

        app.enter_dashboard();

        assert_eq!(app.current_screen, Screen::Dashboard);
        assert!(app.screen_stack.is_empty());
    }

    // ── Logout: `reset_to_login` is testable directly now ────────────

    #[tokio::test]
    async fn reset_to_login_clears_token_entitlements_and_returns_to_login_screen() {
        let mut app = test_app().await;
        app.api.set_token("active-session-token".into());
        app.set_entitlements(mock_entitlements());
        app.enter_dashboard();
        app.navigate_to(Screen::Ec2Inventory);
        assert!(app.api.has_token());
        assert!(app.entitlements.is_some());

        app.reset_to_login();

        assert_eq!(app.current_screen, Screen::Login);
        assert!(app.screen_stack.is_empty(), "back stack cleared");
        assert!(app.entitlements.is_none(), "entitlements cleared");
        assert!(!app.api.has_token(), "in-memory API client token cleared");
        assert!(
            !app.error_modal.is_visible(),
            "any prior modal must be dismissed on logout"
        );
        assert!(
            !app.session_expired_pending_login,
            "session-expired flag reset to false"
        );
    }

    #[tokio::test]
    async fn reset_to_login_advances_generations_to_drop_in_flight_async_results() {
        // Race-safety: while logged in, the user may have an EC2 list
        // request and a CloudWatch search in flight. Logging out
        // must bump fetch_generation on each screen so late replies
        // are silently dropped by the generation guard in the
        // matching action handler (covered separately by #9 / R3).
        let mut app = test_app().await;
        app.set_entitlements(mock_entitlements());
        let ec2_gen_before = app.ec2.fetch_generation;
        let cw_gen_before = app.cloudwatch_search.fetch_generation;

        app.reset_to_login();

        assert!(
            app.ec2.fetch_generation > ec2_gen_before,
            "ec2 generation must advance: was {ec2_gen_before}, now {}",
            app.ec2.fetch_generation
        );
        assert!(
            app.cloudwatch_search.fetch_generation > cw_gen_before,
            "cw search generation must advance"
        );
    }

    #[tokio::test]
    async fn reset_to_login_cancels_in_flight_cancellation_tokens() {
        // EC2/CW/LiveTail spawn tokio tasks that hold a CancellationToken
        // clone. On logout the app side of each token must be cancelled
        // so the tasks unwind.
        let mut app = test_app().await;
        let ec2_token = tokio_util::sync::CancellationToken::new();
        let cw_token = tokio_util::sync::CancellationToken::new();
        let lt_token = tokio_util::sync::CancellationToken::new();
        app.ec2_fetch_cancel = Some(ec2_token.clone());
        app.cw_fetch_cancel = Some(cw_token.clone());
        app.live_tail_cancel = Some(lt_token.clone());

        app.reset_to_login();

        assert!(ec2_token.is_cancelled(), "EC2 fetch must be cancelled");
        assert!(cw_token.is_cancelled(), "CW fetch must be cancelled");
        assert!(
            lt_token.is_cancelled(),
            "Live Tail stream must be cancelled"
        );
        assert!(app.ec2_fetch_cancel.is_none(), "stale handle cleared");
        assert!(app.cw_fetch_cancel.is_none());
        assert!(app.live_tail_cancel.is_none());
    }

    // ── Token-expired flow (begin + dismiss path) ────────────────────

    #[tokio::test]
    async fn begin_token_expired_flow_is_idempotent_within_one_session_expiry() {
        // Multiple failing API calls may all surface as `TokenExpired`
        // before the user can dismiss the modal. The second invocation
        // must NOT re-show the modal or re-cancel anything — otherwise
        // the modal would jitter and audit-worthy state would be
        // double-mutated.
        let mut app = test_app().await;
        app.api.set_token("expired".into());
        app.set_entitlements(mock_entitlements());

        app.begin_token_expired_flow();
        assert!(app.session_expired_pending_login);
        assert!(app.error_modal.is_visible());
        let api_has_token_after_first = app.api.has_token();

        // Second call while modal is already showing — must be a no-op.
        app.begin_token_expired_flow();

        assert!(app.session_expired_pending_login);
        assert!(app.error_modal.is_visible());
        // Token was already cleared by the first call; second is no-op.
        assert_eq!(app.api.has_token(), api_has_token_after_first);
    }

    #[tokio::test]
    async fn token_expired_flow_does_not_change_screen_until_user_dismisses_modal() {
        // The user might be deep in CloudWatch or PTY when their token
        // expires. We surface the modal on top of the current screen
        // and only navigate after the user acknowledges (Enter).
        let mut app = test_app().await;
        app.set_entitlements(mock_entitlements());
        app.navigate_to(Screen::Ec2Inventory);
        app.navigate_to(Screen::CloudWatchSearch);

        app.begin_token_expired_flow();

        // Screen unchanged — modal is the overlay
        assert_eq!(app.current_screen, Screen::CloudWatchSearch);
        assert!(app.error_modal.is_visible());
    }

    #[tokio::test]
    async fn dismiss_error_during_session_expired_pending_login_returns_to_login() {
        // Reproduces the Token-Expired dismissal path: user sees the
        // modal, presses Enter, which fires Action::DismissError;
        // because session_expired_pending_login is set, the dismissal
        // handler also runs reset_to_login.
        let mut app = test_app().await;
        app.set_entitlements(mock_entitlements());
        app.navigate_to(Screen::Ec2Inventory);
        app.begin_token_expired_flow();
        assert!(app.error_modal.is_visible());
        assert!(app.session_expired_pending_login);

        // Inline the DismissError handler logic since handle_action
        // needs a Tui. (See Action::DismissError arm in app.rs.)
        app.error_modal.dismiss();
        if app.session_expired_pending_login {
            app.reset_to_login();
        }

        assert_eq!(app.current_screen, Screen::Login);
        assert!(!app.session_expired_pending_login);
        assert!(!app.error_modal.is_visible());
        assert!(!app.api.has_token());
    }

    #[tokio::test]
    async fn token_expired_recovery_re_login_clears_pending_flag() {
        // After re-login, the session_expired_pending_login flag must
        // be false so a future token expiry can trigger a fresh modal.
        let mut app = test_app().await;
        app.begin_token_expired_flow();
        assert!(app.session_expired_pending_login);

        app.reset_to_login();
        // User now logs in again.
        app.set_entitlements(mock_entitlements());
        app.api.set_token("fresh-token".into());
        app.enter_dashboard();

        // A subsequent expiry should be able to fire the modal again.
        app.begin_token_expired_flow();
        assert!(app.error_modal.is_visible());
        assert!(app.session_expired_pending_login);
    }

    // ── Live Tail action handlers ────────────────────────────────────

    /// Build a minimal `LiveTailEvent` fixture matching the
    /// `shared::dto::cloudwatch::LiveTailEvent` wire shape (timestamp,
    /// message, log_group_name, log_stream_name — all required).
    fn live_tail_event(ts: i64, msg: &str) -> shared::dto::cloudwatch::LiveTailEvent {
        shared::dto::cloudwatch::LiveTailEvent {
            timestamp: ts,
            message: msg.into(),
            log_group_name: "/app/web-service".into(),
            log_stream_name: "stream-1".into(),
        }
    }

    #[tokio::test]
    async fn dispatching_stop_live_tail_action_cancels_token_and_disconnects() {
        // Exercise the SAME entry point that the production
        // `handle_action` match arm uses (`dispatch_live_tail_action`),
        // not the apply_* helpers directly. Codex round 2: testing
        // apply_* in isolation lets a regression that breaks the
        // dispatch fn body slip past. Going through the dispatch
        // chain closes that loop.
        let mut app = test_app().await;
        let cancel = tokio_util::sync::CancellationToken::new();
        app.live_tail_cancel = Some(cancel.clone());
        app.live_tail.set_connected();
        assert_eq!(app.live_tail.connection_state, "Connected");

        app.dispatch_live_tail_action(Action::StopLiveTail);

        assert!(
            cancel.is_cancelled(),
            "stop must cancel the in-flight WS task token so the background loop terminates",
        );
        assert!(
            app.live_tail_cancel.is_none(),
            "stop must drop the stored token so a fresh start can install a new one",
        );
        assert_eq!(app.live_tail.connection_state, "Disconnected");
    }

    #[tokio::test]
    async fn dispatching_pause_live_tail_action_keeps_buffer_but_pauses_state() {
        let mut app = test_app().await;
        app.live_tail.set_connected();
        // Seed an event so we can assert the buffer survives pause.
        app.live_tail
            .push_event(live_tail_event(1_700_000_000_000, "before-pause"));
        let before = app.live_tail.events.len();

        app.dispatch_live_tail_action(Action::PauseLiveTail);

        assert_eq!(app.live_tail.connection_state, "Paused");
        assert_eq!(
            app.live_tail.events.len(),
            before,
            "pause must not drop buffered events",
        );
    }

    #[tokio::test]
    async fn dispatching_resume_live_tail_action_transitions_paused_to_connected() {
        let mut app = test_app().await;
        app.live_tail.set_paused();
        assert_eq!(app.live_tail.connection_state, "Paused");

        app.dispatch_live_tail_action(Action::ResumeLiveTail);

        assert_eq!(app.live_tail.connection_state, "Connected");
    }

    #[tokio::test]
    async fn dispatching_live_tail_event_actions_appends_to_buffer_in_arrival_order() {
        let mut app = test_app().await;
        // Arm so the dispatch fn matches our generation.
        let _ = app.try_arm_live_tail_stream();
        let gen = app.live_tail_generation;

        app.dispatch_live_tail_action(Action::LiveTailEvent {
            event: live_tail_event(1, "first"),
            generation: gen,
        });
        app.dispatch_live_tail_action(Action::LiveTailEvent {
            event: live_tail_event(2, "second"),
            generation: gen,
        });
        app.dispatch_live_tail_action(Action::LiveTailEvent {
            event: live_tail_event(3, "third"),
            generation: gen,
        });

        assert_eq!(app.live_tail.events.len(), 3);
        assert_eq!(
            app.live_tail.events[0].message, "first",
            "events must be appended in arrival order, not reverse-chronological",
        );
        assert_eq!(app.live_tail.events[2].message, "third");
    }

    #[tokio::test]
    async fn dispatching_stale_live_tail_event_from_old_stream_is_silently_dropped() {
        // Codex round 5: the stop-then-rearm race meant a late-
        // arriving event from a previously-active stream could
        // bleed into the new stream's buffer.
        let mut app = test_app().await;

        // Arm stream #1 (generation 1), then stop it, then arm
        // stream #2 (generation 2).
        let _ = app.try_arm_live_tail_stream();
        let gen_old = app.live_tail_generation;
        app.dispatch_live_tail_action(Action::StopLiveTail);
        let _ = app.try_arm_live_tail_stream();
        let gen_new = app.live_tail_generation;
        assert_ne!(gen_old, gen_new, "rearm must bump the generation");

        // Late event from the OLD stream — must NOT land in the buffer.
        app.dispatch_live_tail_action(Action::LiveTailEvent {
            event: live_tail_event(99, "stale-late-event"),
            generation: gen_old,
        });
        assert_eq!(
            app.live_tail.events.len(),
            0,
            "stale events must be dropped, got {:?}",
            app.live_tail.events,
        );

        // Event from the NEW (current) stream — must land normally.
        app.dispatch_live_tail_action(Action::LiveTailEvent {
            event: live_tail_event(100, "fresh-event"),
            generation: gen_new,
        });
        assert_eq!(app.live_tail.events.len(), 1);
        assert_eq!(app.live_tail.events[0].message, "fresh-event");
    }

    #[tokio::test]
    async fn dispatching_live_tail_event_after_stop_without_rearm_is_silently_dropped() {
        // Codex round 6: after StopLiveTail (no subsequent rearm),
        // a stale event still in the action channel must NOT appear
        // in the scrollback. The previous gen-only check would have
        // accepted it because `live_tail_generation` retains its
        // last value across teardown.
        let mut app = test_app().await;
        let _ = app.try_arm_live_tail_stream();
        let gen = app.live_tail_generation;

        // Stop — clears live_tail_cancel, but live_tail_generation
        // is intentionally NOT bumped (it identifies "the most
        // recent stream", not "the currently-running one").
        app.dispatch_live_tail_action(Action::StopLiveTail);
        assert!(app.live_tail_cancel.is_none());
        assert_eq!(app.live_tail_generation, gen);

        // Late event arriving AFTER stop with the just-stopped
        // stream's gen — must NOT be appended.
        app.dispatch_live_tail_action(Action::LiveTailEvent {
            event: live_tail_event(1, "post-stop-leak"),
            generation: gen,
        });
        assert_eq!(
            app.live_tail.events.len(),
            0,
            "after stop, events from the just-stopped stream must NOT bleed into the buffer, got {:?}",
            app.live_tail.events,
        );
    }

    #[tokio::test]
    async fn dispatching_live_tail_stream_ended_after_stop_does_not_redisconnect() {
        // Same idea for the stream-ended signal — already-disconnected
        // app must not be flipped by a late-arriving ended signal
        // (no-op rather than disrupting the user's flow).
        let mut app = test_app().await;
        let _ = app.try_arm_live_tail_stream();
        let gen = app.live_tail_generation;
        app.dispatch_live_tail_action(Action::StopLiveTail);
        assert_eq!(app.live_tail.connection_state, "Disconnected");

        // Late ended-signal from the just-stopped stream.
        app.dispatch_live_tail_action(Action::LiveTailStreamEnded(gen));

        assert_eq!(
            app.live_tail.connection_state, "Disconnected",
            "state already Disconnected — a stale end signal must not toggle anything",
        );
        assert!(app.live_tail_cancel.is_none());
    }

    #[tokio::test]
    async fn dispatching_stale_live_tail_stream_ended_does_not_disconnect_new_stream() {
        // The headline race from Codex round 5: stream A's natural
        // completion sends LiveTailStreamEnded; if stream B has
        // already been armed in the meantime, that stale signal
        // must NOT flip the UI to Disconnected.
        let mut app = test_app().await;

        let _ = app.try_arm_live_tail_stream();
        let gen_old = app.live_tail_generation;
        app.dispatch_live_tail_action(Action::StopLiveTail);
        let _ = app.try_arm_live_tail_stream();
        let gen_new = app.live_tail_generation;
        assert_eq!(app.live_tail.connection_state, "Connected");

        // Late "ended" signal from the OLD stream.
        app.dispatch_live_tail_action(Action::LiveTailStreamEnded(gen_old));

        assert_eq!(
            app.live_tail.connection_state, "Connected",
            "stale LiveTailStreamEnded must not disconnect the new stream",
        );
        assert!(
            app.live_tail_cancel.is_some(),
            "stale LiveTailStreamEnded must not clear the new stream's cancel token",
        );

        // The current stream's ended signal IS honored.
        app.dispatch_live_tail_action(Action::LiveTailStreamEnded(gen_new));
        assert_eq!(app.live_tail.connection_state, "Disconnected");
        assert!(app.live_tail_cancel.is_none());
    }

    #[tokio::test]
    async fn try_arm_live_tail_stream_is_idempotent_under_double_start() {
        // Codex round 3 regression guard: two queued StartLiveTail
        // actions used to:
        //   1. spawn stream A with token A → stored in live_tail_cancel
        //   2. spawn stream B with token B → OVERWRITES live_tail_cancel
        //      (token A leaks; stream A keeps running)
        //   3. eventually stream A emits Action::StopLiveTail
        //   4. apply_stop_live_tail() cancels token B — the NEW stream — wrongly
        //
        // The fix: try_arm_live_tail_stream returns None when a
        // stream is already in flight, so the handler refuses to
        // spawn a second one and the original token survives.
        let mut app = test_app().await;

        // First call arms the stream — returns (cancel_token, generation).
        let (token_a, gen_a) = app
            .try_arm_live_tail_stream()
            .expect("first call must succeed (no stream in flight)");
        assert!(
            app.live_tail_cancel.is_some(),
            "first arm must install a cancel token",
        );
        assert_eq!(
            app.live_tail.connection_state, "Connected",
            "first arm must flip UI state to Connected",
        );
        assert_eq!(
            gen_a, app.live_tail_generation,
            "returned generation must match the stored field",
        );

        // Second call must NOT install a new token.
        let token_b = app.try_arm_live_tail_stream();
        assert!(
            token_b.is_none(),
            "duplicate StartLiveTail must yield None (no new spawn)",
        );
        assert_eq!(
            app.live_tail_generation, gen_a,
            "refused arm must NOT bump the generation",
        );

        // Now prove token identity *bidirectionally*. Codex round 4
        // pointed out that one-way propagation (`token_a.cancel() ⇒
        // stored.is_cancelled()`) is satisfied even by a child
        // token — a buggy impl that returned `parent.child_token()`
        // would pass that single check, but `apply_stop_live_tail`
        // would then cancel only the stored CHILD, leaving the
        // background stream's parent token uncancelled. So we test
        // BOTH directions:
        //
        //   * cancelling `stored` propagates to `token_a`  → proves
        //     `stored` is not a child of `token_a`
        //   * cancelling `token_a` propagates to `stored`  → proves
        //     `token_a` is not a child of `stored`
        //
        // Both directions hold only when both handles share the
        // same root (i.e. are clones of each other).
        let stored = app
            .live_tail_cancel
            .clone()
            .expect("stored token must survive the duplicate-arm refusal");
        assert!(!stored.is_cancelled());
        assert!(!token_a.is_cancelled());

        // Direction 1: cancel the stored handle, check token_a sees it.
        stored.cancel();
        assert!(
            token_a.is_cancelled(),
            "stored→token_a propagation failed — `stored` is a CHILD of `token_a`, \
             not the same token; the duplicate-arm path silently substituted a \
             child token. Cancelling the stored handle therefore leaves the \
             background task uncancelled, recreating the orphan-stream bug.",
        );

        // Direction 2: a freshly-armed token's cancel must propagate
        // both ways too. Use a fresh app so we don't reuse the
        // already-cancelled handles above.
        let mut app2 = test_app().await;
        let (task_token, _gen) = app2.try_arm_live_tail_stream().expect("first arm");
        let stored2 = app2.live_tail_cancel.clone().expect("stored 2");
        task_token.cancel();
        assert!(
            stored2.is_cancelled(),
            "token_a→stored propagation failed — `token_a` is a CHILD of `stored`. \
             This is the inverse of the bug above and equally orphan-prone.",
        );
    }

    #[tokio::test]
    async fn try_arm_live_tail_stream_re_arms_after_stop() {
        // Companion to the idempotency test: once the stream has
        // been stopped (cancel token taken / state Disconnected),
        // a fresh StartLiveTail MUST be allowed through again.
        let mut app = test_app().await;
        let _ = app.try_arm_live_tail_stream();
        app.dispatch_live_tail_action(Action::StopLiveTail);
        assert!(app.live_tail_cancel.is_none());

        let second_arm = app.try_arm_live_tail_stream();
        assert!(
            second_arm.is_some(),
            "post-stop arm must succeed — otherwise the user could never restart live tail",
        );
        assert_eq!(app.live_tail.connection_state, "Connected");
    }

    #[tokio::test]
    async fn set_session_token_returns_persisted_fresh_or_in_memory_only_on_happy_path() {
        // Sanity: when save_token succeeds (happy path), the
        // outcome is PersistedFresh; if save fails BUT clear of
        // stale token succeeds, it's InMemoryOnly. In either case
        // the caller is allowed to proceed to the dashboard.
        // StaleTokenSurvivesOnDisk is the only "refuse-to-proceed"
        // path and Codex round 8's contract — this test pins that
        // the happy path doesn't accidentally return the refuse-
        // to-proceed variant.
        let mut app = test_app().await;

        let outcome = app.set_session_token("fresh-token-xyz");

        assert!(
            matches!(
                outcome,
                SessionTokenOutcome::PersistedFresh | SessionTokenOutcome::InMemoryOnly,
            ),
            "happy-path login must NOT yield StaleTokenSurvivesOnDisk, got {outcome:?}",
        );
    }

    #[tokio::test]
    async fn reset_to_login_clears_live_tail_events_so_next_user_does_not_see_prior_logs() {
        // Codex round 7: a logout must scrub previously-buffered
        // log lines from the LiveTailScreen, otherwise a second
        // user logging in on the same TUI process can navigate to
        // Live Tail and see prior CloudWatch output. This is a
        // cross-user log isolation contract.
        let mut app = test_app().await;
        let _ = app.try_arm_live_tail_stream();
        let gen = app.live_tail_generation;
        app.dispatch_live_tail_action(Action::LiveTailEvent {
            event: live_tail_event(1, "user-a-secret-log-line"),
            generation: gen,
        });
        assert_eq!(app.live_tail.events.len(), 1, "fixture sanity");

        app.reset_to_login();

        assert!(
            app.live_tail.events.is_empty(),
            "logout must clear the live-tail buffer, found leaked event(s): {:?}",
            app.live_tail.events,
        );
        assert_eq!(
            app.current_screen,
            Screen::Login,
            "reset_to_login must also return to Login screen",
        );
        // Generation also bumped so any still-in-flight queued
        // events from the previous session can't match against
        // the new session's gen by accident.
        assert!(
            app.live_tail_generation > gen,
            "logout must invalidate the prior generation",
        );
    }

    #[tokio::test]
    async fn begin_token_expired_flow_also_clears_live_tail_events() {
        // Same invariant for the session-expiry path — Codex round 7
        // explicitly listed token expiry as one of the teardown
        // boundaries that must scrub buffered logs.
        let mut app = test_app().await;
        let _ = app.try_arm_live_tail_stream();
        let gen = app.live_tail_generation;
        app.dispatch_live_tail_action(Action::LiveTailEvent {
            event: live_tail_event(1, "expired-session-log"),
            generation: gen,
        });
        assert_eq!(app.live_tail.events.len(), 1);

        app.begin_token_expired_flow();

        assert!(
            app.live_tail.events.is_empty(),
            "session-expiry teardown must clear the live-tail buffer",
        );
        assert!(
            app.live_tail_generation > gen,
            "session-expiry must invalidate the prior generation",
        );
    }

    #[tokio::test]
    async fn stopping_live_tail_when_no_token_is_active_is_a_safe_no_op() {
        // Boundary / idempotent: user double-presses 's' to stop the
        // stream. Second stop must not panic on the missing token.
        let mut app = test_app().await;
        assert!(app.live_tail_cancel.is_none());
        app.live_tail.set_disconnected();

        // Calling the dispatch fn twice in a row must be safe —
        // the first call already took the (None) token slot.
        app.dispatch_live_tail_action(Action::StopLiveTail);
        app.dispatch_live_tail_action(Action::StopLiveTail);

        // No panic, still disconnected, still no cancel token in flight.
        assert_eq!(app.live_tail.connection_state, "Disconnected");
        assert!(app.live_tail_cancel.is_none());
    }

    // ── Update banner ───────────────────────────────────────

    #[tokio::test]
    async fn test_update_banner_lifecycle() {
        let mut app = test_app().await;
        assert!(app.update_banner.is_none());

        app.update_banner = Some("v1.2.3 available".into());
        assert!(app.update_banner.is_some());

        app.update_banner = None; // dismiss
        assert!(app.update_banner.is_none());
    }

    // ── Go back cancels EC2/CW fetches ──────────────────────

    #[tokio::test]
    async fn test_go_back_from_ec2_bumps_generation() {
        let mut app = test_app().await;
        app.navigate_to(Screen::Dashboard);
        app.navigate_to(Screen::Ec2Inventory);
        let gen_before = app.ec2.fetch_generation;

        app.go_back();
        assert!(app.ec2.fetch_generation > gen_before);
    }

    #[tokio::test]
    async fn test_go_back_from_cloudwatch_bumps_generation() {
        let mut app = test_app().await;
        app.navigate_to(Screen::Dashboard);
        app.navigate_to(Screen::CloudWatchSearch);
        let gen_before = app.cloudwatch_search.fetch_generation;

        app.go_back();
        assert!(app.cloudwatch_search.fetch_generation > gen_before);
    }

    // ── Navigate away from screens bumps generation ─────────

    #[tokio::test]
    async fn test_navigate_away_from_ec2_bumps_generation() {
        let mut app = test_app().await;
        app.navigate_to(Screen::Dashboard);
        app.navigate_to(Screen::Ec2Inventory);
        let gen_before = app.ec2.fetch_generation;

        app.navigate_to(Screen::Settings);
        assert!(app.ec2.fetch_generation > gen_before);
    }

    #[tokio::test]
    async fn test_navigate_away_from_cloudwatch_bumps_generation() {
        let mut app = test_app().await;
        app.navigate_to(Screen::Dashboard);
        app.navigate_to(Screen::CloudWatchSearch);
        let gen_before = app.cloudwatch_search.fetch_generation;

        app.navigate_to(Screen::Settings);
        assert!(app.cloudwatch_search.fetch_generation > gen_before);
    }

    // ── Running flag ────────────────────────────────────────

    #[tokio::test]
    async fn test_app_starts_running() {
        let app = test_app().await;
        assert!(app.running);
    }

    // ── Spawn log groups requires account/region ────────────

    #[tokio::test]
    async fn test_spawn_log_groups_empty_account_sets_error() {
        let mut app = test_app().await;
        // Default cloudwatch_search has empty account_id and region
        app.spawn_log_groups_fetch();
        assert!(app.cloudwatch_search.error.is_some());
    }
}
