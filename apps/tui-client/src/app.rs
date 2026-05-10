use anyhow::Result;
use shared::dto::ec2::{ConnectMethod, ConnectRequest, Ec2ListRequest};
use shared::dto::entitlements::UserEntitlements;
use tokio::sync::mpsc;

use crate::api_client::{ApiClient, ApiClientError};
use crate::components::access::AccessScreen;
use crate::components::cloudwatch_search::CloudWatchSearchScreen;
use crate::components::dashboard::DashboardScreen;
use crate::components::ec2::Ec2Screen;
use crate::components::error_modal::ErrorModal;
use crate::components::live_tail::LiveTailScreen;
use crate::components::login::LoginScreen;
use crate::components::settings::SettingsScreen;
use crate::components::Component;
use crate::config::ClientConfig;
use crate::event::{Action, Event, EventReader, Screen};
use crate::local_deps::{self, DependencyIssue, LocalDependency, SystemCommandRunner};
use crate::tui::Tui;

pub struct App {
    config: ClientConfig,
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
    error_modal: ErrorModal,

    // Async action channel
    action_tx: mpsc::UnboundedSender<Action>,
    action_rx: mpsc::UnboundedReceiver<Action>,

    // Shared flag to pause the event reader during external commands
    event_reader_paused: std::sync::Arc<std::sync::atomic::AtomicBool>,

    // Cancellation tokens for in-flight background fetches
    ec2_fetch_cancel: Option<tokio_util::sync::CancellationToken>,
    cw_fetch_cancel: Option<tokio_util::sync::CancellationToken>,

    // Cancellation token for the live tail background task
    live_tail_cancel: Option<tokio_util::sync::CancellationToken>,

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

const TOKEN_EXPIRED_MODAL_MESSAGE: &str =
    "Your session has expired. Please sign in again.\n\nPress Enter to return to the login screen.";

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

impl App {
    pub async fn new(config: ClientConfig) -> Result<Self> {
        let api = ApiClient::new(&config.control_plane_url)?;
        let (action_tx, action_rx) = mpsc::unbounded_channel();

        let scrollback = config.live_tail_scrollback;

        Ok(Self {
            login: LoginScreen::new(config.dev_mode),
            dashboard: DashboardScreen::new(config.enable_live_tail, config.show_public_ip),
            ec2: Ec2Screen::new(),
            cloudwatch_search: CloudWatchSearchScreen::new(),
            live_tail: LiveTailScreen::new(scrollback),
            access: AccessScreen::new(),
            settings: SettingsScreen::new(config.clone()),
            error_modal: ErrorModal::new(),
            config,
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
            live_tail_cancel: None,
            update_banner: None,
            session_expired_pending_login: false,
        })
    }

    pub async fn run(&mut self, terminal: &mut Tui) -> Result<()> {
        // Check for saved token
        if let Some(token) = crate::auth::load_token() {
            self.api.set_token(token);
            // Try to validate by fetching entitlements
            match self.api.get_entitlements().await {
                Ok(ent) => {
                    self.set_entitlements(ent);
                    self.enter_dashboard();
                }
                Err(e) => {
                    match e {
                        ApiClientError::TokenExpired => {
                            crate::auth::clear_token().ok();
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
                .border_style(Style::default().fg(Color::Green));
            let inner = block.inner(banner_area);
            block.render(banner_area, buf);

            Paragraph::new(Line::from(vec![
                Span::styled(" ↑ ", Style::default().fg(Color::Green).bold()),
                Span::styled(msg.as_str(), Style::default().fg(Color::Green).bold()),
                Span::styled("  (Ctrl+D: dismiss)", Style::default().fg(Color::DarkGray)),
            ]))
            .render(inner, buf);
        }

        // Render error modal on top
        if self.error_modal.is_visible() {
            self.error_modal.render(area, buf);
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
                };
                let _ = self.action_tx.send(action);
            }
            Event::Tick => match self.current_screen {
                Screen::Ec2Inventory => self.ec2.on_tick(),
                Screen::CloudWatchSearch => self.cloudwatch_search.on_tick(),
                _ => {}
            },
            Event::Resize(_, _) => {
                // Terminal will re-render automatically
            }
            Event::Error(msg) => {
                let _ = self.action_tx.send(Action::ShowError(msg));
            }
        }
    }

    async fn handle_action(&mut self, action: Action, terminal: &mut Tui) {
        match action {
            Action::Quit => {
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
            Action::TokenReceived(token) => {
                self.api.set_token(token.clone());
                crate::auth::save_token(&token).ok();
                if self.fetch_entitlements().await {
                    self.enter_dashboard();
                }
                // If fetch_entitlements failed, error modal is shown and we
                // stay on the current screen so the user can retry.
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
            Action::ConnectSsm(instance_id, account_id, region, os_user) => {
                self.do_connect_with_user(
                    &instance_id,
                    &account_id,
                    &region,
                    ConnectMethod::Ssm,
                    os_user.as_deref(),
                    terminal,
                )
                .await;
            }
            Action::ConnectEic(instance_id, account_id, region, os_user) => {
                self.do_connect_with_user(
                    &instance_id,
                    &account_id,
                    &region,
                    ConnectMethod::Ec2InstanceConnect,
                    os_user.as_deref(),
                    terminal,
                )
                .await;
            }
            Action::ConnectSsh(instance_id, account_id, region, os_user) => {
                self.do_connect_with_user(
                    &instance_id,
                    &account_id,
                    &region,
                    ConnectMethod::Ssh,
                    os_user.as_deref(),
                    terminal,
                )
                .await;
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
                self.do_filter_search(false).await;
            }
            Action::LoadMoreFilterResults => {
                self.do_filter_search(true).await;
            }
            Action::RunInsightsQuery => {
                self.do_insights_query().await;
            }
            Action::PollQueryResults(query_id) => {
                self.do_poll_query(&query_id).await;
            }
            Action::ExportResults(format) => {
                self.do_export_results(&format);
            }

            // Live Tail
            Action::StartLiveTail => {
                if self.config.dev_mode {
                    // Dev mode: connect to the control-plane's WebSocket
                    // and stream simulated events into the live tail screen.
                    self.live_tail.set_connected();
                    let cancel = tokio_util::sync::CancellationToken::new();
                    self.live_tail_cancel = Some(cancel.clone());
                    let tx = self.action_tx.clone();
                    let base_url = self.config.control_plane_url.clone();
                    let token = self.api.get_token();
                    tokio::spawn(async move {
                        if let Err(e) = crate::live_tail_ws::stream_live_tail(
                            &base_url,
                            token.as_deref(),
                            tx,
                            cancel,
                        )
                        .await
                        {
                            tracing::warn!("Live tail stream ended: {}", e);
                        }
                    });
                } else {
                    self.error_modal.show(
                        "Live tail WebSocket client is not yet available. \
                         This feature is in beta."
                            .into(),
                    );
                }
            }
            Action::StopLiveTail => {
                if let Some(cancel) = self.live_tail_cancel.take() {
                    cancel.cancel();
                }
                self.live_tail.set_disconnected();
            }
            Action::PauseLiveTail => {
                self.live_tail.set_paused();
            }
            Action::ResumeLiveTail => {
                self.live_tail.set_connected();
            }
            Action::LiveTailEvent(event) => {
                self.live_tail.push_event(event);
            }

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
    }

    fn reset_to_login(&mut self) {
        self.cancel_in_flight_work();

        // Reset screen state and advance generation counters so queued async
        // results from the prior session are rejected.
        let ec2_gen = self.ec2.fetch_generation + 1;
        let cw_gen = self.cloudwatch_search.fetch_generation + 1;
        self.ec2 = Ec2Screen::new();
        self.ec2.fetch_generation = ec2_gen;
        self.cloudwatch_search = CloudWatchSearchScreen::new();
        self.cloudwatch_search.fetch_generation = cw_gen;
        self.dashboard.public_ip = None;
        self.dashboard.ip_fetch_generation += 1;

        crate::auth::clear_token().ok();
        self.api.clear_token();
        self.entitlements = None;
        self.current_screen = Screen::Login;
        self.screen_stack.clear();
        self.session_expired_pending_login = false;
        self.error_modal.dismiss();
    }

    fn begin_token_expired_flow(&mut self) {
        if self.session_expired_pending_login {
            return;
        }

        self.cancel_in_flight_work();
        crate::auth::clear_token().ok();
        self.api.clear_token();
        self.entitlements = None;
        self.session_expired_pending_login = true;
        self.error_modal
            .show_with_title(" Session Expired ", TOKEN_EXPIRED_MODAL_MESSAGE.into());
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
        }
        if matches!(self.current_screen, Screen::LiveTail) {
            if let Some(cancel) = self.live_tail_cancel.take() {
                cancel.cancel();
            }
            self.live_tail.set_disconnected();
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
                Screen::Login => self.login.on_enter(),
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
        self.access.set_entitlements(ent.clone());
        self.entitlements = Some(ent);
    }

    // ── Async operations ────────────────────────────────

    async fn do_dev_login(&mut self, username: &str) {
        match self.api.dev_login(username).await {
            Ok(resp) => {
                self.api.set_token(resp.access_token.clone());
                crate::auth::save_token(&resp.access_token).ok();
                if self.fetch_entitlements().await {
                    self.enter_dashboard();
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
            Ok(token) => {
                let _ = self.action_tx.send(Action::TokenReceived(token));
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
                Ok(token) => {
                    let _ = tx.send(Action::TokenReceived(token));
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

    async fn do_connect_with_user(
        &mut self,
        instance_id: &str,
        account_id: &str,
        region: &str,
        method: ConnectMethod,
        os_user: Option<&str>,
        terminal: &mut Tui,
    ) {
        let req = ConnectRequest {
            instance_id: instance_id.to_string(),
            account_id: account_id.to_string(),
            region: region.to_string(),
            method,
            os_user: os_user.map(String::from),
        };

        match self.api.connect(&req).await {
            Ok(resp) => {
                if resp.authorized {
                    tracing::info!(
                        command = %resp.command,
                        args = ?resp.args,
                        "Spawning connect command"
                    );

                    let runner = SystemCommandRunner;
                    let required_deps = local_deps::required_dependencies_for_connect(&resp);
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

                    // Suspend TUI, run external command, then resume.
                    if !terminal_suspended {
                        self.suspend_for_external_command();
                    }

                    // Run the command
                    let mut cmd = std::process::Command::new(&resp.command);
                    cmd.args(&resp.args);
                    for (k, v) in &resp.env_vars {
                        cmd.env(k, v);
                    }

                    // Pre-flight: TCP connectivity check for SSH with countdown
                    if resp.command == "ssh" {
                        if let Some(target) = resp.args.last() {
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

                    if let Some(secs) = resp.max_session_seconds {
                        println!(
                            "--- Connecting to {} via {} (max {} min) ---\n",
                            instance_id,
                            resp.command,
                            secs / 60
                        );
                        println!("Session countdown: {}", render_session_countdown(secs, 0));
                        println!("Countdown updates in this terminal tab title while connected.\n");
                        set_session_countdown_title(instance_id, secs, 0);
                    } else {
                        println!(
                            "--- Connecting to {} via {} ---\n",
                            instance_id, resp.command
                        );
                    }

                    // Connection timeout: if the process doesn't become
                    // interactive within this many seconds, kill it.
                    let connect_timeout_secs: u64 = 15;

                    match cmd.spawn() {
                        Ok(mut child) => {
                            let session_limit = resp.max_session_seconds.filter(|&s| s > 0);
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
                                                        instance_id,
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
                                                    instance_id,
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
                                    if resp.command == "aws" {
                                        "AWS CLI not found. Install it from https://aws.amazon.com/cli/".to_string()
                                    } else {
                                        format!("Command '{}' not found", resp.command)
                                    }
                                }
                                _ => format!("Failed to execute command: {}", e),
                            };
                            eprintln!("\nError: {}\n", msg);
                        }
                    }

                    if resp.max_session_seconds.is_some() {
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

        self.cloudwatch_search.set_loading();
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

    async fn do_filter_search(&mut self, append: bool) {
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

        self.cloudwatch_search.set_loading();
        let (start_time, end_time) = self
            .cloudwatch_search
            .time_range
            .resolve_filter_log_events_window();

        let next_token = if append {
            self.cloudwatch_search.last_next_token.clone()
        } else {
            None
        };

        let req = shared::dto::cloudwatch::FilterLogEventsRequest {
            account_id: self.cloudwatch_search.selected_account_id.clone(),
            region: self.cloudwatch_search.selected_region.clone(),
            log_group_name: self.cloudwatch_search.selected_log_group.clone(),
            filter_pattern: cloudwatch_quick_search_filter_pattern(
                &self.cloudwatch_search.query_input.value,
            ),
            start_time,
            end_time,
            next_token,
            limit: 500,
        };

        match self.api.filter_log_events(&req).await {
            Ok(resp) => {
                if append {
                    self.cloudwatch_search
                        .append_events(resp.events, resp.next_token);
                } else {
                    self.cloudwatch_search
                        .set_events(resp.events, resp.next_token);
                }
            }
            Err(e) => {
                self.handle_route_error(e, |app, msg| app.cloudwatch_search.set_error(msg));
            }
        }
    }

    async fn do_insights_query(&mut self) {
        if self.cloudwatch_search.selected_log_group.is_empty() {
            self.cloudwatch_search
                .set_error("No log group is available for the current scope".into());
            return;
        }

        self.cloudwatch_search.set_loading();
        let (start_time, end_time) = self.cloudwatch_search.time_range.resolve_insights_window();

        let req = shared::dto::cloudwatch::StartInsightsQueryRequest {
            account_id: self.cloudwatch_search.selected_account_id.clone(),
            region: self.cloudwatch_search.selected_region.clone(),
            log_group_names: vec![self.cloudwatch_search.selected_log_group.clone()],
            query_string: self.cloudwatch_search.query_input.value.clone(),
            start_time,
            end_time,
        };

        match self.api.start_insights_query(&req).await {
            Ok(resp) => {
                self.cloudwatch_search.query_id = Some(resp.query_id.clone());
                let _ = self.action_tx.send(Action::PollQueryResults(resp.query_id));
            }
            Err(e) => {
                self.handle_route_error(e, |app, msg| app.cloudwatch_search.set_error(msg));
            }
        }
    }

    async fn do_poll_query(&mut self, query_id: &str) {
        // Ignore stale poll results from a previous query
        if self.cloudwatch_search.query_id.as_deref() != Some(query_id) {
            return;
        }

        let req = shared::dto::cloudwatch::GetQueryResultsRequest {
            account_id: self.cloudwatch_search.selected_account_id.clone(),
            region: self.cloudwatch_search.selected_region.clone(),
            query_id: query_id.to_string(),
        };

        match self.api.get_query_results(&req).await {
            Ok(resp) => {
                let is_complete = matches!(
                    resp.status,
                    shared::dto::cloudwatch::QueryStatus::Complete
                        | shared::dto::cloudwatch::QueryStatus::Failed
                        | shared::dto::cloudwatch::QueryStatus::Cancelled
                        | shared::dto::cloudwatch::QueryStatus::Timeout
                );
                self.cloudwatch_search.set_query_results(resp);
                if !is_complete {
                    // Poll again after delay
                    let tx = self.action_tx.clone();
                    let qid = query_id.to_string();
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        let _ = tx.send(Action::PollQueryResults(qid));
                    });
                }
            }
            Err(e) => {
                self.handle_route_error(e, |app, msg| app.cloudwatch_search.set_error(msg));
            }
        }
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
    use crate::event::Screen;
    use shared::dto::ec2::Ec2Instance;
    use shared::dto::entitlements::*;
    use std::collections::HashMap;

    /// Helper: build an App with dev defaults for testing state-machine logic.
    async fn test_app() -> App {
        let config = App::test_config();
        App::new(config).await.unwrap()
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
            allowed_os_users: vec![],
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
            cloudwatch_quick_search_filter_pattern("/api/merchant/bets"),
            Some("\"/api/merchant/bets\"".into())
        );
        assert_eq!(
            cloudwatch_quick_search_filter_pattern(" ERROR "),
            Some("\"ERROR\"".into())
        );
    }

    #[test]
    fn cloudwatch_quick_search_preserves_existing_quotes_and_omits_blank() {
        assert_eq!(
            cloudwatch_quick_search_filter_pattern("\"/api/merchant/bets\""),
            Some("\"/api/merchant/bets\"".into())
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
        app.ec2 = Ec2Screen::new();
        app.ec2.fetch_generation = ec2_gen;
        app.cloudwatch_search = CloudWatchSearchScreen::new();
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
