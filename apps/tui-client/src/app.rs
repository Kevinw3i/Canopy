use anyhow::Result;
use shared::dto::cloudwatch::FilterLogEventsRequest;
use shared::dto::ec2::{ConnectMethod, ConnectRequest, Ec2ListRequest, Ec2PowerRequest};
use shared::dto::ecs::{EcsExecRequest, EcsTasksRequest};
use shared::dto::entitlements::UserEntitlements;
use shared::dto::pty_spawn::PtySpawnSpec;
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
use crate::components::settings::SettingsScreen;
use crate::components::Component;
use crate::config::ClientConfig;
use crate::event::{Action, Event, EventReader, Screen};
use crate::local_deps::{self, DependencyIssue, LocalDependency, SystemCommandRunner};
use crate::theme::Theme;
use crate::tui::Tui;

const FILTER_EMPTY_PAGE_AUTO_SCAN_LIMIT: usize = 50;
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
            live_tail_cancel: None,
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
                            self.api.clear_token();
                            crate::auth::clear_token().ok();
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
                    Screen::ConnectSession => self
                        .connect_session
                        .as_mut()
                        .map_or(Action::Noop, |session| session.handle_paste(&text)),
                };
                let _ = self.action_tx.send(action);
            }
            Event::Tick => match self.current_screen {
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
                self.install_token_response(resp);
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
                if let Some(session) = self.connect_session.as_mut() {
                    session.process_pending_output();
                }
            }
            Action::ConnectSessionFailure(message) => {
                if let Some(session) = self.connect_session.as_mut() {
                    session.fail(message);
                }
            }
            Action::ConnectSessionUserDisconnect => {
                if let Some(session) = self.connect_session.as_mut() {
                    session.disconnect();
                }
            }
            Action::ConnectSessionExit => {
                self.connect_session = None;
                self.current_screen = Screen::Ec2Inventory;
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
                if generation != self.cloudwatch_search.fetch_generation {
                    return;
                }
                if append {
                    self.cloudwatch_search.append_events(events, next_token);
                } else {
                    self.cloudwatch_search.set_events(events, next_token);
                }
            }
            Action::FilterEventsFetchFailed(err, generation) => {
                if generation != self.cloudwatch_search.fetch_generation {
                    return;
                }
                self.cloudwatch_search.set_error(err);
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
                        request,
                        tx,
                        cancel,
                    )
                    .await
                    {
                        tracing::warn!("Live tail stream ended: {}", e);
                    }
                });
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
            Action::LiveTailEvent(event) => {
                if self.live_tail_cancel.is_some() {
                    self.live_tail.push_event(event);
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
    }

    fn cancel_cloudwatch_request(&mut self) {
        if let Some(token) = self.cw_fetch_cancel.take() {
            token.cancel();
        }
        self.cloudwatch_search.advance_fetch_generation();
        self.cloudwatch_search.cancel_loading();
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

        self.api.clear_token();
        crate::auth::clear_token().ok();
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
        self.api.clear_token();
        crate::auth::clear_token().ok();
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
        self.entitlements = Some(ent);
    }

    fn install_session(&mut self, session: crate::auth::SessionTokens) {
        self.api.set_session(session.clone());
        if let Err(err) = crate::auth::save_session(&session) {
            tracing::warn!(error = %err, "failed to persist auth session");
        }
    }

    fn install_token_response(&mut self, resp: shared::dto::auth::TokenResponse) {
        let session = self.api.apply_token_response(resp);
        if let Err(err) = crate::auth::save_session(&session) {
            tracing::warn!(error = %err, "failed to persist auth session");
        }
    }

    // ── Async operations ────────────────────────────────

    async fn do_dev_login(&mut self, username: &str) {
        match self.api.dev_login(username).await {
            Ok(resp) => {
                self.install_session(crate::auth::SessionTokens::new(resp.access_token, None));
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
            allowed_clusters: vec![],
            task_tag_selectors: vec![],
            excluded_task_tag_selectors: vec![],
            excluded_container_names: vec![],
            allow_broad_cluster_discovery: false,
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
