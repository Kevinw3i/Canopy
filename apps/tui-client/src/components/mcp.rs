use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
};
use shared::dto::entitlements::UserEntitlements;

use super::Component;
use crate::event::Action;
use crate::mcp::McpRuntimeStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpServerState {
    Stopped,
    Starting,
    Running,
    Failed,
}

pub struct McpScreen {
    entitlements: Option<UserEntitlements>,
    state: McpServerState,
    endpoint: Option<String>,
    stable_endpoint: Option<String>,
    session_file: Option<String>,
    status_line: String,
    last_error: Option<String>,
}

impl McpScreen {
    pub fn new() -> Self {
        Self {
            entitlements: None,
            state: McpServerState::Stopped,
            endpoint: None,
            stable_endpoint: None,
            session_file: None,
            status_line: "Stopped".into(),
            last_error: None,
        }
    }

    pub fn set_entitlements(&mut self, entitlements: UserEntitlements) {
        self.entitlements = Some(entitlements);
    }

    pub fn set_starting(&mut self) {
        self.state = McpServerState::Starting;
        self.status_line = "Starting local MCP server...".into();
        self.last_error = None;
    }

    pub fn set_running(&mut self, status: &McpRuntimeStatus) {
        self.state = McpServerState::Running;
        self.endpoint = Some(status.endpoint.clone());
        self.stable_endpoint = Some(status.stable_endpoint.clone());
        self.session_file = Some(status.session_file.display().to_string());
        self.status_line = format!("Running until {}", status.expires_at);
        self.last_error = None;
    }

    pub fn set_stopped(&mut self) {
        self.state = McpServerState::Stopped;
        self.status_line = "Stopped".into();
        self.endpoint = None;
        self.stable_endpoint = None;
        self.session_file = None;
    }

    pub fn set_error(&mut self, error: String) {
        self.state = McpServerState::Failed;
        self.status_line = "Failed".into();
        self.last_error = Some(error);
    }

    pub fn set_status_line(&mut self, status: String) {
        self.status_line = status;
        if matches!(self.state, McpServerState::Failed) {
            self.state = McpServerState::Running;
        }
        self.last_error = None;
    }

    fn can_use_mcp(&self) -> bool {
        self.entitlements
            .as_ref()
            .is_some_and(|ent| ent.features.can_use_mcp)
    }
}

impl Default for McpScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl Component for McpScreen {
    fn handle_key(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => Action::GoBack,
            KeyCode::Char('e') => {
                if self.can_use_mcp() {
                    Action::EnableMcp
                } else {
                    Action::ShowError("MCP is not enabled for this user".into())
                }
            }
            KeyCode::Char('l') => {
                if self.can_use_mcp() {
                    Action::LaunchMcpAiClient
                } else {
                    Action::ShowError("MCP is not enabled for this user".into())
                }
            }
            KeyCode::Char('s') => Action::StopMcp,
            KeyCode::Char('r') => Action::RestartMcp,
            KeyCode::Char('t') => Action::TestMcp,
            _ => Action::Noop,
        }
    }

    fn render(&mut self, area: Rect, buf: &mut Buffer) {
        let outer = Block::default()
            .borders(Borders::ALL)
            .title(" MCP / AI Tools ")
            .border_style(Style::default().fg(Color::Cyan));
        let inner = outer.inner(area);
        outer.render(area, buf);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4),
                Constraint::Length(8),
                Constraint::Min(8),
                Constraint::Length(2),
            ])
            .split(inner);

        let entitlement_text = match self.entitlements.as_ref() {
            Some(ent) if ent.features.can_use_mcp => {
                let cloudwatch = if ent.features.can_use_mcp_cloudwatch {
                    "cloudwatch discovery"
                } else {
                    "cloudwatch disabled"
                };
                format!("Entitlement: enabled ({cloudwatch})")
            }
            Some(_) => "Entitlement: disabled".into(),
            None => "Entitlement: loading".into(),
        };

        let state_style = match self.state {
            McpServerState::Running => Style::default().fg(Color::Green).bold(),
            McpServerState::Starting => Style::default().fg(Color::Yellow).bold(),
            McpServerState::Failed => Style::default().fg(Color::Red).bold(),
            McpServerState::Stopped => Style::default().fg(Color::Gray),
        };

        Paragraph::new(vec![
            Line::from(vec![
                Span::styled("State: ", Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{:?}", self.state), state_style),
            ]),
            Line::from(entitlement_text),
            Line::from(self.status_line.clone()),
        ])
        .render(chunks[0], buf);

        let endpoint_text = format!(
            "Preferred URL: {}\nDirect URL: {}\nSession file: {}",
            self.stable_endpoint.as_deref().unwrap_or("-"),
            self.endpoint.as_deref().unwrap_or("-"),
            self.session_file.as_deref().unwrap_or("-"),
        );
        Paragraph::new(endpoint_text)
            .block(Block::default().borders(Borders::ALL).title(" Setup "))
            .wrap(Wrap { trim: true })
            .render(chunks[1], buf);

        let help = "Use e to enable the local MCP server, then choose the AI client and terminal in the TUI selector. Use l to launch another CLI against the already-running MCP server; it will not start MCP automatically. Use s to stop, r to restart, t to test health. Phase 3 exposes CloudWatch discovery plus preflight-gated search and Insights tools.";
        let body = if let Some(error) = self.last_error.as_ref() {
            format!("{help}\n\nLast error:\n{error}")
        } else {
            help.into()
        };
        Paragraph::new(body)
            .block(Block::default().borders(Borders::ALL).title(" Notes "))
            .wrap(Wrap { trim: true })
            .render(chunks[2], buf);

        Paragraph::new(
            "e: enable + launch | l: launch CLI | s: stop | r: restart | t: test | Esc/q: back",
        )
        .style(Style::default().fg(Color::Gray))
        .render(chunks[3], buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    use shared::dto::entitlements::FeatureFlags;
    use std::path::PathBuf;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn entitlements_with_mcp(can_use_mcp: bool) -> UserEntitlements {
        UserEntitlements {
            user_id: "u".into(),
            email: "u@x.com".into(),
            display_name: "U".into(),
            groups: vec![],
            features: FeatureFlags {
                can_use_mcp,
                ..Default::default()
            },
            allowed_accounts: vec![],
            allowed_regions: vec![],
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
            business_scopes: vec![],
        }
    }

    fn sample_runtime_status() -> McpRuntimeStatus {
        McpRuntimeStatus {
            endpoint: "http://127.0.0.1:53121".into(),
            stable_endpoint: "http://localhost:51234".into(),
            session_file: PathBuf::from("/tmp/canopy-mcp/session.json"),
            expires_at: chrono::Utc
                .with_ymd_and_hms(2026, 5, 20, 18, 0, 0)
                .single()
                .unwrap(),
        }
    }

    fn rendered(screen: &mut McpScreen, area: Rect) -> String {
        let mut buf = Buffer::empty(area);
        screen.render(area, &mut buf);
        buf.content.iter().map(|c| c.symbol()).collect()
    }

    // ── Key handling ──

    #[test]
    fn esc_key_returns_go_back_action() {
        let mut screen = McpScreen::new();
        assert!(matches!(
            screen.handle_key(key(KeyCode::Esc)),
            Action::GoBack
        ));
    }

    #[test]
    fn q_key_returns_go_back_action() {
        let mut screen = McpScreen::new();
        assert!(matches!(
            screen.handle_key(key(KeyCode::Char('q'))),
            Action::GoBack
        ));
    }

    #[test]
    fn e_returns_enable_mcp_when_entitlement_allows() {
        // Permission-positive: user has can_use_mcp = true.
        let mut screen = McpScreen::new();
        screen.set_entitlements(entitlements_with_mcp(true));

        assert!(matches!(
            screen.handle_key(key(KeyCode::Char('e'))),
            Action::EnableMcp
        ));
    }

    #[test]
    fn e_returns_show_error_when_entitlement_denies() {
        // Permission-negative: user lacks can_use_mcp.
        let mut screen = McpScreen::new();
        screen.set_entitlements(entitlements_with_mcp(false));

        let action = screen.handle_key(key(KeyCode::Char('e')));
        match action {
            Action::ShowError(msg) => {
                assert!(
                    msg.contains("MCP is not enabled"),
                    "expected denial message, got {msg:?}"
                );
            }
            other => panic!("expected ShowError, got {other:?}"),
        }
    }

    #[test]
    fn e_returns_show_error_before_entitlements_are_loaded() {
        // Null/missing: entitlements have not arrived yet.
        let mut screen = McpScreen::new();
        let action = screen.handle_key(key(KeyCode::Char('e')));
        assert!(matches!(action, Action::ShowError(_)));
    }

    #[test]
    fn l_returns_launch_mcp_ai_client_when_entitlement_allows() {
        let mut screen = McpScreen::new();
        screen.set_entitlements(entitlements_with_mcp(true));

        assert!(matches!(
            screen.handle_key(key(KeyCode::Char('l'))),
            Action::LaunchMcpAiClient
        ));
    }

    #[test]
    fn l_returns_show_error_when_entitlement_denies() {
        let mut screen = McpScreen::new();
        screen.set_entitlements(entitlements_with_mcp(false));

        let action = screen.handle_key(key(KeyCode::Char('l')));
        match action {
            Action::ShowError(msg) => {
                assert!(
                    msg.contains("MCP is not enabled"),
                    "expected denial message, got {msg:?}"
                );
            }
            other => panic!("expected ShowError, got {other:?}"),
        }
    }

    #[test]
    fn l_returns_show_error_before_entitlements_are_loaded() {
        let mut screen = McpScreen::new();
        let action = screen.handle_key(key(KeyCode::Char('l')));
        assert!(matches!(action, Action::ShowError(_)));
    }

    #[test]
    fn s_r_t_keys_dispatch_stop_restart_and_test_actions() {
        let mut screen = McpScreen::new();
        assert!(matches!(
            screen.handle_key(key(KeyCode::Char('s'))),
            Action::StopMcp
        ));
        assert!(matches!(
            screen.handle_key(key(KeyCode::Char('r'))),
            Action::RestartMcp
        ));
        assert!(matches!(
            screen.handle_key(key(KeyCode::Char('t'))),
            Action::TestMcp
        ));
    }

    #[test]
    fn unrelated_keys_return_noop() {
        let mut screen = McpScreen::new();
        for code in [
            KeyCode::Up,
            KeyCode::Down,
            KeyCode::Enter,
            KeyCode::Tab,
            KeyCode::Char('x'),
        ] {
            assert!(
                matches!(screen.handle_key(key(code)), Action::Noop),
                "{code:?} should be no-op"
            );
        }
    }

    // ── State transitions ──

    #[test]
    fn new_screen_starts_in_stopped_state() {
        let screen = McpScreen::new();
        assert_eq!(screen.state, McpServerState::Stopped);
        assert!(screen.endpoint.is_none());
        assert!(screen.last_error.is_none());
    }

    #[test]
    fn set_starting_transitions_to_starting_and_clears_error() {
        let mut screen = McpScreen::new();
        screen.set_error("previous failure".into());

        screen.set_starting();

        assert_eq!(screen.state, McpServerState::Starting);
        assert!(screen.last_error.is_none());
        assert!(screen.status_line.contains("Starting"));
    }

    #[test]
    fn set_running_publishes_endpoints_and_session_file() {
        let mut screen = McpScreen::new();
        let status = sample_runtime_status();

        screen.set_running(&status);

        assert_eq!(screen.state, McpServerState::Running);
        assert_eq!(screen.endpoint.as_deref(), Some("http://127.0.0.1:53121"));
        assert_eq!(
            screen.stable_endpoint.as_deref(),
            Some("http://localhost:51234")
        );
        assert!(screen
            .session_file
            .as_deref()
            .is_some_and(|p| p.contains("session.json")));
        assert!(screen.last_error.is_none());
    }

    #[test]
    fn set_stopped_clears_endpoints_and_session_file() {
        let mut screen = McpScreen::new();
        screen.set_running(&sample_runtime_status());

        screen.set_stopped();

        assert_eq!(screen.state, McpServerState::Stopped);
        assert!(screen.endpoint.is_none());
        assert!(screen.stable_endpoint.is_none());
        assert!(screen.session_file.is_none());
        assert_eq!(screen.status_line, "Stopped");
    }

    #[test]
    fn set_error_transitions_to_failed_and_records_error_message() {
        let mut screen = McpScreen::new();
        screen.set_error("port 51234 already in use".into());

        assert_eq!(screen.state, McpServerState::Failed);
        assert_eq!(
            screen.last_error.as_deref(),
            Some("port 51234 already in use")
        );
        assert!(screen.status_line.contains("Failed"));
    }

    #[test]
    fn set_status_line_recovers_from_failed_to_running_when_message_arrives() {
        // Failed → status update treated as recovery; transitions to Running.
        let mut screen = McpScreen::new();
        screen.set_error("oops".into());
        assert_eq!(screen.state, McpServerState::Failed);

        screen.set_status_line("Running until 2026-05-20".into());

        assert_eq!(screen.state, McpServerState::Running);
        assert!(screen.last_error.is_none());
    }

    #[test]
    fn set_status_line_does_not_change_state_when_already_running() {
        let mut screen = McpScreen::new();
        screen.set_running(&sample_runtime_status());

        screen.set_status_line("Health: ok".into());

        assert_eq!(screen.state, McpServerState::Running);
        assert_eq!(screen.status_line, "Health: ok");
    }

    // ── Render: smoke ──

    #[test]
    fn render_includes_state_label_and_shortcut_help() {
        let mut screen = McpScreen::new();
        let text = rendered(&mut screen, Rect::new(0, 0, 120, 30));

        // Default state label
        assert!(text.contains("Stopped"));
        // Help line
        assert!(text.contains("e: enable + launch"));
        assert!(text.contains("l: launch CLI"));
        assert!(text.contains("will not start MCP automatically"));
        assert!(text.contains("Esc/q: back"));
    }

    #[test]
    fn render_shows_entitlement_loading_state_before_entitlements_set() {
        let mut screen = McpScreen::new();
        let text = rendered(&mut screen, Rect::new(0, 0, 120, 30));
        assert!(text.contains("Entitlement: loading"));
    }

    #[test]
    fn render_shows_entitlement_disabled_when_can_use_mcp_is_false() {
        let mut screen = McpScreen::new();
        screen.set_entitlements(entitlements_with_mcp(false));

        let text = rendered(&mut screen, Rect::new(0, 0, 120, 30));
        assert!(text.contains("Entitlement: disabled"));
    }

    #[test]
    fn render_shows_endpoint_after_set_running() {
        let mut screen = McpScreen::new();
        screen.set_running(&sample_runtime_status());

        let text = rendered(&mut screen, Rect::new(0, 0, 120, 30));
        assert!(text.contains("http://127.0.0.1:53121"));
        assert!(text.contains("http://localhost:51234"));
    }

    #[test]
    fn render_includes_last_error_when_failed() {
        let mut screen = McpScreen::new();
        screen.set_error("connection refused".into());

        let text = rendered(&mut screen, Rect::new(0, 0, 120, 30));
        assert!(text.contains("connection refused"));
    }

    #[test]
    fn render_does_not_panic_in_minimal_area() {
        let mut screen = McpScreen::new();
        let mut buf = Buffer::empty(Rect::new(0, 0, 20, 5));
        screen.render(Rect::new(0, 0, 20, 5), &mut buf);
        // Test passes if no panic.
    }
}
