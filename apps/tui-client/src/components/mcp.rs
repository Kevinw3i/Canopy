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
                    "cloudwatch reserved"
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

        let help = "Use e to enable the local MCP server, verify healthz, then choose Codex CLI or Claude Code. Use s to stop, r to restart, t to test health. Phase 1 only exposes canopy_describe_capabilities and canopy_get_guidance; CloudWatch data tools remain disabled.";
        let body = if let Some(error) = self.last_error.as_ref() {
            format!("{help}\n\nLast error:\n{error}")
        } else {
            help.into()
        };
        Paragraph::new(body)
            .block(Block::default().borders(Borders::ALL).title(" Notes "))
            .wrap(Wrap { trim: true })
            .render(chunks[2], buf);

        Paragraph::new("e: enable + launch | s: stop | r: restart | t: test | Esc/q: back")
            .style(Style::default().fg(Color::Gray))
            .render(chunks[3], buf);
    }
}
