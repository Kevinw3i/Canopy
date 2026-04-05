use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};

use super::Component;
use crate::config::ClientConfig;
use crate::event::Action;

pub struct SettingsScreen {
    pub config: ClientConfig,
}

impl SettingsScreen {
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }
}

impl Component for SettingsScreen {
    fn handle_key(&mut self, key: KeyEvent) -> Action {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Action::Quit;
        }
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => Action::GoBack,
            _ => Action::Noop,
        }
    }

    fn render(&mut self, area: Rect, buf: &mut Buffer) {
        let outer = Block::default()
            .borders(Borders::ALL)
            .title(" Settings ")
            .border_style(Style::default().fg(Color::Cyan));
        let inner = outer.inner(area);
        outer.render(area, buf);

        let lines = vec![
            Line::from(vec![
                Span::styled("Control Plane URL:  ", Style::default().bold()),
                Span::raw(&self.config.control_plane_url),
            ]),
            Line::from(vec![
                Span::styled("Dev Mode:           ", Style::default().bold()),
                Span::raw(if self.config.dev_mode { "Yes" } else { "No" }),
            ]),
            Line::from(vec![
                Span::styled("Refresh Interval:   ", Style::default().bold()),
                Span::raw(format!("{}s", self.config.refresh_interval_secs)),
            ]),
            Line::from(vec![
                Span::styled("Live Tail Scrollback:", Style::default().bold()),
                Span::raw(format!(" {}", self.config.live_tail_scrollback)),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "Edit config at ~/.config/canopy/config.toml",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            Line::from("Esc/q: back"),
        ];

        Paragraph::new(lines).render(inner, buf);
    }
}
