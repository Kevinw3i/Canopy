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
            KeyCode::Char('p') if key.modifiers.is_empty() => Action::ChangePassword,
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
            Line::from(vec![
                Span::styled("Change Password:    ", Style::default().bold()),
                Span::raw("Press p to open the password page"),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "Edit config in the OS config directory",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            Line::from("p: change password | Esc/q: back"),
        ];

        Paragraph::new(lines).render(inner, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn modified_key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn test_config() -> ClientConfig {
        ClientConfig {
            control_plane_url: "https://canopy.example.com".into(),
            dev_mode: false,
            refresh_interval_secs: 30,
            live_tail_scrollback: 10_000,
            pkce_callback_port: 9876,
            enable_live_tail: false,
            show_public_ip: false,
            auto_update: false,
            update_repo_owner: "Kevinw3i".into(),
            update_repo_name: "Canopy".into(),
            change_password_url: None,
        }
    }

    #[test]
    fn p_opens_change_password() {
        let mut screen = SettingsScreen::new(test_config());
        let action = screen.handle_key(key(KeyCode::Char('p')));
        assert!(matches!(action, Action::ChangePassword));
    }

    #[test]
    fn modified_p_does_not_open_change_password() {
        let mut screen = SettingsScreen::new(test_config());
        assert!(matches!(
            screen.handle_key(modified_key(KeyCode::Char('p'), KeyModifiers::CONTROL)),
            Action::Noop
        ));
        assert!(matches!(
            screen.handle_key(modified_key(KeyCode::Char('p'), KeyModifiers::ALT)),
            Action::Noop
        ));
    }

    #[test]
    fn esc_and_q_go_back() {
        let mut screen = SettingsScreen::new(test_config());
        assert!(matches!(
            screen.handle_key(key(KeyCode::Esc)),
            Action::GoBack
        ));
        assert!(matches!(
            screen.handle_key(key(KeyCode::Char('q'))),
            Action::GoBack
        ));
    }
}
