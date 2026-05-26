use crossterm::event::KeyEvent;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};

use super::Component;
use crate::config::ClientConfig;
use crate::event::Action;
use crate::keybindings::KeyBindings;

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
        if self
            .config
            .keybindings
            .matches_any(&self.config.keybindings.quit, &key)
        {
            return Action::Quit;
        }
        if self
            .config
            .keybindings
            .matches_any(&self.config.keybindings.settings_back, &key)
        {
            return Action::GoBack;
        }
        if self
            .config
            .keybindings
            .matches_any(&self.config.keybindings.settings_change_password, &key)
        {
            return Action::ChangePassword;
        }
        Action::Noop
    }

    fn render(&mut self, area: Rect, buf: &mut Buffer) {
        let outer = Block::default()
            .borders(Borders::ALL)
            .title(" Settings ")
            .border_style(Style::default().fg(Color::Cyan));
        let inner = outer.inner(area);
        outer.render(area, buf);

        let mut lines = vec![
            Line::from(Span::styled(
                "Runtime",
                Style::default().fg(Color::Cyan).bold(),
            )),
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
                Span::raw(format!(
                    "Press {} to open the password page",
                    KeyBindings::first_label(&self.config.keybindings.settings_change_password)
                )),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "Keyboard Shortcuts",
                Style::default().fg(Color::Cyan).bold(),
            )),
        ];

        let rows = self.config.keybindings.settings_rows();
        for row in rows.chunks(2) {
            let left = shortcut_cell(row[0].0, &row[0].1);
            let line = if let Some(right) = row.get(1) {
                format!("{left:<38}{}", shortcut_cell(right.0, &right.1))
            } else {
                left
            };
            lines.push(Line::from(line));
        }

        lines.extend([
            Line::from(""),
            Line::from(vec![
                Span::styled("Config File:        ", Style::default().bold()),
                Span::raw(ClientConfig::config_path().display().to_string()),
            ]),
            Line::from(Span::styled(
                "Edit [keybindings] in the OS config file to customize shortcuts",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            Line::from(format!(
                "{}: change password | {}: back",
                KeyBindings::first_label(&self.config.keybindings.settings_change_password),
                KeyBindings::first_label(&self.config.keybindings.settings_back)
            )),
        ]);

        Paragraph::new(lines).render(inner, buf);
    }
}

fn shortcut_cell(name: &str, keys: &str) -> String {
    format!("{name}: {keys}")
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
            keybindings: crate::keybindings::KeyBindings::default(),
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

    #[test]
    fn custom_settings_shortcuts_replace_defaults() {
        let mut config = test_config();
        config.keybindings.settings_back = vec!["b".into()];
        config.keybindings.settings_change_password = vec!["P".into()];
        let mut screen = SettingsScreen::new(config);

        assert!(matches!(
            screen.handle_key(key(KeyCode::Char('q'))),
            Action::Noop
        ));
        assert!(matches!(
            screen.handle_key(key(KeyCode::Char('b'))),
            Action::GoBack
        ));
        assert!(matches!(
            screen.handle_key(key(KeyCode::Char('p'))),
            Action::Noop
        ));
        assert!(matches!(
            screen.handle_key(key(KeyCode::Char('P'))),
            Action::ChangePassword
        ));
    }

    #[test]
    fn render_shows_keyboard_shortcuts() {
        let mut screen = SettingsScreen::new(test_config());
        let area = Rect::new(0, 0, 80, 24);
        let mut buf = Buffer::empty(area);
        screen.render(area, &mut buf);

        let text = buf
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains("Keyboard Shortcuts"));
        assert!(text.contains("Dashboard select"));
        assert!(text.contains("enter"));
        assert!(text.contains("Config File:"));
    }
}
