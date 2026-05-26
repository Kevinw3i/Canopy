use crossterm::event::KeyEvent;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};

use super::Component;
use crate::config::ClientConfig;
use crate::event::Action;
use crate::keybindings::KeyBindings;
use crate::theme::{color_label, Theme};

pub struct SettingsScreen {
    pub config: ClientConfig,
    theme: Theme,
}

impl SettingsScreen {
    pub fn new(config: ClientConfig, theme: Theme) -> Self {
        Self { config, theme }
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
        let heading_style = Style::default().fg(self.theme.accent).bold();
        let label_style = Style::default().fg(self.theme.text).bold();
        let muted_style = Style::default().fg(self.theme.muted);
        let body_style = Style::default().fg(self.theme.text);
        let outer = Block::default()
            .borders(Borders::ALL)
            .title(" Settings ")
            .border_style(Style::default().fg(self.theme.accent));
        let inner = outer.inner(area);
        outer.render(area, buf);

        let mut lines = vec![
            Line::from(Span::styled("Runtime", heading_style)),
            Line::from(vec![
                Span::styled("Control Plane URL:  ", label_style),
                Span::raw(&self.config.control_plane_url),
            ]),
            Line::from(vec![
                Span::styled("Dev Mode:           ", label_style),
                Span::raw(if self.config.dev_mode { "Yes" } else { "No" }),
            ]),
            Line::from(vec![
                Span::styled("Refresh Interval:   ", label_style),
                Span::raw(format!("{}s", self.config.refresh_interval_secs)),
            ]),
            Line::from(vec![
                Span::styled("Live Tail Scrollback:", label_style),
                Span::raw(format!(" {}", self.config.live_tail_scrollback)),
            ]),
            Line::from(Span::styled("Theme", heading_style)),
            Line::from(vec![
                Span::styled("Preset:             ", label_style),
                Span::raw(&self.config.theme.preset),
            ]),
            Line::from(vec![
                Span::styled("Accent/Text/Muted:  ", label_style),
                Span::raw(format!(
                    "{} / {} / {}",
                    color_label(self.theme.accent),
                    color_label(self.theme.text),
                    color_label(self.theme.muted)
                )),
            ]),
            Line::from(vec![
                Span::styled("Selected:           ", label_style),
                Span::raw(format!(
                    "{} on {}",
                    color_label(self.theme.selected_fg),
                    color_label(self.theme.selected_bg)
                )),
            ]),
            Line::from(vec![
                Span::styled("Status:             ", label_style),
                Span::raw(format!(
                    "ok {} warn {} err {}",
                    color_label(self.theme.success),
                    color_label(self.theme.warning),
                    color_label(self.theme.danger)
                )),
            ]),
            Line::from(Span::styled("Keyboard Shortcuts", heading_style)),
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
            Line::from(vec![
                Span::styled("Config File:        ", label_style),
                Span::raw(ClientConfig::config_path().display().to_string()),
            ]),
            Line::from(Span::styled(
                "Edit [theme] or [keybindings] in the OS config file",
                muted_style,
            )),
            Line::from(Span::styled(
                format!(
                    "{}: change password | {}: back",
                    KeyBindings::first_label(&self.config.keybindings.settings_change_password),
                    KeyBindings::first_label(&self.config.keybindings.settings_back)
                ),
                muted_style,
            )),
        ]);

        Paragraph::new(lines).style(body_style).render(inner, buf);
    }
}

fn shortcut_cell(name: &str, keys: &str) -> String {
    format!("{name}: {keys}")
}

#[cfg(test)]
fn theme_from_config(config: &ClientConfig) -> Theme {
    config
        .theme
        .resolve()
        .expect("test configs should resolve a valid theme")
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
            theme: crate::theme::ThemeConfig::default(),
        }
    }

    fn test_theme() -> Theme {
        theme_from_config(&test_config())
    }

    fn rendered_text(screen: &mut SettingsScreen) -> String {
        let area = Rect::new(0, 0, 80, 24);
        let mut buf = Buffer::empty(area);
        screen.render(area, &mut buf);

        buf.content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>()
    }

    #[test]
    fn p_opens_change_password() {
        let mut screen = SettingsScreen::new(test_config(), test_theme());
        let action = screen.handle_key(key(KeyCode::Char('p')));
        assert!(matches!(action, Action::ChangePassword));
    }

    #[test]
    fn modified_p_does_not_open_change_password() {
        let mut screen = SettingsScreen::new(test_config(), test_theme());
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
        let mut screen = SettingsScreen::new(test_config(), test_theme());
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
        let theme = theme_from_config(&config);
        let mut screen = SettingsScreen::new(config, theme);

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
    fn render_shows_keyboard_shortcuts_and_theme_at_80x24() {
        let mut screen = SettingsScreen::new(test_config(), test_theme());
        let text = rendered_text(&mut screen);

        assert!(text.contains("Theme"));
        assert!(text.contains("Preset:"));
        assert!(text.contains("Keyboard Shortcuts"));
        assert!(text.contains("Dashboard select"));
        assert!(text.contains("enter"));
        assert!(text.contains("Config File:"));
        assert!(text.contains("change password"));
    }

    #[test]
    fn render_shows_resolved_high_contrast_theme() {
        let mut config = test_config();
        config.theme.preset = "high_contrast".into();
        let theme = theme_from_config(&config);
        let mut screen = SettingsScreen::new(config, theme);
        let text = rendered_text(&mut screen);

        assert!(text.contains("high_contrast"));
        assert!(text.contains("yellow / white / white"));
        assert!(text.contains("black on yellow"));
        assert!(text.contains("err light_red"));
    }
}
