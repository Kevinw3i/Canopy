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
use shared::dto::auth::{MfaFactorKind, MfaStatusResponse};

pub struct SettingsScreen {
    pub config: ClientConfig,
    theme: Theme,
    mfa_status: Option<MfaStatusResponse>,
    mfa_loading: bool,
    mfa_error: Option<String>,
}

impl SettingsScreen {
    pub fn new(config: ClientConfig, theme: Theme) -> Self {
        Self {
            config,
            theme,
            mfa_status: None,
            mfa_loading: false,
            mfa_error: None,
        }
    }

    pub fn set_mfa_loading(&mut self) {
        self.mfa_loading = true;
        self.mfa_error = None;
    }

    pub fn set_mfa_status(&mut self, status: MfaStatusResponse) {
        self.mfa_status = Some(status);
        self.mfa_loading = false;
        self.mfa_error = None;
    }

    pub fn set_mfa_error(&mut self, error: String) {
        self.mfa_loading = false;
        self.mfa_error = Some(error);
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
        if key.modifiers.is_empty() && matches!(key.code, crossterm::event::KeyCode::Char('r')) {
            return Action::RefreshMfaStatus;
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
                Span::styled("Dev/Refresh/Tail:   ", label_style),
                Span::raw(format!(
                    "{} / {}s / {}",
                    if self.config.dev_mode { "Yes" } else { "No" },
                    self.config.refresh_interval_secs,
                    self.config.live_tail_scrollback
                )),
            ]),
            Line::from(Span::styled("MFA & Step-up", heading_style)),
            self.mfa_line(
                "Provider step-up:   ",
                self.mfa_status
                    .as_ref()
                    .map(|status| status.provider_step_up_configured),
                "configured",
                "not configured",
            ),
            self.factor_line("Local TOTP:         ", MfaFactorKind::Totp),
            self.factor_line("Local WebAuthn:     ", MfaFactorKind::WebAuthn),
            self.mfa_line(
                "Step-up:            ",
                self.mfa_status
                    .as_ref()
                    .map(|status| status.local_step_up_available),
                "available",
                "not configured",
            ),
            Line::from(Span::styled("Theme", heading_style)),
            Line::from(vec![
                Span::styled("Preset:             ", label_style),
                Span::raw(format!(
                    "{} / selected {} on {}",
                    self.config.theme.preset,
                    color_label(self.theme.selected_fg),
                    color_label(self.theme.selected_bg)
                )),
            ]),
            Line::from(vec![
                Span::styled("Colors: ", label_style),
                Span::raw(format!(
                    "{} / {} / {}; err {}",
                    color_label(self.theme.accent),
                    color_label(self.theme.text),
                    color_label(self.theme.muted),
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
                    "r: refresh MFA | {}: change password | {}: back",
                    KeyBindings::first_label(&self.config.keybindings.settings_change_password),
                    KeyBindings::first_label(&self.config.keybindings.settings_back)
                ),
                muted_style,
            )),
        ]);

        Paragraph::new(lines).style(body_style).render(inner, buf);
    }

    fn on_enter(&mut self) -> Vec<Action> {
        vec![Action::RefreshMfaStatus]
    }
}

fn shortcut_cell(name: &str, keys: &str) -> String {
    format!("{name}: {keys}")
}

impl SettingsScreen {
    fn mfa_line(
        &self,
        label: &'static str,
        value: Option<bool>,
        enabled: &'static str,
        disabled: &'static str,
    ) -> Line<'static> {
        let label_style = Style::default().fg(self.theme.text).bold();
        let value_style = if self.mfa_loading {
            self.theme.warning_style()
        } else if self.mfa_error.is_some() {
            self.theme.danger_style()
        } else if value == Some(true) {
            self.theme.success_style()
        } else {
            self.theme.muted_style()
        };
        let text = if self.mfa_loading {
            "loading".into()
        } else if let Some(error) = self.mfa_error.as_deref() {
            format!("error: {}", truncate(error, 42))
        } else if let Some(value) = value {
            if value {
                enabled.into()
            } else {
                disabled.into()
            }
        } else {
            "unknown".into()
        };

        Line::from(vec![
            Span::styled(label, label_style),
            Span::styled(text, value_style),
        ])
    }

    fn factor_line(&self, label: &'static str, kind: MfaFactorKind) -> Line<'static> {
        let factor = self
            .mfa_status
            .as_ref()
            .and_then(|status| status.factors.iter().find(|factor| factor.kind == kind));
        match factor {
            Some(factor) if factor.available && factor.enrolled => {
                self.mfa_line(label, Some(true), "enrolled", "not enrolled")
            }
            Some(factor) if factor.available => {
                self.mfa_line(label, Some(false), "enrolled", "not enrolled")
            }
            Some(_) => self.mfa_line(label, Some(false), "enrolled", "not configured"),
            None => self.mfa_line(label, None, "enrolled", "not configured"),
        }
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let mut out = String::new();
    for _ in 0..max_chars {
        let Some(ch) = chars.next() else {
            return out;
        };
        out.push(ch);
    }
    if chars.next().is_some() {
        out.push_str("...");
    }
    out
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
    fn r_refreshes_mfa_status() {
        let mut screen = SettingsScreen::new(test_config(), test_theme());
        let action = screen.handle_key(key(KeyCode::Char('r')));
        assert!(matches!(action, Action::RefreshMfaStatus));
    }

    #[test]
    fn render_shows_keyboard_shortcuts_and_theme_at_80x24() {
        let mut screen = SettingsScreen::new(test_config(), test_theme());
        screen.set_mfa_status(MfaStatusResponse {
            user_id: "dev-admin".into(),
            provider_step_up_configured: true,
            local_step_up_available: false,
            step_up_required: false,
            factors: vec![
                shared::dto::auth::MfaFactorStatus {
                    kind: MfaFactorKind::Totp,
                    available: false,
                    enrolled: false,
                    label: Some("Authenticator app".into()),
                },
                shared::dto::auth::MfaFactorStatus {
                    kind: MfaFactorKind::WebAuthn,
                    available: false,
                    enrolled: false,
                    label: Some("Security key".into()),
                },
            ],
            message: "OIDC provider MFA/re-auth controls are configured.".into(),
        });
        let text = rendered_text(&mut screen);

        assert!(text.contains("MFA & Step-up"));
        assert!(text.contains("Provider step-up:"));
        assert!(text.contains("Local TOTP:"));
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
