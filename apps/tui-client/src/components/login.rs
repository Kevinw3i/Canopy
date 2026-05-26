use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
};

use super::Component;
use crate::event::Action;
use crate::theme::Theme;
use crate::widgets::input::TextInput;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LoginFocus {
    Username,
    LoginButton,
    SsoButton,
    DeviceCodeButton,
}

pub struct LoginScreen {
    username_input: TextInput,
    focus: LoginFocus,
    status_message: Option<String>,
    dev_mode: bool,
    theme: Theme,
}

impl LoginScreen {
    pub fn new(dev_mode: bool) -> Self {
        Self::with_theme(dev_mode, Theme::default())
    }

    pub fn with_theme(dev_mode: bool, theme: Theme) -> Self {
        let mut input = TextInput::new("Username").with_theme(theme);
        input.value = "dev-admin".to_string();
        input.cursor_pos = 9;

        // In non-dev mode, start focus on SSO button (dev controls are hidden)
        let initial_focus = if dev_mode {
            input.focused = true;
            LoginFocus::Username
        } else {
            input.focused = false;
            LoginFocus::SsoButton
        };

        Self {
            username_input: input,
            focus: initial_focus,
            status_message: None,
            dev_mode,
            theme,
        }
    }

    pub fn set_status(&mut self, msg: String) {
        self.status_message = Some(msg);
    }

    fn next_focus(&mut self) {
        if self.dev_mode {
            self.focus = match self.focus {
                LoginFocus::Username => LoginFocus::LoginButton,
                LoginFocus::LoginButton => LoginFocus::SsoButton,
                LoginFocus::SsoButton => LoginFocus::DeviceCodeButton,
                LoginFocus::DeviceCodeButton => LoginFocus::Username,
            };
        } else {
            // Skip Username and LoginButton — they are not visible
            self.focus = match self.focus {
                LoginFocus::SsoButton => LoginFocus::DeviceCodeButton,
                _ => LoginFocus::SsoButton,
            };
        }
        self.username_input.focused = self.dev_mode && self.focus == LoginFocus::Username;
    }

    fn prev_focus(&mut self) {
        if self.dev_mode {
            self.focus = match self.focus {
                LoginFocus::Username => LoginFocus::DeviceCodeButton,
                LoginFocus::LoginButton => LoginFocus::Username,
                LoginFocus::SsoButton => LoginFocus::LoginButton,
                LoginFocus::DeviceCodeButton => LoginFocus::SsoButton,
            };
        } else {
            self.focus = match self.focus {
                LoginFocus::DeviceCodeButton => LoginFocus::SsoButton,
                _ => LoginFocus::DeviceCodeButton,
            };
        }
        self.username_input.focused = self.dev_mode && self.focus == LoginFocus::Username;
    }
}

impl Component for LoginScreen {
    fn handle_key(&mut self, key: KeyEvent) -> Action {
        // Global quit
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Action::Quit;
        }

        match key.code {
            KeyCode::Tab => {
                self.next_focus();
                Action::Noop
            }
            KeyCode::BackTab => {
                self.prev_focus();
                Action::Noop
            }
            KeyCode::Enter => match self.focus {
                LoginFocus::Username | LoginFocus::LoginButton => {
                    if !self.dev_mode {
                        // Dev controls are hidden — ignore
                        Action::Noop
                    } else if self.username_input.value.is_empty() {
                        self.status_message = Some("Username is required".into());
                        Action::Noop
                    } else {
                        self.status_message = Some("Authenticating...".into());
                        Action::LoginDevMode(self.username_input.value.clone())
                    }
                }
                LoginFocus::SsoButton => Action::LoginPkce,
                LoginFocus::DeviceCodeButton => Action::LoginDeviceCode,
            },
            _ => {
                if self.dev_mode && self.focus == LoginFocus::Username {
                    self.username_input.handle_key(key);
                }
                Action::Noop
            }
        }
    }

    fn handle_paste(&mut self, text: &str) -> Action {
        if self.dev_mode && self.focus == LoginFocus::Username {
            self.username_input
                .insert_str(&text.replace("\r\n", "\n").replace(['\r', '\n'], " "));
        }
        Action::Noop
    }

    fn render(&mut self, area: Rect, buf: &mut Buffer) {
        let outer = Block::default()
            .borders(Borders::ALL)
            .title(" Canopy - Login ")
            .border_style(self.theme.accent_style());

        let inner = outer.inner(area);
        outer.render(area, buf);

        // Center the login form
        let form_width = 50u16.min(inner.width);
        let form_height = 18u16.min(inner.height);
        let form_area = Rect {
            x: inner.x + (inner.width.saturating_sub(form_width)) / 2,
            y: inner.y + (inner.height.saturating_sub(form_height)) / 2,
            width: form_width,
            height: form_height,
        };

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Title
                Constraint::Length(1), // Spacer
                Constraint::Length(3), // Username input
                Constraint::Length(1), // Spacer
                Constraint::Length(1), // Dev login button
                Constraint::Length(1), // Spacer
                Constraint::Length(1), // SSO button
                Constraint::Length(1), // Spacer
                Constraint::Length(1), // Device code button
                Constraint::Length(1), // Spacer
                Constraint::Length(2), // Status
                Constraint::Min(0),    // Remainder
            ])
            .split(form_area);

        // Title
        let title = Paragraph::new(vec![
            Line::from(Span::styled(
                "Operations Console",
                self.theme.accent_style().bold(),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "Sign in to continue",
                self.theme.muted_style(),
            )),
        ])
        .alignment(Alignment::Center);
        title.render(chunks[0], buf);

        // Username input (dev mode only)
        if self.dev_mode {
            self.username_input.render(chunks[2], buf);
        }

        // Buttons
        let dev_btn_style = if self.focus == LoginFocus::LoginButton {
            self.theme.selected_plain_style()
        } else {
            self.theme.accent_style()
        };
        let sso_btn_style = if self.focus == LoginFocus::SsoButton {
            self.theme.selected_plain_style()
        } else {
            self.theme.success_style()
        };
        let dc_btn_style = if self.focus == LoginFocus::DeviceCodeButton {
            self.theme.selected_plain_style()
        } else {
            self.theme.warning_style()
        };

        if self.dev_mode {
            Paragraph::new(Line::from(vec![Span::styled(
                "  [ Dev Login ]  ",
                dev_btn_style,
            )]))
            .alignment(Alignment::Center)
            .render(chunks[4], buf);
        }

        Paragraph::new(Line::from(vec![Span::styled(
            "  [ SSO / OIDC (PKCE) ]  ",
            sso_btn_style,
        )]))
        .alignment(Alignment::Center)
        .render(chunks[6], buf);

        Paragraph::new(Line::from(vec![Span::styled(
            "  [ Device Code (Headless) ]  ",
            dc_btn_style,
        )]))
        .alignment(Alignment::Center)
        .render(chunks[8], buf);

        // Status message
        if let Some(ref msg) = self.status_message {
            let style = if msg.contains("error") || msg.contains("failed") {
                self.theme.danger_style()
            } else {
                self.theme.warning_style()
            };
            Paragraph::new(Line::from(Span::styled(msg.as_str(), style)))
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true })
                .render(chunks[10], buf);
        }
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

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent {
            code: KeyCode::Char(c),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    // ── Dev mode tests ──

    #[test]
    fn dev_mode_initial_focus_is_username() {
        let screen = LoginScreen::new(true);
        assert!(screen.username_input.focused);
        assert_eq!(screen.focus, LoginFocus::Username);
    }

    #[test]
    fn dev_mode_tab_cycles_through_all_buttons() {
        let mut screen = LoginScreen::new(true);

        screen.handle_key(key(KeyCode::Tab));
        assert_eq!(screen.focus, LoginFocus::LoginButton);

        screen.handle_key(key(KeyCode::Tab));
        assert_eq!(screen.focus, LoginFocus::SsoButton);

        screen.handle_key(key(KeyCode::Tab));
        assert_eq!(screen.focus, LoginFocus::DeviceCodeButton);

        screen.handle_key(key(KeyCode::Tab));
        assert_eq!(screen.focus, LoginFocus::Username);
        assert!(screen.username_input.focused);
    }

    #[test]
    fn dev_mode_backtab_cycles_reverse() {
        let mut screen = LoginScreen::new(true);

        screen.handle_key(key(KeyCode::BackTab));
        assert_eq!(screen.focus, LoginFocus::DeviceCodeButton);

        screen.handle_key(key(KeyCode::BackTab));
        assert_eq!(screen.focus, LoginFocus::SsoButton);
    }

    #[test]
    fn dev_mode_enter_on_username_dispatches_login() {
        let mut screen = LoginScreen::new(true);
        // Default value is "dev-admin"
        let action = screen.handle_key(key(KeyCode::Enter));
        assert!(matches!(action, Action::LoginDevMode(ref u) if u == "dev-admin"));
    }

    #[test]
    fn dev_mode_enter_on_empty_username_shows_error() {
        let mut screen = LoginScreen::new(true);
        screen.username_input.value.clear();
        screen.username_input.cursor_pos = 0;

        let action = screen.handle_key(key(KeyCode::Enter));
        assert!(matches!(action, Action::Noop));
        assert_eq!(
            screen.status_message.as_deref(),
            Some("Username is required")
        );
    }

    #[test]
    fn dev_mode_paste_inserts_username_text() {
        let mut screen = LoginScreen::new(true);
        screen.username_input.clear();

        screen.handle_paste("alice@example.com\nignored");

        assert_eq!(screen.username_input.value, "alice@example.com ignored");
    }

    #[test]
    fn dev_mode_enter_on_sso_button_dispatches_pkce() {
        let mut screen = LoginScreen::new(true);
        screen.focus = LoginFocus::SsoButton;

        let action = screen.handle_key(key(KeyCode::Enter));
        assert!(matches!(action, Action::LoginPkce));
    }

    #[test]
    fn dev_mode_enter_on_device_code_button() {
        let mut screen = LoginScreen::new(true);
        screen.focus = LoginFocus::DeviceCodeButton;

        let action = screen.handle_key(key(KeyCode::Enter));
        assert!(matches!(action, Action::LoginDeviceCode));
    }

    // ── Production mode tests ──

    #[test]
    fn prod_mode_initial_focus_is_sso() {
        let screen = LoginScreen::new(false);
        assert!(!screen.username_input.focused);
        assert_eq!(screen.focus, LoginFocus::SsoButton);
    }

    #[test]
    fn prod_mode_tab_only_toggles_sso_and_device_code() {
        let mut screen = LoginScreen::new(false);
        assert_eq!(screen.focus, LoginFocus::SsoButton);

        screen.handle_key(key(KeyCode::Tab));
        assert_eq!(screen.focus, LoginFocus::DeviceCodeButton);

        screen.handle_key(key(KeyCode::Tab));
        assert_eq!(screen.focus, LoginFocus::SsoButton);
    }

    #[test]
    fn ctrl_c_quits() {
        let mut screen = LoginScreen::new(false);
        let action = screen.handle_key(ctrl('c'));
        assert!(matches!(action, Action::Quit));
    }

    #[test]
    fn set_status_message() {
        let mut screen = LoginScreen::new(false);
        screen.set_status("Authenticating...".into());
        assert_eq!(screen.status_message.as_deref(), Some("Authenticating..."));
    }
}
