use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};

use super::Component;
use crate::config::ClientConfig;
use crate::event::Action;
use crate::keybindings::KeyBindings;
use crate::theme::{color_label, Theme};
use crate::widgets::input::TextInput;
use shared::dto::auth::{
    MfaFactorKind, MfaStatusResponse, RecoveryCodesGenerateResponse, TotpEnrollStartResponse,
    TotpVerifyResponse,
};

pub struct SettingsScreen {
    pub config: ClientConfig,
    theme: Theme,
    mfa_status: Option<MfaStatusResponse>,
    mfa_loading: bool,
    mfa_error: Option<String>,
    totp_starting: bool,
    totp_success: Option<String>,
    totp_enrollment: Option<TotpEnrollmentState>,
    totp_step_up_success: Option<String>,
    totp_verification: Option<TotpVerificationState>,
    recovery_codes_generating: bool,
    recovery_codes_error: Option<String>,
    recovery_codes: Option<Vec<String>>,
}

struct TotpEnrollmentState {
    response: TotpEnrollStartResponse,
    code_input: TextInput,
    submitting: bool,
    error: Option<String>,
}

struct TotpVerificationState {
    code_input: TextInput,
    submitting: bool,
    error: Option<String>,
}

impl SettingsScreen {
    pub fn new(config: ClientConfig, theme: Theme) -> Self {
        Self {
            config,
            theme,
            mfa_status: None,
            mfa_loading: false,
            mfa_error: None,
            totp_starting: false,
            totp_success: None,
            totp_enrollment: None,
            totp_step_up_success: None,
            totp_verification: None,
            recovery_codes_generating: false,
            recovery_codes_error: None,
            recovery_codes: None,
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
        self.totp_starting = false;
        self.recovery_codes_generating = false;
    }

    pub fn set_mfa_error(&mut self, error: String) {
        self.mfa_loading = false;
        self.mfa_error = Some(error);
        self.totp_starting = false;
        self.recovery_codes_generating = false;
    }

    pub fn set_totp_starting(&mut self) {
        self.totp_starting = true;
        self.totp_success = None;
        self.totp_enrollment = None;
        self.totp_step_up_success = None;
        self.totp_verification = None;
        self.mfa_error = None;
        self.recovery_codes = None;
        self.recovery_codes_error = None;
    }

    pub fn set_totp_started(&mut self, response: TotpEnrollStartResponse) {
        let mut code_input = TextInput::new("Verification code").with_theme(self.theme);
        code_input.focused = true;
        self.totp_enrollment = Some(TotpEnrollmentState {
            response,
            code_input,
            submitting: false,
            error: None,
        });
        self.totp_starting = false;
        self.totp_success = None;
        self.totp_step_up_success = None;
        self.totp_verification = None;
        self.mfa_error = None;
        self.recovery_codes_error = None;
    }

    pub fn set_totp_start_error(&mut self, error: String) {
        self.totp_starting = false;
        self.mfa_error = Some(error);
    }

    pub fn set_totp_confirming(&mut self) {
        if let Some(enrollment) = self.totp_enrollment.as_mut() {
            enrollment.submitting = true;
            enrollment.error = None;
        }
    }

    pub fn set_totp_confirm_error(&mut self, error: String) {
        if let Some(enrollment) = self.totp_enrollment.as_mut() {
            enrollment.submitting = false;
            enrollment.error = Some(error);
        }
    }

    pub fn set_totp_confirmed(&mut self, status: MfaStatusResponse) {
        self.totp_enrollment = None;
        self.totp_starting = false;
        self.totp_success = Some("TOTP enrolled".into());
        self.set_mfa_status(status);
    }

    pub fn start_totp_step_up_verification(&mut self) {
        let mut code_input = TextInput::new("Step-up code").with_theme(self.theme);
        code_input.focused = true;
        self.totp_verification = Some(TotpVerificationState {
            code_input,
            submitting: false,
            error: None,
        });
        self.totp_step_up_success = None;
        self.totp_enrollment = None;
        self.mfa_error = None;
    }

    pub fn set_totp_step_up_verifying(&mut self) {
        if let Some(verification) = self.totp_verification.as_mut() {
            verification.submitting = true;
            verification.error = None;
        }
    }

    pub fn set_totp_step_up_verify_error(&mut self, error: String) {
        if let Some(verification) = self.totp_verification.as_mut() {
            verification.submitting = false;
            verification.error = Some(error);
        }
    }

    pub fn set_totp_step_up_verified(&mut self, response: TotpVerifyResponse) {
        self.totp_verification = None;
        self.totp_step_up_success = Some(format!("verified until {}", response.step_up_expires_at));
        self.set_mfa_status(response.status);
    }

    pub fn set_recovery_codes_generating(&mut self) {
        self.recovery_codes_generating = true;
        self.recovery_codes_error = None;
        self.recovery_codes = None;
        self.mfa_error = None;
    }

    pub fn set_recovery_codes_generated(&mut self, response: RecoveryCodesGenerateResponse) {
        self.mfa_status = Some(response.status);
        self.mfa_loading = false;
        self.mfa_error = None;
        self.recovery_codes_generating = false;
        self.recovery_codes_error = None;
        self.recovery_codes = Some(response.codes);
    }

    pub fn set_recovery_codes_generate_error(&mut self, error: String) {
        self.recovery_codes_generating = false;
        self.recovery_codes_error = Some(error);
        self.recovery_codes = None;
    }
}

impl Component for SettingsScreen {
    fn handle_key(&mut self, key: KeyEvent) -> Action {
        if self.totp_enrollment.is_some() {
            return self.handle_totp_enrollment_key(key);
        }
        if self.totp_verification.is_some() {
            return self.handle_totp_verification_key(key);
        }

        if self
            .config
            .keybindings
            .matches_any(&self.config.keybindings.quit, &key)
        {
            return Action::Quit;
        }
        if key.modifiers.is_empty()
            && matches!(key.code, KeyCode::Esc)
            && self.recovery_codes.is_some()
        {
            self.recovery_codes = None;
            return Action::Noop;
        }
        if self
            .config
            .keybindings
            .matches_any(&self.config.keybindings.settings_back, &key)
        {
            self.recovery_codes = None;
            return Action::GoBack;
        }
        if self
            .config
            .keybindings
            .matches_any(&self.config.keybindings.settings_change_password, &key)
        {
            return Action::ChangePassword;
        }
        if key.modifiers.is_empty() && matches!(key.code, KeyCode::Char('r')) {
            return Action::RefreshMfaStatus;
        }
        if key.modifiers.is_empty()
            && matches!(key.code, KeyCode::Char('e'))
            && self.can_start_totp_enrollment()
            && !self.totp_starting
        {
            return Action::StartTotpEnrollment;
        }
        if key.modifiers.is_empty()
            && matches!(key.code, KeyCode::Char('v'))
            && self.can_verify_totp_step_up()
        {
            return Action::StartTotpStepUpVerification;
        }
        if key.modifiers.is_empty()
            && matches!(key.code, KeyCode::Char('g'))
            && self.can_generate_recovery_codes()
            && !self.recovery_codes_generating
        {
            return Action::GenerateRecoveryCodes;
        }
        Action::Noop
    }

    fn handle_paste(&mut self, text: &str) -> Action {
        let digits: String = text
            .chars()
            .filter(|ch| ch.is_ascii_digit())
            .take(6)
            .collect();
        if let Some(enrollment) = self.totp_enrollment.as_mut() {
            enrollment.code_input.insert_str(&digits);
        } else if let Some(verification) = self.totp_verification.as_mut() {
            verification.code_input.insert_str(&digits);
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

        let has_code_input = self.totp_enrollment.is_some() || self.totp_verification.is_some();
        let (content_area, code_input_area) = if has_code_input && inner.height > 8 {
            let chunks = Layout::vertical([Constraint::Min(0), Constraint::Length(3)]).split(inner);
            (chunks[0], Some(chunks[1]))
        } else {
            (inner, None)
        };

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
        ];

        lines.extend(self.totp_lines());
        lines.extend(self.recovery_code_lines());

        lines.extend([
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
        ]);

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

        Paragraph::new(lines)
            .style(body_style)
            .render(content_area, buf);

        if let (Some(enrollment), Some(area)) = (self.totp_enrollment.as_ref(), code_input_area) {
            enrollment.code_input.render(area, buf);
        } else if let (Some(verification), Some(area)) =
            (self.totp_verification.as_ref(), code_input_area)
        {
            verification.code_input.render(area, buf);
        }
    }

    fn on_enter(&mut self) -> Vec<Action> {
        vec![Action::RefreshMfaStatus]
    }
}

fn shortcut_cell(name: &str, keys: &str) -> String {
    format!("{name}: {keys}")
}

impl SettingsScreen {
    fn handle_totp_enrollment_key(&mut self, key: KeyEvent) -> Action {
        let Some(enrollment) = self.totp_enrollment.as_mut() else {
            return Action::Noop;
        };

        match key.code {
            KeyCode::Esc => {
                self.totp_enrollment = None;
                Action::Noop
            }
            KeyCode::Enter if !enrollment.submitting => {
                let code = enrollment.code_input.value.trim().to_string();
                if code.is_empty() {
                    enrollment.error = Some("Enter the current 6-digit code".into());
                    Action::Noop
                } else {
                    Action::ConfirmTotpEnrollment {
                        factor_id: enrollment.response.factor_id.clone(),
                        code,
                    }
                }
            }
            _ => {
                enrollment.code_input.handle_key(key);
                Action::Noop
            }
        }
    }

    fn handle_totp_verification_key(&mut self, key: KeyEvent) -> Action {
        let Some(verification) = self.totp_verification.as_mut() else {
            return Action::Noop;
        };

        match key.code {
            KeyCode::Esc => {
                self.totp_verification = None;
                Action::Noop
            }
            KeyCode::Enter if !verification.submitting => {
                let code = verification.code_input.value.trim().to_string();
                if code.is_empty() {
                    verification.error = Some("Enter the current 6-digit code".into());
                    Action::Noop
                } else {
                    Action::VerifyTotpStepUp { code }
                }
            }
            _ => {
                verification.code_input.handle_key(key);
                Action::Noop
            }
        }
    }

    fn totp_lines(&self) -> Vec<Line<'static>> {
        let heading_style = Style::default().fg(self.theme.accent).bold();
        let label_style = Style::default().fg(self.theme.text).bold();
        let muted_style = self.theme.muted_style();
        let success_style = self.theme.success_style();
        let warning_style = self.theme.warning_style();
        let danger_style = self.theme.danger_style();

        let mut lines = Vec::new();
        if self.totp_starting {
            lines.push(Line::from(vec![
                Span::styled("TOTP enrollment:   ", label_style),
                Span::styled("starting", warning_style),
            ]));
        } else if let Some(enrollment) = self.totp_enrollment.as_ref() {
            lines.push(Line::from(Span::styled("TOTP Setup", heading_style)));
            lines.push(Line::from(vec![
                Span::styled("Secret:             ", label_style),
                Span::raw(truncate(&enrollment.response.secret_base32, 72)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("otpauth URL:        ", label_style),
                Span::raw(truncate(&enrollment.response.otpauth_url, 72)),
            ]));
            let state = if enrollment.submitting {
                Span::styled("verifying", warning_style)
            } else if let Some(error) = enrollment.error.as_deref() {
                Span::styled(format!("error: {}", truncate(error, 46)), danger_style)
            } else {
                Span::styled("Enter verifies; Esc cancels local setup view", muted_style)
            };
            lines.push(Line::from(vec![
                Span::styled("Status:             ", label_style),
                state,
            ]));
        } else if let Some(success) = self.totp_success.as_deref() {
            lines.push(Line::from(vec![
                Span::styled("TOTP enrollment:   ", label_style),
                Span::styled(success.to_string(), success_style),
            ]));
        } else if self.can_start_totp_enrollment() {
            lines.push(Line::from(vec![
                Span::styled("TOTP enrollment:   ", label_style),
                Span::styled("press e to set up", success_style),
            ]));
        } else if self.totp_enrolled() {
            lines.push(Line::from(vec![
                Span::styled("TOTP enrollment:   ", label_style),
                Span::styled("enrolled", success_style),
            ]));
        }

        if let Some(verification) = self.totp_verification.as_ref() {
            lines.push(Line::from(Span::styled("TOTP Step-up", heading_style)));
            let state = if verification.submitting {
                Span::styled("verifying", warning_style)
            } else if let Some(error) = verification.error.as_deref() {
                Span::styled(format!("error: {}", truncate(error, 46)), danger_style)
            } else {
                Span::styled(
                    "Enter verifies; Esc cancels local step-up view",
                    muted_style,
                )
            };
            lines.push(Line::from(vec![
                Span::styled("Status:             ", label_style),
                state,
            ]));
        } else if let Some(success) = self.totp_step_up_success.as_deref() {
            lines.push(Line::from(vec![
                Span::styled("TOTP step-up:       ", label_style),
                Span::styled(truncate(success, 72), success_style),
            ]));
        } else if self.can_verify_totp_step_up() {
            lines.push(Line::from(vec![
                Span::styled("TOTP step-up:       ", label_style),
                Span::styled("press v to verify", success_style),
            ]));
        }

        lines
    }

    fn can_start_totp_enrollment(&self) -> bool {
        self.totp_factor()
            .is_some_and(|factor| factor.available && !factor.enrolled)
    }

    fn totp_enrolled(&self) -> bool {
        self.totp_factor().is_some_and(|factor| factor.enrolled)
    }

    fn can_verify_totp_step_up(&self) -> bool {
        self.totp_factor()
            .is_some_and(|factor| factor.available && factor.enrolled)
    }

    fn can_generate_recovery_codes(&self) -> bool {
        self.can_verify_totp_step_up() && self.totp_step_up_success.is_some()
    }

    fn recovery_code_lines(&self) -> Vec<Line<'static>> {
        if !self.totp_enrolled()
            && !self.recovery_codes_generating
            && self.recovery_codes_error.is_none()
            && self.recovery_codes.is_none()
        {
            return Vec::new();
        }

        let heading_style = Style::default().fg(self.theme.accent).bold();
        let label_style = Style::default().fg(self.theme.text).bold();
        let muted_style = self.theme.muted_style();
        let success_style = self.theme.success_style();
        let warning_style = self.theme.warning_style();
        let danger_style = self.theme.danger_style();

        let mut lines = Vec::new();
        if self.recovery_codes_generating {
            lines.push(Line::from(vec![
                Span::styled("Recovery codes:    ", label_style),
                Span::styled("generating", warning_style),
            ]));
            return lines;
        }
        if let Some(error) = self.recovery_codes_error.as_deref() {
            lines.push(Line::from(vec![
                Span::styled("Recovery codes:    ", label_style),
                Span::styled(format!("error: {}", truncate(error, 44)), danger_style),
            ]));
            return lines;
        }
        if let Some(codes) = self.recovery_codes.as_ref() {
            lines.push(Line::from(Span::styled("Recovery Codes", heading_style)));
            lines.push(Line::from(Span::styled(
                "Shown once; store them now. Esc closes this view.",
                warning_style,
            )));
            for chunk in codes.chunks(2) {
                lines.push(Line::from(Span::styled(chunk.join("    "), warning_style)));
            }
            return lines;
        }
        if self.totp_step_up_success.is_none() {
            lines.push(Line::from(vec![
                Span::styled("Recovery codes:    ", label_style),
                Span::styled("verify step-up first; press v", muted_style),
            ]));
            return lines;
        }

        let text = match self
            .mfa_status
            .as_ref()
            .and_then(|status| status.recovery_codes_remaining)
        {
            Some(0) => "press g to generate".into(),
            Some(count) => format!("{count} unused; press g to rotate"),
            None => "press g to generate".into(),
        };
        let style = if text.starts_with("press ") {
            muted_style
        } else {
            success_style
        };
        lines.push(Line::from(vec![
            Span::styled("Recovery codes:    ", label_style),
            Span::styled(text, style),
        ]));
        lines
    }

    fn totp_factor(&self) -> Option<&shared::dto::auth::MfaFactorStatus> {
        self.mfa_status.as_ref().and_then(|status| {
            status
                .factors
                .iter()
                .find(|factor| factor.kind == MfaFactorKind::Totp)
        })
    }

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
    fn e_starts_totp_enrollment_when_available() {
        let mut screen = SettingsScreen::new(test_config(), test_theme());
        screen.set_mfa_status(MfaStatusResponse {
            user_id: "dev-admin".into(),
            provider_step_up_configured: false,
            local_step_up_available: false,
            step_up_required: false,
            factors: vec![
                shared::dto::auth::MfaFactorStatus {
                    kind: MfaFactorKind::Totp,
                    available: true,
                    enrolled: false,
                    label: Some("Authenticator app".into()),
                },
                shared::dto::auth::MfaFactorStatus {
                    kind: MfaFactorKind::WebAuthn,
                    available: true,
                    enrolled: false,
                    label: Some("Security key".into()),
                },
            ],
            recovery_codes_remaining: Some(0),
            message: "Local MFA factor store and TOTP enrollment are configured.".into(),
        });

        let action = screen.handle_key(key(KeyCode::Char('e')));

        assert!(matches!(action, Action::StartTotpEnrollment));
    }

    #[test]
    fn totp_setup_accepts_paste_and_confirms() {
        let mut screen = SettingsScreen::new(test_config(), test_theme());
        screen.set_totp_started(TotpEnrollStartResponse {
            factor_id: "factor-1".into(),
            secret_base32: "ABCDEFGHIJKLMNOP".into(),
            otpauth_url: "otpauth://totp/Canopy:dev-admin".into(),
            issuer: "Canopy".into(),
            account_name: "dev-admin".into(),
        });

        screen.handle_paste("123\n456");
        let action = screen.handle_key(key(KeyCode::Enter));

        assert!(matches!(
            action,
            Action::ConfirmTotpEnrollment { factor_id, code }
                if factor_id == "factor-1" && code == "123456"
        ));
    }

    #[test]
    fn v_opens_totp_step_up_when_enrolled() {
        let mut screen = SettingsScreen::new(test_config(), test_theme());
        screen.set_mfa_status(MfaStatusResponse {
            user_id: "dev-admin".into(),
            provider_step_up_configured: false,
            local_step_up_available: true,
            step_up_required: false,
            factors: vec![
                shared::dto::auth::MfaFactorStatus {
                    kind: MfaFactorKind::Totp,
                    available: true,
                    enrolled: true,
                    label: Some("Authenticator app".into()),
                },
                shared::dto::auth::MfaFactorStatus {
                    kind: MfaFactorKind::WebAuthn,
                    available: true,
                    enrolled: false,
                    label: Some("Security key".into()),
                },
            ],
            recovery_codes_remaining: Some(2),
            message: "Local MFA factor store and TOTP enrollment are configured.".into(),
        });

        let action = screen.handle_key(key(KeyCode::Char('v')));

        assert!(matches!(action, Action::StartTotpStepUpVerification));
    }

    #[test]
    fn g_generates_recovery_codes_when_totp_enrolled() {
        let mut screen = SettingsScreen::new(test_config(), test_theme());
        let status = MfaStatusResponse {
            user_id: "dev-admin".into(),
            provider_step_up_configured: false,
            local_step_up_available: true,
            step_up_required: false,
            factors: vec![
                shared::dto::auth::MfaFactorStatus {
                    kind: MfaFactorKind::Totp,
                    available: true,
                    enrolled: true,
                    label: Some("Authenticator app".into()),
                },
                shared::dto::auth::MfaFactorStatus {
                    kind: MfaFactorKind::WebAuthn,
                    available: true,
                    enrolled: false,
                    label: Some("Security key".into()),
                },
            ],
            recovery_codes_remaining: Some(0),
            message: "Local MFA factor store and TOTP enrollment are configured.".into(),
        };
        screen.set_mfa_status(status.clone());
        assert!(matches!(
            screen.handle_key(key(KeyCode::Char('g'))),
            Action::Noop
        ));
        screen.set_totp_step_up_verified(TotpVerifyResponse {
            factor_id: "factor-1".into(),
            verified: true,
            verified_at: "2026-05-27T00:00:00Z".into(),
            step_up_expires_at: "2026-05-27T00:05:00Z".into(),
            status,
        });

        let action = screen.handle_key(key(KeyCode::Char('g')));

        assert!(matches!(action, Action::GenerateRecoveryCodes));
    }

    #[test]
    fn recovery_codes_generated_renders_codes_and_esc_closes_view() {
        let mut screen = SettingsScreen::new(test_config(), test_theme());
        screen.totp_step_up_success = Some("verified until 2026-05-27T00:05:00Z".into());
        screen.set_recovery_codes_generated(RecoveryCodesGenerateResponse {
            codes: vec![
                "AAAA-BBBB-CCCC-DDDD-EEEE".into(),
                "FFFF-1111-2222-3333-4444".into(),
            ],
            generated_at: "2026-05-27T00:00:00Z".into(),
            remaining_codes: 2,
            status: MfaStatusResponse {
                user_id: "dev-admin".into(),
                provider_step_up_configured: false,
                local_step_up_available: true,
                step_up_required: false,
                factors: vec![shared::dto::auth::MfaFactorStatus {
                    kind: MfaFactorKind::Totp,
                    available: true,
                    enrolled: true,
                    label: Some("Authenticator app".into()),
                }],
                recovery_codes_remaining: Some(2),
                message: "Local MFA factor store and TOTP enrollment are configured.".into(),
            },
        });
        let text = rendered_text(&mut screen);

        assert!(text.contains("Recovery Codes"));
        assert!(text.contains("Shown once"));
        assert!(text.contains("AAAA-BBBB-CCCC-DDDD-EEEE"));

        assert!(matches!(screen.handle_key(key(KeyCode::Esc)), Action::Noop));
        let text = rendered_text(&mut screen);
        assert!(text.contains("2 unused; press g to rotate"));
        assert!(!text.contains("AAAA-BBBB-CCCC-DDDD-EEEE"));
    }

    #[test]
    fn recovery_codes_are_cleared_when_leaving_settings() {
        let mut screen = SettingsScreen::new(test_config(), test_theme());
        screen.totp_step_up_success = Some("verified until 2026-05-27T00:05:00Z".into());
        screen.set_recovery_codes_generated(RecoveryCodesGenerateResponse {
            codes: vec!["AAAA-BBBB-CCCC-DDDD-EEEE".into()],
            generated_at: "2026-05-27T00:00:00Z".into(),
            remaining_codes: 1,
            status: MfaStatusResponse {
                user_id: "dev-admin".into(),
                provider_step_up_configured: false,
                local_step_up_available: true,
                step_up_required: false,
                factors: vec![shared::dto::auth::MfaFactorStatus {
                    kind: MfaFactorKind::Totp,
                    available: true,
                    enrolled: true,
                    label: Some("Authenticator app".into()),
                }],
                recovery_codes_remaining: Some(1),
                message: "Local MFA factor store and TOTP enrollment are configured.".into(),
            },
        });

        assert!(matches!(
            screen.handle_key(key(KeyCode::Char('q'))),
            Action::GoBack
        ));
        let text = rendered_text(&mut screen);
        assert!(!text.contains("AAAA-BBBB-CCCC-DDDD-EEEE"));
    }

    #[test]
    fn totp_step_up_accepts_paste_and_verifies() {
        let mut screen = SettingsScreen::new(test_config(), test_theme());
        screen.start_totp_step_up_verification();

        screen.handle_paste("123\n456");
        let action = screen.handle_key(key(KeyCode::Enter));

        assert!(matches!(
            action,
            Action::VerifyTotpStepUp { code } if code == "123456"
        ));
    }

    #[test]
    fn render_shows_totp_setup_without_secret_in_input() {
        let mut screen = SettingsScreen::new(test_config(), test_theme());
        screen.set_totp_started(TotpEnrollStartResponse {
            factor_id: "factor-1".into(),
            secret_base32: "ABCDEFGHIJKLMNOP".into(),
            otpauth_url: "otpauth://totp/Canopy:dev-admin".into(),
            issuer: "Canopy".into(),
            account_name: "dev-admin".into(),
        });
        let text = rendered_text(&mut screen);

        assert!(text.contains("TOTP Setup"));
        assert!(text.contains("Secret:"));
        assert!(text.contains("ABCDEFGHIJKLMNOP"));
        assert!(text.contains("Verification code"));
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
            recovery_codes_remaining: Some(0),
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
