use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

use crate::event::Action;
use crate::theme::Theme;

/// Modal overlay that shows error messages
pub struct ErrorModal {
    pub message: Option<String>,
    title: String,
    theme: Theme,
}

impl Default for ErrorModal {
    fn default() -> Self {
        Self::new()
    }
}

impl ErrorModal {
    pub fn new() -> Self {
        Self {
            message: None,
            title: " Error ".into(),
            theme: Theme::default(),
        }
    }

    pub fn with_theme(mut self, theme: Theme) -> Self {
        self.theme = theme;
        self
    }

    pub fn show(&mut self, message: String) {
        self.title = " Error ".into();
        self.message = Some(message);
    }

    pub fn show_with_title(&mut self, title: impl Into<String>, message: String) {
        self.title = title.into();
        self.message = Some(message);
    }

    pub fn dismiss(&mut self) {
        self.message = None;
        self.title = " Error ".into();
    }

    pub fn is_visible(&self) -> bool {
        self.message.is_some()
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                self.dismiss();
                Action::DismissError
            }
            _ => Action::Noop,
        }
    }

    #[cfg(test)]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    fn message_lines(message: &str, max_lines: usize) -> Vec<Line<'static>> {
        Self::message_lines_with_theme(message, max_lines, Theme::default())
    }

    fn message_lines_with_theme(
        message: &str,
        max_lines: usize,
        theme: Theme,
    ) -> Vec<Line<'static>> {
        let max_lines = max_lines.max(1);
        let mut raw_lines = message.lines().map(str::to_string).collect::<Vec<_>>();
        if raw_lines.is_empty() {
            raw_lines.push(String::new());
        }
        if raw_lines.len() > max_lines {
            let omitted = raw_lines.len() - max_lines + 1;
            raw_lines.truncate(max_lines);
            if let Some(last) = raw_lines.last_mut() {
                *last = format!("... {omitted} more lines");
            }
        }

        raw_lines
            .into_iter()
            .map(|line| Line::from(Span::styled(line, theme.danger_style())))
            .collect()
    }

    pub fn render(&self, area: Rect, buf: &mut Buffer) {
        let Some(ref message) = self.message else {
            return;
        };

        // Center the modal
        let modal_width = 60u16.min(area.width.saturating_sub(4));
        let max_modal_height = area.height.saturating_sub(4);
        if modal_width == 0 || max_modal_height == 0 {
            return;
        }
        let raw_line_count = message.lines().count().max(1) as u16;
        let desired_height = (raw_line_count + 5).max(6);
        let modal_height = desired_height.min(max_modal_height);
        let modal_area = Rect {
            x: area.x + (area.width.saturating_sub(modal_width)) / 2,
            y: area.y + (area.height.saturating_sub(modal_height)) / 2,
            width: modal_width,
            height: modal_height,
        };

        // Clear the area behind the modal
        Clear.render(modal_area, buf);

        let block = Block::default()
            .borders(Borders::ALL)
            .title(self.title.as_str())
            .border_style(self.theme.danger_style().bold());
        let inner = block.inner(modal_area);
        block.render(modal_area, buf);

        let max_message_lines = inner.height.saturating_sub(3).max(1) as usize;
        let mut text = vec![Line::from("")];
        text.extend(Self::message_lines_with_theme(
            message,
            max_message_lines,
            self.theme,
        ));
        text.push(Line::from(""));
        text.push(Line::from(Span::styled(
            "Press Esc or Enter to dismiss",
            self.theme.muted_style(),
        )));

        Paragraph::new(text)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .render(inner, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    fn buffer_text(buf: &Buffer, area: Rect) -> String {
        let mut text = String::new();
        for y in area.y..area.y + area.height {
            for x in area.x..area.x + area.width {
                text.push_str(buf[(x, y)].symbol());
            }
            text.push('\n');
        }
        text
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    #[test]
    fn show_and_dismiss_cycle() {
        let mut modal = ErrorModal::new();
        assert!(!modal.is_visible());

        modal.show("something broke".into());
        assert!(modal.is_visible());
        assert_eq!(modal.message(), Some("something broke"));

        modal.dismiss();
        assert!(!modal.is_visible());
    }

    #[test]
    fn esc_dismisses_and_returns_dismiss_action() {
        let mut modal = ErrorModal::new();
        modal.show("err".into());

        let action = modal.handle_key(key(KeyCode::Esc));
        assert!(!modal.is_visible());
        assert!(matches!(action, Action::DismissError));
    }

    #[test]
    fn enter_dismisses_and_returns_dismiss_action() {
        let mut modal = ErrorModal::new();
        modal.show("err".into());

        let action = modal.handle_key(key(KeyCode::Enter));
        assert!(!modal.is_visible());
        assert!(matches!(action, Action::DismissError));
    }

    #[test]
    fn other_keys_return_noop_and_keep_visible() {
        let mut modal = ErrorModal::new();
        modal.show("err".into());

        let action = modal.handle_key(key(KeyCode::Char('x')));
        assert!(modal.is_visible());
        assert!(matches!(action, Action::Noop));
    }

    #[test]
    fn message_lines_preserve_explicit_newlines() {
        let lines = ErrorModal::message_lines("scope-a failed\nscope-b failed", 5);

        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].spans[0].content.as_ref(), "scope-a failed");
        assert_eq!(lines[1].spans[0].content.as_ref(), "scope-b failed");
    }

    #[test]
    fn message_lines_truncate_when_modal_is_short() {
        let lines = ErrorModal::message_lines("one\ntwo\nthree", 2);

        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].spans[0].content.as_ref(), "one");
        assert_eq!(lines[1].spans[0].content.as_ref(), "... 2 more lines");
    }

    #[test]
    fn render_displays_multiline_message_lines() {
        let area = Rect::new(0, 0, 80, 20);
        let mut buf = Buffer::empty(area);
        let mut modal = ErrorModal::new();
        modal.show("Some ECS scopes failed:\naccount-a us-east-1\naccount-b eu-west-1".into());

        modal.render(area, &mut buf);

        let text = buffer_text(&buf, area);
        assert!(text.contains("Some ECS scopes failed:"));
        assert!(text.contains("account-a us-east-1"));
        assert!(text.contains("account-b eu-west-1"));
        assert!(text.contains("Press Esc or Enter to dismiss"));
    }
}
