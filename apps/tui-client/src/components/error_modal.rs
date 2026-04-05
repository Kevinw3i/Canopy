use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

use crate::event::Action;

/// Modal overlay that shows error messages
pub struct ErrorModal {
    pub message: Option<String>,
}

impl ErrorModal {
    pub fn new() -> Self {
        Self { message: None }
    }

    pub fn show(&mut self, message: String) {
        self.message = Some(message);
    }

    pub fn dismiss(&mut self) {
        self.message = None;
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

    pub fn render(&self, area: Rect, buf: &mut Buffer) {
        let Some(ref message) = self.message else {
            return;
        };

        // Center the modal
        let modal_width = 60u16.min(area.width.saturating_sub(4));
        let modal_height = 8u16.min(area.height.saturating_sub(4));
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
            .title(" Error ")
            .border_style(Style::default().fg(Color::Red).bold());
        let inner = block.inner(modal_area);
        block.render(modal_area, buf);

        let text = vec![
            Line::from(""),
            Line::from(Span::styled(
                message.as_str(),
                Style::default().fg(Color::Red),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "Press Esc or Enter to dismiss",
                Style::default().fg(Color::Gray),
            )),
        ];

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
}
