//! Modal overlay for editing a custom CloudWatch search time range (UTC).
//!
//! UX: two stacked `TextInput`s (start / end), one optional error line.
//! Validation (parse + 30-day max) is performed on Enter; errors keep the
//! modal open so the user can correct without retyping.

use chrono::{TimeZone, Utc};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph},
};

use crate::widgets::input::TextInput;

use super::time_range::{
    parse_utc_datetime, TimeRange, TimeRangeError, CUSTOM_DATETIME_FMT, MAX_CUSTOM_RANGE_SECS,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModalField {
    Start,
    End,
}

/// Outcome of handling a key event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModalOutcome {
    /// Keep the modal open. Caller does nothing.
    Continue,
    /// Cancel — close the modal without changing state.
    Cancel,
    /// Reset the time range to the default 1h preset and close.
    ResetToOneHour,
    /// Submit succeeded — close and apply the resolved (start_secs, end_secs).
    Submit { start_secs: i64, end_secs: i64 },
}

pub struct TimeRangeModal {
    pub start: TextInput,
    pub end: TextInput,
    pub active: ModalField,
    pub error: Option<String>,
}

impl TimeRangeModal {
    /// Open a fresh modal pre-filled from `current`. If `current` is a custom
    /// range, the inputs are populated with its values; otherwise the inputs
    /// default to `start = now - 1h`, `end = now`.
    pub fn open(current: &TimeRange) -> Self {
        let mut start = TextInput::new("Start (UTC, YYYY-MM-DD HH:MM)");
        let mut end = TextInput::new("End (UTC, YYYY-MM-DD HH:MM)");

        let (start_secs, end_secs) = match current {
            TimeRange::Custom {
                start_secs,
                end_secs,
            } => (*start_secs, *end_secs),
            TimeRange::Preset(_) => {
                let now = Utc::now().timestamp();
                (now - 3_600, now)
            }
        };

        if let Some(dt) = Utc.timestamp_opt(start_secs, 0).single() {
            start.value = dt.format(CUSTOM_DATETIME_FMT).to_string();
            start.cursor_pos = start.value.chars().count();
        }
        if let Some(dt) = Utc.timestamp_opt(end_secs, 0).single() {
            end.value = dt.format(CUSTOM_DATETIME_FMT).to_string();
            end.cursor_pos = end.value.chars().count();
        }

        start.focused = true;
        end.focused = false;

        Self {
            start,
            end,
            active: ModalField::Start,
            error: None,
        }
    }

    fn switch_field(&mut self) {
        self.active = match self.active {
            ModalField::Start => ModalField::End,
            ModalField::End => ModalField::Start,
        };
        self.start.focused = matches!(self.active, ModalField::Start);
        self.end.focused = matches!(self.active, ModalField::End);
    }

    fn try_submit(&mut self) -> ModalOutcome {
        // Try start first so an error highlights the start field.
        let start_secs = match parse_utc_datetime(&self.start.value, "start") {
            Ok(v) => v,
            Err(e) => {
                self.error = Some(e.to_string());
                self.active = ModalField::Start;
                self.start.focused = true;
                self.end.focused = false;
                return ModalOutcome::Continue;
            }
        };
        let end_secs = match parse_utc_datetime(&self.end.value, "end") {
            Ok(v) => v,
            Err(e) => {
                self.error = Some(e.to_string());
                self.active = ModalField::End;
                self.start.focused = false;
                self.end.focused = true;
                return ModalOutcome::Continue;
            }
        };

        if end_secs <= start_secs {
            self.error = Some(TimeRangeError::EndBeforeStart.to_string());
            return ModalOutcome::Continue;
        }
        if end_secs - start_secs > MAX_CUSTOM_RANGE_SECS {
            self.error = Some(TimeRangeError::RangeTooLong.to_string());
            return ModalOutcome::Continue;
        }

        ModalOutcome::Submit {
            start_secs,
            end_secs,
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> ModalOutcome {
        // Ctrl+R = reset to 1h preset and close.
        if key.code == KeyCode::Char('r') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return ModalOutcome::ResetToOneHour;
        }

        match key.code {
            KeyCode::Esc => ModalOutcome::Cancel,
            KeyCode::Tab | KeyCode::Up | KeyCode::Down => {
                self.switch_field();
                ModalOutcome::Continue
            }
            KeyCode::Enter => self.try_submit(),
            _ => {
                // Forward to the active TextInput. Any keystroke clears any
                // stale error so the user gets immediate feedback while editing.
                self.error = None;
                match self.active {
                    ModalField::Start => {
                        self.start.handle_key(key);
                    }
                    ModalField::End => {
                        self.end.handle_key(key);
                    }
                }
                ModalOutcome::Continue
            }
        }
    }

    pub fn render(&self, area: Rect, buf: &mut Buffer) {
        let modal_width = 64u16.min(area.width.saturating_sub(4));
        let modal_height = 12u16.min(area.height.saturating_sub(4));
        let modal_area = Rect {
            x: area.x + (area.width.saturating_sub(modal_width)) / 2,
            y: area.y + (area.height.saturating_sub(modal_height)) / 2,
            width: modal_width,
            height: modal_height,
        };

        Clear.render(modal_area, buf);

        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Custom Range (UTC) ")
            .border_style(Style::default().fg(Color::Cyan).bold());
        let inner = block.inner(modal_area);
        block.render(modal_area, buf);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // start input
                Constraint::Length(3), // end input
                Constraint::Length(1), // error / hint
                Constraint::Min(1),    // footer
            ])
            .split(inner);

        self.start.render(chunks[0], buf);
        self.end.render(chunks[1], buf);

        let error_line = match &self.error {
            Some(msg) => Line::from(Span::styled(msg.as_str(), Style::default().fg(Color::Red))),
            None => Line::from(Span::styled(
                "Range max 30 days. Both fields are UTC.",
                Style::default().fg(Color::DarkGray),
            )),
        };
        Paragraph::new(error_line).render(chunks[2], buf);

        let hint = Line::from(vec![
            Span::styled("Tab/↑↓", Style::default().fg(Color::Cyan)),
            Span::raw(" switch  "),
            Span::styled("Enter", Style::default().fg(Color::Cyan)),
            Span::raw(" submit  "),
            Span::styled("Esc", Style::default().fg(Color::Cyan)),
            Span::raw(" cancel  "),
            Span::styled("Ctrl+R", Style::default().fg(Color::Cyan)),
            Span::raw(" reset to 1h"),
        ]);
        Paragraph::new(hint)
            .style(Style::default().fg(Color::Gray))
            .render(chunks[3], buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn key_ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn type_str(modal: &mut TimeRangeModal, s: &str) {
        for c in s.chars() {
            modal.handle_key(key(KeyCode::Char(c)));
        }
    }

    #[test]
    fn open_from_preset_prefills_now_minus_1h_and_now() {
        let modal = TimeRangeModal::open(&TimeRange::default());
        // Both fields populated as YYYY-MM-DD HH:MM (16 chars)
        assert_eq!(modal.start.value.len(), 16);
        assert_eq!(modal.end.value.len(), 16);
        assert!(modal.start.focused);
        assert!(!modal.end.focused);
    }

    #[test]
    fn open_from_custom_prefills_existing_values() {
        // Derive epoch from chrono so the test stays correct regardless of
        // when it runs.
        let start_dt = Utc.with_ymd_and_hms(2026, 5, 1, 14, 0, 0).unwrap();
        let end_dt = start_dt + chrono::Duration::days(1);
        let current = TimeRange::Custom {
            start_secs: start_dt.timestamp(),
            end_secs: end_dt.timestamp(),
        };
        let modal = TimeRangeModal::open(&current);
        assert_eq!(modal.start.value, "2026-05-01 14:00");
        assert_eq!(modal.end.value, "2026-05-02 14:00");
    }

    #[test]
    fn tab_switches_field_focus() {
        let mut modal = TimeRangeModal::open(&TimeRange::default());
        assert_eq!(modal.active, ModalField::Start);
        modal.handle_key(key(KeyCode::Tab));
        assert_eq!(modal.active, ModalField::End);
        assert!(!modal.start.focused);
        assert!(modal.end.focused);
        modal.handle_key(key(KeyCode::Up));
        assert_eq!(modal.active, ModalField::Start);
    }

    #[test]
    fn esc_cancels() {
        let mut modal = TimeRangeModal::open(&TimeRange::default());
        let out = modal.handle_key(key(KeyCode::Esc));
        assert_eq!(out, ModalOutcome::Cancel);
    }

    #[test]
    fn ctrl_r_resets_to_one_hour() {
        let mut modal = TimeRangeModal::open(&TimeRange::default());
        let out = modal.handle_key(key_ctrl(KeyCode::Char('r')));
        assert_eq!(out, ModalOutcome::ResetToOneHour);
    }

    #[test]
    fn enter_with_invalid_date_sets_error_and_keeps_open() {
        let mut modal = TimeRangeModal::open(&TimeRange::default());
        modal.start.value.clear();
        modal.start.value.push_str("not a date");
        modal.start.cursor_pos = modal.start.value.chars().count();

        let out = modal.handle_key(key(KeyCode::Enter));
        assert_eq!(out, ModalOutcome::Continue);
        assert!(modal.error.is_some());
        assert_eq!(modal.active, ModalField::Start);
    }

    #[test]
    fn enter_with_31_day_range_shows_30_day_error() {
        let mut modal = TimeRangeModal::open(&TimeRange::default());
        modal.start.value = "2026-04-01 00:00".into();
        modal.start.cursor_pos = modal.start.value.chars().count();
        modal.end.value = "2026-05-02 00:01".into(); // 31d 1m
        modal.end.cursor_pos = modal.end.value.chars().count();

        let out = modal.handle_key(key(KeyCode::Enter));
        assert_eq!(out, ModalOutcome::Continue);
        assert_eq!(
            modal.error.as_deref(),
            Some(TimeRangeError::RangeTooLong.to_string().as_str())
        );
    }

    #[test]
    fn enter_with_end_before_start_shows_error() {
        let mut modal = TimeRangeModal::open(&TimeRange::default());
        modal.start.value = "2026-05-02 00:00".into();
        modal.start.cursor_pos = modal.start.value.chars().count();
        modal.end.value = "2026-05-01 00:00".into();
        modal.end.cursor_pos = modal.end.value.chars().count();

        let out = modal.handle_key(key(KeyCode::Enter));
        assert_eq!(out, ModalOutcome::Continue);
        assert!(modal.error.as_deref().is_some_and(|s| s.contains("after")));
    }

    #[test]
    fn enter_with_valid_inputs_returns_submit_with_secs() {
        let mut modal = TimeRangeModal::open(&TimeRange::default());
        modal.start.value = "2026-05-01 14:00".into();
        modal.start.cursor_pos = modal.start.value.chars().count();
        modal.end.value = "2026-05-08 14:00".into();
        modal.end.cursor_pos = modal.end.value.chars().count();

        let out = modal.handle_key(key(KeyCode::Enter));
        match out {
            ModalOutcome::Submit {
                start_secs,
                end_secs,
            } => {
                assert_eq!(end_secs - start_secs, 7 * 86_400);
            }
            other => panic!("expected Submit, got {:?}", other),
        }
    }

    #[test]
    fn typing_clears_stale_error() {
        let mut modal = TimeRangeModal::open(&TimeRange::default());
        modal.start.value = "bad".into();
        modal.start.cursor_pos = 3;
        modal.handle_key(key(KeyCode::Enter)); // produces error
        assert!(modal.error.is_some());
        type_str(&mut modal, "x");
        assert!(modal.error.is_none());
    }
}
