use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};
use shared::dto::cloudwatch::LiveTailEvent;
use std::collections::VecDeque;

use super::Component;
use crate::event::Action;
use crate::widgets::input::TextInput;

#[derive(Debug, PartialEq, Eq)]
enum TailState {
    Stopped,
    Running,
    Paused,
    Reconnecting,
}

pub struct LiveTailScreen {
    pub events: VecDeque<LiveTailEvent>,
    pub scrollback_limit: usize,
    pub connection_state: String,
    pub events_per_second: f64,

    state: TailState,
    filter_input: TextInput,
    filter_active: bool,
    auto_scroll: bool,
    scroll_offset: usize,
}

impl LiveTailScreen {
    pub fn new(scrollback_limit: usize) -> Self {
        Self {
            events: VecDeque::with_capacity(scrollback_limit),
            scrollback_limit,
            connection_state: "Disconnected".into(),
            events_per_second: 0.0,
            state: TailState::Stopped,
            filter_input: TextInput::new("Local filter"),
            filter_active: false,
            auto_scroll: true,
            scroll_offset: 0,
        }
    }

    pub fn push_event(&mut self, event: LiveTailEvent) {
        if self.events.len() >= self.scrollback_limit {
            self.events.pop_front();
        }
        self.events.push_back(event);
        if self.auto_scroll {
            self.scroll_offset = 0;
        }
    }

    pub fn set_connected(&mut self) {
        self.state = TailState::Running;
        self.connection_state = "Connected".into();
    }

    pub fn set_reconnecting(&mut self) {
        self.state = TailState::Reconnecting;
        self.connection_state = "Reconnecting...".into();
    }

    pub fn set_paused(&mut self) {
        self.state = TailState::Paused;
        self.connection_state = "Paused".into();
    }

    pub fn set_disconnected(&mut self) {
        self.state = TailState::Stopped;
        self.connection_state = "Disconnected".into();
    }

    fn filtered_events(&self) -> Vec<&LiveTailEvent> {
        let filter = self.filter_input.value.to_lowercase();
        if filter.is_empty() {
            self.events.iter().collect()
        } else {
            self.events
                .iter()
                .filter(|e| e.message.to_lowercase().contains(&filter))
                .collect()
        }
    }

    fn colorize_message<'a>(&self, message: &'a str) -> Span<'a> {
        if message.contains("ERROR") || message.contains("\"level\":\"ERROR\"") {
            Span::styled(message, Style::default().fg(Color::Red))
        } else if message.contains("WARN") || message.contains("\"level\":\"WARN\"") {
            Span::styled(message, Style::default().fg(Color::Yellow))
        } else if message.contains("INFO") || message.contains("\"level\":\"INFO\"") {
            Span::styled(message, Style::default().fg(Color::Green))
        } else if message.contains("DEBUG") || message.contains("\"level\":\"DEBUG\"") {
            Span::styled(message, Style::default().fg(Color::Cyan))
        } else {
            Span::raw(message)
        }
    }
}

impl Component for LiveTailScreen {
    fn handle_key(&mut self, key: KeyEvent) -> Action {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Action::Quit;
        }

        if self.filter_active {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    self.filter_active = false;
                    self.filter_input.focused = false;
                    return Action::Noop;
                }
                _ => {
                    self.filter_input.handle_key(key);
                    return Action::Noop;
                }
            }
        }

        match key.code {
            KeyCode::Esc => Action::GoBack,
            KeyCode::Char('s') => match self.state {
                TailState::Stopped | TailState::Reconnecting => Action::StartLiveTail,
                TailState::Running => Action::StopLiveTail,
                TailState::Paused => Action::StopLiveTail,
            },
            KeyCode::Char('p') => match self.state {
                TailState::Running => Action::PauseLiveTail,
                TailState::Paused => Action::ResumeLiveTail,
                _ => Action::Noop,
            },
            KeyCode::Char('/') => {
                self.filter_active = true;
                self.filter_input.focused = true;
                Action::Noop
            }
            KeyCode::Char('a') => {
                self.auto_scroll = !self.auto_scroll;
                Action::Noop
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.auto_scroll = false;
                self.scroll_offset = self.scroll_offset.saturating_add(1);
                Action::Noop
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.scroll_offset > 0 {
                    self.scroll_offset -= 1;
                } else {
                    self.auto_scroll = true;
                }
                Action::Noop
            }
            KeyCode::Char('c') => {
                self.events.clear();
                self.scroll_offset = 0;
                Action::Noop
            }
            _ => Action::Noop,
        }
    }

    fn render(&mut self, area: Rect, buf: &mut Buffer) {
        let outer = Block::default()
            .borders(Borders::ALL)
            .title(" Live Tail ")
            .border_style(Style::default().fg(Color::Cyan));
        let inner = outer.inner(area);
        outer.render(area, buf);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // Connection status
                Constraint::Length(3), // Filter
                Constraint::Min(5),    // Log output
                Constraint::Length(2), // Status bar
            ])
            .split(inner);

        // Connection status
        let conn_style = match self.state {
            TailState::Running => Style::default().fg(Color::Green),
            TailState::Paused => Style::default().fg(Color::Yellow),
            TailState::Reconnecting => Style::default().fg(Color::Yellow),
            TailState::Stopped => Style::default().fg(Color::Red),
        };
        let conn_text = format!(
            "{} | {:.1} events/sec | {} events buffered",
            self.connection_state,
            self.events_per_second,
            self.events.len(),
        );
        Paragraph::new(conn_text)
            .style(conn_style)
            .render(chunks[0], buf);

        // Filter
        self.filter_input.render(chunks[1], buf);

        // Log output
        let log_block = Block::default()
            .borders(Borders::ALL)
            .title(if self.auto_scroll {
                " Logs (auto-scroll) "
            } else {
                " Logs (manual scroll) "
            })
            .border_style(Style::default().fg(Color::Gray));
        let log_inner = log_block.inner(chunks[2]);
        log_block.render(chunks[2], buf);

        let filtered = self.filtered_events();
        let visible_height = log_inner.height as usize;
        let total = filtered.len();
        let start = if total > visible_height + self.scroll_offset {
            total - visible_height - self.scroll_offset
        } else {
            0
        };
        let end = total.saturating_sub(self.scroll_offset);

        let visible_events = &filtered[start..end];
        let lines: Vec<Line> = visible_events
            .iter()
            .map(|ev| {
                let ts = chrono::DateTime::from_timestamp_millis(ev.timestamp)
                    .map(|dt| dt.format("%H:%M:%S%.3f").to_string())
                    .unwrap_or_default();

                Line::from(vec![
                    Span::styled(format!("{} ", ts), Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("[{}] ", ev.log_stream_name),
                        Style::default().fg(Color::Cyan),
                    ),
                    self.colorize_message(&ev.message),
                ])
            })
            .collect();

        Paragraph::new(lines).render(log_inner, buf);

        // Status bar
        Paragraph::new(
            "s: start/stop | p: pause/resume | /: filter | a: auto-scroll | c: clear | Esc: back",
        )
        .style(Style::default().fg(Color::Gray))
        .render(chunks[3], buf);
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

    fn sample_event(msg: &str) -> LiveTailEvent {
        LiveTailEvent {
            timestamp: 1700000000000,
            message: msg.into(),
            log_stream_name: "stream-1".into(),
            log_group_name: "/app/test".into(),
        }
    }

    // ── State machine ──

    #[test]
    fn initial_state_is_stopped() {
        let screen = LiveTailScreen::new(1000);
        assert_eq!(screen.state, TailState::Stopped);
        assert_eq!(screen.connection_state, "Disconnected");
    }

    #[test]
    fn state_transitions() {
        let mut screen = LiveTailScreen::new(1000);

        screen.set_connected();
        assert_eq!(screen.state, TailState::Running);

        screen.set_paused();
        assert_eq!(screen.state, TailState::Paused);

        screen.set_reconnecting();
        assert_eq!(screen.state, TailState::Reconnecting);

        screen.set_disconnected();
        assert_eq!(screen.state, TailState::Stopped);
    }

    // ── Key handling ──

    #[test]
    fn s_starts_when_stopped() {
        let mut screen = LiveTailScreen::new(1000);
        let action = screen.handle_key(key(KeyCode::Char('s')));
        assert!(matches!(action, Action::StartLiveTail));
    }

    #[test]
    fn s_stops_when_running() {
        let mut screen = LiveTailScreen::new(1000);
        screen.set_connected();
        let action = screen.handle_key(key(KeyCode::Char('s')));
        assert!(matches!(action, Action::StopLiveTail));
    }

    #[test]
    fn p_pauses_when_running() {
        let mut screen = LiveTailScreen::new(1000);
        screen.set_connected();
        let action = screen.handle_key(key(KeyCode::Char('p')));
        assert!(matches!(action, Action::PauseLiveTail));
    }

    #[test]
    fn p_resumes_when_paused() {
        let mut screen = LiveTailScreen::new(1000);
        screen.set_connected();
        screen.set_paused();
        let action = screen.handle_key(key(KeyCode::Char('p')));
        assert!(matches!(action, Action::ResumeLiveTail));
    }

    #[test]
    fn p_noop_when_stopped() {
        let mut screen = LiveTailScreen::new(1000);
        let action = screen.handle_key(key(KeyCode::Char('p')));
        assert!(matches!(action, Action::Noop));
    }

    #[test]
    fn esc_goes_back() {
        let mut screen = LiveTailScreen::new(1000);
        let action = screen.handle_key(key(KeyCode::Esc));
        assert!(matches!(action, Action::GoBack));
    }

    // ── Event buffer ──

    #[test]
    fn push_event_respects_scrollback_limit() {
        let mut screen = LiveTailScreen::new(3);
        for i in 0..5 {
            screen.push_event(sample_event(&format!("msg-{}", i)));
        }
        assert_eq!(screen.events.len(), 3);
        assert_eq!(screen.events[0].message, "msg-2");
    }

    #[test]
    fn c_clears_events() {
        let mut screen = LiveTailScreen::new(100);
        screen.push_event(sample_event("hello"));
        assert_eq!(screen.events.len(), 1);

        screen.handle_key(key(KeyCode::Char('c')));
        assert!(screen.events.is_empty());
    }

    // ── Scroll ──

    #[test]
    fn scroll_up_disables_auto_scroll() {
        let mut screen = LiveTailScreen::new(100);
        assert!(screen.auto_scroll);

        screen.handle_key(key(KeyCode::Up));
        assert!(!screen.auto_scroll);
        assert_eq!(screen.scroll_offset, 1);
    }

    #[test]
    fn scroll_down_to_zero_re_enables_auto_scroll() {
        let mut screen = LiveTailScreen::new(100);
        screen.auto_scroll = false;
        screen.scroll_offset = 1;

        screen.handle_key(key(KeyCode::Down));
        assert_eq!(screen.scroll_offset, 0);
        // Next scroll down should re-enable auto scroll
        screen.handle_key(key(KeyCode::Down));
        assert!(screen.auto_scroll);
    }

    #[test]
    fn a_toggles_auto_scroll() {
        let mut screen = LiveTailScreen::new(100);
        assert!(screen.auto_scroll);

        screen.handle_key(key(KeyCode::Char('a')));
        assert!(!screen.auto_scroll);

        screen.handle_key(key(KeyCode::Char('a')));
        assert!(screen.auto_scroll);
    }

    // ── Filter mode ──

    #[test]
    fn slash_activates_filter_esc_deactivates() {
        let mut screen = LiveTailScreen::new(100);
        assert!(!screen.filter_active);

        screen.handle_key(key(KeyCode::Char('/')));
        assert!(screen.filter_active);
        assert!(screen.filter_input.focused);

        // While in filter mode, Esc exits filter, not the screen
        let action = screen.handle_key(key(KeyCode::Esc));
        assert!(!screen.filter_active);
        assert!(matches!(action, Action::Noop));
    }

    #[test]
    fn filter_mode_enter_also_exits() {
        let mut screen = LiveTailScreen::new(100);
        screen.handle_key(key(KeyCode::Char('/')));
        assert!(screen.filter_active);

        let action = screen.handle_key(key(KeyCode::Enter));
        assert!(!screen.filter_active);
        assert!(matches!(action, Action::Noop));
    }

    #[test]
    fn filtered_events_respects_filter_text() {
        let mut screen = LiveTailScreen::new(100);
        screen.push_event(sample_event("INFO hello"));
        screen.push_event(sample_event("ERROR crash"));
        screen.push_event(sample_event("INFO world"));

        // No filter
        assert_eq!(screen.filtered_events().len(), 3);

        // Set filter
        screen.filter_input.value = "error".into();
        assert_eq!(screen.filtered_events().len(), 1);
        assert_eq!(screen.filtered_events()[0].message, "ERROR crash");
    }
}
