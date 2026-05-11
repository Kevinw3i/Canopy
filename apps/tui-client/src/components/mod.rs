pub mod access;
pub mod cloudwatch_search;
pub mod connect_session;
pub mod dashboard;
pub mod ec2;
pub mod error_modal;
pub mod live_tail;
pub mod loading;
pub mod login;
pub mod settings;
pub mod time_range;
pub mod time_range_modal;

use crate::event::Action;
use crossterm::event::KeyEvent;
use ratatui::prelude::*;

/// Trait that every screen component implements
pub trait Component {
    /// Handle a key event, return an action if one should be dispatched
    fn handle_key(&mut self, key: KeyEvent) -> Action;

    /// Handle bracketed paste text. Screens with text inputs can override this.
    fn handle_paste(&mut self, _text: &str) -> Action {
        Action::Noop
    }

    /// Render the component
    fn render(&mut self, area: Rect, buf: &mut Buffer);

    /// Called when the component becomes the active screen
    fn on_enter(&mut self) -> Vec<Action> {
        vec![]
    }

    /// Called on each tick (every ~250ms) for animations
    fn on_tick(&mut self) {}

    /// Called when the component is leaving the active screen
    fn on_leave(&mut self) {}
}

/// Animated scope-switch overlay shown briefly when cycling account/region.
/// Blocks further cycling while active to prevent rapid-fire switches.
pub struct ScopeTransition {
    /// Text to display in the overlay
    pub label: String,
    /// Ticks remaining (each tick ≈ 250ms)
    pub remaining_ticks: u8,
}

impl ScopeTransition {
    /// Total ticks for the transition (3 × 250ms = 750ms)
    const DURATION: u8 = 3;

    pub fn new(label: String) -> Self {
        Self {
            label,
            remaining_ticks: Self::DURATION,
        }
    }

    /// Returns true while the transition is still active.
    pub fn is_active(&self) -> bool {
        self.remaining_ticks > 0
    }

    /// Check if an `Option<ScopeTransition>` is currently blocking input.
    pub fn is_blocking(opt: &Option<ScopeTransition>) -> bool {
        opt.as_ref().is_some_and(|t| t.is_active())
    }

    /// Advance one tick. Returns false when finished.
    pub fn tick(&mut self) -> bool {
        self.remaining_ticks = self.remaining_ticks.saturating_sub(1);
        self.remaining_ticks > 0
    }

    /// Render a centered overlay banner.
    pub fn render(&self, area: Rect, buf: &mut Buffer) {
        use ratatui::widgets::{Block, Borders, Clear, Paragraph};

        let text_width = (self.label.len() as u16 + 6).min(area.width.saturating_sub(4));
        let popup = Rect {
            x: area.x + (area.width.saturating_sub(text_width)) / 2,
            y: area.y + (area.height / 2).saturating_sub(1),
            width: text_width,
            height: 3,
        };

        Clear.render(popup, buf);

        // Fade effect: brighter when fresh, dimmer near end
        let fg = if self.remaining_ticks >= 2 {
            Color::White
        } else {
            Color::Gray
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));
        let inner = block.inner(popup);
        block.render(popup, buf);

        Paragraph::new(Line::from(vec![
            Span::styled("⟳ ", Style::default().fg(Color::Cyan)),
            Span::styled(&self.label, Style::default().fg(fg).bold()),
        ]))
        .alignment(Alignment::Center)
        .render(inner, buf);
    }
}
