use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph},
};

use crate::theme::Theme;

/// Loading spinner animation
pub struct LoadingIndicator {
    message: String,
    frame: usize,
    theme: Theme,
}

const SPINNER_FRAMES: &[&str] = &[
    "[    ]", "[=   ]", "[==  ]", "[=== ]", "[ ===]", "[  ==]", "[   =]",
];

impl LoadingIndicator {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.into(),
            frame: 0,
            theme: Theme::default(),
        }
    }

    pub fn with_theme(mut self, theme: Theme) -> Self {
        self.theme = theme;
        self
    }

    pub fn tick(&mut self) {
        self.frame = (self.frame + 1) % SPINNER_FRAMES.len();
    }

    pub fn set_message(&mut self, message: &str) {
        self.message = message.into();
    }

    pub fn render(&self, area: Rect, buf: &mut Buffer) {
        let spinner = SPINNER_FRAMES[self.frame];
        let text = format!("{} {}", spinner, self.message);
        Paragraph::new(text)
            .style(self.theme.warning_style())
            .render(area, buf);
    }

    /// Render a centered loading overlay popup within the given area.
    pub fn render_overlay(&self, area: Rect, buf: &mut Buffer) {
        let popup_width = (self.message.len() as u16 + 12).min(area.width.saturating_sub(4));
        let popup = Rect {
            x: area.x + (area.width.saturating_sub(popup_width)) / 2,
            y: area.y + (area.height / 2).saturating_sub(2),
            width: popup_width,
            height: 5,
        };

        Clear.render(popup, buf);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(self.theme.accent_style());
        let inner = block.inner(popup);
        block.render(popup, buf);

        self.render(inner, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(indicator: &LoadingIndicator, area: Rect) -> String {
        let mut buf = Buffer::empty(area);
        indicator.render(area, &mut buf);
        buf.content.iter().map(|cell| cell.symbol()).collect()
    }

    #[test]
    fn new_indicator_renders_first_spinner_frame_with_message() {
        let indicator = LoadingIndicator::new("Loading log groups...");

        let area = Rect::new(0, 0, 40, 1);
        let text = rendered(&indicator, area);

        assert!(
            text.starts_with("[    ]"),
            "first frame should be the all-blank spinner, got {text:?}"
        );
        assert!(text.contains("Loading log groups..."));
    }

    #[test]
    fn tick_advances_through_all_spinner_frames_and_wraps() {
        let mut indicator = LoadingIndicator::new("test");
        let area = Rect::new(0, 0, 40, 1);

        // Walk through one full cycle (7 frames) plus one wrap.
        let mut seen = Vec::new();
        for _ in 0..SPINNER_FRAMES.len() + 1 {
            seen.push(rendered(&indicator, area));
            indicator.tick();
        }

        // After 8 ticks we should have seen all 7 frames at least once
        // and wrapped back to frame[0] on the 8th sample.
        assert!(seen[0].starts_with(SPINNER_FRAMES[0]));
        assert!(seen[1].starts_with(SPINNER_FRAMES[1]));
        assert!(seen[SPINNER_FRAMES.len()].starts_with(SPINNER_FRAMES[0]));
    }

    #[test]
    fn set_message_replaces_text_while_preserving_current_frame() {
        let mut indicator = LoadingIndicator::new("first");
        indicator.tick(); // advance to frame 1
        indicator.set_message("second");

        let area = Rect::new(0, 0, 40, 1);
        let text = rendered(&indicator, area);

        assert!(text.contains("second"));
        assert!(!text.contains("first"));
        assert!(
            text.starts_with("[=   ]"),
            "frame should still be 1, got {text:?}"
        );
    }

    #[test]
    fn render_overlay_renders_message_inside_popup_region() {
        // The overlay is centred inside the surrounding area; a long
        // background ("X" fill) outside the popup should survive.
        let area = Rect::new(0, 0, 60, 10);
        let mut buf = Buffer::empty(area);
        for cell in buf.content.iter_mut() {
            cell.set_char('X');
        }

        let indicator = LoadingIndicator::new("Loading");
        indicator.render_overlay(area, &mut buf);

        let full: String = buf.content.iter().map(|c| c.symbol()).collect();
        assert!(
            full.contains("Loading"),
            "overlay must render the message text inside the popup"
        );
        assert!(
            full.contains('X'),
            "outside the popup the original 'X' fill must survive"
        );
    }

    #[test]
    fn render_in_extremely_small_area_does_not_panic() {
        // Defensive: extremely narrow / empty rect should not crash
        // (caught a real ratatui panic when the surrounding screen
        // shrank mid-render in earlier rounds).
        let indicator = LoadingIndicator::new("any");
        let mut buf = Buffer::empty(Rect::new(0, 0, 1, 1));
        indicator.render(Rect::new(0, 0, 1, 1), &mut buf);
    }

    #[test]
    fn render_overlay_in_narrow_area_clamps_popup_width_safely() {
        // Even with a tiny surrounding area + very long message,
        // popup width math must saturating_sub instead of underflowing.
        let indicator = LoadingIndicator::new(&"long-message-".repeat(20));
        let mut buf = Buffer::empty(Rect::new(0, 0, 8, 5));
        indicator.render_overlay(Rect::new(0, 0, 8, 5), &mut buf);
        // Test passes if it does not panic.
    }
}
