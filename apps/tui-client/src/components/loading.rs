use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph},
};

/// Loading spinner animation
pub struct LoadingIndicator {
    pub message: String,
    frame: usize,
}

const SPINNER_FRAMES: &[&str] = &[
    "[    ]", "[=   ]", "[==  ]", "[=== ]", "[ ===]", "[  ==]", "[   =]",
];

impl LoadingIndicator {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.into(),
            frame: 0,
        }
    }

    pub fn tick(&mut self) {
        self.frame = (self.frame + 1) % SPINNER_FRAMES.len();
    }

    pub fn render(&self, area: Rect, buf: &mut Buffer) {
        let spinner = SPINNER_FRAMES[self.frame];
        let text = format!("{} {}", spinner, self.message);
        Paragraph::new(text)
            .style(Style::default().fg(Color::Yellow))
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
            .border_style(Style::default().fg(Color::Cyan));
        let inner = block.inner(popup);
        block.render(popup, buf);

        self.render(inner, buf);
    }
}
