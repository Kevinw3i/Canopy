use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Row, Table, TableState},
};

use crate::theme::Theme;

pub(crate) const SELECTED_ROW_SYMBOL: &str = "> ";

pub(crate) fn selected_row_style(theme: Theme) -> Style {
    theme.selected_style()
}

pub(crate) fn table_border_style(focused: bool, theme: Theme) -> Style {
    if focused {
        theme.focused_border_style()
    } else {
        theme.accent_style()
    }
}

/// Reusable table widget with keyboard navigation
pub struct SelectableTable {
    pub state: TableState,
    pub row_count: usize,
    pub column_widths: Vec<Constraint>,
    pub headers: Vec<String>,
    column_spacing: u16,
    theme: Theme,
}

impl SelectableTable {
    pub fn new(headers: Vec<String>, column_widths: Vec<Constraint>) -> Self {
        Self {
            state: TableState::default(),
            row_count: 0,
            column_widths,
            headers,
            column_spacing: 2,
            theme: Theme::default(),
        }
    }

    pub fn with_theme(mut self, theme: Theme) -> Self {
        self.theme = theme;
        self
    }

    pub fn with_column_spacing(mut self, spacing: u16) -> Self {
        self.column_spacing = spacing;
        self
    }

    pub fn set_column_spacing(&mut self, spacing: u16) {
        self.column_spacing = spacing;
    }

    pub fn set_row_count(&mut self, count: usize) {
        self.row_count = count;
        if count == 0 {
            self.state.select(None);
        } else if self.state.selected().is_none() && count > 0 {
            self.state.select(Some(0));
        } else if let Some(sel) = self.state.selected() {
            if sel >= count {
                self.state.select(Some(count.saturating_sub(1)));
            }
        }
    }

    pub fn selected(&self) -> Option<usize> {
        self.state.selected()
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        if self.row_count == 0 {
            return false;
        }

        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                let i = self.state.selected().unwrap_or(0);
                let next = if i == 0 { self.row_count - 1 } else { i - 1 };
                self.state.select(Some(next));
                true
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let i = self.state.selected().unwrap_or(0);
                let next = if i >= self.row_count - 1 { 0 } else { i + 1 };
                self.state.select(Some(next));
                true
            }
            KeyCode::Home | KeyCode::Char('g') => {
                self.state.select(Some(0));
                true
            }
            KeyCode::End | KeyCode::Char('G') => {
                self.state.select(Some(self.row_count.saturating_sub(1)));
                true
            }
            KeyCode::PageUp => {
                let i = self.state.selected().unwrap_or(0);
                let next = i.saturating_sub(20);
                self.state.select(Some(next));
                true
            }
            KeyCode::PageDown => {
                let i = self.state.selected().unwrap_or(0);
                let next = (i + 20).min(self.row_count.saturating_sub(1));
                self.state.select(Some(next));
                true
            }
            _ => false,
        }
    }

    /// Thin wrapper for call sites that do not track focus yet. Prefer
    /// `render_with_rows_focused` for new code so the table border can reflect
    /// active focus consistently.
    pub fn render_with_rows<'a>(
        &mut self,
        rows: impl Iterator<Item = Row<'a>>,
        title: &str,
        area: Rect,
        buf: &mut Buffer,
    ) {
        self.render_with_rows_focused(rows, title, area, buf, false);
    }

    pub fn render_with_rows_focused<'a>(
        &mut self,
        rows: impl Iterator<Item = Row<'a>>,
        title: &str,
        area: Rect,
        buf: &mut Buffer,
        focused: bool,
    ) {
        let header = Row::new(
            self.headers
                .iter()
                .map(|h| Cell::from(h.as_str()).style(self.theme.accent_style().bold())),
        )
        .height(1);

        let table = Table::new(rows, &self.column_widths)
            .header(header)
            .column_spacing(self.column_spacing)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {} ", title))
                    .border_style(table_border_style(focused, self.theme)),
            )
            .highlight_style(selected_row_style(self.theme))
            .highlight_symbol(SELECTED_ROW_SYMBOL);

        StatefulWidget::render(table, area, buf, &mut self.state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn make_table(rows: usize) -> SelectableTable {
        let mut t = SelectableTable::new(
            vec!["A".into(), "B".into()],
            vec![Constraint::Min(10), Constraint::Min(10)],
        );
        t.set_row_count(rows);
        t
    }

    #[test]
    fn test_initial_selection() {
        let t = make_table(5);
        assert_eq!(t.selected(), Some(0));
    }

    #[test]
    fn test_empty_table_no_selection() {
        let t = make_table(0);
        assert_eq!(t.selected(), None);
    }

    #[test]
    fn test_j_k_navigation() {
        let mut t = make_table(5);
        t.handle_key(key(KeyCode::Char('j'))); // 0 → 1
        assert_eq!(t.selected(), Some(1));
        t.handle_key(key(KeyCode::Char('j'))); // 1 → 2
        assert_eq!(t.selected(), Some(2));
        t.handle_key(key(KeyCode::Char('k'))); // 2 → 1
        assert_eq!(t.selected(), Some(1));
    }

    #[test]
    fn test_wraps_around_bottom() {
        let mut t = make_table(3);
        t.handle_key(key(KeyCode::Char('j'))); // 0 → 1
        t.handle_key(key(KeyCode::Char('j'))); // 1 → 2
        t.handle_key(key(KeyCode::Char('j'))); // 2 → 0 (wrap)
        assert_eq!(t.selected(), Some(0));
    }

    #[test]
    fn test_wraps_around_top() {
        let mut t = make_table(3);
        t.handle_key(key(KeyCode::Char('k'))); // 0 → 2 (wrap)
        assert_eq!(t.selected(), Some(2));
    }

    #[test]
    fn test_home_end() {
        let mut t = make_table(10);
        t.handle_key(key(KeyCode::End));
        assert_eq!(t.selected(), Some(9));
        t.handle_key(key(KeyCode::Home));
        assert_eq!(t.selected(), Some(0));
    }

    #[test]
    fn test_page_down_up() {
        let mut t = make_table(50);
        t.handle_key(key(KeyCode::PageDown)); // 0 → 20
        assert_eq!(t.selected(), Some(20));
        t.handle_key(key(KeyCode::PageUp)); // 20 → 0
        assert_eq!(t.selected(), Some(0));
    }

    #[test]
    fn test_page_down_clamps() {
        let mut t = make_table(5);
        t.handle_key(key(KeyCode::PageDown)); // 0 → min(20, 4) = 4
        assert_eq!(t.selected(), Some(4));
    }

    #[test]
    fn test_set_row_count_clamps_selection() {
        let mut t = make_table(10);
        t.handle_key(key(KeyCode::End)); // select 9
        t.set_row_count(5); // shrink → clamp to 4
        assert_eq!(t.selected(), Some(4));
    }

    #[test]
    fn test_set_row_count_zero_clears() {
        let mut t = make_table(5);
        t.set_row_count(0);
        assert_eq!(t.selected(), None);
    }

    #[test]
    fn test_empty_table_ignores_keys() {
        let mut t = make_table(0);
        assert!(!t.handle_key(key(KeyCode::Char('j'))));
        assert!(!t.handle_key(key(KeyCode::Char('k'))));
    }

    #[test]
    fn render_uses_configured_theme() {
        let theme = Theme {
            accent: Color::Magenta,
            warning: Color::Red,
            selected_bg: Color::Blue,
            selected_fg: Color::LightYellow,
            ..Theme::default()
        };
        let mut table = SelectableTable::new(
            vec!["A".into(), "B".into()],
            vec![Constraint::Length(8), Constraint::Length(8)],
        )
        .with_theme(theme);
        table.set_row_count(1);

        let rows = vec![Row::new(vec![Cell::from("one"), Cell::from("two")])];
        let area = Rect::new(0, 0, 24, 5);
        let mut buf = Buffer::empty(area);
        table.render_with_rows_focused(rows.into_iter(), "Demo", area, &mut buf, true);

        assert_eq!(buf[(0, 0)].fg, Color::Red);
        assert!(buf
            .content
            .iter()
            .any(|cell| cell.symbol() == "A" && cell.fg == Color::Magenta));
        assert!(buf.content.iter().any(|cell| {
            cell.symbol() != " " && cell.bg == Color::Blue && cell.fg == Color::LightYellow
        }));
    }

    #[test]
    fn render_uses_configured_column_spacing() {
        let mut table = SelectableTable::new(
            vec!["A".into(), "B".into()],
            vec![Constraint::Length(3), Constraint::Length(3)],
        )
        .with_column_spacing(4);
        table.set_row_count(1);

        let rows = vec![Row::new(vec![Cell::from("one"), Cell::from("two")])];
        let area = Rect::new(0, 0, 18, 5);
        let mut buf = Buffer::empty(area);
        table.render_with_rows_focused(rows.into_iter(), "Demo", area, &mut buf, false);

        let rendered = buf
            .content
            .chunks(area.width as usize)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("one    two"));
    }
}
