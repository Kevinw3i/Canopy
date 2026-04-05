use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Row, Table, TableState},
};

/// Reusable table widget with keyboard navigation
pub struct SelectableTable {
    pub state: TableState,
    pub row_count: usize,
    pub column_widths: Vec<Constraint>,
    pub headers: Vec<String>,
}

impl SelectableTable {
    pub fn new(headers: Vec<String>, column_widths: Vec<Constraint>) -> Self {
        Self {
            state: TableState::default(),
            row_count: 0,
            column_widths,
            headers,
        }
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

    pub fn render_with_rows<'a>(
        &mut self,
        rows: impl Iterator<Item = Row<'a>>,
        title: &str,
        area: Rect,
        buf: &mut Buffer,
    ) {
        let header = Row::new(
            self.headers
                .iter()
                .map(|h| Cell::from(h.as_str()).style(Style::default().bold().fg(Color::Cyan))),
        )
        .height(1);

        let table = Table::new(rows, &self.column_widths)
            .header(header)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {} ", title))
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::Indexed(236)) // subtle dark gray background
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");

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
}
