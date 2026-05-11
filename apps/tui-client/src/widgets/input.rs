use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};

/// Reusable text input widget with cursor.
///
/// `cursor_pos` is a **character** index (not byte index) so that cursor
/// movement works correctly with multi-byte UTF-8 characters.
pub struct TextInput {
    pub value: String,
    /// Cursor position as a character index (0 = before first char).
    pub cursor_pos: usize,
    pub label: String,
    pub focused: bool,
    pub masked: bool,
}

impl TextInput {
    pub fn new(label: &str) -> Self {
        Self {
            value: String::new(),
            cursor_pos: 0,
            label: label.to_string(),
            focused: false,
            masked: false,
        }
    }

    pub fn masked(mut self) -> Self {
        self.masked = true;
        self
    }

    /// Convert a character index to a byte offset in `self.value`.
    fn char_to_byte(&self, char_idx: usize) -> usize {
        self.value
            .char_indices()
            .nth(char_idx)
            .map(|(byte_idx, _)| byte_idx)
            .unwrap_or(self.value.len())
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                let byte_pos = self.char_to_byte(self.cursor_pos);
                self.value.insert(byte_pos, c);
                self.cursor_pos += 1;
                true
            }
            KeyCode::Backspace => {
                if self.cursor_pos > 0 {
                    self.cursor_pos -= 1;
                    let byte_pos = self.char_to_byte(self.cursor_pos);
                    self.value.remove(byte_pos);
                }
                true
            }
            KeyCode::Delete => {
                let char_count = self.value.chars().count();
                if self.cursor_pos < char_count {
                    let byte_pos = self.char_to_byte(self.cursor_pos);
                    self.value.remove(byte_pos);
                }
                true
            }
            KeyCode::Left => {
                if self.cursor_pos > 0 {
                    self.cursor_pos -= 1;
                }
                true
            }
            KeyCode::Right => {
                let char_count = self.value.chars().count();
                if self.cursor_pos < char_count {
                    self.cursor_pos += 1;
                }
                true
            }
            KeyCode::Home => {
                self.cursor_pos = 0;
                true
            }
            KeyCode::End => {
                self.cursor_pos = self.value.chars().count();
                true
            }
            _ => false,
        }
    }

    pub fn insert_str(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }

        let byte_pos = self.char_to_byte(self.cursor_pos);
        self.value.insert_str(byte_pos, text);
        self.cursor_pos += text.chars().count();
    }

    pub fn clear(&mut self) {
        self.value.clear();
        self.cursor_pos = 0;
    }

    pub fn render(&self, area: Rect, buf: &mut Buffer) {
        let border_style = if self.focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::Gray)
        };

        let display_value = if self.masked {
            "*".repeat(self.value.chars().count())
        } else {
            self.value.clone()
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(format!(" {} ", self.label));

        let inner = block.inner(area);

        // Render block
        block.render(area, buf);

        // Render text with cursor
        let text = if self.focused {
            let byte_split = display_value
                .char_indices()
                .nth(self.cursor_pos)
                .map(|(i, _)| i)
                .unwrap_or(display_value.len());
            let (before, after) = display_value.split_at(byte_split);

            // Get first character of `after` for the cursor block
            let cursor_char_len = after.chars().next().map(|c| c.len_utf8()).unwrap_or(0);

            Line::from(vec![
                Span::raw(before.to_string()),
                Span::styled(
                    if cursor_char_len == 0 {
                        " ".to_string()
                    } else {
                        after[..cursor_char_len].to_string()
                    },
                    Style::default().bg(Color::White).fg(Color::Black),
                ),
                Span::raw(if cursor_char_len < after.len() {
                    after[cursor_char_len..].to_string()
                } else {
                    String::new()
                }),
            ])
        } else {
            Line::from(display_value)
        };

        Paragraph::new(text).render(inner, buf);
    }
}

/// Multi-line text input for compact in-terminal editors.
///
/// `cursor_pos` is a character index over the full string, including `\n`.
pub struct TextAreaInput {
    pub value: String,
    pub cursor_pos: usize,
    pub label: String,
    pub focused: bool,
    scroll_line: usize,
}

impl TextAreaInput {
    pub fn new(label: &str) -> Self {
        Self::with_value(label, "")
    }

    pub fn with_value(label: &str, value: &str) -> Self {
        Self {
            value: value.to_string(),
            cursor_pos: value.chars().count(),
            label: label.to_string(),
            focused: false,
            scroll_line: 0,
        }
    }

    fn char_to_byte(&self, char_idx: usize) -> usize {
        self.value
            .char_indices()
            .nth(char_idx)
            .map(|(byte_idx, _)| byte_idx)
            .unwrap_or(self.value.len())
    }

    fn char_count(&self) -> usize {
        self.value.chars().count()
    }

    fn lines(&self) -> Vec<&str> {
        self.value.split('\n').collect()
    }

    fn cursor_line_col(&self) -> (usize, usize) {
        let mut pos = 0;
        for (idx, line) in self.lines().iter().enumerate() {
            let line_len = line.chars().count();
            if self.cursor_pos <= pos + line_len {
                return (idx, self.cursor_pos - pos);
            }
            pos += line_len + 1;
        }
        let lines = self.lines();
        let last_idx = lines.len().saturating_sub(1);
        (
            last_idx,
            lines.get(last_idx).map(|l| l.chars().count()).unwrap_or(0),
        )
    }

    fn line_col_to_pos(&self, target_line: usize, target_col: usize) -> usize {
        let lines = self.lines();
        let clamped_line = target_line.min(lines.len().saturating_sub(1));
        let mut pos = 0;
        for line in lines.iter().take(clamped_line) {
            pos += line.chars().count() + 1;
        }
        pos + target_col.min(lines[clamped_line].chars().count())
    }

    fn insert_char(&mut self, c: char) {
        let byte_pos = self.char_to_byte(self.cursor_pos);
        self.value.insert(byte_pos, c);
        self.cursor_pos += 1;
    }

    pub fn insert_str(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }

        let byte_pos = self.char_to_byte(self.cursor_pos);
        self.value.insert_str(byte_pos, text);
        self.cursor_pos += text.chars().count();
    }

    pub fn set_value(&mut self, value: String) {
        self.cursor_pos = value.chars().count();
        self.value = value;
        self.scroll_line = 0;
    }

    pub fn set_cursor_to_first_match(&mut self, needle: &str) {
        if needle.is_empty() {
            return;
        }

        if let Some(byte_idx) = self.value.find(needle) {
            self.cursor_pos = self.value[..byte_idx].chars().count();
            self.scroll_line = 0;
        }
    }

    pub fn clear(&mut self) {
        self.value.clear();
        self.cursor_pos = 0;
        self.scroll_line = 0;
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.insert_char(c);
                true
            }
            KeyCode::Enter => {
                self.insert_char('\n');
                true
            }
            KeyCode::Backspace => {
                if self.cursor_pos > 0 {
                    self.cursor_pos -= 1;
                    let byte_pos = self.char_to_byte(self.cursor_pos);
                    self.value.remove(byte_pos);
                }
                true
            }
            KeyCode::Delete => {
                if self.cursor_pos < self.char_count() {
                    let byte_pos = self.char_to_byte(self.cursor_pos);
                    self.value.remove(byte_pos);
                }
                true
            }
            KeyCode::Left => {
                if self.cursor_pos > 0 {
                    self.cursor_pos -= 1;
                }
                true
            }
            KeyCode::Right => {
                if self.cursor_pos < self.char_count() {
                    self.cursor_pos += 1;
                }
                true
            }
            KeyCode::Up => {
                let (line, col) = self.cursor_line_col();
                if line > 0 {
                    self.cursor_pos = self.line_col_to_pos(line - 1, col);
                }
                true
            }
            KeyCode::Down => {
                let (line, col) = self.cursor_line_col();
                let line_count = self.lines().len();
                if line + 1 < line_count {
                    self.cursor_pos = self.line_col_to_pos(line + 1, col);
                }
                true
            }
            KeyCode::Home => {
                let (line, _) = self.cursor_line_col();
                self.cursor_pos = self.line_col_to_pos(line, 0);
                true
            }
            KeyCode::End => {
                let (line, _) = self.cursor_line_col();
                let line_len = self.lines()[line].chars().count();
                self.cursor_pos = self.line_col_to_pos(line, line_len);
                true
            }
            _ => false,
        }
    }

    fn ensure_cursor_visible(&mut self, visible_rows: usize) {
        if visible_rows == 0 {
            return;
        }

        let (cursor_line, _) = self.cursor_line_col();
        if cursor_line < self.scroll_line {
            self.scroll_line = cursor_line;
        } else if cursor_line >= self.scroll_line + visible_rows {
            self.scroll_line = cursor_line + 1 - visible_rows;
        }
    }

    pub fn render(&mut self, area: Rect, buf: &mut Buffer) {
        let border_style = if self.focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::Gray)
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(format!(" {} ", self.label));
        let inner = block.inner(area);
        block.render(area, buf);

        let visible_rows = inner.height as usize;
        self.ensure_cursor_visible(visible_rows);

        let lines = self.lines();
        let line_no_width = lines.len().max(1).to_string().len().max(2);
        let (cursor_line, cursor_col) = self.cursor_line_col();
        let visible = (0..visible_rows).map(|offset| {
            let line_idx = self.scroll_line + offset;
            let Some(line) = lines.get(line_idx) else {
                return Line::from("");
            };

            let line_no = format!("{:>width$} ", line_idx + 1, width = line_no_width);
            let line_style = if self.focused && line_idx == cursor_line {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(Color::Gray)
            };

            if self.focused && line_idx == cursor_line {
                let byte_split = line
                    .char_indices()
                    .nth(cursor_col)
                    .map(|(i, _)| i)
                    .unwrap_or(line.len());
                let (before, after) = line.split_at(byte_split);
                let cursor_char_len = after.chars().next().map(|c| c.len_utf8()).unwrap_or(0);

                Line::from(vec![
                    Span::styled(line_no, Style::default().fg(Color::Blue)),
                    Span::styled(before.to_string(), line_style),
                    Span::styled(
                        if cursor_char_len == 0 {
                            " ".to_string()
                        } else {
                            after[..cursor_char_len].to_string()
                        },
                        Style::default().bg(Color::White).fg(Color::Black),
                    ),
                    Span::styled(
                        if cursor_char_len < after.len() {
                            after[cursor_char_len..].to_string()
                        } else {
                            String::new()
                        },
                        line_style,
                    ),
                ])
            } else {
                Line::from(vec![
                    Span::styled(line_no, Style::default().fg(Color::Blue)),
                    Span::styled(line.to_string(), line_style),
                ])
            }
        });

        Paragraph::new(visible.collect::<Vec<_>>()).render(inner, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn modified_key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    #[test]
    fn test_type_and_cursor() {
        let mut input = TextInput::new("Test");
        input.handle_key(key(KeyCode::Char('a')));
        input.handle_key(key(KeyCode::Char('b')));
        input.handle_key(key(KeyCode::Char('c')));
        assert_eq!(input.value, "abc");
        assert_eq!(input.cursor_pos, 3);
    }

    #[test]
    fn test_backspace() {
        let mut input = TextInput::new("Test");
        input.handle_key(key(KeyCode::Char('a')));
        input.handle_key(key(KeyCode::Char('b')));
        input.handle_key(key(KeyCode::Backspace));
        assert_eq!(input.value, "a");
        assert_eq!(input.cursor_pos, 1);
    }

    #[test]
    fn test_backspace_at_start_is_noop() {
        let mut input = TextInput::new("Test");
        input.handle_key(key(KeyCode::Backspace));
        assert_eq!(input.value, "");
        assert_eq!(input.cursor_pos, 0);
    }

    #[test]
    fn test_left_right_navigation() {
        let mut input = TextInput::new("Test");
        for c in "abc".chars() {
            input.handle_key(key(KeyCode::Char(c)));
        }
        input.handle_key(key(KeyCode::Left));
        assert_eq!(input.cursor_pos, 2);
        input.handle_key(key(KeyCode::Left));
        assert_eq!(input.cursor_pos, 1);
        input.handle_key(key(KeyCode::Right));
        assert_eq!(input.cursor_pos, 2);
    }

    #[test]
    fn test_home_end() {
        let mut input = TextInput::new("Test");
        for c in "hello".chars() {
            input.handle_key(key(KeyCode::Char(c)));
        }
        input.handle_key(key(KeyCode::Home));
        assert_eq!(input.cursor_pos, 0);
        input.handle_key(key(KeyCode::End));
        assert_eq!(input.cursor_pos, 5);
    }

    #[test]
    fn test_insert_in_middle() {
        let mut input = TextInput::new("Test");
        for c in "ac".chars() {
            input.handle_key(key(KeyCode::Char(c)));
        }
        input.handle_key(key(KeyCode::Left)); // cursor at 1
        input.handle_key(key(KeyCode::Char('b')));
        assert_eq!(input.value, "abc");
        assert_eq!(input.cursor_pos, 2);
    }

    #[test]
    fn test_insert_str_in_middle() {
        let mut input = TextInput::new("Test");
        input.insert_str("ac");
        input.handle_key(key(KeyCode::Left)); // cursor at 1
        input.insert_str("b");
        assert_eq!(input.value, "abc");
        assert_eq!(input.cursor_pos, 2);
    }

    #[test]
    fn textinput_ignores_ctrl_and_alt_char_input() {
        let mut input = TextInput::new("Test");

        assert!(!input.handle_key(modified_key(KeyCode::Char('c'), KeyModifiers::CONTROL)));
        assert!(!input.handle_key(modified_key(KeyCode::Char('w'), KeyModifiers::ALT)));

        assert_eq!(input.value, "");
    }

    #[test]
    fn test_delete() {
        let mut input = TextInput::new("Test");
        for c in "abc".chars() {
            input.handle_key(key(KeyCode::Char(c)));
        }
        input.handle_key(key(KeyCode::Home));
        input.handle_key(key(KeyCode::Delete));
        assert_eq!(input.value, "bc");
        assert_eq!(input.cursor_pos, 0);
    }

    #[test]
    fn test_utf8_multibyte() {
        let mut input = TextInput::new("Test");
        for c in "你好".chars() {
            input.handle_key(key(KeyCode::Char(c)));
        }
        assert_eq!(input.value, "你好");
        assert_eq!(input.cursor_pos, 2);

        input.handle_key(key(KeyCode::Backspace));
        assert_eq!(input.value, "你");
        assert_eq!(input.cursor_pos, 1);
    }

    #[test]
    fn test_clear() {
        let mut input = TextInput::new("Test");
        for c in "hello".chars() {
            input.handle_key(key(KeyCode::Char(c)));
        }
        input.clear();
        assert_eq!(input.value, "");
        assert_eq!(input.cursor_pos, 0);
    }

    #[test]
    fn textarea_enter_inserts_newline() {
        let mut input = TextAreaInput::new("Query");
        input.insert_str("abc");
        input.handle_key(key(KeyCode::Enter));
        input.insert_str("def");

        assert_eq!(input.value, "abc\ndef");
        assert_eq!(input.cursor_line_col(), (1, 3));
    }

    #[test]
    fn textarea_up_down_preserves_column_when_possible() {
        let mut input = TextAreaInput::with_value("Query", "abcd\nxy\n12345");
        input.cursor_pos = "abcd\nxy\n1234".chars().count();

        input.handle_key(key(KeyCode::Up));
        assert_eq!(input.cursor_line_col(), (1, 2));

        input.handle_key(key(KeyCode::Up));
        assert_eq!(input.cursor_line_col(), (0, 2));

        input.handle_key(key(KeyCode::Down));
        assert_eq!(input.cursor_line_col(), (1, 2));
    }

    #[test]
    fn textarea_sets_cursor_to_first_match() {
        let mut input = TextAreaInput::with_value("Query", "first\n[keyword]\nlast");
        input.set_cursor_to_first_match("[keyword]");
        assert_eq!(input.cursor_line_col(), (1, 0));
    }

    #[test]
    fn textarea_ignores_ctrl_and_alt_char_input() {
        let mut input = TextAreaInput::new("Query");

        assert!(!input.handle_key(modified_key(KeyCode::Char('a'), KeyModifiers::CONTROL)));
        assert!(!input.handle_key(modified_key(KeyCode::Char('x'), KeyModifiers::ALT)));

        assert_eq!(input.value, "");
    }
}
