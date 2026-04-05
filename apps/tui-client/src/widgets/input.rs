use crossterm::event::{KeyCode, KeyEvent};
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
            KeyCode::Char(c) => {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
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
}
