use anyhow::Result;
use crossterm::{
    event::{DisableBracketedPaste, EnableBracketedPaste},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;
use std::io::{self, stdout};

pub type Tui = Terminal<CrosstermBackend<io::Stdout>>;

/// Initialize the terminal in alternate screen mode.
///
/// Bracketed paste lets crossterm deliver pasted text as a single
/// `Event::Paste(String)` payload instead of replaying it as keystrokes. The
/// app routes that event to text inputs and the embedded SSH PTY explicitly.
pub fn init() -> Result<Tui> {
    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen, EnableBracketedPaste)?;
    let backend = CrosstermBackend::new(stdout());
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

/// Restore terminal to normal mode
pub fn restore() -> Result<()> {
    disable_raw_mode()?;
    execute!(stdout(), LeaveAlternateScreen, DisableBracketedPaste)?;
    Ok(())
}

/// Temporarily leave alternate screen (for spawning external commands like SSM)
pub fn suspend() -> Result<()> {
    disable_raw_mode()?;
    execute!(stdout(), LeaveAlternateScreen, DisableBracketedPaste)?;
    Ok(())
}

/// Resume alternate screen after external command
pub fn resume() -> Result<Tui> {
    init()
}
