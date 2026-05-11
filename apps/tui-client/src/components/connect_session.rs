use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use ratatui::prelude::*;
use shared::dto::ec2::ConnectMethod;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use crate::event::Action;

const STATUS_RIGHT_PADDING: u16 = 1;
const STATUS_GAP: u16 = 2;
const READ_CHUNK_BYTES: usize = 8192;
const MAX_BUFFERED_OUTPUT_BYTES: usize = 1024 * 1024;
// Some shells or commands are quiet after PTY spawn. After this grace period,
// show the session as connected instead of leaving the status bar on Connecting.
const CONNECT_FALLBACK_TIMEOUT: Duration = Duration::from_secs(3);
const DISCONNECT_HINT: &str = "Ctrl+] / Ctrl+5 disconnect";

pub(crate) struct ConnectSessionLaunch {
    pub instance_id: String,
    pub instance_name: Option<String>,
    pub account_id: String,
    pub region: String,
    pub method: ConnectMethod,
    pub command: String,
    pub args: Vec<String>,
    pub env_vars: HashMap<String, String>,
    pub max_session_seconds: u64,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectSessionStatus {
    Connecting,
    Connected,
    Closed,
    TimedOut,
    Disconnected,
    Failed,
}

#[derive(Debug, Default)]
struct OutputBuffer {
    bytes: Vec<u8>,
    signal_pending: bool,
    dropped_bytes: usize,
}

impl OutputBuffer {
    fn push(&mut self, incoming: &[u8]) {
        if incoming.len() >= MAX_BUFFERED_OUTPUT_BYTES {
            self.dropped_bytes += self.bytes.len() + incoming.len() - MAX_BUFFERED_OUTPUT_BYTES;
            self.bytes.clear();
            self.bytes
                .extend_from_slice(&incoming[incoming.len() - MAX_BUFFERED_OUTPUT_BYTES..]);
            return;
        }

        let overflow =
            (self.bytes.len() + incoming.len()).saturating_sub(MAX_BUFFERED_OUTPUT_BYTES);
        if overflow > 0 {
            self.bytes.drain(..overflow);
            self.dropped_bytes += overflow;
        }
        self.bytes.extend_from_slice(incoming);
    }

    fn drain(&mut self) -> (Vec<u8>, usize) {
        self.signal_pending = false;
        let bytes = std::mem::take(&mut self.bytes);
        let dropped_bytes = std::mem::take(&mut self.dropped_bytes);
        (bytes, dropped_bytes)
    }
}

pub(crate) struct ConnectSessionScreen {
    instance_id: String,
    instance_name: Option<String>,
    account_id: String,
    region: String,
    method: ConnectMethod,
    max_session_seconds: u64,
    started_at: Instant,
    status: ConnectSessionStatus,
    parser: vt100::Parser,
    output_buffer: Arc<Mutex<OutputBuffer>>,
    master: Box<dyn MasterPty + Send>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    child: Box<dyn Child + Send + Sync>,
    terminal_message: Option<String>,
    pty_cols: u16,
    pty_rows: u16,
}

impl ConnectSessionScreen {
    pub(crate) fn spawn(
        launch: ConnectSessionLaunch,
        action_tx: mpsc::UnboundedSender<Action>,
    ) -> anyhow::Result<Self> {
        let pty_cols = launch.cols.max(1);
        let pty_rows = launch.rows.saturating_sub(1).max(1);
        let pty_size = pty_size(pty_rows, pty_cols);
        let pty_system = native_pty_system();
        let pair = pty_system.openpty(pty_size)?;

        let mut cmd = CommandBuilder::new(&launch.command);
        cmd.args(&launch.args);
        for (key, value) in &launch.env_vars {
            cmd.env(key, value);
        }

        let child = pair.slave.spawn_command(cmd)?;
        let mut reader = pair.master.try_clone_reader()?;
        let writer = Arc::new(Mutex::new(pair.master.take_writer()?));
        let output_buffer = Arc::new(Mutex::new(OutputBuffer::default()));
        let reader_output_buffer = Arc::clone(&output_buffer);
        drop(pair.slave);

        std::thread::spawn(move || {
            let mut buf = [0u8; READ_CHUNK_BYTES];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let should_signal = match reader_output_buffer.lock() {
                            Ok(mut output) => {
                                output.push(&buf[..n]);
                                if output.signal_pending {
                                    false
                                } else {
                                    output.signal_pending = true;
                                    true
                                }
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "PTY output buffer mutex poisoned");
                                let _ = action_tx.send(Action::ConnectSessionFailure(format!(
                                    "PTY output buffer unavailable: {e}"
                                )));
                                break;
                            }
                        };

                        if should_signal
                            && action_tx.send(Action::ConnectSessionStdoutReady).is_err()
                        {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = action_tx.send(Action::ConnectSessionFailure(e.to_string()));
                        break;
                    }
                }
            }
        });

        Ok(Self {
            instance_id: launch.instance_id,
            instance_name: launch.instance_name,
            account_id: launch.account_id,
            region: launch.region,
            method: launch.method,
            max_session_seconds: launch.max_session_seconds,
            started_at: Instant::now(),
            status: ConnectSessionStatus::Connecting,
            parser: vt100::Parser::new(pty_rows, pty_cols, 1000),
            output_buffer,
            master: pair.master,
            writer,
            child,
            terminal_message: None,
            pty_cols,
            pty_rows,
        })
    }

    pub(crate) fn process_pending_output(&mut self) {
        let drain_result = {
            match self.output_buffer.lock() {
                Ok(mut output) => Ok(output.drain()),
                Err(e) => Err(e.to_string()),
            }
        };
        let (bytes, dropped_bytes) = match drain_result {
            Ok(output) => output,
            Err(e) => {
                tracing::error!(error = %e, "PTY output buffer mutex poisoned");
                self.fail(format!("PTY output buffer unavailable: {e}"));
                return;
            }
        };

        if dropped_bytes > 0 {
            self.process_output(
                format!("\r\n[Canopy dropped {dropped_bytes} bytes of remote output]\r\n")
                    .as_bytes(),
            );
        }
        if !bytes.is_empty() {
            self.process_output(&bytes);
        }
    }

    fn process_output(&mut self, bytes: &[u8]) {
        self.parser.process(bytes);
        if self.status == ConnectSessionStatus::Connecting {
            self.status = ConnectSessionStatus::Connected;
        }
    }

    pub(crate) fn fail(&mut self, message: String) {
        if !self.is_terminal() {
            self.status = ConnectSessionStatus::Failed;
            self.terminal_message = Some(message);
            let _ = self.kill_child();
        }
    }

    pub(crate) fn disconnect(&mut self) {
        if !self.is_terminal() {
            self.status = ConnectSessionStatus::Disconnected;
            self.terminal_message = Some("Disconnected by local operator.".into());
            let _ = self.kill_child();
        }
    }

    pub(crate) fn tick(&mut self) {
        if self.is_terminal() {
            return;
        }

        if self.status == ConnectSessionStatus::Connecting
            && self.started_at.elapsed() >= CONNECT_FALLBACK_TIMEOUT
        {
            self.status = ConnectSessionStatus::Connected;
        }

        if self.remaining_secs() == 0 {
            self.status = ConnectSessionStatus::TimedOut;
            self.terminal_message = Some(format!(
                "Session timeout ({}). Press Enter to return.",
                format_countdown_duration(self.max_session_seconds)
            ));
            let _ = self.kill_child();
            return;
        }

        match self.child.try_wait() {
            Ok(Some(status)) => {
                self.status = ConnectSessionStatus::Closed;
                let message = if status.success() {
                    "Connection closed. Press Enter to return.".to_string()
                } else if let Some(signal) = status.signal() {
                    format!("Connection closed by signal {signal}. Press Enter to return.")
                } else {
                    format!(
                        "Connection exited with code {}. Press Enter to return.",
                        status.exit_code()
                    )
                };
                self.terminal_message = Some(message);
            }
            Ok(None) => {}
            Err(e) => self.fail(format!("Connection monitor failed: {e}")),
        }
    }

    pub(crate) fn resize(&mut self, cols: u16, rows: u16) {
        let pty_cols = cols.max(1);
        let pty_rows = rows.saturating_sub(1).max(1);
        if pty_cols == self.pty_cols && pty_rows == self.pty_rows {
            return;
        }

        self.pty_cols = pty_cols;
        self.pty_rows = pty_rows;
        self.parser.screen_mut().set_size(pty_rows, pty_cols);
        let _ = self.master.resize(pty_size(pty_rows, pty_cols));
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> Action {
        if key.kind != KeyEventKind::Press && key.kind != KeyEventKind::Repeat {
            return Action::Noop;
        }

        if self.is_terminal() {
            return match key.code {
                KeyCode::Enter => Action::ConnectSessionExit,
                _ => Action::Noop,
            };
        }

        if is_local_disconnect_key(&key) {
            return Action::ConnectSessionUserDisconnect;
        }

        if let Some(bytes) = key_to_pty_bytes(key) {
            let write_result = match self.writer.lock() {
                Ok(mut writer) => writer.write_all(&bytes).and_then(|_| writer.flush()),
                Err(e) => {
                    tracing::error!(error = %e, "PTY writer mutex poisoned");
                    return Action::ConnectSessionFailure(format!("PTY writer unavailable: {e}"));
                }
            };
            if let Err(e) = write_result {
                return Action::ConnectSessionFailure(format!("Write to PTY failed: {e}"));
            }
        }
        Action::Noop
    }

    pub(crate) fn render(&self, area: Rect, buf: &mut Buffer) {
        if area.is_empty() {
            return;
        }

        let status_area = Rect {
            x: area.x,
            y: area.y,
            width: area.width,
            height: 1,
        };
        self.render_status_bar(status_area, buf);

        let terminal_area = Rect {
            x: area.x,
            y: area.y.saturating_add(1),
            width: area.width,
            height: area.height.saturating_sub(1),
        };
        self.render_terminal(terminal_area, buf);

        if self.is_terminal() && terminal_area.height > 0 {
            let msg = self
                .terminal_message
                .as_deref()
                .unwrap_or("Press Enter to return.");
            let y = terminal_area
                .y
                .saturating_add(terminal_area.height.saturating_sub(1));
            let max = terminal_area.width as usize;
            for (i, ch) in truncate_for_width(msg, max).chars().enumerate() {
                if i >= max {
                    break;
                }
                buf[(terminal_area.x + i as u16, y)]
                    .set_char(ch)
                    .set_style(Style::default().fg(Color::Yellow).bold());
            }
        }
    }

    fn render_status_bar(&self, area: Rect, buf: &mut Buffer) {
        for col in 0..area.width {
            buf[(area.x + col, area.y)]
                .set_char(' ')
                .set_style(Style::default().bg(Color::DarkGray));
        }

        let (right_text, right_style) = self.status_label();
        let left = self.left_status_text();
        let layout = status_bar_layout(area.width, &left, &right_text);
        for (i, ch) in layout.left_text.chars().enumerate() {
            buf[(area.x + i as u16, area.y)]
                .set_char(ch)
                .set_style(Style::default().fg(Color::White).bg(Color::DarkGray).bold());
        }

        for (i, ch) in right_text.chars().enumerate() {
            let x = area.x + layout.right_x + i as u16;
            if x < area.x + area.width {
                buf[(x, area.y)].set_char(ch).set_style(right_style);
            }
        }
    }

    fn render_terminal(&self, area: Rect, buf: &mut Buffer) {
        for row in 0..area.height {
            for col in 0..area.width {
                let cell = &mut buf[(area.x + col, area.y + row)];
                cell.set_char(' ');
                cell.set_style(Style::default());
            }
        }

        let screen = self.parser.screen();
        let (rows, cols) = screen.size();
        let rows = rows.min(area.height);
        let cols = cols.min(area.width);

        for row in 0..rows {
            for col in 0..cols {
                let Some(term_cell) = screen.cell(row, col) else {
                    continue;
                };
                if term_cell.is_wide_continuation() {
                    continue;
                }

                let symbol = if term_cell.has_contents() {
                    term_cell.contents()
                } else {
                    " "
                };
                let cell = &mut buf[(area.x + col, area.y + row)];
                cell.set_symbol(symbol);
                cell.set_style(vt_style(term_cell));
            }
        }
    }

    fn left_status_text(&self) -> String {
        let instance = instance_label(&self.instance_id, self.instance_name.as_deref());
        match self.status {
            ConnectSessionStatus::Connecting => format!(
                "Canopy SSH  Connecting...  {}  {}/{}  [{}]",
                instance, self.account_id, self.region, DISCONNECT_HINT
            ),
            _ => format!(
                "Canopy SSH  {}  {}  {}/{}  [{}]",
                instance,
                method_label(&self.method),
                self.account_id,
                self.region,
                DISCONNECT_HINT
            ),
        }
    }

    fn status_label(&self) -> (String, Style) {
        match self.status {
            ConnectSessionStatus::Closed => (
                "CLOSED".into(),
                Style::default().fg(Color::Gray).bg(Color::DarkGray).bold(),
            ),
            ConnectSessionStatus::Disconnected => (
                "DISCONNECTED".into(),
                Style::default()
                    .fg(Color::Yellow)
                    .bg(Color::DarkGray)
                    .bold(),
            ),
            ConnectSessionStatus::Failed => (
                "FAILED".into(),
                Style::default().fg(Color::Red).bg(Color::DarkGray).bold(),
            ),
            ConnectSessionStatus::TimedOut => (
                "SESSION EXPIRED".into(),
                Style::default()
                    .fg(Color::Red)
                    .bg(Color::White)
                    .add_modifier(Modifier::BOLD | Modifier::REVERSED),
            ),
            ConnectSessionStatus::Connecting | ConnectSessionStatus::Connected => {
                countdown_status(self.remaining_secs())
            }
        }
    }

    fn remaining_secs(&self) -> u64 {
        self.max_session_seconds
            .saturating_sub(self.started_at.elapsed().as_secs())
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            ConnectSessionStatus::Closed
                | ConnectSessionStatus::TimedOut
                | ConnectSessionStatus::Disconnected
                | ConnectSessionStatus::Failed
        )
    }

    fn kill_child(&mut self) -> std::io::Result<()> {
        self.child.kill()
    }
}

fn pty_size(rows: u16, cols: u16) -> PtySize {
    PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    }
}

fn method_label(method: &ConnectMethod) -> &'static str {
    match method {
        ConnectMethod::Ssm => "SSM",
        ConnectMethod::Ec2InstanceConnect => "EIC",
        ConnectMethod::Ssh => "SSH",
    }
}

fn instance_label(instance_id: &str, instance_name: Option<&str>) -> String {
    match instance_name.map(str::trim).filter(|name| !name.is_empty()) {
        Some(name) => format!("{instance_id}  {name}"),
        None => instance_id.to_string(),
    }
}

fn format_countdown_duration(secs: u64) -> String {
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes:02}:{seconds:02}")
    }
}

fn countdown_status(remaining_secs: u64) -> (String, Style) {
    if remaining_secs == 0 {
        return (
            "SESSION EXPIRED".into(),
            Style::default()
                .fg(Color::Red)
                .bg(Color::White)
                .add_modifier(Modifier::BOLD | Modifier::REVERSED),
        );
    }

    let (prefix, color, critical) = if remaining_secs <= 60 {
        ("!", Color::Red, true)
    } else if remaining_secs <= 5 * 60 {
        ("!", Color::Red, false)
    } else if remaining_secs <= 15 * 60 {
        ("▲", Color::Yellow, false)
    } else {
        ("●", Color::Cyan, false)
    };

    let mut style = Style::default()
        .fg(color)
        .bg(Color::DarkGray)
        .add_modifier(Modifier::BOLD);
    if critical {
        style = style.add_modifier(Modifier::REVERSED);
    }

    (
        format!(
            "{prefix} {} LEFT",
            format_countdown_duration(remaining_secs)
        ),
        style,
    )
}

fn truncate_for_width(text: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let count = text.chars().count();
    if count <= max_chars {
        return text.to_string();
    }
    if max_chars <= 1 {
        return "…".into();
    }
    let mut out: String = text.chars().take(max_chars - 1).collect();
    out.push('…');
    out
}

#[derive(Debug, PartialEq, Eq)]
struct StatusBarLayout {
    left_text: String,
    right_x: u16,
}

fn status_bar_layout(width: u16, left: &str, right: &str) -> StatusBarLayout {
    let right_width = right.chars().count() as u16;
    let right_x = width.saturating_sub(right_width + STATUS_RIGHT_PADDING);
    let left_max = width.saturating_sub(right_width + STATUS_RIGHT_PADDING + STATUS_GAP) as usize;
    StatusBarLayout {
        left_text: truncate_for_width(left, left_max),
        right_x,
    }
}

fn is_local_disconnect_key(key: &KeyEvent) -> bool {
    match key.code {
        // Many Unix terminals send Ctrl+] as ASCII GS (0x1d), which crossterm
        // reports as Ctrl+5. Accept both forms so the documented shortcut works.
        KeyCode::Char('\u{1d}') => true,
        KeyCode::Char(']') | KeyCode::Char('5') => key.modifiers.contains(KeyModifiers::CONTROL),
        _ => false,
    }
}

fn key_to_pty_bytes(key: KeyEvent) -> Option<Vec<u8>> {
    if is_local_disconnect_key(&key) {
        return None;
    }

    let alt = key.modifiers.contains(KeyModifiers::ALT);
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let mut bytes = Vec::new();
    if alt {
        bytes.push(0x1b);
    }

    match key.code {
        KeyCode::Char(c) if ctrl => {
            let lower = c.to_ascii_lowercase();
            if lower.is_ascii_lowercase() {
                bytes.push((lower as u8) - b'a' + 1);
            } else {
                match c {
                    ' ' | '@' => bytes.push(0),
                    '2' => bytes.push(0),
                    '[' => bytes.push(0x1b),
                    '3' => bytes.push(0x1b),
                    '\\' => bytes.push(0x1c),
                    '4' => bytes.push(0x1c),
                    ']' | '5' => return None,
                    '^' => bytes.push(0x1e),
                    '6' => bytes.push(0x1e),
                    '_' => bytes.push(0x1f),
                    '7' => bytes.push(0x1f),
                    '?' => bytes.push(0x7f),
                    '8' => bytes.push(0x7f),
                    _ => return None,
                }
            }
        }
        KeyCode::Char(c) => {
            let mut buf = [0u8; 4];
            bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
        KeyCode::Enter => bytes.push(b'\r'),
        KeyCode::Backspace => bytes.push(0x7f),
        KeyCode::Tab => bytes.push(b'\t'),
        KeyCode::Esc => bytes.push(0x1b),
        KeyCode::Up => bytes.extend_from_slice(b"\x1b[A"),
        KeyCode::Down => bytes.extend_from_slice(b"\x1b[B"),
        KeyCode::Right => bytes.extend_from_slice(b"\x1b[C"),
        KeyCode::Left => bytes.extend_from_slice(b"\x1b[D"),
        KeyCode::Home => bytes.extend_from_slice(b"\x1b[H"),
        KeyCode::End => bytes.extend_from_slice(b"\x1b[F"),
        KeyCode::PageUp => bytes.extend_from_slice(b"\x1b[5~"),
        KeyCode::PageDown => bytes.extend_from_slice(b"\x1b[6~"),
        KeyCode::Delete => bytes.extend_from_slice(b"\x1b[3~"),
        KeyCode::Insert => bytes.extend_from_slice(b"\x1b[2~"),
        KeyCode::F(n) => match n {
            1 => bytes.extend_from_slice(b"\x1bOP"),
            2 => bytes.extend_from_slice(b"\x1bOQ"),
            3 => bytes.extend_from_slice(b"\x1bOR"),
            4 => bytes.extend_from_slice(b"\x1bOS"),
            5 => bytes.extend_from_slice(b"\x1b[15~"),
            6 => bytes.extend_from_slice(b"\x1b[17~"),
            7 => bytes.extend_from_slice(b"\x1b[18~"),
            8 => bytes.extend_from_slice(b"\x1b[19~"),
            9 => bytes.extend_from_slice(b"\x1b[20~"),
            10 => bytes.extend_from_slice(b"\x1b[21~"),
            11 => bytes.extend_from_slice(b"\x1b[23~"),
            12 => bytes.extend_from_slice(b"\x1b[24~"),
            _ => return None,
        },
        _ => return None,
    }

    Some(bytes)
}

fn vt_style(cell: &vt100::Cell) -> Style {
    let mut style = Style::default()
        .fg(vt_color(cell.fgcolor()))
        .bg(vt_color(cell.bgcolor()));
    if cell.bold() {
        style = style.add_modifier(Modifier::BOLD);
    }
    if cell.dim() {
        style = style.add_modifier(Modifier::DIM);
    }
    if cell.italic() {
        style = style.add_modifier(Modifier::ITALIC);
    }
    if cell.underline() {
        style = style.add_modifier(Modifier::UNDERLINED);
    }
    if cell.inverse() {
        style = style.add_modifier(Modifier::REVERSED);
    }
    style
}

fn vt_color(color: vt100::Color) -> Color {
    match color {
        vt100::Color::Default => Color::Reset,
        vt100::Color::Rgb(r, g, b) => Color::Rgb(r, g, b),
        vt100::Color::Idx(idx) => match idx {
            0 => Color::Black,
            1 => Color::Red,
            2 => Color::Green,
            3 => Color::Yellow,
            4 => Color::Blue,
            5 => Color::Magenta,
            6 => Color::Cyan,
            7 => Color::Gray,
            8 => Color::DarkGray,
            9 => Color::LightRed,
            10 => Color::LightGreen,
            11 => Color::LightYellow,
            12 => Color::LightBlue,
            13 => Color::LightMagenta,
            14 => Color::LightCyan,
            15 => Color::White,
            _ => Color::Reset,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    #[cfg(unix)]
    fn spawn_sleeping_session() -> ConnectSessionScreen {
        spawn_test_session(vec!["-c".into(), "sleep 30".into()])
    }

    #[cfg(unix)]
    fn spawn_test_session(args: Vec<String>) -> ConnectSessionScreen {
        let (tx, _rx) = mpsc::unbounded_channel();
        ConnectSessionScreen::spawn(
            ConnectSessionLaunch {
                instance_id: "i-0123456789abcdef0".into(),
                instance_name: Some("web-prod-01".into()),
                account_id: "123456789012".into(),
                region: "ap-northeast-1".into(),
                method: ConnectMethod::Ssh,
                command: "/bin/sh".into(),
                args,
                env_vars: std::collections::HashMap::new(),
                max_session_seconds: 3600,
                cols: 80,
                rows: 24,
            },
            tx,
        )
        .expect("test PTY session should spawn")
    }

    #[cfg(unix)]
    fn cleanup_session(mut session: ConnectSessionScreen) {
        let _ = session.kill_child();
        let _ = session.child.wait();
    }

    #[test]
    fn countdown_duration_formats_hours_and_minutes() {
        assert_eq!(format_countdown_duration(3600), "1:00:00");
        assert_eq!(format_countdown_duration(3522), "58:42");
        assert_eq!(format_countdown_duration(299), "04:59");
        assert_eq!(format_countdown_duration(59), "00:59");
    }

    #[test]
    fn countdown_status_uses_expected_thresholds() {
        let (text, style) = countdown_status(16 * 60);
        assert_eq!(text, "● 16:00 LEFT");
        assert_eq!(style.fg, Some(Color::Cyan));

        let (text, style) = countdown_status(15 * 60);
        assert_eq!(text, "▲ 15:00 LEFT");
        assert_eq!(style.fg, Some(Color::Yellow));

        let (text, style) = countdown_status(5 * 60);
        assert_eq!(text, "! 05:00 LEFT");
        assert_eq!(style.fg, Some(Color::Red));
        assert!(!style.add_modifier.contains(Modifier::REVERSED));

        let (text, style) = countdown_status(60);
        assert_eq!(text, "! 01:00 LEFT");
        assert!(style.add_modifier.contains(Modifier::REVERSED));

        let (text, style) = countdown_status(0);
        assert_eq!(text, "SESSION EXPIRED");
        assert!(style.add_modifier.contains(Modifier::REVERSED));
    }

    #[test]
    fn key_mapping_forwards_common_terminal_keys() {
        assert_eq!(
            key_to_pty_bytes(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Some(vec![3])
        );
        assert_eq!(
            key_to_pty_bytes(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            Some(vec![b'\r'])
        );
        assert_eq!(
            key_to_pty_bytes(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE)),
            Some(b"\x1b[A".to_vec())
        );
        assert_eq!(
            key_to_pty_bytes(KeyEvent::new(KeyCode::Char('\\'), KeyModifiers::CONTROL)),
            Some(vec![0x1c])
        );
        assert_eq!(
            key_to_pty_bytes(KeyEvent::new(KeyCode::Char('_'), KeyModifiers::CONTROL)),
            Some(vec![0x1f])
        );
        assert_eq!(
            key_to_pty_bytes(KeyEvent::new(KeyCode::Char('3'), KeyModifiers::CONTROL)),
            Some(vec![0x1b])
        );
        assert_eq!(
            key_to_pty_bytes(KeyEvent::new(KeyCode::Char('8'), KeyModifiers::CONTROL)),
            Some(vec![0x7f])
        );
    }

    #[test]
    fn local_disconnect_key_is_not_forwarded() {
        let key = KeyEvent::new(KeyCode::Char(']'), KeyModifiers::CONTROL);
        assert!(is_local_disconnect_key(&key));
        assert_eq!(key_to_pty_bytes(key), None);

        let key = KeyEvent::new(KeyCode::Char('5'), KeyModifiers::CONTROL);
        assert!(is_local_disconnect_key(&key));
        assert_eq!(key_to_pty_bytes(key), None);

        let key = KeyEvent::new(KeyCode::Char('\u{1d}'), KeyModifiers::NONE);
        assert!(is_local_disconnect_key(&key));
        assert_eq!(key_to_pty_bytes(key), None);
    }

    #[test]
    fn instance_label_includes_name_when_available() {
        assert_eq!(
            instance_label("i-0123456789abcdef0", Some("web-prod-01")),
            "i-0123456789abcdef0  web-prod-01"
        );
        assert_eq!(
            instance_label("i-0123456789abcdef0", Some("  ")),
            "i-0123456789abcdef0"
        );
        assert_eq!(
            instance_label("i-0123456789abcdef0", None),
            "i-0123456789abcdef0"
        );
    }

    #[test]
    fn truncate_preserves_right_side_room() {
        assert_eq!(truncate_for_width("abcdef", 4), "abc…");
        assert_eq!(truncate_for_width("abc", 4), "abc");
        assert_eq!(truncate_for_width("abc", 0), "");
    }

    #[test]
    fn status_bar_layout_preserves_countdown_side() {
        let layout = status_bar_layout(20, "Canopy SSH very long left side", "● 58:42 LEFT");
        assert_eq!(layout.right_x, 7);
        assert_eq!(layout.left_text, "Cano…");
    }

    #[test]
    fn output_buffer_caps_remote_output() {
        let mut output = OutputBuffer::default();
        output.push(b"abc");
        assert_eq!(output.bytes, b"abc");

        let oversized = vec![b'x'; MAX_BUFFERED_OUTPUT_BYTES + 10];
        output.push(&oversized);
        assert_eq!(output.bytes.len(), MAX_BUFFERED_OUTPUT_BYTES);
        assert_eq!(output.dropped_bytes, 13);

        output.signal_pending = true;
        let (bytes, dropped) = output.drain();
        assert_eq!(bytes.len(), MAX_BUFFERED_OUTPUT_BYTES);
        assert_eq!(dropped, 13);
        assert!(!output.signal_pending);
    }

    #[cfg(unix)]
    #[test]
    fn process_output_marks_session_connected() {
        let mut session = spawn_sleeping_session();
        assert_eq!(session.status, ConnectSessionStatus::Connecting);
        session.process_output(b"hello");
        assert_eq!(session.status, ConnectSessionStatus::Connected);
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn tick_times_out_expired_session() {
        let mut session = spawn_sleeping_session();
        session.max_session_seconds = 1;
        session.started_at = Instant::now() - Duration::from_secs(2);
        session.tick();
        assert_eq!(session.status, ConnectSessionStatus::TimedOut);
        assert!(session
            .terminal_message
            .as_deref()
            .is_some_and(|msg| msg.contains("Session timeout")));
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn tick_marks_child_exit_closed() {
        let mut session = spawn_test_session(vec!["-c".into(), "exit 7".into()]);
        for _ in 0..20 {
            session.tick();
            if session.status == ConnectSessionStatus::Closed {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert_eq!(session.status, ConnectSessionStatus::Closed);
        assert!(session
            .terminal_message
            .as_deref()
            .is_some_and(|msg| msg.contains("exited with code 7")));
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn resize_updates_pty_and_parser_dimensions() {
        let mut session = spawn_sleeping_session();
        session.resize(100, 40);
        assert_eq!(session.pty_cols, 100);
        assert_eq!(session.pty_rows, 39);
        assert_eq!(session.parser.screen().size(), (39, 100));
        cleanup_session(session);
    }
}
