use base64::{engine::general_purpose, Engine as _};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use shared::dto::pty_spawn::PtySpawnSpec;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::event::{Action, MouseInput, MouseInputKind, MouseScrollDirection};
use crate::theme::Theme;

const STATUS_RIGHT_PADDING: u16 = 1;
const STATUS_GAP: u16 = 2;
const STATUS_BAR_HEIGHT: u16 = 1;
const READ_CHUNK_BYTES: usize = 8192;
const MAX_BUFFERED_OUTPUT_BYTES: usize = 1024 * 1024;
const SCROLLBACK_PAGE_OVERLAP_ROWS: u16 = 1;
const MAX_COPY_FILE_BYTES: usize = 5 * 1024 * 1024;
const MAX_COPY_CAPTURE_BYTES: usize = MAX_COPY_FILE_BYTES * 2;
// Some shells or commands are quiet after PTY spawn. After this grace period,
// show the session as connected instead of leaving the status bar on Connecting.
const CONNECT_FALLBACK_TIMEOUT: Duration = Duration::from_secs(3);
const SESSION_HINTS: &str = "Ctrl+H help";

trait ClipboardWriter: Send + Sync {
    fn write_clipboard(&self, bytes: &[u8]) -> Result<(), String>;
}

struct SystemClipboardWriter;

impl ClipboardWriter for SystemClipboardWriter {
    fn write_clipboard(&self, bytes: &[u8]) -> Result<(), String> {
        write_system_clipboard(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConnectOverlay {
    Help,
    CopyPrompt {
        input: String,
        cursor: usize,
        error: Option<String>,
    },
    CopyMessage {
        title: String,
        message: String,
        is_error: bool,
        dismissible: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CopyCaptureMode {
    AwaitMarker,
    Success,
    Error,
}

#[derive(Debug, Clone)]
struct CopyCapture {
    path: String,
    begin_marker: Vec<u8>,
    error_marker: Vec<u8>,
    end_marker: Vec<u8>,
    buffer: Vec<u8>,
    mode: CopyCaptureMode,
}

impl CopyCapture {
    fn new(path: String, id: &str) -> Self {
        Self {
            path,
            begin_marker: format!("__CANOPY_COPY_BEGIN_{id}__").into_bytes(),
            error_marker: format!("__CANOPY_COPY_ERROR_{id}__").into_bytes(),
            end_marker: format!("__CANOPY_COPY_END_{id}__").into_bytes(),
            buffer: Vec::new(),
            mode: CopyCaptureMode::AwaitMarker,
        }
    }
}

pub(crate) struct ConnectSessionLaunch {
    pub instance_id: String,
    pub instance_name: Option<String>,
    pub account_id: String,
    pub region: String,
    pub method_label: String,
    pub spawn: PtySpawnSpec,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SelectionPoint {
    row: u16,
    col: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MouseSelection {
    anchor: SelectionPoint,
    focus: SelectionPoint,
    dragging: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectionNotice {
    Copied { chars: usize },
    CopyFailed,
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

#[derive(Debug, Default)]
struct TerminalResponseCallbacks {
    responses: Vec<u8>,
}

impl TerminalResponseCallbacks {
    fn take_responses(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.responses)
    }

    fn push_cursor_position_report(&mut self, screen: &vt100::Screen, private: bool) {
        let (row, col) = screen.cursor_position();
        if private {
            self.responses.extend_from_slice(
                format!("\x1b[?{};{}R", row.saturating_add(1), col.saturating_add(1)).as_bytes(),
            );
        } else {
            self.responses.extend_from_slice(
                format!("\x1b[{};{}R", row.saturating_add(1), col.saturating_add(1)).as_bytes(),
            );
        }
    }
}

impl vt100::Callbacks for TerminalResponseCallbacks {
    fn unhandled_csi(
        &mut self,
        screen: &mut vt100::Screen,
        i1: Option<u8>,
        i2: Option<u8>,
        params: &[&[u16]],
        c: char,
    ) {
        if i2.is_some() {
            return;
        }

        let first_param = csi_first_param(params);
        match (i1, c, first_param) {
            // Reline/readline asks for the current cursor position with DSR.
            // Without this response, Rails console can block after drawing the prompt.
            (None, 'n', 5) => self.responses.extend_from_slice(b"\x1b[0n"),
            (None, 'n', 6) => self.push_cursor_position_report(screen, false),
            (Some(b'?'), 'n', 6) => self.push_cursor_position_report(screen, true),
            (None, 'c', 0) => self.responses.extend_from_slice(b"\x1b[?1;2c"),
            (Some(b'>'), 'c', 0) => self.responses.extend_from_slice(b"\x1b[>0;0;0c"),
            _ => {}
        }
    }
}

fn csi_first_param(params: &[&[u16]]) -> u16 {
    params
        .first()
        .and_then(|param| param.first())
        .copied()
        .unwrap_or(0)
}

pub(crate) struct ConnectSessionScreen {
    instance_id: String,
    instance_name: Option<String>,
    account_id: String,
    region: String,
    method_label: String,
    max_session_seconds: u64,
    started_at: Instant,
    status: ConnectSessionStatus,
    parser: vt100::Parser<TerminalResponseCallbacks>,
    output_buffer: Arc<Mutex<OutputBuffer>>,
    master: Box<dyn MasterPty + Send>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    child: Box<dyn Child + Send + Sync>,
    terminal_message: Option<String>,
    overlay: Option<ConnectOverlay>,
    copy_capture: Option<CopyCapture>,
    selection: Option<MouseSelection>,
    selection_notice: Option<SelectionNotice>,
    clipboard: Arc<dyn ClipboardWriter>,
    pty_cols: u16,
    pty_rows: u16,
    theme: Theme,
}

impl ConnectSessionScreen {
    pub(crate) fn spawn(
        launch: ConnectSessionLaunch,
        action_tx: mpsc::UnboundedSender<Action>,
    ) -> anyhow::Result<Self> {
        Self::spawn_with_theme(launch, action_tx, Theme::default())
    }

    pub(crate) fn spawn_with_theme(
        launch: ConnectSessionLaunch,
        action_tx: mpsc::UnboundedSender<Action>,
        theme: Theme,
    ) -> anyhow::Result<Self> {
        let pty_cols = launch.cols.max(1);
        let pty_rows = launch.rows.saturating_sub(1).max(1);
        let pty_size = pty_size(pty_rows, pty_cols);
        let pty_system = native_pty_system();
        let pair = pty_system.openpty(pty_size)?;

        let mut cmd = CommandBuilder::new(&launch.spawn.command);
        cmd.args(&launch.spawn.args);
        for (key, value) in &launch.spawn.env_vars {
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
            method_label: launch.method_label,
            max_session_seconds: launch.max_session_seconds,
            started_at: Instant::now(),
            status: ConnectSessionStatus::Connecting,
            parser: vt100::Parser::new_with_callbacks(
                pty_rows,
                pty_cols,
                1000,
                TerminalResponseCallbacks::default(),
            ),
            output_buffer,
            master: pair.master,
            writer,
            child,
            terminal_message: None,
            overlay: None,
            copy_capture: None,
            selection: None,
            selection_notice: None,
            clipboard: Arc::new(SystemClipboardWriter),
            pty_cols,
            pty_rows,
            theme,
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
        let bytes = match self.capture_copy_output(bytes) {
            Some(bytes) => bytes,
            None => return,
        };
        if bytes.is_empty() {
            return;
        }

        self.clear_selection();
        self.parser.process(&bytes);
        let terminal_responses = self.parser.callbacks_mut().take_responses();
        if !terminal_responses.is_empty() {
            if let Err(e) = self.write_to_pty(&terminal_responses) {
                self.fail(e);
                return;
            }
        }
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

        self.clear_selection();
        self.pty_cols = pty_cols;
        self.pty_rows = pty_rows;
        self.parser.screen_mut().set_size(pty_rows, pty_cols);
        let _ = self.master.resize(pty_size(pty_rows, pty_cols));
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> Action {
        if key.kind != KeyEventKind::Press && key.kind != KeyEventKind::Repeat {
            return Action::Noop;
        }

        self.clear_selection();
        if self.is_terminal() {
            return match key.code {
                KeyCode::Enter => Action::ConnectSessionExit,
                _ => Action::Noop,
            };
        }

        if self.handle_overlay_key(key) {
            return Action::Noop;
        }

        if is_help_key(&key) {
            self.overlay = Some(ConnectOverlay::Help);
            return Action::Noop;
        }

        if self.handle_copy_shortcut(&key) {
            return Action::Noop;
        }

        if self.copy_capture.is_some() {
            return Action::Noop;
        }

        if is_local_disconnect_key(&key) {
            return Action::ConnectSessionUserDisconnect;
        }

        if self.handle_local_scrollback_key(&key) {
            return Action::Noop;
        }

        self.reset_scrollback();

        if let Some(bytes) = self.key_to_pty_bytes(key) {
            if let Err(e) = self.write_to_pty(&bytes) {
                return Action::ConnectSessionFailure(e);
            }
        }
        Action::Noop
    }

    pub(crate) fn handle_paste(&mut self, text: &str) -> Action {
        if self.is_terminal()
            || text.is_empty()
            || self.overlay.is_some()
            || self.copy_capture.is_some()
        {
            return Action::Noop;
        }

        self.clear_selection();
        let bytes = bracketed_paste_bytes(text);
        if let Err(e) = self.write_to_pty(&bytes) {
            return Action::ConnectSessionFailure(e);
        }
        Action::Noop
    }

    pub(crate) fn handle_mouse_scroll(&mut self, direction: MouseScrollDirection) -> Action {
        if self.is_terminal()
            || self.overlay.is_some()
            || self.copy_capture.is_some()
            || self.parser.screen().alternate_screen()
        {
            return Action::Noop;
        }
        if self.selection.is_some_and(|selection| selection.dragging) {
            return Action::Noop;
        }

        let current = self.parser.screen().scrollback();
        let target = match direction {
            MouseScrollDirection::Up => Some(current.saturating_add(1)),
            MouseScrollDirection::Down if current > 0 => Some(current.saturating_sub(1)),
            MouseScrollDirection::Down => None,
        };

        if let Some(target) = target {
            self.clear_selection();
            self.parser.screen_mut().set_scrollback(target);
        }

        Action::Noop
    }

    pub(crate) fn handle_mouse_input(&mut self, mouse: MouseInput) -> Action {
        if self.is_terminal() || self.overlay.is_some() || self.copy_capture.is_some() {
            return Action::Noop;
        }

        match mouse.kind {
            MouseInputKind::LeftDown => {
                let Some(point) = self.mouse_to_selection_point(mouse, false) else {
                    return Action::Noop;
                };
                self.selection_notice = None;
                self.selection = Some(MouseSelection {
                    anchor: point,
                    focus: point,
                    dragging: true,
                });
            }
            MouseInputKind::LeftDrag => {
                let Some(current) = self.selection else {
                    return Action::Noop;
                };
                if !current.dragging {
                    return Action::Noop;
                }
                let Some(point) = self.mouse_to_selection_point(mouse, true) else {
                    return Action::Noop;
                };
                self.selection = Some(MouseSelection {
                    focus: point,
                    ..current
                });
            }
            MouseInputKind::LeftUp => {
                let Some(current) = self.selection else {
                    return Action::Noop;
                };
                if !current.dragging {
                    return Action::Noop;
                }
                let Some(point) = self.mouse_to_selection_point(mouse, true) else {
                    return Action::Noop;
                };
                self.selection = Some(MouseSelection {
                    focus: point,
                    dragging: false,
                    ..current
                });
                self.copy_selection_to_clipboard();
            }
        }

        Action::Noop
    }

    fn mouse_to_selection_point(&self, mouse: MouseInput, clamp: bool) -> Option<SelectionPoint> {
        let max_col = self.pty_cols.saturating_sub(1);
        let max_row = self.pty_rows.saturating_sub(1);

        if !clamp {
            if mouse.row < STATUS_BAR_HEIGHT || mouse.col >= self.pty_cols {
                return None;
            }
            let row = mouse.row - STATUS_BAR_HEIGHT;
            if row >= self.pty_rows {
                return None;
            }
            return Some(SelectionPoint {
                row,
                col: mouse.col,
            });
        }

        let row = mouse.row.saturating_sub(STATUS_BAR_HEIGHT).min(max_row);
        let col = mouse.col.min(max_col);
        Some(SelectionPoint { row, col })
    }

    fn clear_selection(&mut self) {
        self.selection = None;
        self.selection_notice = None;
    }

    fn copy_selection_to_clipboard(&mut self) {
        let Some(selection) = self.selection else {
            return;
        };
        let text = self.extract_selection_text(selection);
        if !text.chars().any(|ch| ch != ' ' && ch != '\n') {
            self.selection_notice = None;
            return;
        }

        match self.clipboard.write_clipboard(text.as_bytes()) {
            Ok(()) => {
                self.selection_notice = Some(SelectionNotice::Copied {
                    chars: text.chars().count(),
                });
            }
            Err(_) => {
                self.selection_notice = Some(SelectionNotice::CopyFailed);
            }
        }
    }

    fn extract_selection_text(&self, selection: MouseSelection) -> String {
        let (start, end) = ordered_selection_points(selection.anchor, selection.focus);
        let screen = self.parser.screen();
        let mut lines = Vec::new();

        for row in start.row..=end.row {
            let start_col = if row == start.row { start.col } else { 0 };
            let end_col = if row == end.row {
                end.col
            } else {
                self.pty_cols.saturating_sub(1)
            };
            let mut line = String::new();
            for col in start_col..=end_col {
                let Some(cell) = screen.cell(row, col) else {
                    line.push(' ');
                    continue;
                };
                if cell.is_wide_continuation() {
                    continue;
                }
                if cell.has_contents() {
                    line.push_str(cell.contents());
                } else {
                    line.push(' ');
                }
            }
            lines.push(line.trim_end_matches(' ').to_string());
        }

        lines.join("\n")
    }

    pub(crate) fn render(&self, area: Rect, buf: &mut Buffer) {
        if area.is_empty() {
            return;
        }

        let status_area = Rect {
            x: area.x,
            y: area.y,
            width: area.width,
            height: STATUS_BAR_HEIGHT,
        };
        self.render_status_bar(status_area, buf);

        let terminal_area = Rect {
            x: area.x,
            y: area.y.saturating_add(STATUS_BAR_HEIGHT),
            width: area.width,
            height: area.height.saturating_sub(STATUS_BAR_HEIGHT),
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
                    .set_style(self.theme.warning_style().bold());
            }
        }

        if let Some(overlay) = &self.overlay {
            self.render_overlay(overlay, area, buf);
        }
    }

    pub(crate) fn cursor_position(&self, area: Rect) -> Option<(u16, u16)> {
        if self.is_terminal() || area.width == 0 || area.height <= STATUS_BAR_HEIGHT {
            return None;
        }

        let screen = self.parser.screen();
        if screen.scrollback() > 0 {
            return None;
        }
        if screen.hide_cursor() {
            return None;
        }

        let (row, col) = screen.cursor_position();
        let terminal_height = area.height.saturating_sub(STATUS_BAR_HEIGHT);
        Some((
            area.x + col.min(area.width.saturating_sub(1)),
            area.y + STATUS_BAR_HEIGHT + row.min(terminal_height.saturating_sub(1)),
        ))
    }

    fn render_status_bar(&self, area: Rect, buf: &mut Buffer) {
        for col in 0..area.width {
            buf[(area.x + col, area.y)]
                .set_char(' ')
                .set_style(self.theme.muted_style().bg(self.theme.selected_bg));
        }

        let (right_text, right_style) = self.status_label();
        let left = self.left_status_text();
        let layout = status_bar_layout(area.width, &left, &right_text);
        for (i, ch) in layout.left_text.chars().enumerate() {
            buf[(area.x + i as u16, area.y)]
                .set_char(ch)
                .set_style(self.theme.text_style().bg(self.theme.selected_bg).bold());
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
                let style = if self.selection_contains_cell(row, col) {
                    self.theme.selected_plain_style()
                } else {
                    vt_style(term_cell)
                };
                let cell = &mut buf[(area.x + col, area.y + row)];
                cell.set_symbol(symbol);
                cell.set_style(style);
            }
        }
    }

    fn selection_contains_cell(&self, row: u16, col: u16) -> bool {
        let Some(selection) = self.selection else {
            return false;
        };
        let (start, end) = ordered_selection_points(selection.anchor, selection.focus);
        if row < start.row || row > end.row {
            return false;
        }
        let start_col = if row == start.row { start.col } else { 0 };
        let end_col = if row == end.row {
            end.col
        } else {
            self.pty_cols.saturating_sub(1)
        };
        col >= start_col && col <= end_col
    }

    fn render_overlay(&self, overlay: &ConnectOverlay, area: Rect, buf: &mut Buffer) {
        match overlay {
            ConnectOverlay::Help => self.render_help_overlay(area, buf),
            ConnectOverlay::CopyPrompt {
                input,
                cursor,
                error,
            } => self.render_copy_prompt(input, *cursor, error.as_deref(), area, buf),
            ConnectOverlay::CopyMessage {
                title,
                message,
                is_error,
                dismissible,
            } => self.render_copy_message(title, message, *is_error, *dismissible, area, buf),
        }
    }

    fn render_help_overlay(&self, area: Rect, buf: &mut Buffer) {
        let modal_area = centered_rect(area, 74, 14);
        Clear.render(modal_area, buf);

        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Connect Session Help ")
            .border_style(self.theme.accent_style().bold());
        let inner = block.inner(modal_area);
        block.render(modal_area, buf);

        let lines = vec![
            Line::from(vec![
                Span::styled("PageUp", self.theme.warning_style().bold()),
                Span::raw("        scroll up one page"),
            ]),
            Line::from(vec![
                Span::styled("PageDown", self.theme.warning_style().bold()),
                Span::raw("      scroll down one page"),
            ]),
            Line::from(vec![
                Span::styled("Shift+Up", self.theme.warning_style().bold()),
                Span::raw("      scroll up one line"),
            ]),
            Line::from(vec![
                Span::styled("Shift+Down", self.theme.warning_style().bold()),
                Span::raw("    scroll down one line"),
            ]),
            Line::from(vec![
                Span::styled("Mouse wheel", self.theme.warning_style().bold()),
                Span::raw("  scrolls local scrollback"),
            ]),
            Line::from(vec![
                Span::styled("Drag mouse", self.theme.warning_style().bold()),
                Span::raw("   select and copy text"),
            ]),
            Line::from(vec![
                Span::styled("End", self.theme.warning_style().bold()),
                Span::raw("           return to live view"),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("F2", self.theme.success_style().bold()),
                Span::raw("            copy remote file to local clipboard"),
            ]),
            Line::from(vec![
                Span::styled("Ctrl+] / Ctrl+5", self.theme.danger_style().bold()),
                Span::raw(" disconnect"),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "Esc / Enter closes this help.",
                self.theme.muted_style(),
            )),
        ];

        Paragraph::new(lines).render(inner, buf);
    }

    fn render_copy_prompt(
        &self,
        input: &str,
        cursor: usize,
        error: Option<&str>,
        area: Rect,
        buf: &mut Buffer,
    ) {
        let modal_area = centered_rect(area, 78, 9);
        Clear.render(modal_area, buf);

        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Copy remote file ")
            .border_style(self.theme.success_style().bold());
        let inner = block.inner(modal_area);
        block.render(modal_area, buf);

        let input_line = copy_prompt_line(input, cursor, self.theme);
        let mut lines = vec![
            Line::from("Remote file path"),
            input_line,
            Line::from(""),
            Line::from(Span::styled(
                "Enter: copy to clipboard  Esc: cancel",
                self.theme.muted_style(),
            )),
        ];
        if let Some(error) = error {
            lines.insert(
                3,
                Line::from(Span::styled(error, self.theme.danger_style())),
            );
        }

        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .render(inner, buf);
    }

    fn render_copy_message(
        &self,
        title: &str,
        message: &str,
        is_error: bool,
        dismissible: bool,
        area: Rect,
        buf: &mut Buffer,
    ) {
        let modal_area = centered_rect(area, 70, 7);
        Clear.render(modal_area, buf);

        let style = if is_error {
            self.theme.danger_style()
        } else {
            self.theme.success_style()
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(style.bold());
        let inner = block.inner(modal_area);
        block.render(modal_area, buf);

        let mut lines = vec![
            Line::from(""),
            Line::from(Span::styled(message, style)),
            Line::from(""),
        ];
        if dismissible {
            lines.push(Line::from(Span::styled(
                "Press Esc or Enter to dismiss.",
                self.theme.muted_style(),
            )));
        }

        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .render(inner, buf);
    }

    fn left_status_text(&self) -> String {
        let instance = instance_label(&self.instance_id, self.instance_name.as_deref());
        let surface = if self.method_label == "ECS" {
            "Canopy ECS"
        } else {
            "Canopy SSH"
        };
        match self.status {
            ConnectSessionStatus::Connecting => format!(
                "{}  Connecting...  {}  {}/{}  [{}]",
                surface, instance, self.account_id, self.region, SESSION_HINTS
            ),
            _ => format!(
                "{}  {}  {}  {}/{}  [{}]",
                surface,
                instance,
                self.method_label.as_str(),
                self.account_id,
                self.region,
                SESSION_HINTS
            ),
        }
    }

    fn status_label(&self) -> (String, Style) {
        match self.status {
            ConnectSessionStatus::Closed => (
                "CLOSED".into(),
                self.theme.muted_style().bg(self.theme.selected_bg).bold(),
            ),
            ConnectSessionStatus::Disconnected => (
                "DISCONNECTED".into(),
                self.theme.warning_style().bg(self.theme.selected_bg).bold(),
            ),
            ConnectSessionStatus::Failed => (
                "FAILED".into(),
                self.theme.danger_style().bg(self.theme.selected_bg).bold(),
            ),
            ConnectSessionStatus::TimedOut => (
                "SESSION EXPIRED".into(),
                self.theme
                    .danger_style()
                    .bg(self.theme.selected_fg)
                    .add_modifier(Modifier::BOLD | Modifier::REVERSED),
            ),
            ConnectSessionStatus::Connecting | ConnectSessionStatus::Connected => {
                let (timer, style) = countdown_status_with_theme(self.remaining_secs(), self.theme);
                let scrollback = self.parser.screen().scrollback();
                let copying = self.copy_capture.is_some();
                let selecting = self.selection.is_some_and(|selection| selection.dragging);
                if selecting {
                    (
                        "SELECTING".into(),
                        self.theme.warning_style().bg(self.theme.selected_bg).bold(),
                    )
                } else if let Some(notice) = self.selection_notice {
                    match notice {
                        SelectionNotice::Copied { chars } => (
                            format!("COPIED {chars} chars"),
                            self.theme.success_style().bg(self.theme.selected_bg).bold(),
                        ),
                        SelectionNotice::CopyFailed => (
                            "COPY FAILED".into(),
                            self.theme.danger_style().bg(self.theme.selected_bg).bold(),
                        ),
                    }
                } else if scrollback > 0 {
                    (format!("SCROLL +{scrollback}  {timer}"), style)
                } else if copying {
                    (format!("COPYING  {timer}"), style)
                } else {
                    (timer, style)
                }
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

    fn key_to_pty_bytes(&self, key: KeyEvent) -> Option<Vec<u8>> {
        key_to_pty_bytes(key, self.parser.screen().application_cursor())
    }

    fn write_to_pty(&self, bytes: &[u8]) -> Result<(), String> {
        match self.writer.lock() {
            Ok(mut writer) => writer
                .write_all(bytes)
                .and_then(|_| writer.flush())
                .map_err(|e| format!("Write to PTY failed: {e}")),
            Err(e) => {
                tracing::error!(error = %e, "PTY writer mutex poisoned");
                Err(format!("PTY writer unavailable: {e}"))
            }
        }
    }

    fn handle_overlay_key(&mut self, key: KeyEvent) -> bool {
        let Some(overlay) = self.overlay.take() else {
            return false;
        };

        match overlay {
            ConnectOverlay::Help => match key.code {
                KeyCode::Esc | KeyCode::Enter => true,
                _ if is_help_key(&key) => true,
                _ => {
                    self.overlay = Some(ConnectOverlay::Help);
                    true
                }
            },
            ConnectOverlay::CopyMessage {
                title,
                message,
                is_error,
                dismissible,
            } => {
                if dismissible && matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
                    true
                } else {
                    self.overlay = Some(ConnectOverlay::CopyMessage {
                        title,
                        message,
                        is_error,
                        dismissible,
                    });
                    true
                }
            }
            ConnectOverlay::CopyPrompt {
                mut input,
                mut cursor,
                error,
            } => match key.code {
                KeyCode::Esc => true,
                KeyCode::Enter => {
                    let path = input.trim().to_string();
                    match validate_copy_path(&path) {
                        Ok(()) => {
                            if let Err(message) = self.start_remote_file_copy(path) {
                                self.overlay = Some(ConnectOverlay::CopyMessage {
                                    title: " Copy remote file ".into(),
                                    message,
                                    is_error: true,
                                    dismissible: true,
                                });
                            }
                            true
                        }
                        Err(message) => {
                            self.overlay = Some(ConnectOverlay::CopyPrompt {
                                input,
                                cursor,
                                error: Some(message),
                            });
                            true
                        }
                    }
                }
                KeyCode::Backspace => {
                    if cursor > 0 {
                        cursor -= 1;
                        let byte_pos = char_to_byte(&input, cursor);
                        input.remove(byte_pos);
                    }
                    self.overlay = Some(ConnectOverlay::CopyPrompt {
                        input,
                        cursor,
                        error,
                    });
                    true
                }
                KeyCode::Delete => {
                    let char_count = input.chars().count();
                    if cursor < char_count {
                        let byte_pos = char_to_byte(&input, cursor);
                        input.remove(byte_pos);
                    }
                    self.overlay = Some(ConnectOverlay::CopyPrompt {
                        input,
                        cursor,
                        error,
                    });
                    true
                }
                KeyCode::Left => {
                    cursor = cursor.saturating_sub(1);
                    self.overlay = Some(ConnectOverlay::CopyPrompt {
                        input,
                        cursor,
                        error,
                    });
                    true
                }
                KeyCode::Right => {
                    cursor = cursor.saturating_add(1).min(input.chars().count());
                    self.overlay = Some(ConnectOverlay::CopyPrompt {
                        input,
                        cursor,
                        error,
                    });
                    true
                }
                KeyCode::Home => {
                    cursor = 0;
                    self.overlay = Some(ConnectOverlay::CopyPrompt {
                        input,
                        cursor,
                        error,
                    });
                    true
                }
                KeyCode::End => {
                    cursor = input.chars().count();
                    self.overlay = Some(ConnectOverlay::CopyPrompt {
                        input,
                        cursor,
                        error,
                    });
                    true
                }
                KeyCode::Char(c)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    let byte_pos = char_to_byte(&input, cursor);
                    input.insert(byte_pos, c);
                    cursor += 1;
                    self.overlay = Some(ConnectOverlay::CopyPrompt {
                        input,
                        cursor,
                        error: None,
                    });
                    true
                }
                _ => {
                    self.overlay = Some(ConnectOverlay::CopyPrompt {
                        input,
                        cursor,
                        error,
                    });
                    true
                }
            },
        }
    }

    fn handle_copy_shortcut(&mut self, key: &KeyEvent) -> bool {
        if !matches!(key.code, KeyCode::F(2)) || self.parser.screen().alternate_screen() {
            return false;
        }

        self.reset_scrollback();
        self.overlay = Some(ConnectOverlay::CopyPrompt {
            input: String::new(),
            cursor: 0,
            error: None,
        });
        true
    }

    fn start_remote_file_copy(&mut self, path: String) -> Result<(), String> {
        let id = Uuid::new_v4().simple().to_string();
        let command = remote_copy_command(&path, &id);
        let write_result = match self.writer.lock() {
            Ok(mut writer) => writer
                .write_all(command.as_bytes())
                .and_then(|_| writer.write_all(b"\r"))
                .and_then(|_| writer.flush()),
            Err(e) => {
                tracing::error!(error = %e, "PTY writer mutex poisoned");
                return Err(format!("PTY writer unavailable: {e}"));
            }
        };
        if let Err(e) = write_result {
            return Err(format!("Write to PTY failed: {e}"));
        }

        self.copy_capture = Some(CopyCapture::new(path.clone(), &id));
        self.overlay = Some(ConnectOverlay::CopyMessage {
            title: " Copy remote file ".into(),
            message: format!("Copying {path}..."),
            is_error: false,
            dismissible: false,
        });
        Ok(())
    }

    fn capture_copy_output(&mut self, bytes: &[u8]) -> Option<Vec<u8>> {
        let Some(capture) = self.copy_capture.as_mut() else {
            return Some(bytes.to_vec());
        };
        capture.buffer.extend_from_slice(bytes);

        if capture.mode == CopyCaptureMode::AwaitMarker {
            let begin = find_bytes(&capture.buffer, &capture.begin_marker);
            let error = find_bytes(&capture.buffer, &capture.error_marker);

            let marker = match (begin, error) {
                (Some(begin), Some(error)) if begin <= error => {
                    Some((begin, capture.begin_marker.len(), CopyCaptureMode::Success))
                }
                (Some(_), Some(error)) => {
                    Some((error, capture.error_marker.len(), CopyCaptureMode::Error))
                }
                (Some(begin), None) => {
                    Some((begin, capture.begin_marker.len(), CopyCaptureMode::Success))
                }
                (None, Some(error)) => {
                    Some((error, capture.error_marker.len(), CopyCaptureMode::Error))
                }
                (None, None) => None,
            };

            if let Some((idx, marker_len, mode)) = marker {
                capture.buffer.drain(..idx + marker_len);
                trim_leading_line_breaks(&mut capture.buffer);
                capture.mode = mode;
            } else {
                if capture.buffer.len() > MAX_COPY_CAPTURE_BYTES {
                    self.finish_copy_error(
                        "Copy output did not contain Canopy markers; aborting copy.".into(),
                    );
                }
                return None;
            }
        }

        let end = find_bytes(&capture.buffer, &capture.end_marker)?;
        let payload = capture.buffer[..end].to_vec();
        let trailing = capture.buffer[end + capture.end_marker.len()..].to_vec();
        let path = capture.path.clone();
        let mode = capture.mode.clone();
        self.copy_capture = None;

        match mode {
            CopyCaptureMode::Success => self.finish_copy_success(&path, &payload),
            CopyCaptureMode::Error => {
                self.finish_copy_error(remote_error_message(&payload, "Remote copy failed"));
            }
            CopyCaptureMode::AwaitMarker => {
                self.finish_copy_error("Remote copy failed before data marker.".into());
            }
        }

        Some(trailing)
    }

    fn finish_copy_success(&mut self, path: &str, payload: &[u8]) {
        match decode_copy_payload(payload).and_then(|bytes| {
            let len = bytes.len();
            self.clipboard.write_clipboard(&bytes).map(|_| len)
        }) {
            Ok(len) => {
                self.overlay = Some(ConnectOverlay::CopyMessage {
                    title: " Copy remote file ".into(),
                    message: format!("Copied {len} bytes from {path} to clipboard."),
                    is_error: false,
                    dismissible: true,
                });
            }
            Err(message) => self.finish_copy_error(message),
        }
    }

    fn finish_copy_error(&mut self, message: String) {
        self.copy_capture = None;
        self.overlay = Some(ConnectOverlay::CopyMessage {
            title: " Copy remote file ".into(),
            message,
            is_error: true,
            dismissible: true,
        });
    }

    fn handle_local_scrollback_key(&mut self, key: &KeyEvent) -> bool {
        if self.parser.screen().alternate_screen() {
            return false;
        }

        let current = self.parser.screen().scrollback();
        let page_rows = self.scroll_page_rows();
        let target = match key.code {
            KeyCode::PageUp => Some(current.saturating_add(page_rows)),
            KeyCode::PageDown if current > 0 => Some(current.saturating_sub(page_rows)),
            KeyCode::End if current > 0 => Some(0),
            KeyCode::Home if key.modifiers.contains(KeyModifiers::SHIFT) => Some(usize::MAX),
            KeyCode::Up if key.modifiers.contains(KeyModifiers::SHIFT) => {
                Some(current.saturating_add(1))
            }
            KeyCode::Down if key.modifiers.contains(KeyModifiers::SHIFT) && current > 0 => {
                Some(current.saturating_sub(1))
            }
            _ => None,
        };

        let Some(target) = target else {
            return false;
        };

        self.clear_selection();
        self.parser.screen_mut().set_scrollback(target);
        true
    }

    fn reset_scrollback(&mut self) {
        self.clear_selection();
        if self.parser.screen().scrollback() > 0 {
            self.parser.screen_mut().set_scrollback(0);
        }
    }

    fn scroll_page_rows(&self) -> usize {
        self.pty_rows
            .saturating_sub(SCROLLBACK_PAGE_OVERLAP_ROWS)
            .max(1) as usize
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

fn ordered_selection_points(
    a: SelectionPoint,
    b: SelectionPoint,
) -> (SelectionPoint, SelectionPoint) {
    if (a.row, a.col) <= (b.row, b.col) {
        (a, b)
    } else {
        (b, a)
    }
}

fn instance_label(instance_id: &str, instance_name: Option<&str>) -> String {
    match instance_name.map(str::trim).filter(|name| !name.is_empty()) {
        Some(name) => format!("{instance_id}  {name}"),
        None => instance_id.to_string(),
    }
}

fn bracketed_paste_bytes(text: &str) -> Vec<u8> {
    let payload = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut bytes = Vec::with_capacity(payload.len() + "\x1b[200~\x1b[201~".len());
    bytes.extend_from_slice(b"\x1b[200~");
    bytes.extend_from_slice(payload.as_bytes());
    bytes.extend_from_slice(b"\x1b[201~");
    bytes
}

fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width.saturating_sub(4)).max(1);
    let height = height.min(area.height.saturating_sub(4)).max(1);
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    }
}

fn copy_prompt_line(input: &str, cursor: usize, theme: Theme) -> Line<'static> {
    let cursor = cursor.min(input.chars().count());
    let byte_split = char_to_byte(input, cursor);
    let (before, after) = input.split_at(byte_split);
    let cursor_char_len = after.chars().next().map(char::len_utf8).unwrap_or(0);

    Line::from(vec![
        Span::raw(before.to_string()),
        Span::styled(
            if cursor_char_len == 0 {
                " ".to_string()
            } else {
                after[..cursor_char_len].to_string()
            },
            theme.cursor_style(),
        ),
        Span::raw(if cursor_char_len < after.len() {
            after[cursor_char_len..].to_string()
        } else {
            String::new()
        }),
    ])
}

fn char_to_byte(value: &str, char_idx: usize) -> usize {
    value
        .char_indices()
        .nth(char_idx)
        .map(|(byte_idx, _)| byte_idx)
        .unwrap_or(value.len())
}

// Keep validation intentionally permissive: shell_single_quote handles shell
// metacharacters, and users may need to copy any readable path on the host.
fn validate_copy_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("Remote file path is required.".into());
    }
    if path.chars().any(char::is_control) {
        return Err("Remote file path cannot contain newlines or control characters.".into());
    }
    Ok(())
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn remote_copy_command(path: &str, id: &str) -> String {
    let path = shell_single_quote(path);
    let id = shell_single_quote(id);
    format!(
        concat!(
            "__canopy_id={id}; ",
            "__canopy_path={path}; ",
            "__canopy_max={max}; ",
            "__canopy_begin=\"__CANOPY_COPY_BEGIN_${{__canopy_id}}__\"; ",
            "__canopy_error=\"__CANOPY_COPY_ERROR_${{__canopy_id}}__\"; ",
            "__canopy_end=\"__CANOPY_COPY_END_${{__canopy_id}}__\"; ",
            "if ! command -v base64 >/dev/null 2>&1; then ",
            "printf '%s\\n%s\\n%s\\n' \"$__canopy_error\" 'base64 command not found on remote host' \"$__canopy_end\"; ",
            "elif ! command -v wc >/dev/null 2>&1; then ",
            "printf '%s\\n%s\\n%s\\n' \"$__canopy_error\" 'wc command not found on remote host' \"$__canopy_end\"; ",
            "elif [ ! -f \"$__canopy_path\" ]; then ",
            "printf '%s\\n%s\\n%s\\n' \"$__canopy_error\" 'not a regular file' \"$__canopy_end\"; ",
            "elif [ ! -r \"$__canopy_path\" ]; then ",
            "printf '%s\\n%s\\n%s\\n' \"$__canopy_error\" 'file is not readable' \"$__canopy_end\"; ",
            "else ",
            "__canopy_size=$(wc -c < \"$__canopy_path\" 2>/dev/null | tr -d '[:space:]'); ",
            "if [ -z \"$__canopy_size\" ]; then ",
            "printf '%s\\n%s\\n%s\\n' \"$__canopy_error\" 'unable to determine file size' \"$__canopy_end\"; ",
            "elif [ \"$__canopy_size\" -gt \"$__canopy_max\" ]; then ",
            "printf '%s\\n%s\\n%s\\n' \"$__canopy_error\" \"file is too large ($__canopy_size bytes, max $__canopy_max)\" \"$__canopy_end\"; ",
            "else ",
            "printf '%s\\n' \"$__canopy_begin\"; ",
            "base64 < \"$__canopy_path\"; ",
            "printf '\\n%s\\n' \"$__canopy_end\"; ",
            "fi; ",
            "fi; ",
            "unset __canopy_id __canopy_path __canopy_max __canopy_begin __canopy_error __canopy_end __canopy_size"
        ),
        id = id,
        path = path,
        max = MAX_COPY_FILE_BYTES
    )
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn trim_leading_line_breaks(bytes: &mut Vec<u8>) {
    let trim = bytes
        .iter()
        .take_while(|byte| matches!(byte, b'\r' | b'\n'))
        .count();
    if trim > 0 {
        bytes.drain(..trim);
    }
}

fn trim_line_breaks(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !matches!(byte, b'\r' | b'\n'))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !matches!(byte, b'\r' | b'\n'))
        .map(|idx| idx + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

fn remote_error_message(payload: &[u8], fallback: &str) -> String {
    let message = String::from_utf8_lossy(trim_line_breaks(payload))
        .trim()
        .to_string();
    if message.is_empty() {
        fallback.into()
    } else {
        message
    }
}

fn decode_copy_payload(payload: &[u8]) -> Result<Vec<u8>, String> {
    let encoded: Vec<u8> = payload
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("Failed to decode copied file payload: {e}"))
}

fn write_system_clipboard(bytes: &[u8]) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        write_to_clipboard_command("pbcopy", &[], bytes).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "pbcopy was not found; cannot write to clipboard.".into()
            } else {
                format!("pbcopy failed: {e}")
            }
        })
    }

    #[cfg(target_os = "linux")]
    {
        let candidates: &[(&str, &[&str])] = &[
            ("wl-copy", &[]),
            ("xclip", &["-selection", "clipboard"]),
            ("xsel", &["--clipboard", "--input"]),
        ];
        let mut saw_command = false;
        let mut last_error = None;
        for (program, args) in candidates {
            match write_to_clipboard_command(program, args, bytes) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    saw_command = true;
                    last_error = Some(format!("{program} failed: {e}"));
                }
            }
        }
        if saw_command {
            Err(last_error.unwrap_or_else(|| "Clipboard command failed.".into()))
        } else {
            Err("No clipboard command found. Install wl-copy, xclip, or xsel.".into())
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = bytes;
        Err("Clipboard copy is only supported on macOS and Linux.".into())
    }
}

fn write_to_clipboard_command(program: &str, args: &[&str], bytes: &[u8]) -> std::io::Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(bytes)?;
    }
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "{program} exited with status {status}"
        )))
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
    countdown_status_with_theme(remaining_secs, Theme::default())
}

fn countdown_status_with_theme(remaining_secs: u64, theme: Theme) -> (String, Style) {
    if remaining_secs == 0 {
        return (
            "SESSION EXPIRED".into(),
            theme
                .danger_style()
                .bg(theme.selected_fg)
                .add_modifier(Modifier::BOLD | Modifier::REVERSED),
        );
    }

    let (prefix, style, critical) = if remaining_secs <= 60 {
        ("!", theme.danger_style(), true)
    } else if remaining_secs <= 5 * 60 {
        ("!", theme.danger_style(), false)
    } else if remaining_secs <= 15 * 60 {
        ("▲", theme.warning_style(), false)
    } else {
        ("●", theme.accent_style(), false)
    };

    let mut style = style.bg(theme.selected_bg).add_modifier(Modifier::BOLD);
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

fn is_help_key(key: &KeyEvent) -> bool {
    matches!(key.code, KeyCode::Char('h') | KeyCode::Char('H'))
        && key.modifiers.contains(KeyModifiers::CONTROL)
}

fn key_to_pty_bytes(key: KeyEvent, application_cursor: bool) -> Option<Vec<u8>> {
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
        KeyCode::Up => bytes.extend_from_slice(if application_cursor {
            b"\x1bOA"
        } else {
            b"\x1b[A"
        }),
        KeyCode::Down => bytes.extend_from_slice(if application_cursor {
            b"\x1bOB"
        } else {
            b"\x1b[B"
        }),
        KeyCode::Right => bytes.extend_from_slice(if application_cursor {
            b"\x1bOC"
        } else {
            b"\x1b[C"
        }),
        KeyCode::Left => bytes.extend_from_slice(if application_cursor {
            b"\x1bOD"
        } else {
            b"\x1b[D"
        }),
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
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct FakeClipboard {
        bytes: Mutex<Vec<u8>>,
        error: Mutex<Option<String>>,
    }

    impl ClipboardWriter for FakeClipboard {
        fn write_clipboard(&self, bytes: &[u8]) -> Result<(), String> {
            if let Some(error) = self.error.lock().expect("fake clipboard lock").clone() {
                return Err(error);
            }
            *self.bytes.lock().expect("fake clipboard lock") = bytes.to_vec();
            Ok(())
        }
    }

    #[cfg(unix)]
    fn spawn_sleeping_session() -> ConnectSessionScreen {
        spawn_test_session(vec!["-c".into(), "sleep 30".into()])
    }

    #[cfg(unix)]
    fn spawn_test_session(args: Vec<String>) -> ConnectSessionScreen {
        spawn_test_session_with_method(args, "SSH")
    }

    #[cfg(unix)]
    fn spawn_test_session_with_method(
        args: Vec<String>,
        method_label: &str,
    ) -> ConnectSessionScreen {
        let (tx, _rx) = mpsc::unbounded_channel();
        ConnectSessionScreen::spawn(
            ConnectSessionLaunch {
                instance_id: "i-0123456789abcdef0".into(),
                instance_name: Some("web-prod-01".into()),
                account_id: "123456789012".into(),
                region: "ap-northeast-1".into(),
                method_label: method_label.into(),
                spawn: PtySpawnSpec {
                    command: "/bin/sh".into(),
                    args,
                    env_vars: std::collections::HashMap::new(),
                    max_session_seconds: Some(3600),
                },
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

    #[cfg(unix)]
    fn feed_scrollback_lines(session: &mut ConnectSessionScreen, count: usize) {
        let mut output = String::new();
        for i in 0..count {
            output.push_str(&format!("line-{i}\r\n"));
        }
        session.process_output(output.as_bytes());
    }

    #[cfg(unix)]
    fn feed_enough_scrollback_lines(session: &mut ConnectSessionScreen) {
        feed_scrollback_lines(session, usize::from(session.pty_rows) * 4);
        session.parser.screen_mut().set_scrollback(usize::MAX);
        assert!(session.parser.screen().scrollback() > 0);
        session.parser.screen_mut().set_scrollback(0);
    }

    fn mouse(kind: MouseInputKind, col: u16, row: u16) -> MouseInput {
        MouseInput { kind, col, row }
    }

    fn buffer_text(buf: &Buffer, area: Rect) -> String {
        let mut lines = Vec::new();
        for row in area.y..area.y.saturating_add(area.height) {
            let mut line = String::new();
            for col in area.x..area.x.saturating_add(area.width) {
                line.push_str(buf[(col, row)].symbol());
            }
            lines.push(line.trim_end().to_string());
        }
        lines.join("\n")
    }

    #[cfg(unix)]
    fn visible_screen_row_text(session: &ConnectSessionScreen, row: u16) -> String {
        let screen = session.parser.screen();
        let mut line = String::new();
        for col in 0..session.pty_cols {
            let Some(cell) = screen.cell(row, col) else {
                line.push(' ');
                continue;
            };
            if cell.is_wide_continuation() {
                continue;
            }
            if cell.has_contents() {
                line.push_str(cell.contents());
            } else {
                line.push(' ');
            }
        }
        line.trim_end_matches(' ').to_string()
    }

    #[cfg(unix)]
    #[test]
    fn left_status_text_uses_ecs_surface_for_ecs_method() {
        let session = spawn_test_session_with_method(vec!["-c".into(), "sleep 30".into()], "ECS");

        let text = session.left_status_text();

        assert!(text.contains("Canopy ECS"));
        assert!(!text.contains("Canopy SSH"));
        cleanup_session(session);
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
            key_to_pty_bytes(
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
                false
            ),
            Some(vec![3])
        );
        assert_eq!(
            key_to_pty_bytes(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), false),
            Some(vec![b'\r'])
        );
        assert_eq!(
            key_to_pty_bytes(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE), false),
            Some(b"\x1b[A".to_vec())
        );
        assert_eq!(
            key_to_pty_bytes(
                KeyEvent::new(KeyCode::Char('\\'), KeyModifiers::CONTROL),
                false
            ),
            Some(vec![0x1c])
        );
        assert_eq!(
            key_to_pty_bytes(
                KeyEvent::new(KeyCode::Char('_'), KeyModifiers::CONTROL),
                false
            ),
            Some(vec![0x1f])
        );
        assert_eq!(
            key_to_pty_bytes(
                KeyEvent::new(KeyCode::Char('3'), KeyModifiers::CONTROL),
                false
            ),
            Some(vec![0x1b])
        );
        assert_eq!(
            key_to_pty_bytes(
                KeyEvent::new(KeyCode::Char('8'), KeyModifiers::CONTROL),
                false
            ),
            Some(vec![0x7f])
        );
    }

    #[test]
    fn key_mapping_uses_application_cursor_mode_for_arrows() {
        assert_eq!(
            key_to_pty_bytes(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE), true),
            Some(b"\x1bOA".to_vec())
        );
        assert_eq!(
            key_to_pty_bytes(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE), true),
            Some(b"\x1bOB".to_vec())
        );
        assert_eq!(
            key_to_pty_bytes(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE), true),
            Some(b"\x1bOC".to_vec())
        );
        assert_eq!(
            key_to_pty_bytes(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE), true),
            Some(b"\x1bOD".to_vec())
        );
    }

    #[test]
    fn key_mapping_uses_normal_cursor_mode_for_arrows() {
        assert_eq!(
            key_to_pty_bytes(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE), false),
            Some(b"\x1b[A".to_vec())
        );
        assert_eq!(
            key_to_pty_bytes(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE), false),
            Some(b"\x1b[B".to_vec())
        );
        assert_eq!(
            key_to_pty_bytes(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE), false),
            Some(b"\x1b[C".to_vec())
        );
        assert_eq!(
            key_to_pty_bytes(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE), false),
            Some(b"\x1b[D".to_vec())
        );
    }

    #[test]
    fn terminal_response_callbacks_reply_to_cursor_position_report() {
        let mut parser =
            vt100::Parser::new_with_callbacks(24, 80, 1000, TerminalResponseCallbacks::default());

        parser.process(b"abc\x1b[6n");

        assert_eq!(
            parser.callbacks_mut().take_responses(),
            b"\x1b[1;4R".to_vec()
        );
    }

    #[test]
    fn terminal_response_callbacks_reply_to_device_status_and_attributes() {
        let mut parser =
            vt100::Parser::new_with_callbacks(24, 80, 1000, TerminalResponseCallbacks::default());

        parser.process(b"\x1b[5n\x1b[c\x1b[>c");

        assert_eq!(
            parser.callbacks_mut().take_responses(),
            b"\x1b[0n\x1b[?1;2c\x1b[>0;0;0c".to_vec()
        );
    }

    #[test]
    fn local_disconnect_key_is_not_forwarded() {
        let key = KeyEvent::new(KeyCode::Char(']'), KeyModifiers::CONTROL);
        assert!(is_local_disconnect_key(&key));
        assert_eq!(key_to_pty_bytes(key, false), None);

        let key = KeyEvent::new(KeyCode::Char('5'), KeyModifiers::CONTROL);
        assert!(is_local_disconnect_key(&key));
        assert_eq!(key_to_pty_bytes(key, false), None);

        let key = KeyEvent::new(KeyCode::Char('\u{1d}'), KeyModifiers::NONE);
        assert!(is_local_disconnect_key(&key));
        assert_eq!(key_to_pty_bytes(key, true), None);
    }

    #[test]
    fn paste_payload_is_forwarded_with_bracketed_paste_markers() {
        assert_eq!(
            bracketed_paste_bytes("echo one\nls\r\npwd"),
            b"\x1b[200~echo one\nls\npwd\x1b[201~".to_vec()
        );
    }

    #[cfg(unix)]
    #[test]
    fn ctrl_h_toggles_help_overlay_and_dismisses() {
        let mut session = spawn_sleeping_session();
        let action = session.handle_key(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::CONTROL));
        assert!(matches!(action, Action::Noop));
        assert!(matches!(session.overlay, Some(ConnectOverlay::Help)));

        let action = session.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(action, Action::Noop));
        assert!(session.overlay.is_none());
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn f2_opens_copy_prompt_outside_alternate_screen() {
        let mut session = spawn_sleeping_session();
        let action = session.handle_key(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE));

        assert!(matches!(action, Action::Noop));
        assert!(matches!(
            session.overlay,
            Some(ConnectOverlay::CopyPrompt { .. })
        ));
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn f2_is_not_intercepted_in_alternate_screen() {
        let mut session = spawn_sleeping_session();
        session.process_output(b"\x1b[?1049h");
        assert!(session.parser.screen().alternate_screen());

        assert!(!session.handle_copy_shortcut(&KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE)));
        assert!(session.overlay.is_none());
        cleanup_session(session);
    }

    #[test]
    fn copy_path_validation_rejects_empty_and_control_chars() {
        assert!(validate_copy_path("").is_err());
        assert!(validate_copy_path("/tmp/a\nb").is_err());
        assert!(validate_copy_path("/tmp/app.log").is_ok());
    }

    #[test]
    fn shell_quote_and_remote_command_do_not_expose_full_markers() {
        assert_eq!(shell_single_quote("/tmp/a'b"), "'/tmp/a'\\''b'");

        let cmd = remote_copy_command("/tmp/a'b", "abc123");
        assert!(cmd.contains("__canopy_id='abc123'"));
        assert!(cmd.contains("__canopy_path='/tmp/a'\\''b'"));
        assert!(cmd.contains("base64 < \"$__canopy_path\""));
        assert!(cmd.contains(&MAX_COPY_FILE_BYTES.to_string()));
        assert!(!cmd.contains("__CANOPY_COPY_BEGIN_abc123__"));
        assert!(!cmd.contains("__CANOPY_COPY_END_abc123__"));
    }

    #[test]
    fn remote_copy_command_shell_escapes_metacharacters() {
        let path = "/tmp/foo'; rm -rf /; echo '";
        let quoted = shell_single_quote(path);
        let cmd = remote_copy_command(path, "copyid");

        assert!(validate_copy_path(path).is_ok());
        assert!(cmd.contains(&format!("__canopy_path={quoted};")));
        assert!(!cmd.contains("__canopy_path='/tmp/foo'; rm -rf /; echo '';"));
        assert!(cmd.contains("command -v wc"));
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
    fn cursor_position_tracks_remote_cursor_with_status_bar_offset() {
        let mut session = spawn_sleeping_session();
        session.process_output(b"abc");
        assert_eq!(
            session.cursor_position(Rect::new(10, 5, 40, 12)),
            Some((13, 6))
        );
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn cursor_position_respects_remote_hide_cursor_mode() {
        let mut session = spawn_sleeping_session();
        session.process_output(b"\x1b[?25l");
        assert_eq!(session.cursor_position(Rect::new(0, 0, 40, 12)), None);
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn cursor_position_is_hidden_for_terminal_sessions_or_empty_area() {
        let mut session = spawn_sleeping_session();
        assert_eq!(session.cursor_position(Rect::new(0, 0, 0, 12)), None);
        assert_eq!(session.cursor_position(Rect::new(0, 0, 40, 1)), None);

        session.disconnect();
        assert_eq!(session.cursor_position(Rect::new(0, 0, 40, 12)), None);
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn cursor_position_clamps_to_terminal_area() {
        let mut session = spawn_sleeping_session();
        session.process_output(b"\x1b[999;999H");
        assert_eq!(
            session.cursor_position(Rect::new(10, 5, 20, 6)),
            Some((29, 10))
        );
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn page_keys_scroll_local_scrollback() {
        let mut session = spawn_sleeping_session();
        feed_enough_scrollback_lines(&mut session);

        assert_eq!(session.parser.screen().scrollback(), 0);
        assert!(matches!(
            session.handle_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE)),
            Action::Noop
        ));
        assert!(session.parser.screen().scrollback() > 0);

        assert!(matches!(
            session.handle_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE)),
            Action::Noop
        ));
        assert_eq!(session.parser.screen().scrollback(), 0);
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn mouse_wheel_scrolls_local_scrollback_only() {
        let mut session = spawn_sleeping_session();
        feed_enough_scrollback_lines(&mut session);

        assert_eq!(session.parser.screen().scrollback(), 0);
        assert!(matches!(
            session.handle_mouse_scroll(MouseScrollDirection::Up),
            Action::Noop
        ));
        assert_eq!(session.parser.screen().scrollback(), 1);

        assert!(matches!(
            session.handle_mouse_scroll(MouseScrollDirection::Down),
            Action::Noop
        ));
        assert_eq!(session.parser.screen().scrollback(), 0);
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn mouse_wheel_does_not_scroll_local_buffer_in_alternate_screen() {
        let mut session = spawn_sleeping_session();
        feed_enough_scrollback_lines(&mut session);
        session.process_output(b"\x1b[?1049h");
        assert!(session.parser.screen().alternate_screen());
        let before = session.parser.screen().scrollback();

        assert!(matches!(
            session.handle_mouse_scroll(MouseScrollDirection::Up),
            Action::Noop
        ));
        assert_eq!(session.parser.screen().scrollback(), before);
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn mouse_wheel_is_noop_during_drag_and_resumes_after_mouse_up() {
        let mut session = spawn_sleeping_session();
        let clipboard = Arc::new(FakeClipboard::default());
        session.clipboard = clipboard;
        feed_enough_scrollback_lines(&mut session);

        assert_eq!(session.parser.screen().scrollback(), 0);
        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 0, STATUS_BAR_HEIGHT));
        assert!(session
            .selection
            .is_some_and(|selection| selection.dragging));

        assert!(matches!(
            session.handle_mouse_scroll(MouseScrollDirection::Up),
            Action::Noop
        ));
        assert_eq!(session.parser.screen().scrollback(), 0);
        assert!(session
            .selection
            .is_some_and(|selection| selection.dragging));

        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftUp, 0, STATUS_BAR_HEIGHT));
        assert!(session
            .selection
            .is_some_and(|selection| !selection.dragging));

        assert!(matches!(
            session.handle_mouse_scroll(MouseScrollDirection::Up),
            Action::Noop
        ));
        assert_eq!(session.parser.screen().scrollback(), 1);
        assert!(session.selection.is_none());
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn alternate_screen_allows_visible_mouse_selection() {
        let mut session = spawn_sleeping_session();
        let clipboard = Arc::new(FakeClipboard::default());
        session.clipboard = clipboard.clone();
        session.process_output(b"\x1b[?1049hALT-VISIBLE");
        assert!(session.parser.screen().alternate_screen());

        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 0, STATUS_BAR_HEIGHT));
        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftUp, 10, STATUS_BAR_HEIGHT));

        assert_eq!(
            clipboard.bytes.lock().expect("lock").as_slice(),
            b"ALT-VISIBLE"
        );
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn mouse_selection_reads_current_scrollback_view() {
        let mut session = spawn_sleeping_session();
        let clipboard = Arc::new(FakeClipboard::default());
        session.clipboard = clipboard.clone();
        feed_scrollback_lines(&mut session, 80);
        session.parser.screen_mut().set_scrollback(10);

        let expected = visible_screen_row_text(&session, 0);
        assert!(expected.starts_with("line-"));
        let end_col = expected.chars().count().saturating_sub(1) as u16;

        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 0, STATUS_BAR_HEIGHT));
        let _ =
            session.handle_mouse_input(mouse(MouseInputKind::LeftUp, end_col, STATUS_BAR_HEIGHT));

        assert_eq!(
            String::from_utf8(clipboard.bytes.lock().expect("lock").clone()).unwrap(),
            expected
        );
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn end_key_returning_to_live_view_clears_mouse_selection() {
        let mut session = spawn_sleeping_session();
        feed_enough_scrollback_lines(&mut session);
        session.parser.screen_mut().set_scrollback(1);

        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 0, STATUS_BAR_HEIGHT));
        assert!(session.selection.is_some());
        assert!(session.parser.screen().scrollback() > 0);

        assert!(matches!(
            session.handle_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE)),
            Action::Noop
        ));
        assert_eq!(session.parser.screen().scrollback(), 0);
        assert!(session.selection.is_none());
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn mouse_input_tracks_selection_lifecycle() {
        let mut session = spawn_sleeping_session();

        assert!(matches!(
            session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 3, STATUS_BAR_HEIGHT)),
            Action::Noop
        ));
        let selection = session.selection.expect("selection starts on left down");
        assert_eq!(selection.anchor, SelectionPoint { row: 0, col: 3 });
        assert_eq!(selection.focus, SelectionPoint { row: 0, col: 3 });
        assert!(selection.dragging);

        assert!(matches!(
            session.handle_mouse_input(mouse(MouseInputKind::LeftDrag, 5, STATUS_BAR_HEIGHT + 2)),
            Action::Noop
        ));
        let selection = session.selection.expect("selection updates on drag");
        assert_eq!(selection.anchor, SelectionPoint { row: 0, col: 3 });
        assert_eq!(selection.focus, SelectionPoint { row: 2, col: 5 });
        assert!(selection.dragging);

        assert!(matches!(
            session.handle_mouse_input(mouse(MouseInputKind::LeftUp, 7, STATUS_BAR_HEIGHT + 3)),
            Action::Noop
        ));
        let selection = session.selection.expect("selection finishes on left up");
        assert_eq!(selection.anchor, SelectionPoint { row: 0, col: 3 });
        assert_eq!(selection.focus, SelectionPoint { row: 3, col: 7 });
        assert!(!selection.dragging);
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn mouse_input_starts_only_inside_terminal_area_and_clamps_drag() {
        let mut session = spawn_sleeping_session();

        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 0, 0));
        assert!(session.selection.is_none());
        let _ = session.handle_mouse_input(mouse(
            MouseInputKind::LeftDown,
            session.pty_cols,
            STATUS_BAR_HEIGHT,
        ));
        assert!(session.selection.is_none());

        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 1, STATUS_BAR_HEIGHT));
        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDrag, u16::MAX, u16::MAX));
        let selection = session.selection.expect("drag clamps existing selection");
        assert_eq!(
            selection.focus,
            SelectionPoint {
                row: session.pty_rows - 1,
                col: session.pty_cols - 1,
            }
        );

        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftUp, 0, 0));
        let selection = session.selection.expect("left up clamps above terminal");
        assert_eq!(selection.focus, SelectionPoint { row: 0, col: 0 });
        assert!(!selection.dragging);
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn mouse_input_is_noop_when_session_cannot_select() {
        let mut session = spawn_sleeping_session();

        session.overlay = Some(ConnectOverlay::Help);
        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 1, STATUS_BAR_HEIGHT));
        assert!(session.selection.is_none());

        session.overlay = None;
        session.copy_capture = Some(CopyCapture::new("/tmp/app.log".into(), "copyid"));
        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 1, STATUS_BAR_HEIGHT));
        assert!(session.selection.is_none());

        session.copy_capture = None;
        session.disconnect();
        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 1, STATUS_BAR_HEIGHT));
        assert!(session.selection.is_none());
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn key_paste_output_scrollback_and_resize_clear_selection() {
        let mut session = spawn_sleeping_session();

        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 1, STATUS_BAR_HEIGHT));
        assert!(session.selection.is_some());
        let _ = session.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
        assert!(session.selection.is_none());

        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 1, STATUS_BAR_HEIGHT));
        assert!(session.selection.is_some());
        let _ = session.handle_paste("hello");
        assert!(session.selection.is_none());

        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 1, STATUS_BAR_HEIGHT));
        assert!(session.selection.is_some());
        session.process_output(b"remote output");
        assert!(session.selection.is_none());

        feed_enough_scrollback_lines(&mut session);
        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 1, STATUS_BAR_HEIGHT));
        assert!(session.selection.is_some());
        let _ = session.handle_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
        assert!(session.selection.is_none());

        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 1, STATUS_BAR_HEIGHT));
        assert!(session.selection.is_some());
        session.resize(100, 40);
        assert!(session.selection.is_none());
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn mouse_selection_copies_single_line_text_to_clipboard() {
        let mut session = spawn_sleeping_session();
        let clipboard = Arc::new(FakeClipboard::default());
        session.clipboard = clipboard.clone();
        session.process_output(b"abcdef");

        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 1, STATUS_BAR_HEIGHT));
        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftUp, 3, STATUS_BAR_HEIGHT));

        assert_eq!(clipboard.bytes.lock().expect("lock").as_slice(), b"bcd");
        assert_eq!(
            session.selection_notice,
            Some(SelectionNotice::Copied { chars: 3 })
        );
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn mouse_selection_copies_reverse_multiline_text() {
        let mut session = spawn_sleeping_session();
        let clipboard = Arc::new(FakeClipboard::default());
        session.clipboard = clipboard.clone();
        session.process_output(b"abcde\r\n12345");

        let _ =
            session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 3, STATUS_BAR_HEIGHT + 1));
        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftUp, 1, STATUS_BAR_HEIGHT));

        assert_eq!(
            clipboard.bytes.lock().expect("lock").as_slice(),
            b"bcde\n1234"
        );
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn mouse_selection_copies_wide_characters_once() {
        let mut session = spawn_sleeping_session();
        let clipboard = Arc::new(FakeClipboard::default());
        session.clipboard = clipboard.clone();
        session.process_output("a中b".as_bytes());

        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 0, STATUS_BAR_HEIGHT));
        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftUp, 3, STATUS_BAR_HEIGHT));

        assert_eq!(
            String::from_utf8(clipboard.bytes.lock().expect("lock").clone()).unwrap(),
            "a中b"
        );
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn mouse_selection_preserves_middle_spaces_and_trims_line_end() {
        let mut session = spawn_sleeping_session();
        let clipboard = Arc::new(FakeClipboard::default());
        session.clipboard = clipboard.clone();
        session.process_output(b"a  b   ");

        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 0, STATUS_BAR_HEIGHT));
        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftUp, 6, STATUS_BAR_HEIGHT));

        assert_eq!(clipboard.bytes.lock().expect("lock").as_slice(), b"a  b");
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn blank_mouse_selection_does_not_overwrite_clipboard() {
        let mut session = spawn_sleeping_session();
        let clipboard = Arc::new(FakeClipboard::default());
        *clipboard.bytes.lock().expect("lock") = b"previous".to_vec();
        session.clipboard = clipboard.clone();

        let _ =
            session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 5, STATUS_BAR_HEIGHT + 5));
        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftUp, 8, STATUS_BAR_HEIGHT + 5));

        assert_eq!(
            clipboard.bytes.lock().expect("lock").as_slice(),
            b"previous"
        );
        assert_eq!(session.selection_notice, None);
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn mouse_selection_reports_clipboard_failure_without_overwriting() {
        let mut session = spawn_sleeping_session();
        let clipboard = Arc::new(FakeClipboard::default());
        *clipboard.bytes.lock().expect("lock") = b"previous".to_vec();
        *clipboard.error.lock().expect("lock") = Some("clipboard denied".into());
        session.clipboard = clipboard.clone();
        session.process_output(b"abc");

        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 0, STATUS_BAR_HEIGHT));
        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftUp, 2, STATUS_BAR_HEIGHT));

        assert_eq!(
            clipboard.bytes.lock().expect("lock").as_slice(),
            b"previous"
        );
        assert_eq!(session.selection_notice, Some(SelectionNotice::CopyFailed));
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn later_mouse_selection_overwrites_previous_clipboard_text() {
        let mut session = spawn_sleeping_session();
        let clipboard = Arc::new(FakeClipboard::default());
        session.clipboard = clipboard.clone();
        session.process_output(b"abcdef");

        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 0, STATUS_BAR_HEIGHT));
        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftUp, 0, STATUS_BAR_HEIGHT));
        assert_eq!(clipboard.bytes.lock().expect("lock").as_slice(), b"a");

        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 3, STATUS_BAR_HEIGHT));
        assert_eq!(session.selection_notice, None);
        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftUp, 5, STATUS_BAR_HEIGHT));
        assert_eq!(clipboard.bytes.lock().expect("lock").as_slice(), b"def");
        assert_eq!(
            session.selection_notice,
            Some(SelectionNotice::Copied { chars: 3 })
        );
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn render_terminal_applies_selection_style_without_clearing_text() {
        let mut session = spawn_sleeping_session();
        let clipboard = Arc::new(FakeClipboard::default());
        session.clipboard = clipboard;
        session.process_output(b"abcdef");

        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 1, STATUS_BAR_HEIGHT));
        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftUp, 3, STATUS_BAR_HEIGHT));

        let theme = session.theme;
        let area = Rect::new(0, 0, 80, 24);
        let mut buf = Buffer::empty(area);
        session.render(area, &mut buf);

        let selected = &buf[(1, STATUS_BAR_HEIGHT)];
        assert_eq!(selected.symbol(), "b");
        assert_eq!(selected.fg, theme.selected_fg);
        assert_eq!(selected.bg, theme.selected_bg);
        assert!(selected.modifier.contains(Modifier::BOLD));

        let unselected = &buf[(0, STATUS_BAR_HEIGHT)];
        assert_eq!(unselected.symbol(), "a");
        assert_ne!(unselected.bg, theme.selected_bg);
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn render_terminal_skips_wide_continuation_selection_highlight() {
        let mut session = spawn_sleeping_session();
        let clipboard = Arc::new(FakeClipboard::default());
        session.clipboard = clipboard;
        session.process_output("a中b".as_bytes());

        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 0, STATUS_BAR_HEIGHT));
        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftUp, 3, STATUS_BAR_HEIGHT));

        let theme = session.theme;
        let area = Rect::new(0, 0, 80, 24);
        let mut buf = Buffer::empty(area);
        session.render(area, &mut buf);

        let wide_lead = &buf[(1, STATUS_BAR_HEIGHT)];
        assert_eq!(wide_lead.symbol(), "中");
        assert_eq!(wide_lead.bg, theme.selected_bg);

        let wide_continuation = &buf[(2, STATUS_BAR_HEIGHT)];
        assert_eq!(wide_continuation.symbol(), " ");
        assert_ne!(wide_continuation.bg, theme.selected_bg);

        let after_wide = &buf[(3, STATUS_BAR_HEIGHT)];
        assert_eq!(after_wide.symbol(), "b");
        assert_eq!(after_wide.bg, theme.selected_bg);
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn status_label_reports_mouse_selection_copy_and_failure() {
        let mut session = spawn_sleeping_session();
        let clipboard = Arc::new(FakeClipboard::default());
        session.clipboard = clipboard.clone();
        session.process_output(b"abc");

        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 0, STATUS_BAR_HEIGHT));
        assert_eq!(session.status_label().0, "SELECTING");

        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftUp, 0, STATUS_BAR_HEIGHT));
        assert_eq!(session.status_label().0, "COPIED 1 chars");

        *clipboard.error.lock().expect("lock") = Some("clipboard denied".into());
        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftDown, 1, STATUS_BAR_HEIGHT));
        assert_eq!(session.status_label().0, "SELECTING");
        let _ = session.handle_mouse_input(mouse(MouseInputKind::LeftUp, 2, STATUS_BAR_HEIGHT));
        assert_eq!(session.status_label().0, "COPY FAILED");
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn help_overlay_includes_mouse_selection_hint() {
        let mut session = spawn_sleeping_session();
        session.overlay = Some(ConnectOverlay::Help);

        let area = Rect::new(0, 0, 100, 30);
        let mut buf = Buffer::empty(area);
        session.render(area, &mut buf);
        let text = buffer_text(&buf, area);

        assert!(text.contains("Drag mouse"));
        assert!(text.contains("select and copy text"));
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn typing_while_scrolled_returns_to_live_view() {
        let mut session = spawn_sleeping_session();
        feed_enough_scrollback_lines(&mut session);
        let _ = session.handle_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
        assert!(session.parser.screen().scrollback() > 0);

        let _ = session.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
        assert_eq!(session.parser.screen().scrollback(), 0);
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn cursor_is_hidden_while_scrolled_back() {
        let mut session = spawn_sleeping_session();
        feed_enough_scrollback_lines(&mut session);
        let _ = session.handle_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));

        assert_eq!(session.cursor_position(Rect::new(0, 0, 80, 24)), None);
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn copy_marker_success_writes_clipboard_and_hides_payload_from_terminal() {
        let mut session = spawn_sleeping_session();
        let clipboard = Arc::new(FakeClipboard::default());
        session.clipboard = clipboard.clone();
        session.copy_capture = Some(CopyCapture::new("/tmp/app.log".into(), "copyid"));

        let encoded = general_purpose::STANDARD.encode("hello from remote");
        let output = format!(
            "echoed command\r\n__CANOPY_COPY_BEGIN_copyid__\r\n{encoded}\r\n__CANOPY_COPY_END_copyid__\r\nPROMPT> "
        );
        session.process_output(output.as_bytes());

        assert_eq!(
            clipboard
                .bytes
                .lock()
                .expect("fake clipboard lock")
                .as_slice(),
            b"hello from remote"
        );
        assert!(matches!(
            session.overlay,
            Some(ConnectOverlay::CopyMessage {
                is_error: false,
                dismissible: true,
                ..
            })
        ));
        let contents = session.parser.screen().contents();
        assert!(contents.contains("PROMPT"));
        assert!(!contents.contains(&encoded));
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn copy_marker_error_shows_message_and_does_not_write_clipboard() {
        let mut session = spawn_sleeping_session();
        let clipboard = Arc::new(FakeClipboard::default());
        session.clipboard = clipboard.clone();
        session.copy_capture = Some(CopyCapture::new("/tmp/missing.log".into(), "copyid"));

        session.process_output(
            b"__CANOPY_COPY_ERROR_copyid__\r\nnot a regular file\r\n__CANOPY_COPY_END_copyid__\r\n",
        );

        assert!(clipboard
            .bytes
            .lock()
            .expect("fake clipboard lock")
            .is_empty());
        assert!(matches!(
            session.overlay,
            Some(ConnectOverlay::CopyMessage {
                is_error: true,
                dismissible: true,
                ..
            })
        ));
        match &session.overlay {
            Some(ConnectOverlay::CopyMessage { message, .. }) => {
                assert!(message.contains("not a regular file"));
            }
            _ => panic!("expected copy message overlay"),
        }
        cleanup_session(session);
    }

    // ── F2 copy capture: buffer overflow / boundary ──────────────────

    #[cfg(unix)]
    #[test]
    fn copy_capture_aborts_when_buffer_exceeds_max_without_finding_markers() {
        // Simulate a remote shell that produces a flood of output but
        // never emits the BEGIN / ERROR markers (e.g. user pasted F2
        // path into wrong shell, or remote command crashed mid-output).
        // The capture buffer must bound itself at MAX_COPY_CAPTURE_BYTES
        // and surface a clear error instead of growing unbounded.
        let mut session = spawn_sleeping_session();
        let clipboard = Arc::new(FakeClipboard::default());
        session.clipboard = clipboard.clone();
        session.copy_capture = Some(CopyCapture::new(
            "/tmp/never-finds-marker.log".into(),
            "copyid-overflow",
        ));

        // Feed one large marker-free chunk past the cap. A single
        // process_output call is dramatically faster than a per-chunk
        // loop here because the vt100 parser path is short-circuited
        // while the capture is active.
        let oversize = vec![b'x'; MAX_COPY_CAPTURE_BYTES + 1024];
        session.process_output(&oversize);

        // After abort:
        // 1. Capture cleared so subsequent PTY bytes flow normally
        assert!(
            session.copy_capture.is_none(),
            "capture must be cleared after overflow"
        );
        // 2. Clipboard untouched
        assert!(
            clipboard
                .bytes
                .lock()
                .expect("fake clipboard lock")
                .is_empty(),
            "no partial data should land in clipboard"
        );
        // 3. User sees an error overlay
        match &session.overlay {
            Some(ConnectOverlay::CopyMessage {
                is_error, message, ..
            }) => {
                assert!(*is_error);
                assert!(
                    message.contains("did not contain Canopy markers")
                        || message.contains("aborting"),
                    "error message should explain overflow, got {message:?}"
                );
            }
            other => panic!("expected error CopyMessage overlay, got {other:?}"),
        }
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn copy_capture_handles_marker_split_across_two_chunks() {
        // PTY output frequently arrives in arbitrarily-sized chunks.
        // The capture state machine must handle a BEGIN marker that
        // spans a chunk boundary.
        let mut session = spawn_sleeping_session();
        let clipboard = Arc::new(FakeClipboard::default());
        session.clipboard = clipboard.clone();
        session.copy_capture = Some(CopyCapture::new("/tmp/split.log".into(), "splitid"));

        let encoded = general_purpose::STANDARD.encode("split content");
        let begin = "__CANOPY_COPY_BEGIN_splitid__";
        let end = "__CANOPY_COPY_END_splitid__";

        // Send the marker in two parts that cut through it.
        let split_at = 12;
        let (begin_a, begin_b) = begin.split_at(split_at);
        session.process_output(format!("prefix\r\n{begin_a}").as_bytes());
        session.process_output(format!("{begin_b}\r\n{encoded}\r\n{end}\r\nDONE").as_bytes());

        assert_eq!(
            clipboard.bytes.lock().expect("lock").as_slice(),
            b"split content"
        );
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn copy_capture_succeeds_at_max_file_size_boundary() {
        // 5 MiB file (the documented MAX_COPY_FILE_BYTES) — the
        // capture buffer headroom is 10 MiB so this must succeed.
        // Decode result must equal what we encoded.
        let mut session = spawn_sleeping_session();
        let clipboard = Arc::new(FakeClipboard::default());
        session.clipboard = clipboard.clone();
        session.copy_capture = Some(CopyCapture::new("/tmp/max-size.bin".into(), "maxid"));

        let payload = vec![b'A'; MAX_COPY_FILE_BYTES];
        let encoded = general_purpose::STANDARD.encode(&payload);
        let output =
            format!("__CANOPY_COPY_BEGIN_maxid__\r\n{encoded}\r\n__CANOPY_COPY_END_maxid__\r\n");
        session.process_output(output.as_bytes());

        let written = clipboard.bytes.lock().expect("lock").clone();
        assert_eq!(written.len(), payload.len());
        assert!(written.iter().all(|&b| b == b'A'));
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn copy_capture_with_empty_payload_writes_empty_clipboard() {
        // Remote file of length 0 — base64("") is "" — capture flow
        // must still write an empty payload (or surface a clean
        // success), not panic on decode.
        let mut session = spawn_sleeping_session();
        let clipboard = Arc::new(FakeClipboard::default());
        session.clipboard = clipboard.clone();
        session.copy_capture = Some(CopyCapture::new("/tmp/empty.txt".into(), "emptyid"));

        session.process_output(
            b"__CANOPY_COPY_BEGIN_emptyid__\r\n\r\n__CANOPY_COPY_END_emptyid__\r\n",
        );

        let written = clipboard.bytes.lock().expect("lock").clone();
        assert!(written.is_empty(), "empty file → empty clipboard payload");
        assert!(matches!(
            session.overlay,
            Some(ConnectOverlay::CopyMessage {
                is_error: false,
                ..
            })
        ));
        cleanup_session(session);
    }

    #[cfg(unix)]
    #[test]
    fn copy_capture_treats_malformed_base64_as_error() {
        // Garbage between markers — decode must fail and we surface
        // a user-visible error, not silently swallow.
        let mut session = spawn_sleeping_session();
        let clipboard = Arc::new(FakeClipboard::default());
        session.clipboard = clipboard.clone();
        session.copy_capture = Some(CopyCapture::new("/tmp/bad.bin".into(), "garbageid"));

        session.process_output(
            b"__CANOPY_COPY_BEGIN_garbageid__\r\n!!!not valid base64@@@\r\n__CANOPY_COPY_END_garbageid__\r\n",
        );

        assert!(clipboard.bytes.lock().expect("lock").is_empty());
        match &session.overlay {
            Some(ConnectOverlay::CopyMessage {
                is_error, message, ..
            }) => {
                assert!(*is_error);
                assert!(
                    message.to_lowercase().contains("decode"),
                    "expected decode failure message, got {message:?}"
                );
            }
            other => panic!("expected error overlay, got {other:?}"),
        }
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
