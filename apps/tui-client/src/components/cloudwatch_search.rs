use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Wrap},
};
use shared::dto::cloudwatch::*;
use shared::dto::entitlements::UserEntitlements;

use super::time_range::{TimeRange, TimeRangePreset};
use super::time_range_modal::{ModalOutcome, TimeRangeModal};
use super::{loading::LoadingIndicator, Component, ScopeTransition};
use crate::event::{Action, ExportFormat};
use crate::theme::Theme;
use crate::widgets::input::{TextAreaInput, TextInput};
use crate::widgets::table::{
    selected_row_style, table_border_style, SelectableTable, SELECTED_ROW_SYMBOL,
};

const INSIGHTS_KEYWORD_PLACEHOLDER: &str = "[keyword輸入在這裡]";
const DEFAULT_INSIGHTS_QUERY_TEMPLATE: &str = "fields @timestamp, @logStream, @message\n| filter @message like /[keyword輸入在這裡]/\n| sort @timestamp asc\n| limit 500";

fn normalize_pasted_single_line_text(text: &str) -> String {
    text.replace("\r\n", "\n").replace(['\r', '\n'], " ")
}

fn normalize_pasted_multiline_text(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

fn escape_insights_regex_literal(text: &str) -> String {
    text.replace('\\', "\\\\").replace('/', "\\/")
}

fn default_insights_query(keyword: &str) -> String {
    let keyword = keyword.trim();
    let needle = if keyword.is_empty() {
        INSIGHTS_KEYWORD_PLACEHOLDER.to_string()
    } else {
        escape_insights_regex_literal(keyword)
    };

    format!(
        "fields @timestamp, @logStream, @message\n| filter @message like /{}/\n| sort @timestamp asc\n| limit 500",
        needle
    )
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    let mut chars = text.chars();
    let mut out: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        out.push('…');
    }
    out
}

/// Strip terminal control sequences before rendering CloudWatch log text.
///
/// Rules:
/// - CSI sequences (`ESC [` ... final byte) are removed.
/// - OSC sequences (`ESC ]` ... BEL/ST) are removed.
/// - DCS/SOS/PM-style strings (`ESC P`, `ESC _`, `ESC ^` ... ST) are removed.
/// - Other single-character ESC sequences are removed.
/// - Non-printing control chars are removed, except `\n` and `\t` for readability.
/// - `\r` is normalized to a newline for CR-only logs, while CRLF stays a single newline.
fn sanitize_log_text_for_tui(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            match chars.peek().copied() {
                Some('[') => {
                    chars.next();
                    for c in chars.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    chars.next();
                    while let Some(c) = chars.next() {
                        if c == '\x07' {
                            break;
                        }
                        if c == '\x1b' && matches!(chars.peek(), Some('\\')) {
                            chars.next();
                            break;
                        }
                    }
                }
                Some('P' | '_' | '^') => {
                    chars.next();
                    while let Some(c) = chars.next() {
                        if c == '\x1b' && matches!(chars.peek(), Some('\\')) {
                            chars.next();
                            break;
                        }
                    }
                }
                Some(_) => {
                    chars.next();
                }
                None => {}
            }
            continue;
        }

        if ch.is_control() {
            match ch {
                '\n' => out.push('\n'),
                '\r' if !matches!(chars.peek(), Some('\n')) => out.push('\n'),
                '\r' => {}
                '\t' => out.push('\t'),
                _ => {}
            }
        } else {
            out.push(ch);
        }
    }

    out
}

/// Sanitized one-line table preview capped to the message column budget.
fn sanitize_log_preview_for_tui(text: &str) -> String {
    sanitize_log_text_for_tui(text).chars().take(200).collect()
}

/// Sanitized full detail text for an Insights row, preserving all returned fields.
fn query_result_detail_text(row: &[QueryResultField]) -> String {
    row.iter()
        .map(|f| format!("{}: {}", f.field, sanitize_log_text_for_tui(&f.value)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Sanitized `@message` preview for the Insights results table.
fn query_result_message_preview(row: &[QueryResultField]) -> String {
    row.iter()
        .find(|f| f.field == "@message")
        .map(|f| sanitize_log_preview_for_tui(&f.value))
        .unwrap_or_else(|| "-".into())
}

enum CwFocus {
    LogGroupList,
    LogGroupFilter,
    QueryInput,
    ResultsTable,
    EventDetail,
}

enum SearchMode {
    QuickSearch,
    InsightsQuery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloudWatchLoadingKind {
    LogGroups,
    SearchingLogs,
    LoadingMoreEvents,
    StartingInsightsQuery,
    WaitingForInsightsResults,
}

impl CloudWatchLoadingKind {
    fn message(self) -> &'static str {
        match self {
            Self::LogGroups => "Loading log groups...",
            Self::SearchingLogs => "Searching CloudWatch logs...",
            Self::LoadingMoreEvents => "Loading more events...",
            Self::StartingInsightsQuery => "Starting Insights query...",
            Self::WaitingForInsightsResults => "Waiting for Insights results...",
        }
    }

    fn status_text(self, query_status: Option<&QueryStatus>) -> String {
        match (self, query_status) {
            (Self::WaitingForInsightsResults, Some(status)) => {
                format!("Query status: {status:?}")
            }
            _ => self.message().into(),
        }
    }
}

pub struct CloudWatchSearchScreen {
    pub log_groups: Vec<LogGroup>,
    pub events: Vec<LogEvent>,
    pub query_results: Vec<Vec<QueryResultField>>,
    event_detail_texts: Vec<String>,
    event_preview_texts: Vec<String>,
    query_result_detail_texts: Vec<String>,
    query_result_preview_texts: Vec<String>,
    pub query_status: Option<QueryStatus>,
    pub query_id: Option<String>,
    loading: Option<CloudWatchLoadingKind>,
    pub error: Option<String>,

    // Entitlement-derived scope for CloudWatch queries
    pub selected_account_id: String,
    pub selected_region: String,
    pub selected_log_group: String,

    /// All available accounts and regions from entitlements, for cycling
    pub available_accounts: Vec<String>,
    pub available_regions: Vec<String>,

    pub query_input: TextInput,
    insights_query_input: TextAreaInput,
    insights_query_customized: bool,
    scope_transition: Option<ScopeTransition>,
    loading_spinner: LoadingIndicator,
    /// Generation counter for log-group fetches (separate from query loading)
    pub fetch_generation: u64,
    search_mode: SearchMode,
    focus: CwFocus,
    log_group_filter: TextInput,
    /// Indices into `log_groups` that match the current filter.
    filtered_indices: Vec<usize>,
    log_group_table: SelectableTable,
    table: SelectableTable,
    selected_event: Option<usize>,
    query_history: Vec<String>,
    /// Active time-range selection (preset or custom). Drives both Quick
    /// Search (FilterLogEvents) and Insights query windows.
    pub time_range: TimeRange,
    theme: Theme,
    /// Optional custom-range modal overlay. When `Some`, all key events are
    /// routed to the modal instead of the screen.
    time_range_modal: Option<TimeRangeModal>,
    /// `next_token` returned by the most recent FilterLogEvents response.
    /// `Some(_)` means there are more pages available; `None` means the
    /// last response exhausted the result set (or no search has run yet).
    pub last_next_token: Option<String>,
    /// Convenience mirror of `last_next_token.is_some()` so render code can
    /// branch without `as_ref().is_some()` boilerplate.
    pub has_more: bool,
}

impl Default for CloudWatchSearchScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudWatchSearchScreen {
    pub fn new() -> Self {
        Self::with_theme(Theme::default())
    }

    pub fn with_theme(theme: Theme) -> Self {
        let mut screen = Self {
            log_groups: Vec::new(),
            events: Vec::new(),
            query_results: Vec::new(),
            event_detail_texts: Vec::new(),
            event_preview_texts: Vec::new(),
            query_result_detail_texts: Vec::new(),
            query_result_preview_texts: Vec::new(),
            query_status: None,
            query_id: None,
            loading: None,
            error: None,
            selected_account_id: String::new(),
            selected_region: String::new(),
            selected_log_group: String::new(),
            available_accounts: Vec::new(),
            available_regions: Vec::new(),
            query_input: TextInput::new("Keyword").with_theme(theme),
            insights_query_input: TextAreaInput::with_value(
                "Insights query",
                DEFAULT_INSIGHTS_QUERY_TEMPLATE,
            )
            .with_theme(theme),
            insights_query_customized: false,
            scope_transition: None,
            loading_spinner: LoadingIndicator::new("Loading log groups...").with_theme(theme),
            fetch_generation: 0,
            search_mode: SearchMode::QuickSearch,
            focus: CwFocus::LogGroupList,
            log_group_filter: TextInput::new("Search log groups...").with_theme(theme),
            filtered_indices: Vec::new(),
            log_group_table: SelectableTable::new(
                vec!["Log Group".into(), "Retention".into(), "Size".into()],
                vec![
                    Constraint::Min(40),
                    Constraint::Length(12),
                    Constraint::Length(12),
                ],
            )
            .with_theme(theme),
            table: SelectableTable::new(
                vec!["Timestamp".into(), "Stream".into(), "Message".into()],
                vec![
                    Constraint::Length(24),
                    Constraint::Length(30),
                    Constraint::Min(40),
                ],
            )
            .with_theme(theme),
            selected_event: None,
            query_history: Vec::new(),
            time_range: TimeRange::default(),
            theme,
            time_range_modal: None,
            last_next_token: None,
            has_more: false,
        };
        screen
            .insights_query_input
            .set_cursor_to_first_match(INSIGHTS_KEYWORD_PLACEHOLDER);
        screen
    }

    fn sync_query_focus(&mut self) {
        let focused = matches!(self.focus, CwFocus::QueryInput);
        self.query_input.focused = focused && matches!(self.search_mode, SearchMode::QuickSearch);
        self.insights_query_input.focused =
            focused && matches!(self.search_mode, SearchMode::InsightsQuery);
    }

    fn set_focus(&mut self, focus: CwFocus) {
        self.focus = focus;
        self.sync_query_focus();
    }

    fn refresh_default_insights_query_from_keyword(&mut self) {
        if self.insights_query_customized {
            return;
        }

        let query = default_insights_query(&self.query_input.value);
        self.insights_query_input.set_value(query);
        if self.query_input.value.trim().is_empty() {
            self.insights_query_input
                .set_cursor_to_first_match(INSIGHTS_KEYWORD_PLACEHOLDER);
        }
    }

    fn replace_insights_placeholder_with(&mut self, replacement: &str) {
        let Some(byte_idx) = self
            .insights_query_input
            .value
            .find(INSIGHTS_KEYWORD_PLACEHOLDER)
        else {
            self.insights_query_input.insert_str(replacement);
            self.insights_query_customized = true;
            return;
        };

        let replacement_end = byte_idx + INSIGHTS_KEYWORD_PLACEHOLDER.len();
        let prefix_chars = self.insights_query_input.value[..byte_idx].chars().count();
        self.insights_query_input
            .value
            .replace_range(byte_idx..replacement_end, replacement);
        self.insights_query_input.cursor_pos = prefix_chars + replacement.chars().count();
        self.insights_query_customized = true;
    }

    fn replace_default_insights_query_with_paste(&mut self, text: String) {
        self.insights_query_input.set_value(text);
        self.insights_query_customized = true;
    }

    fn toggle_search_mode(&mut self) {
        self.search_mode = match self.search_mode {
            SearchMode::QuickSearch => {
                self.refresh_default_insights_query_from_keyword();
                SearchMode::InsightsQuery
            }
            SearchMode::InsightsQuery => SearchMode::QuickSearch,
        };
        self.sync_query_focus();
    }

    pub(crate) fn insights_query_text(&self) -> &str {
        &self.insights_query_input.value
    }

    pub fn set_entitlements(&mut self, ent: UserEntitlements) {
        // Populate available accounts (deduplicated) and regions
        self.available_accounts = ent
            .allowed_accounts
            .iter()
            .map(|a| a.account_id.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        self.available_accounts.sort();
        self.available_regions = ent.allowed_regions.clone();

        // Default to first allowed account/region
        if let Some(acct) = ent.allowed_accounts.first() {
            self.selected_account_id = acct.account_id.clone();
        }
        if let Some(region) = ent.allowed_regions.first() {
            self.selected_region = region.clone();
        }
        // Default log group from the first allowed ARN pattern, if any
        if let Some(arn) = ent.allowed_log_group_arns.first() {
            // Extract log group name from ARN pattern like
            // "arn:aws:logs:*:*:log-group:/app/web-service"
            if let Some(pos) = arn.find("log-group:") {
                let name = &arn[pos + "log-group:".len()..];
                // Strip trailing wildcard for a usable default
                self.selected_log_group = name.trim_end_matches('*').to_string();
            }
        }
    }

    pub fn set_log_groups(&mut self, groups: Vec<LogGroup>) {
        // Auto-select the first log group if we don't have a valid selection
        if let Some(first) = groups.first() {
            if self.selected_log_group.is_empty()
                || !groups.iter().any(|g| g.name == self.selected_log_group)
            {
                self.selected_log_group = first.name.clone();
            }
        } else {
            self.selected_log_group.clear();
        }
        self.log_groups = groups;
        self.refilter_log_groups();
        self.loading = None;
        self.error = None;
    }

    /// Clear all scope-dependent state when account/region changes.
    fn clear_scope_state(&mut self) {
        // Advance generation first so any in-flight response is rejected
        self.fetch_generation += 1;
        self.log_groups.clear();
        self.filtered_indices.clear();
        self.log_group_table.set_row_count(0);
        self.selected_log_group.clear();
        self.log_group_filter.clear();
        self.events.clear();
        self.query_results.clear();
        self.event_detail_texts.clear();
        self.event_preview_texts.clear();
        self.query_result_detail_texts.clear();
        self.query_result_preview_texts.clear();
        self.query_id = None;
        self.query_status = None;
        self.table.set_row_count(0);
        self.selected_event = None;
        self.last_next_token = None;
        self.has_more = false;
    }

    fn cycle_account(&mut self, forward: bool) -> bool {
        if self.available_accounts.len() <= 1 {
            return false;
        }
        let cur_idx = self
            .available_accounts
            .iter()
            .position(|a| a == &self.selected_account_id)
            .unwrap_or(0);
        let next = if forward {
            (cur_idx + 1) % self.available_accounts.len()
        } else {
            (cur_idx + self.available_accounts.len() - 1) % self.available_accounts.len()
        };
        self.selected_account_id = self.available_accounts[next].clone();
        self.clear_scope_state();
        true
    }

    fn cycle_region(&mut self, forward: bool) -> bool {
        if self.available_regions.len() <= 1 {
            return false;
        }
        let cur_idx = self
            .available_regions
            .iter()
            .position(|r| r == &self.selected_region)
            .unwrap_or(0);
        let next = if forward {
            (cur_idx + 1) % self.available_regions.len()
        } else {
            (cur_idx + self.available_regions.len() - 1) % self.available_regions.len()
        };
        self.selected_region = self.available_regions[next].clone();
        self.clear_scope_state();
        true
    }

    fn refilter_log_groups(&mut self) {
        let query = self.log_group_filter.value.to_lowercase();
        self.filtered_indices = self
            .log_groups
            .iter()
            .enumerate()
            .filter(|(_, lg)| query.is_empty() || lg.name.to_lowercase().contains(&query))
            .map(|(i, _)| i)
            .collect();

        self.log_group_table
            .set_row_count(self.filtered_indices.len());

        // Try to keep the current selection highlighted
        if !self.selected_log_group.is_empty() {
            if let Some(pos) = self.filtered_indices.iter().position(|&i| {
                self.log_groups
                    .get(i)
                    .map(|lg| lg.name == self.selected_log_group)
                    .unwrap_or(false)
            }) {
                self.log_group_table.state.select(Some(pos));
            }
        }
    }

    /// Replace the current event list with a fresh search response.
    /// Resets pagination state from the new `next_token`.
    pub fn set_events(&mut self, events: Vec<LogEvent>, next_token: Option<String>) {
        self.event_detail_texts = events
            .iter()
            .map(|event| sanitize_log_text_for_tui(&event.message))
            .collect();
        self.event_preview_texts = self
            .event_detail_texts
            .iter()
            .map(|message| message.chars().take(200).collect())
            .collect();
        self.table.set_row_count(events.len());
        self.events = events;
        self.last_next_token = next_token;
        self.has_more = self.last_next_token.is_some();
        // Clear stale Insights results so exports and rendering don't
        // accidentally use old query_results instead of the new events.
        self.query_results.clear();
        self.query_result_detail_texts.clear();
        self.query_result_preview_texts.clear();
        self.query_id = None;
        self.loading = None;
        self.error = None;
    }

    /// Append the next page of events to the current list. Updates the
    /// pagination state from the new `next_token`.
    pub fn append_events(&mut self, events: Vec<LogEvent>, next_token: Option<String>) {
        let new_detail_texts: Vec<_> = events
            .iter()
            .map(|event| sanitize_log_text_for_tui(&event.message))
            .collect();
        let new_preview_texts: Vec<_> = new_detail_texts
            .iter()
            .map(|message| message.chars().take(200).collect())
            .collect();
        self.event_detail_texts.extend(new_detail_texts);
        self.event_preview_texts.extend(new_preview_texts);
        self.events.extend(events);
        self.table.set_row_count(self.events.len());
        self.last_next_token = next_token;
        self.has_more = self.last_next_token.is_some();
        self.query_results.clear();
        self.query_result_detail_texts.clear();
        self.query_result_preview_texts.clear();
        self.query_id = None;
        self.loading = None;
        self.error = None;
    }

    pub fn set_query_results(&mut self, results: GetQueryResultsResponse) {
        let is_terminal = results.status.is_terminal();
        self.query_status = Some(results.status);
        self.table.set_row_count(results.results.len());
        self.query_result_detail_texts = results
            .results
            .iter()
            .map(|row| query_result_detail_text(row))
            .collect();
        self.query_result_preview_texts = results
            .results
            .iter()
            .map(|row| query_result_message_preview(row))
            .collect();
        self.query_results = results.results;
        // Clear stale quick-search events so detail pane and export
        // don't accidentally use old FilterLogEvents data.
        self.events.clear();
        self.event_detail_texts.clear();
        self.event_preview_texts.clear();
        // Pagination state belongs to FilterLogEvents — reset when we
        // switch into Insights so a stale token can't drive a wrong page.
        self.last_next_token = None;
        self.has_more = false;
        if is_terminal {
            self.loading = None;
        } else {
            self.set_loading(CloudWatchLoadingKind::WaitingForInsightsResults);
        }
        self.error = None;
    }

    pub(crate) fn set_loading(&mut self, kind: CloudWatchLoadingKind) {
        self.loading = Some(kind);
        self.loading_spinner.set_message(kind.message());
        self.error = None;
    }

    pub(crate) fn cancel_loading(&mut self) {
        self.loading = None;
    }

    pub(crate) fn is_loading(&self) -> bool {
        self.loading.is_some()
    }

    /// Bump log-group fetch generation. Called only when starting a log-group refresh.
    pub fn advance_fetch_generation(&mut self) {
        self.fetch_generation += 1;
    }

    pub fn set_error(&mut self, err: String) {
        self.loading = None;
        self.error = Some(err);
    }

    fn format_bytes(bytes: i64) -> String {
        const GB: i64 = 1_073_741_824;
        const MB: i64 = 1_048_576;
        const KB: i64 = 1_024;
        if bytes >= GB {
            format!("{:.1} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.1} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.1} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} B", bytes)
        }
    }

    fn footer_status_text(&self, use_insights: bool) -> String {
        if let Some(kind) = self.loading {
            return kind.status_text(self.query_status.as_ref());
        }
        if let Some(ref err) = self.error {
            return format!("Error: {}", truncate_chars(err, 80));
        }

        // Pagination markers only apply to Quick Search (FilterLogEvents).
        // Insights query has its own result-set semantics.
        let (count_label, page_hint) = if use_insights {
            (self.query_results.len().to_string(), "")
        } else if self.has_more {
            (format!("{}+", self.events.len()), " | n: more")
        } else if !self.events.is_empty() {
            (format!("{} (end)", self.events.len()), "")
        } else {
            (self.events.len().to_string(), "")
        };

        format!(
            "{} results | range: {}{}",
            count_label,
            self.time_range.footer_label(),
            page_hint,
        )
    }

    fn footer_hint_text(&self, use_insights: bool) -> &'static str {
        match self.focus {
            CwFocus::LogGroupList => {
                "[] account | {} region | / filter | Enter query | Tab panel | Esc back"
            }
            CwFocus::LogGroupFilter => "Type filter | Enter accept | Esc clear",
            CwFocus::QueryInput => match self.search_mode {
                SearchMode::QuickSearch => "Enter search | Tab Insights | Esc log groups",
                SearchMode::InsightsQuery => {
                    "Enter run | Ctrl+J newline | Tab Quick Search | Esc log groups"
                }
            },
            CwFocus::ResultsTable if use_insights => {
                "Enter detail | x export | r/R range | / query | Esc log groups"
            }
            CwFocus::ResultsTable => {
                "n more | Enter detail | x export | r/R range | / query | Esc log groups"
            }
            CwFocus::EventDetail => "Esc results | Up/Down move selected event",
        }
    }

    fn render_status_footer(&self, area: Rect, buf: &mut Buffer, use_insights: bool) {
        let status_style = if self.error.is_some() {
            self.theme.danger_style()
        } else if self.loading.is_some() {
            self.theme.warning_style()
        } else {
            self.theme.muted_style()
        };
        let lines = vec![
            Line::styled(self.footer_status_text(use_insights), status_style),
            Line::styled(
                self.footer_hint_text(use_insights),
                self.theme.muted_style(),
            ),
        ];
        Paragraph::new(lines).render(area, buf);
    }

    fn render_event_detail(&self, area: Rect, buf: &mut Buffer) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Event Detail ")
            .border_style(table_border_style(
                matches!(self.focus, CwFocus::EventDetail),
                self.theme,
            ));
        let inner = block.inner(area);
        block.render(area, buf);

        if let Some(idx) = self.table.selected() {
            // Show detail from FilterLogEvents or Insights query results
            let detail_text = if let Some(event) = self.events.get(idx) {
                self.event_detail_texts
                    .get(idx)
                    .map(String::as_str)
                    .or(Some(event.message.as_str()))
            } else if self.query_results.get(idx).is_some() {
                self.query_result_detail_texts.get(idx).map(String::as_str)
            } else {
                None
            };

            if let Some(message) = detail_text {
                let style = if message.contains("\"ERROR\"")
                    || message.contains("\"level\":\"ERROR\"")
                {
                    self.theme.danger_style()
                } else if message.contains("\"WARN\"") || message.contains("\"level\":\"WARN\"") {
                    self.theme.warning_style()
                } else {
                    self.theme.text_style()
                };

                Paragraph::new(message)
                    .style(style)
                    .wrap(Wrap { trim: false })
                    .render(inner, buf);
            }
        }
    }
}

impl Component for CloudWatchSearchScreen {
    fn handle_key(&mut self, key: KeyEvent) -> Action {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Action::Quit;
        }

        // Route everything to the custom-range modal when it is open. The
        // modal owns the key handling until the user submits, cancels, or
        // resets — even Tab and Esc are intercepted before the screen sees
        // them.
        if self.time_range_modal.is_some() {
            let outcome = self
                .time_range_modal
                .as_mut()
                .expect("modal presence checked above")
                .handle_key(key);
            match outcome {
                ModalOutcome::Continue => {}
                ModalOutcome::Cancel => {
                    self.time_range_modal = None;
                }
                ModalOutcome::ResetToOneHour => {
                    self.time_range = TimeRange::Preset(TimeRangePreset::OneHour);
                    self.time_range_modal = None;
                }
                ModalOutcome::Submit {
                    start_secs,
                    end_secs,
                } => {
                    if let Err(e) = self.time_range.set_custom(start_secs, end_secs) {
                        // Defensive: validation already ran inside the modal.
                        // If we somehow reach here, surface the error rather
                        // than silently dropping the input.
                        if let Some(m) = self.time_range_modal.as_mut() {
                            m.error = Some(e.to_string());
                        }
                    } else {
                        self.time_range_modal = None;
                    }
                }
            }
            return Action::Noop;
        }

        match key.code {
            KeyCode::Esc => match self.focus {
                CwFocus::LogGroupList => Action::GoBack,
                CwFocus::LogGroupFilter => {
                    // Clear filter and return to log group list
                    self.log_group_filter.clear();
                    self.log_group_filter.focused = false;
                    self.refilter_log_groups();
                    self.set_focus(CwFocus::LogGroupList);
                    Action::Noop
                }
                CwFocus::QueryInput => {
                    self.set_focus(CwFocus::LogGroupList);
                    Action::Noop
                }
                CwFocus::EventDetail => {
                    self.set_focus(CwFocus::ResultsTable);
                    Action::Noop
                }
                CwFocus::ResultsTable => {
                    self.set_focus(CwFocus::LogGroupList);
                    if self.is_loading() {
                        Action::CancelCloudWatchRequest
                    } else {
                        Action::Noop
                    }
                }
            },
            KeyCode::Tab => {
                match self.focus {
                    CwFocus::LogGroupList | CwFocus::LogGroupFilter => {
                        self.log_group_filter.focused = false;
                        self.set_focus(CwFocus::QueryInput);
                    }
                    CwFocus::QueryInput => {
                        self.toggle_search_mode();
                    }
                    CwFocus::ResultsTable | CwFocus::EventDetail => {
                        self.set_focus(CwFocus::LogGroupList);
                    }
                }
                Action::Noop
            }
            // `[` / `]` in log group list → cycle account
            KeyCode::Char('[') if matches!(self.focus, CwFocus::LogGroupList) => {
                if ScopeTransition::is_blocking(&self.scope_transition) {
                    return Action::Noop;
                }
                if self.cycle_account(false) {
                    let label = format!("Account → {}", self.selected_account_id);
                    self.scope_transition = Some(ScopeTransition::new(label));
                    return Action::RefreshLogGroups;
                }
                Action::Noop
            }
            KeyCode::Char(']') if matches!(self.focus, CwFocus::LogGroupList) => {
                if ScopeTransition::is_blocking(&self.scope_transition) {
                    return Action::Noop;
                }
                if self.cycle_account(true) {
                    let label = format!("Account → {}", self.selected_account_id);
                    self.scope_transition = Some(ScopeTransition::new(label));
                    return Action::RefreshLogGroups;
                }
                Action::Noop
            }
            // `{` / `}` in log group list → cycle region
            KeyCode::Char('{') if matches!(self.focus, CwFocus::LogGroupList) => {
                if ScopeTransition::is_blocking(&self.scope_transition) {
                    return Action::Noop;
                }
                if self.cycle_region(false) {
                    let label = format!("Region → {}", self.selected_region);
                    self.scope_transition = Some(ScopeTransition::new(label));
                    return Action::RefreshLogGroups;
                }
                Action::Noop
            }
            KeyCode::Char('}') if matches!(self.focus, CwFocus::LogGroupList) => {
                if ScopeTransition::is_blocking(&self.scope_transition) {
                    return Action::Noop;
                }
                if self.cycle_region(true) {
                    let label = format!("Region → {}", self.selected_region);
                    self.scope_transition = Some(ScopeTransition::new(label));
                    return Action::RefreshLogGroups;
                }
                Action::Noop
            }
            // `r` (anywhere except text inputs) → cycle preset time range
            KeyCode::Char('r')
                if !matches!(self.focus, CwFocus::QueryInput | CwFocus::LogGroupFilter) =>
            {
                self.time_range.cycle_preset();
                Action::Noop
            }
            // `R` (Shift+r, anywhere except text inputs, not while loading)
            // → open the custom-range modal.
            KeyCode::Char('R')
                if !matches!(self.focus, CwFocus::QueryInput | CwFocus::LogGroupFilter)
                    && !self.is_loading() =>
            {
                self.time_range_modal = Some(TimeRangeModal::open_with_theme(
                    &self.time_range,
                    self.theme,
                ));
                Action::Noop
            }
            // `/` in log group list → activate log group filter
            KeyCode::Char('/') if matches!(self.focus, CwFocus::LogGroupList) => {
                self.set_focus(CwFocus::LogGroupFilter);
                self.log_group_filter.focused = true;
                Action::Noop
            }
            // `/` elsewhere (except text inputs) → jump to query input
            KeyCode::Char('/')
                if !matches!(self.focus, CwFocus::QueryInput | CwFocus::LogGroupFilter) =>
            {
                self.set_focus(CwFocus::QueryInput);
                Action::Noop
            }
            KeyCode::Char('j')
                if matches!(self.focus, CwFocus::QueryInput)
                    && matches!(self.search_mode, SearchMode::InsightsQuery)
                    && key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                if !self.insights_query_customized {
                    self.replace_insights_placeholder_with("\n");
                } else {
                    self.insights_query_input
                        .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
                }
                Action::Noop
            }
            KeyCode::Enter
                if matches!(self.focus, CwFocus::QueryInput)
                    && matches!(self.search_mode, SearchMode::InsightsQuery)
                    && key.modifiers.contains(KeyModifiers::SHIFT) =>
            {
                if !self.insights_query_customized {
                    self.replace_insights_placeholder_with("\n");
                } else {
                    self.insights_query_input
                        .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
                }
                Action::Noop
            }
            KeyCode::Enter => match self.focus {
                CwFocus::LogGroupFilter => {
                    // Accept filter and go back to list navigation
                    self.log_group_filter.focused = false;
                    self.set_focus(CwFocus::LogGroupList);
                    Action::Noop
                }
                CwFocus::LogGroupList => {
                    // Select the highlighted log group and move to query input
                    if let Some(table_idx) = self.log_group_table.selected() {
                        if let Some(&real_idx) = self.filtered_indices.get(table_idx) {
                            if let Some(lg) = self.log_groups.get(real_idx) {
                                self.selected_log_group = lg.name.clone();
                            }
                        }
                    }
                    self.set_focus(CwFocus::QueryInput);
                    Action::Noop
                }
                CwFocus::QueryInput => {
                    let query = match self.search_mode {
                        SearchMode::QuickSearch => self.query_input.value.clone(),
                        SearchMode::InsightsQuery => self.insights_query_input.value.clone(),
                    };
                    if !query.is_empty() {
                        self.query_history.push(query);
                    }
                    self.set_focus(CwFocus::ResultsTable);
                    match self.search_mode {
                        SearchMode::QuickSearch => Action::RunFilterSearch,
                        SearchMode::InsightsQuery => Action::RunInsightsQuery,
                    }
                }
                CwFocus::ResultsTable => {
                    self.focus = CwFocus::EventDetail;
                    Action::Noop
                }
                CwFocus::EventDetail => Action::Noop,
            },
            KeyCode::Char('x') if matches!(self.focus, CwFocus::ResultsTable) => {
                Action::ExportResults(ExportFormat::Json)
            }
            // `n` in results table → load next page of FilterLogEvents
            // results. Only fires when there is a pending next_token and no
            // request is in-flight.
            KeyCode::Char('n')
                if matches!(self.focus, CwFocus::ResultsTable)
                    && self.has_more
                    && !self.is_loading() =>
            {
                Action::LoadMoreFilterResults
            }
            _ => {
                match self.focus {
                    CwFocus::LogGroupFilter => {
                        self.log_group_filter.handle_key(key);
                        self.refilter_log_groups();
                    }
                    CwFocus::LogGroupList => {
                        self.log_group_table.handle_key(key);
                        // Sync selection via filtered indices
                        if let Some(table_idx) = self.log_group_table.selected() {
                            if let Some(&real_idx) = self.filtered_indices.get(table_idx) {
                                if let Some(lg) = self.log_groups.get(real_idx) {
                                    self.selected_log_group = lg.name.clone();
                                }
                            }
                        }
                    }
                    CwFocus::QueryInput => match self.search_mode {
                        SearchMode::QuickSearch => {
                            self.query_input.handle_key(key);
                        }
                        SearchMode::InsightsQuery => {
                            if !self.insights_query_customized {
                                match key.code {
                                    KeyCode::Char(c) => {
                                        self.replace_insights_placeholder_with(&c.to_string());
                                    }
                                    KeyCode::Backspace | KeyCode::Delete => {
                                        self.replace_insights_placeholder_with("");
                                    }
                                    _ => {
                                        let before = self.insights_query_input.value.clone();
                                        self.insights_query_input.handle_key(key);
                                        self.insights_query_customized =
                                            before != self.insights_query_input.value;
                                    }
                                }
                            } else {
                                self.insights_query_input.handle_key(key);
                            }
                        }
                    },
                    CwFocus::ResultsTable | CwFocus::EventDetail => {
                        self.table.handle_key(key);
                    }
                }
                Action::Noop
            }
        }
    }

    fn handle_paste(&mut self, text: &str) -> Action {
        if let Some(modal) = self.time_range_modal.as_mut() {
            modal.handle_paste(text);
            return Action::Noop;
        }

        match self.focus {
            CwFocus::QueryInput => match self.search_mode {
                SearchMode::QuickSearch => {
                    let text = normalize_pasted_single_line_text(text);
                    self.query_input.insert_str(&text);
                }
                SearchMode::InsightsQuery => {
                    let text = normalize_pasted_multiline_text(text);
                    let trimmed = text.trim_start();
                    if !self.insights_query_customized
                        && (text.contains('\n') || trimmed.starts_with("fields "))
                    {
                        self.replace_default_insights_query_with_paste(text);
                    } else if !self.insights_query_customized
                        && self
                            .insights_query_input
                            .value
                            .contains(INSIGHTS_KEYWORD_PLACEHOLDER)
                    {
                        self.replace_insights_placeholder_with(&text);
                    } else {
                        self.insights_query_customized = true;
                        self.insights_query_input.insert_str(&text);
                    }
                }
            },
            CwFocus::LogGroupFilter => {
                let text = normalize_pasted_single_line_text(text);
                self.log_group_filter.insert_str(&text);
                self.refilter_log_groups();
            }
            _ => {}
        }
        Action::Noop
    }

    fn render(&mut self, area: Rect, buf: &mut Buffer) {
        let outer = Block::default()
            .borders(Borders::ALL)
            .title(" CloudWatch Search ")
            .border_style(self.theme.accent_style());
        let inner = outer.inner(area);
        outer.render(area, buf);

        // Two-panel layout: left = log group list, right = query + results
        let panels = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(inner);

        // ── Left panel: account/region info + filter + log group list ──
        let left_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2), // Account/Region info
                Constraint::Length(3), // Log group filter input
                Constraint::Min(5),    // Log group table
            ])
            .split(panels[0]);

        // Account/Region header with cycling hints
        let acct_label = if self.available_accounts.len() > 1 {
            format!("Account [/]: {}", self.selected_account_id)
        } else {
            format!("Account: {}", self.selected_account_id)
        };
        let region_label = if self.available_regions.len() > 1 {
            format!("Region {{/}}: {}", self.selected_region)
        } else {
            format!("Region: {}", self.selected_region)
        };
        let scope_line = Line::from(vec![
            Span::styled(" ", Style::default()),
            Span::styled(acct_label, self.theme.warning_style()),
            Span::styled(" │ ", self.theme.muted_style()),
            Span::styled(region_label, self.theme.accent_style()),
        ]);
        Paragraph::new(scope_line).render(left_chunks[0], buf);

        // Log group filter input
        self.log_group_filter.render(left_chunks[1], buf);

        // Log group table (use filtered_indices)
        let lg_focused = matches!(self.focus, CwFocus::LogGroupList | CwFocus::LogGroupFilter);
        let selected_lg = self.selected_log_group.clone();
        let lg_rows = self.filtered_indices.iter().filter_map(|&i| {
            let lg = self.log_groups.get(i)?;
            let retention = lg
                .retention_days
                .map(|d| format!("{}d", d))
                .unwrap_or_else(|| "never".into());
            let size = lg
                .stored_bytes
                .map(Self::format_bytes)
                .unwrap_or_else(|| "-".into());
            let style = if lg.name == selected_lg {
                selected_row_style(self.theme)
            } else {
                Style::default()
            };
            Some(Row::new(vec![
                Cell::from(lg.name.clone()).style(style),
                Cell::from(retention),
                Cell::from(size),
            ]))
        });
        let lg_title = format!(
            "Log Groups ({}/{})",
            self.filtered_indices.len(),
            self.log_groups.len()
        );
        let lg_header = Row::new(
            self.log_group_table
                .headers
                .iter()
                .map(|h| Cell::from(h.as_str()).style(self.theme.accent_style().bold())),
        )
        .height(1);
        let lg_table = ratatui::widgets::Table::new(lg_rows, &self.log_group_table.column_widths)
            .header(lg_header)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {} ", lg_title))
                    .border_style(table_border_style(lg_focused, self.theme)),
            )
            .highlight_style(selected_row_style(self.theme))
            .highlight_symbol(SELECTED_ROW_SYMBOL);
        ratatui::widgets::StatefulWidget::render(
            lg_table,
            left_chunks[2],
            buf,
            &mut self.log_group_table.state,
        );

        // ── Right panel: mode + query + results + status ──
        let query_height = match self.search_mode {
            SearchMode::QuickSearch => 3,
            SearchMode::InsightsQuery => 7,
        };
        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),            // Mode indicator
                Constraint::Length(query_height), // Query input/editor
                Constraint::Min(5),               // Results
                Constraint::Length(2),            // Status
            ])
            .split(panels[1]);

        // Mode indicator
        let mode_text = match self.search_mode {
            SearchMode::QuickSearch => "[Quick Search (FilterLogEvents)] Tab to switch mode",
            SearchMode::InsightsQuery => {
                "[Insights Query (StartQuery)]    Tab to switch mode | Enter: run | Ctrl+J: newline"
            }
        };
        Paragraph::new(mode_text)
            .style(self.theme.accent_style())
            .render(right_chunks[0], buf);

        // Query input
        match self.search_mode {
            SearchMode::QuickSearch => self.query_input.render(right_chunks[1], buf),
            SearchMode::InsightsQuery => self.insights_query_input.render(right_chunks[1], buf),
        }

        // Results
        let result_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(right_chunks[2]);

        let use_insights =
            matches!(self.search_mode, SearchMode::InsightsQuery) && self.query_id.is_some();

        if use_insights {
            let rows = self.query_results.iter().enumerate().map(|(idx, fields)| {
                let ts = fields
                    .iter()
                    .find(|f| f.field == "@timestamp")
                    .map(|f| f.value.as_str())
                    .unwrap_or("-");
                let raw_msg = fields
                    .iter()
                    .find(|f| f.field == "@message")
                    .map(|f| f.value.as_str());
                let msg_display = self
                    .query_result_preview_texts
                    .get(idx)
                    .map(String::as_str)
                    .unwrap_or("-");
                let stream = fields
                    .iter()
                    .find(|f| f.field == "@logStream")
                    .map(|f| f.value.as_str())
                    .unwrap_or("-");

                let msg_style = if raw_msg.is_some_and(|msg| msg.contains("ERROR")) {
                    self.theme.danger_style()
                } else if raw_msg.is_some_and(|msg| msg.contains("WARN")) {
                    self.theme.warning_style()
                } else {
                    Style::default()
                };

                Row::new(vec![
                    Cell::from(ts.to_string()),
                    Cell::from(stream.to_string()),
                    Cell::from(msg_display).style(msg_style),
                ])
            });
            self.table.render_with_rows_focused(
                rows,
                "Insights Results",
                result_chunks[0],
                buf,
                matches!(self.focus, CwFocus::ResultsTable),
            );
        } else {
            let rows = self.events.iter().enumerate().map(|(idx, ev)| {
                let ts = chrono::DateTime::from_timestamp_millis(ev.timestamp)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
                    .unwrap_or_else(|| ev.timestamp.to_string());

                let msg_style = if ev.message.contains("ERROR") {
                    self.theme.danger_style()
                } else if ev.message.contains("WARN") {
                    self.theme.warning_style()
                } else {
                    Style::default()
                };

                Row::new(vec![
                    Cell::from(ts),
                    Cell::from(ev.log_stream_name.as_deref().unwrap_or("-")),
                    Cell::from(
                        self.event_preview_texts
                            .get(idx)
                            .map(String::as_str)
                            .unwrap_or("-"),
                    )
                    .style(msg_style),
                ])
            });
            self.table.render_with_rows_focused(
                rows,
                "Results",
                result_chunks[0],
                buf,
                matches!(self.focus, CwFocus::ResultsTable),
            );
        }

        // Event detail
        self.render_event_detail(result_chunks[1], buf);

        // Status bar
        self.render_status_footer(right_chunks[3], buf, use_insights);

        // Loading overlay for log-group fetches, searches, pagination, and Insights polling.
        if self.loading.is_some() {
            self.loading_spinner.render_overlay(inner, buf);
        }

        // Scope transition overlay
        if let Some(ref t) = self.scope_transition {
            t.render_with_theme(inner, buf, self.theme);
        }

        // Custom-range modal (top-most overlay)
        if let Some(ref modal) = self.time_range_modal {
            modal.render(inner, buf);
        }
    }

    fn on_tick(&mut self) {
        if self.is_loading() {
            self.loading_spinner.tick();
        }
        if let Some(ref mut t) = self.scope_transition {
            if !t.tick() {
                self.scope_transition = None;
            }
        }
    }

    fn on_enter(&mut self) -> Vec<Action> {
        self.set_focus(CwFocus::LogGroupList);
        vec![Action::RefreshLogGroups]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
    use ratatui::prelude::{Buffer, Rect};
    use shared::dto::entitlements::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn test_entitlements() -> UserEntitlements {
        UserEntitlements {
            user_id: "u1".into(),
            email: "t@t.com".into(),
            display_name: "Test".into(),
            groups: vec!["ops".into()],
            features: FeatureFlags::default(),
            allowed_accounts: vec![
                AllowedAccount {
                    account_id: "111".into(),
                    account_name: "dev".into(),
                    role_arn: "arn:1".into(),
                },
                AllowedAccount {
                    account_id: "222".into(),
                    account_name: "prod".into(),
                    role_arn: "arn:2".into(),
                },
            ],
            allowed_regions: vec!["us-east-1".into(), "eu-west-1".into()],
            allowed_log_group_arns: vec!["arn:aws:logs:*:*:log-group:/app/web-service*".into()],
            instance_tag_selectors: vec![],
            excluded_tag_selectors: vec![],
            allowed_clusters: vec![],
            task_tag_selectors: vec![],
            excluded_task_tag_selectors: vec![],
            excluded_container_names: vec![],
            allow_broad_cluster_discovery: false,
            allowed_os_users: vec![],
            max_session_seconds: None,
            database_scopes: vec![],
            business_scopes: vec![],
        }
    }

    fn test_log_groups() -> Vec<LogGroup> {
        vec![
            LogGroup {
                name: "/app/web-service".into(),
                arn: "arn:1".into(),
                stored_bytes: Some(1024),
                retention_days: Some(30),
            },
            LogGroup {
                name: "/app/api-gateway".into(),
                arn: "arn:2".into(),
                stored_bytes: None,
                retention_days: None,
            },
            LogGroup {
                name: "/system/ecs".into(),
                arn: "arn:3".into(),
                stored_bytes: Some(2048),
                retention_days: Some(7),
            },
        ]
    }

    fn rendered_text(screen: &mut CloudWatchSearchScreen) -> String {
        let area = Rect::new(0, 0, 120, 32);
        let mut buf = Buffer::empty(area);
        screen.render(area, &mut buf);

        let mut out = String::new();
        for cell in &buf.content {
            out.push_str(cell.symbol());
        }
        out
    }

    fn query_response(status: QueryStatus) -> GetQueryResultsResponse {
        GetQueryResultsResponse {
            status,
            results: vec![],
            statistics: None,
        }
    }

    // ── Entitlements ──

    #[test]
    fn set_entitlements_populates_scope() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.set_entitlements(test_entitlements());

        assert_eq!(screen.available_accounts, vec!["111", "222"]);
        assert_eq!(screen.available_regions, vec!["us-east-1", "eu-west-1"]);
        assert_eq!(screen.selected_account_id, "111");
        assert_eq!(screen.selected_region, "us-east-1");
        assert_eq!(screen.selected_log_group, "/app/web-service");
    }

    // ── Log group loading ──

    #[test]
    fn set_log_groups_auto_selects_first_when_empty() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.set_log_groups(test_log_groups());

        assert_eq!(screen.selected_log_group, "/app/web-service");
        assert_eq!(screen.filtered_indices.len(), 3);
        assert!(!screen.is_loading());
    }

    #[test]
    fn set_log_groups_keeps_existing_selection() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.selected_log_group = "/system/ecs".into();
        screen.set_log_groups(test_log_groups());

        assert_eq!(screen.selected_log_group, "/system/ecs");
    }

    // ── Log group filter ──

    #[test]
    fn refilter_narrows_list() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.set_log_groups(test_log_groups());

        screen.log_group_filter.value = "api".into();
        screen.refilter_log_groups();

        assert_eq!(screen.filtered_indices.len(), 1);
        assert_eq!(
            screen.log_groups[screen.filtered_indices[0]].name,
            "/app/api-gateway"
        );
    }

    // ── Account/region cycling ──

    #[test]
    fn cycle_account_wraps_around() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.set_entitlements(test_entitlements());

        let gen_before = screen.fetch_generation;
        assert!(screen.cycle_account(true));
        assert_eq!(screen.selected_account_id, "222");
        // Generation was bumped (clear_scope_state)
        assert!(screen.fetch_generation > gen_before);

        assert!(screen.cycle_account(true));
        assert_eq!(screen.selected_account_id, "111"); // wrapped
    }

    #[test]
    fn cycle_region_wraps_around() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.set_entitlements(test_entitlements());

        assert!(screen.cycle_region(true));
        assert_eq!(screen.selected_region, "eu-west-1");

        assert!(screen.cycle_region(true));
        assert_eq!(screen.selected_region, "us-east-1"); // wrapped
    }

    #[test]
    fn cycle_clears_scope_state() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.set_entitlements(test_entitlements());
        screen.set_log_groups(test_log_groups());
        assert_eq!(screen.log_groups.len(), 3);

        screen.cycle_account(true);
        assert!(screen.log_groups.is_empty());
        assert!(screen.events.is_empty());
        assert!(screen.selected_log_group.is_empty());
    }

    #[test]
    fn single_account_cycle_returns_false() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.available_accounts = vec!["111".into()];
        screen.selected_account_id = "111".into();

        assert!(!screen.cycle_account(true));
    }

    // ── Focus management ──

    #[test]
    fn esc_from_log_group_list_goes_back() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::LogGroupList;

        let action = screen.handle_key(key(KeyCode::Esc));
        assert!(matches!(action, Action::GoBack));
    }

    #[test]
    fn esc_from_query_input_returns_to_list() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::QueryInput;
        screen.query_input.focused = true;

        screen.handle_key(key(KeyCode::Esc));
        assert!(matches!(screen.focus, CwFocus::LogGroupList));
        assert!(!screen.query_input.focused);
    }

    #[test]
    fn esc_from_event_detail_returns_to_results() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::EventDetail;

        screen.handle_key(key(KeyCode::Esc));
        assert!(matches!(screen.focus, CwFocus::ResultsTable));
    }

    #[test]
    fn tab_from_log_group_moves_to_query() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::LogGroupList;

        screen.handle_key(key(KeyCode::Tab));
        assert!(matches!(screen.focus, CwFocus::QueryInput));
        assert!(screen.query_input.focused);
    }

    #[test]
    fn tab_in_query_toggles_search_mode() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::QueryInput;

        assert!(matches!(screen.search_mode, SearchMode::QuickSearch));
        screen.handle_key(key(KeyCode::Tab));
        assert!(matches!(screen.search_mode, SearchMode::InsightsQuery));
        screen.handle_key(key(KeyCode::Tab));
        assert!(matches!(screen.search_mode, SearchMode::QuickSearch));
    }

    // ── Query execution ──

    #[test]
    fn enter_in_query_runs_filter_search() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::QueryInput;
        screen.query_input.value = "ERROR".into();

        let action = screen.handle_key(key(KeyCode::Enter));
        assert!(matches!(action, Action::RunFilterSearch));
        assert!(matches!(screen.focus, CwFocus::ResultsTable));
    }

    #[test]
    fn enter_in_query_insights_mode_runs_insights() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.search_mode = SearchMode::InsightsQuery;
        screen.set_focus(CwFocus::QueryInput);
        screen
            .insights_query_input
            .set_value("fields @timestamp".into());

        let action = screen.handle_key(key(KeyCode::Enter));
        assert!(matches!(action, Action::RunInsightsQuery));
    }

    #[test]
    fn paste_multiline_insights_query_preserves_lines() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.search_mode = SearchMode::InsightsQuery;
        screen.set_focus(CwFocus::QueryInput);
        screen.insights_query_input.clear();

        screen.handle_paste(
            "fields @timestamp, @logStream, @message\n| filter @message like /order/\n| limit 500",
        );

        assert_eq!(
            screen.insights_query_input.value,
            "fields @timestamp, @logStream, @message\n| filter @message like /order/\n| limit 500"
        );
    }

    #[test]
    fn switching_to_insights_prefills_template_from_keyword() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.set_focus(CwFocus::QueryInput);
        screen.query_input.value = "A7051".into();

        screen.handle_key(key(KeyCode::Tab));

        assert!(matches!(screen.search_mode, SearchMode::InsightsQuery));
        assert!(screen.insights_query_input.focused);
        assert_eq!(
            screen.insights_query_input.value,
            "fields @timestamp, @logStream, @message\n| filter @message like /A7051/\n| sort @timestamp asc\n| limit 500"
        );
    }

    #[test]
    fn default_insights_editor_contains_keyword_placeholder() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.set_focus(CwFocus::QueryInput);
        screen.handle_key(key(KeyCode::Tab));

        assert_eq!(
            screen.insights_query_input.value,
            DEFAULT_INSIGHTS_QUERY_TEMPLATE
        );
    }

    #[test]
    fn typing_in_pristine_insights_template_replaces_placeholder() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.set_focus(CwFocus::QueryInput);
        screen.handle_key(key(KeyCode::Tab));

        screen.handle_key(key(KeyCode::Char('o')));

        assert_eq!(
            screen.insights_query_input.value,
            "fields @timestamp, @logStream, @message\n| filter @message like /o/\n| sort @timestamp asc\n| limit 500"
        );
    }

    #[test]
    fn pasting_full_query_replaces_pristine_insights_template() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.set_focus(CwFocus::QueryInput);
        screen.handle_key(key(KeyCode::Tab));

        screen.handle_paste("fields @timestamp\n| limit 20");

        assert_eq!(
            screen.insights_query_input.value,
            "fields @timestamp\n| limit 20"
        );
    }

    #[test]
    fn enter_in_query_saves_history() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::QueryInput;
        screen.query_input.value = "some query".into();

        screen.handle_key(key(KeyCode::Enter));
        assert_eq!(screen.query_history, vec!["some query"]);
    }

    #[test]
    fn empty_query_not_saved_to_history() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::QueryInput;
        screen.query_input.value.clear();

        screen.handle_key(key(KeyCode::Enter));
        assert!(screen.query_history.is_empty());
    }

    // ── Results ──

    #[test]
    fn set_events_clears_query_results() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.query_results = vec![vec![QueryResultField {
            field: "f".into(),
            value: "v".into(),
        }]];

        screen.set_events(
            vec![LogEvent {
                timestamp: 1000,
                message: "hello".into(),
                log_stream_name: None,
                ingestion_time: None,
                event_id: None,
            }],
            None,
        );

        assert_eq!(screen.events.len(), 1);
        assert!(screen.query_results.is_empty());
        assert!(!screen.is_loading());
    }

    #[test]
    fn set_query_results_clears_events() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.events = vec![LogEvent {
            timestamp: 1000,
            message: "old".into(),
            log_stream_name: None,
            ingestion_time: None,
            event_id: None,
        }];

        screen.set_query_results(GetQueryResultsResponse {
            status: QueryStatus::Complete,
            results: vec![vec![QueryResultField {
                field: "@message".into(),
                value: "new".into(),
            }]],
            statistics: None,
        });

        assert!(screen.events.is_empty());
        assert_eq!(screen.query_results.len(), 1);
        assert_eq!(screen.query_status, Some(QueryStatus::Complete));
    }

    #[test]
    fn sanitizes_ansi_sequences_before_tui_rendering() {
        let raw = "\x1b[36mMaster Load\x1b[0m \x1b[34mSELECT\x1b[0m\r\nnext\x1b]0;title\x07";

        assert_eq!(sanitize_log_text_for_tui(raw), "Master Load SELECT\nnext");
    }

    #[test]
    fn sanitizer_preserves_crlf_and_cr_only_line_breaks() {
        assert_eq!(sanitize_log_text_for_tui("a\r\nb\rc"), "a\nb\nc");
    }

    // ── Sanitizer boundary cases ─────────────────────────────────────

    #[test]
    fn sanitizer_returns_empty_string_for_empty_input() {
        assert_eq!(sanitize_log_text_for_tui(""), "");
    }

    #[test]
    fn sanitizer_returns_unchanged_text_when_no_escapes_present() {
        let plain = "INFO 2026-05-19 web-01 starting up";
        assert_eq!(sanitize_log_text_for_tui(plain), plain);
    }

    #[test]
    fn sanitizer_preserves_unicode_characters_outside_ascii() {
        let unicode = "錯誤訊息 ✓ 🎉 한국어 中文";
        assert_eq!(sanitize_log_text_for_tui(unicode), unicode);
    }

    #[test]
    fn sanitizer_preserves_tab_within_log_message() {
        assert_eq!(
            sanitize_log_text_for_tui("level\tINFO\tmsg\thello"),
            "level\tINFO\tmsg\thello"
        );
    }

    #[test]
    fn sanitizer_strips_csi_color_sequence_emitted_by_log4j_color_appender() {
        // Typical "\e[31mERROR\e[0m" coloring from Java/Python apps that
        // detect a TTY and emit ANSI colors.
        let raw = "\x1b[31mERROR\x1b[0m: pipeline failed";
        assert_eq!(sanitize_log_text_for_tui(raw), "ERROR: pipeline failed");
    }

    #[test]
    fn sanitizer_strips_csi_cursor_move_sequences() {
        // Cursor moves are a real injection vector: a log line that
        // contains `\e[2J\e[H` would clear the host terminal.
        let raw = "evil\x1b[2J\x1b[Hbenign";
        assert_eq!(sanitize_log_text_for_tui(raw), "evilbenign");
    }

    #[test]
    fn sanitizer_strips_osc_title_with_bel_terminator() {
        let raw = "msg\x1b]0;hijacked title\x07tail";
        assert_eq!(sanitize_log_text_for_tui(raw), "msgtail");
    }

    #[test]
    fn sanitizer_strips_osc_title_with_st_terminator() {
        // OSC strings may end with `ESC \\` (String Terminator) instead of BEL.
        let raw = "msg\x1b]0;hijacked title\x1b\\tail";
        assert_eq!(sanitize_log_text_for_tui(raw), "msgtail");
    }

    #[test]
    fn sanitizer_strips_dcs_p_sequence() {
        // Device Control String: ESC P ... ST
        let raw = "head\x1b\x50payload\x1b\\tail";
        assert_eq!(sanitize_log_text_for_tui(raw), "headtail");
    }

    #[test]
    fn sanitizer_strips_sos_underscore_sequence() {
        // Start of String: ESC _ ... ST
        let raw = "head\x1b_payload\x1b\\tail";
        assert_eq!(sanitize_log_text_for_tui(raw), "headtail");
    }

    #[test]
    fn sanitizer_strips_pm_caret_sequence() {
        // Privacy Message: ESC ^ ... ST
        let raw = "head\x1b^secret\x1b\\tail";
        assert_eq!(sanitize_log_text_for_tui(raw), "headtail");
    }

    #[test]
    fn sanitizer_consumes_lone_escape_at_end_of_input_without_panicking() {
        // ESC with nothing following (truncated stream)
        let raw = "msg\x1b";
        assert_eq!(sanitize_log_text_for_tui(raw), "msg");
    }

    #[test]
    fn sanitizer_drops_other_escape_two_char_sequences() {
        // ESC + non-bracket char (e.g. reverse index `ESC M`,
        // next-line `ESC E`) gets stripped as a two-char sequence
        // (the ESC and the following char are consumed; surrounding
        // text is preserved verbatim).
        let raw = "before\x1bMafter";
        assert_eq!(sanitize_log_text_for_tui(raw), "beforeafter");
    }

    #[test]
    fn sanitizer_drops_csi_without_terminator_to_end_of_input() {
        // Malformed/unterminated CSI swallows the rest of the input.
        // This is intentional — better to drop than to leak escape
        // bytes into the terminal.
        let raw = "before\x1b[31;1;0";
        assert_eq!(sanitize_log_text_for_tui(raw), "before");
    }

    #[test]
    fn sanitizer_drops_osc_without_terminator_to_end_of_input() {
        let raw = "before\x1b]0;runaway title";
        assert_eq!(sanitize_log_text_for_tui(raw), "before");
    }

    #[test]
    fn sanitizer_handles_double_escape_by_consuming_first_as_other() {
        // `\x1b\x1b[31m`: the outer ESC takes its peek branch, sees
        // another ESC (not `[` / `]` / `P` / `_` / `^`), so it
        // consumes that inner ESC as the "other escape + 1 char" path.
        // Result: the remaining `[31m` are emitted as literal text.
        let raw = "\x1b\x1b[31mfoo";
        assert_eq!(sanitize_log_text_for_tui(raw), "[31mfoo");
    }

    #[test]
    fn sanitizer_handles_multiple_sequences_back_to_back() {
        let raw = "\x1b[31m\x1b[1m\x1b[4mbold red underline\x1b[0m\x1b[0m\x1b[0mEND";
        assert_eq!(sanitize_log_text_for_tui(raw), "bold red underlineEND");
    }

    #[test]
    fn sanitizer_drops_non_printing_control_characters_other_than_tab_newline() {
        // BEL (\x07) would ring the host terminal's bell — drop it.
        // BS (\x08) would overwrite previous char — drop it.
        // VT (\x0b) / FF (\x0c) — drop them.
        let raw = "a\x07b\x08c\x0bd\x0ce";
        assert_eq!(sanitize_log_text_for_tui(raw), "abcde");
    }

    #[test]
    fn sanitizer_drops_form_feed_but_preserves_following_text() {
        // Regression: VT/FF characters can appear in Java stack traces;
        // we drop them but must not drop neighbouring printable text.
        let raw = "java.lang.NullPointerException\x0c\tat com.foo.Bar";
        assert_eq!(
            sanitize_log_text_for_tui(raw),
            "java.lang.NullPointerException\tat com.foo.Bar"
        );
    }

    #[test]
    fn sanitizer_terminates_under_pathological_input_with_thousand_escapes() {
        // Build a 10_000-char input of repeated unterminated CSI starts.
        // The sanitizer must terminate without consuming exponential
        // CPU and must produce a finite string.
        let mut raw = String::with_capacity(10_000);
        for _ in 0..1_000 {
            raw.push_str("a\x1b[31m");
        }
        let sanitized = sanitize_log_text_for_tui(&raw);

        // All "a" survive; all CSI strip.
        assert_eq!(sanitized, "a".repeat(1_000));
    }

    #[test]
    fn sanitizer_preview_truncates_to_200_characters() {
        let long = "x".repeat(500);
        let preview = sanitize_log_preview_for_tui(&long);
        assert_eq!(preview.chars().count(), 200);
        assert_eq!(preview, "x".repeat(200));
    }

    #[test]
    fn sanitizer_preview_strips_escapes_before_truncating() {
        // Without sanitizing first, the 200-char window could fall
        // inside an escape sequence and leak partial bytes.
        let raw = format!("\x1b[31m{}", "a".repeat(500));
        let preview = sanitize_log_preview_for_tui(&raw);
        assert!(!preview.contains('\x1b'));
        assert!(preview.starts_with('a'));
    }

    #[test]
    fn sanitizer_keeps_unicode_when_truncating_preview() {
        // 250 chars of multi-byte unicode — preview must not slice
        // through a UTF-8 boundary.
        let raw = "錯".repeat(250);
        let preview = sanitize_log_preview_for_tui(&raw);
        assert_eq!(preview.chars().count(), 200);
        assert!(preview.chars().all(|c| c == '錯'));
    }

    #[test]
    fn set_events_caches_sanitized_display_text() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.set_events(
            vec![LogEvent {
                timestamp: 1000,
                message: "\x1b[36mMaster Load\x1b[0m".into(),
                log_stream_name: None,
                ingestion_time: None,
                event_id: None,
            }],
            None,
        );

        assert_eq!(screen.event_detail_texts, vec!["Master Load"]);
        assert_eq!(screen.event_preview_texts, vec!["Master Load"]);
    }

    #[test]
    fn sanitizes_ansi_sequences_inside_query_result_details() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.set_query_results(GetQueryResultsResponse {
            status: QueryStatus::Complete,
            results: vec![vec![QueryResultField {
                field: "@message".into(),
                value: "\x1b[36mSQL\x1b[0m".into(),
            }]],
            statistics: None,
        });

        assert_eq!(screen.query_result_detail_texts, vec!["@message: SQL"]);
        assert_eq!(screen.query_result_preview_texts, vec!["SQL"]);
    }

    #[test]
    fn x_in_results_table_exports_json() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::ResultsTable;

        let action = screen.handle_key(key(KeyCode::Char('x')));
        assert!(matches!(action, Action::ExportResults(ExportFormat::Json)));
    }

    // ── on_enter lifecycle ──

    #[test]
    fn on_enter_refreshes_log_groups() {
        let mut screen = CloudWatchSearchScreen::new();
        let actions = screen.on_enter();
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::RefreshLogGroups)));
        assert!(matches!(screen.focus, CwFocus::LogGroupList));
    }

    // ── Loading / error ──

    #[test]
    fn loading_and_error_state() {
        let mut screen = CloudWatchSearchScreen::new();

        screen.set_loading(CloudWatchLoadingKind::SearchingLogs);
        assert_eq!(screen.loading, Some(CloudWatchLoadingKind::SearchingLogs));
        assert!(screen.error.is_none());

        screen.set_error("timeout".into());
        assert!(!screen.is_loading());
        assert_eq!(screen.error.as_deref(), Some("timeout"));
    }

    #[test]
    fn search_loading_overlay_renders_message() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.set_log_groups(test_log_groups());
        screen.set_loading(CloudWatchLoadingKind::SearchingLogs);

        assert!(rendered_text(&mut screen).contains("Searching CloudWatch logs..."));
    }

    #[test]
    fn log_group_loading_overlay_still_renders_message() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.set_loading(CloudWatchLoadingKind::LogGroups);

        assert!(rendered_text(&mut screen).contains("Loading log groups..."));
    }

    #[test]
    fn load_more_loading_keeps_existing_events_and_renders_overlay() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.set_log_groups(test_log_groups());
        screen.set_events(vec![ev(1, "existing")], Some("tok-1".into()));

        screen.set_loading(CloudWatchLoadingKind::LoadingMoreEvents);

        assert_eq!(screen.events.len(), 1);
        let rendered = rendered_text(&mut screen);
        assert!(rendered.contains("Loading more events..."));
        assert!(rendered.contains("[    ] Loading more events..."));
    }

    #[test]
    fn insights_non_terminal_status_keeps_loading() {
        for status in [
            QueryStatus::Scheduled,
            QueryStatus::Running,
            QueryStatus::Unknown,
        ] {
            let mut screen = CloudWatchSearchScreen::new();
            screen.set_loading(CloudWatchLoadingKind::WaitingForInsightsResults);

            screen.set_query_results(query_response(status));

            assert_eq!(
                screen.loading,
                Some(CloudWatchLoadingKind::WaitingForInsightsResults)
            );
        }
    }

    #[test]
    fn insights_terminal_status_stops_loading() {
        for status in [
            QueryStatus::Complete,
            QueryStatus::Failed,
            QueryStatus::Cancelled,
            QueryStatus::Timeout,
        ] {
            let mut screen = CloudWatchSearchScreen::new();
            screen.set_loading(CloudWatchLoadingKind::WaitingForInsightsResults);

            screen.set_query_results(query_response(status));

            assert!(!screen.is_loading());
        }
    }

    // ── Time range (B + C) ──

    fn key_shift(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::SHIFT,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    #[test]
    fn default_time_range_is_one_hour_preset() {
        let screen = CloudWatchSearchScreen::new();
        assert_eq!(
            screen.time_range,
            TimeRange::Preset(TimeRangePreset::OneHour)
        );
    }

    #[test]
    fn r_cycles_preset_when_focus_is_log_group_list() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::LogGroupList;

        screen.handle_key(key(KeyCode::Char('r')));
        assert_eq!(
            screen.time_range,
            TimeRange::Preset(TimeRangePreset::ThreeHours)
        );
        screen.handle_key(key(KeyCode::Char('r')));
        screen.handle_key(key(KeyCode::Char('r')));
        assert_eq!(
            screen.time_range,
            TimeRange::Preset(TimeRangePreset::TwentyFourHours)
        );
        screen.handle_key(key(KeyCode::Char('r')));
        assert_eq!(
            screen.time_range,
            TimeRange::Preset(TimeRangePreset::OneHour)
        );
    }

    #[test]
    fn r_ignored_in_query_input_so_user_can_type_r() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::QueryInput;
        screen.query_input.focused = true;

        screen.handle_key(key(KeyCode::Char('r')));
        // Range untouched
        assert_eq!(
            screen.time_range,
            TimeRange::Preset(TimeRangePreset::OneHour)
        );
        // The literal 'r' was forwarded to the query input
        assert_eq!(screen.query_input.value, "r");
    }

    #[test]
    fn r_ignored_in_log_group_filter_so_user_can_type_r() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::LogGroupFilter;
        screen.log_group_filter.focused = true;

        screen.handle_key(key(KeyCode::Char('r')));
        assert_eq!(
            screen.time_range,
            TimeRange::Preset(TimeRangePreset::OneHour)
        );
        assert_eq!(screen.log_group_filter.value, "r");
    }

    #[test]
    fn shift_r_opens_modal_and_esc_closes_it() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::LogGroupList;

        screen.handle_key(key_shift(KeyCode::Char('R')));
        assert!(screen.time_range_modal.is_some());

        screen.handle_key(key(KeyCode::Esc));
        assert!(screen.time_range_modal.is_none());
        // Range was not modified by cancel
        assert_eq!(
            screen.time_range,
            TimeRange::Preset(TimeRangePreset::OneHour)
        );
    }

    #[test]
    fn shift_r_ignored_while_loading() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::LogGroupList;
        screen.set_loading(CloudWatchLoadingKind::SearchingLogs);

        screen.handle_key(key_shift(KeyCode::Char('R')));
        assert!(screen.time_range_modal.is_none());
    }

    #[test]
    fn modal_submit_via_enter_applies_custom_range() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::LogGroupList;

        // Open modal — prefilled with now-1h / now.
        screen.handle_key(key_shift(KeyCode::Char('R')));
        // Replace start/end fields explicitly.
        if let Some(modal) = screen.time_range_modal.as_mut() {
            modal.start.value = "2026-05-01 00:00".into();
            modal.start.cursor_pos = modal.start.value.chars().count();
            modal.end.value = "2026-05-08 00:00".into();
            modal.end.cursor_pos = modal.end.value.chars().count();
        }

        // Submit via Enter while modal is open.
        screen.handle_key(key(KeyCode::Enter));
        assert!(
            screen.time_range_modal.is_none(),
            "modal should close on submit"
        );
        match screen.time_range {
            TimeRange::Custom {
                start_secs,
                end_secs,
            } => {
                assert_eq!(end_secs - start_secs, 7 * 86_400);
            }
            other => panic!("expected Custom range, got {:?}", other),
        }
    }

    #[test]
    fn modal_ctrl_r_resets_to_one_hour_and_closes() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::LogGroupList;
        // Start with a Custom range so reset is observable.
        screen
            .time_range
            .set_custom(1_777_989_600, 1_777_989_600 + 86_400)
            .unwrap();

        screen.handle_key(key_shift(KeyCode::Char('R')));
        assert!(screen.time_range_modal.is_some());

        let ctrl_r = KeyEvent {
            code: KeyCode::Char('r'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        };
        screen.handle_key(ctrl_r);
        assert!(screen.time_range_modal.is_none());
        assert_eq!(
            screen.time_range,
            TimeRange::Preset(TimeRangePreset::OneHour)
        );
    }

    #[test]
    fn mode_switch_via_tab_preserves_range() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::LogGroupList;

        // Cycle to 6h.
        screen.handle_key(key(KeyCode::Char('r')));
        screen.handle_key(key(KeyCode::Char('r')));
        assert_eq!(
            screen.time_range,
            TimeRange::Preset(TimeRangePreset::SixHours)
        );

        // Now move to query input and toggle search mode.
        screen.handle_key(key(KeyCode::Tab)); // → QueryInput
        screen.handle_key(key(KeyCode::Tab)); // → toggles search_mode

        // Range still 6h after mode flip.
        assert_eq!(
            screen.time_range,
            TimeRange::Preset(TimeRangePreset::SixHours)
        );
    }

    #[test]
    fn cycling_from_custom_returns_to_one_hour() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::LogGroupList;
        screen
            .time_range
            .set_custom(1_777_989_600, 1_777_989_600 + 86_400)
            .unwrap();

        screen.handle_key(key(KeyCode::Char('r')));
        assert_eq!(
            screen.time_range,
            TimeRange::Preset(TimeRangePreset::OneHour)
        );
    }

    // ── Pagination ──

    fn ev(ts: i64, msg: &str) -> LogEvent {
        LogEvent {
            timestamp: ts,
            message: msg.into(),
            log_stream_name: None,
            ingestion_time: None,
            event_id: None,
        }
    }

    #[test]
    fn set_events_with_next_token_marks_has_more() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.set_events(vec![ev(1, "a")], Some("tok-1".into()));
        assert!(screen.has_more);
        assert_eq!(screen.last_next_token.as_deref(), Some("tok-1"));
    }

    #[test]
    fn set_events_without_next_token_clears_has_more() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.last_next_token = Some("stale".into());
        screen.has_more = true;

        screen.set_events(vec![ev(1, "a")], None);
        assert!(!screen.has_more);
        assert!(screen.last_next_token.is_none());
    }

    #[test]
    fn append_events_extends_existing_and_updates_token() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.set_events(vec![ev(1, "a"), ev(2, "b")], Some("tok-1".into()));
        assert_eq!(screen.events.len(), 2);

        screen.append_events(vec![ev(3, "c")], Some("tok-2".into()));
        assert_eq!(screen.events.len(), 3);
        assert_eq!(screen.last_next_token.as_deref(), Some("tok-2"));
        assert!(screen.has_more);
    }

    #[test]
    fn append_events_with_no_next_token_marks_end() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.set_events(vec![ev(1, "a")], Some("tok-1".into()));
        screen.append_events(vec![ev(2, "b")], None);
        assert!(!screen.has_more);
        assert!(screen.last_next_token.is_none());
        assert_eq!(screen.events.len(), 2);
    }

    #[test]
    fn n_key_returns_load_more_when_focus_results_and_has_more() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::ResultsTable;
        screen.set_events(vec![ev(1, "a")], Some("tok-1".into()));

        let action = screen.handle_key(key(KeyCode::Char('n')));
        assert!(matches!(action, Action::LoadMoreFilterResults));
    }

    #[test]
    fn footer_splits_status_from_key_hints() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::ResultsTable;
        screen.set_events(vec![ev(1, "a")], Some("tok-1".into()));

        let status = screen.footer_status_text(false);
        let hints = screen.footer_hint_text(false);

        assert_eq!(status, "1+ results | range: 1h | n: more");
        assert!(hints.contains("Enter detail"));
        assert!(!status.contains("Enter"));
        assert!(!status.contains("Esc"));
    }

    #[test]
    fn footer_error_is_truncated() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.set_error("x".repeat(120));

        let status = screen.footer_status_text(false);

        assert!(status.starts_with("Error: "));
        assert!(status.ends_with('…'));
        assert!(status.chars().count() <= "Error: ".chars().count() + 81);
    }

    #[test]
    fn n_key_ignored_when_no_more_pages() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::ResultsTable;
        screen.set_events(vec![ev(1, "a")], None);

        let action = screen.handle_key(key(KeyCode::Char('n')));
        // Falls through to SelectableTable, not LoadMore.
        assert!(!matches!(action, Action::LoadMoreFilterResults));
    }

    #[test]
    fn n_key_ignored_in_log_group_list() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::LogGroupList;
        // Even with has_more=true, focus must be ResultsTable to load more.
        screen.set_events(vec![ev(1, "a")], Some("tok-1".into()));

        let action = screen.handle_key(key(KeyCode::Char('n')));
        assert!(!matches!(action, Action::LoadMoreFilterResults));
    }

    #[test]
    fn n_key_ignored_while_loading() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::ResultsTable;
        screen.set_events(vec![ev(1, "a")], Some("tok-1".into()));
        screen.set_loading(CloudWatchLoadingKind::LoadingMoreEvents);

        let action = screen.handle_key(key(KeyCode::Char('n')));
        assert!(!matches!(action, Action::LoadMoreFilterResults));
    }

    #[test]
    fn esc_from_loading_results_cancels_cloudwatch_request() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.focus = CwFocus::ResultsTable;
        screen.set_loading(CloudWatchLoadingKind::SearchingLogs);

        let action = screen.handle_key(key(KeyCode::Esc));

        assert!(matches!(action, Action::CancelCloudWatchRequest));
        assert!(matches!(screen.focus, CwFocus::LogGroupList));
    }

    #[test]
    fn cycle_account_resets_pagination() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.set_entitlements(test_entitlements());
        screen.set_events(vec![ev(1, "a")], Some("tok-1".into()));
        assert!(screen.has_more);

        screen.cycle_account(true);
        assert!(!screen.has_more);
        assert!(screen.last_next_token.is_none());
    }

    #[test]
    fn set_query_results_resets_pagination() {
        let mut screen = CloudWatchSearchScreen::new();
        screen.set_events(vec![ev(1, "a")], Some("tok-1".into()));
        assert!(screen.has_more);

        screen.set_query_results(GetQueryResultsResponse {
            status: QueryStatus::Complete,
            results: vec![],
            statistics: None,
        });
        assert!(!screen.has_more);
        assert!(screen.last_next_token.is_none());
    }
}
