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
use crate::widgets::input::TextInput;
use crate::widgets::table::SelectableTable;

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

pub struct CloudWatchSearchScreen {
    pub log_groups: Vec<LogGroup>,
    pub events: Vec<LogEvent>,
    pub query_results: Vec<Vec<QueryResultField>>,
    pub query_status: Option<QueryStatus>,
    pub query_id: Option<String>,
    pub loading: bool,
    pub error: Option<String>,

    // Entitlement-derived scope for CloudWatch queries
    pub selected_account_id: String,
    pub selected_region: String,
    pub selected_log_group: String,

    /// All available accounts and regions from entitlements, for cycling
    pub available_accounts: Vec<String>,
    pub available_regions: Vec<String>,

    pub query_input: TextInput,
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
    /// Optional custom-range modal overlay. When `Some`, all key events are
    /// routed to the modal instead of the screen.
    time_range_modal: Option<TimeRangeModal>,
}

impl Default for CloudWatchSearchScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudWatchSearchScreen {
    pub fn new() -> Self {
        Self {
            log_groups: Vec::new(),
            events: Vec::new(),
            query_results: Vec::new(),
            query_status: None,
            query_id: None,
            loading: false,
            error: None,
            selected_account_id: String::new(),
            selected_region: String::new(),
            selected_log_group: String::new(),
            available_accounts: Vec::new(),
            available_regions: Vec::new(),
            query_input: TextInput::new("Filter pattern / Insights query"),
            scope_transition: None,
            loading_spinner: LoadingIndicator::new("Loading log groups..."),
            fetch_generation: 0,
            search_mode: SearchMode::QuickSearch,
            focus: CwFocus::LogGroupList,
            log_group_filter: TextInput::new("Search log groups..."),
            filtered_indices: Vec::new(),
            log_group_table: SelectableTable::new(
                vec!["Log Group".into(), "Retention".into(), "Size".into()],
                vec![
                    Constraint::Min(40),
                    Constraint::Length(12),
                    Constraint::Length(12),
                ],
            ),
            table: SelectableTable::new(
                vec!["Timestamp".into(), "Stream".into(), "Message".into()],
                vec![
                    Constraint::Length(24),
                    Constraint::Length(30),
                    Constraint::Min(40),
                ],
            ),
            selected_event: None,
            query_history: Vec::new(),
            time_range: TimeRange::default(),
            time_range_modal: None,
        }
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
        self.loading = false;
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
        self.query_id = None;
        self.query_status = None;
        self.table.set_row_count(0);
        self.selected_event = None;
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

    pub fn set_events(&mut self, events: Vec<LogEvent>) {
        self.table.set_row_count(events.len());
        self.events = events;
        // Clear stale Insights results so exports and rendering don't
        // accidentally use old query_results instead of the new events.
        self.query_results.clear();
        self.query_id = None;
        self.loading = false;
        self.error = None;
    }

    pub fn set_query_results(&mut self, results: GetQueryResultsResponse) {
        self.query_status = Some(results.status);
        self.table.set_row_count(results.results.len());
        self.query_results = results.results;
        // Clear stale quick-search events so detail pane and export
        // don't accidentally use old FilterLogEvents data.
        self.events.clear();
        self.loading = false;
        self.error = None;
    }

    pub fn set_loading(&mut self) {
        self.loading = true;
        self.error = None;
    }

    /// Bump log-group fetch generation. Called only when starting a log-group refresh.
    pub fn advance_fetch_generation(&mut self) {
        self.fetch_generation += 1;
    }

    pub fn set_error(&mut self, err: String) {
        self.loading = false;
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

    fn render_event_detail(&self, area: Rect, buf: &mut Buffer) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Event Detail ")
            .border_style(Style::default().fg(Color::Yellow));
        let inner = block.inner(area);
        block.render(area, buf);

        if let Some(idx) = self.table.selected() {
            // Show detail from FilterLogEvents or Insights query results
            let detail_text = if let Some(event) = self.events.get(idx) {
                Some(event.message.clone())
            } else if let Some(row) = self.query_results.get(idx) {
                // Format Insights result row as key=value pairs
                Some(
                    row.iter()
                        .map(|f| format!("{}: {}", f.field, f.value))
                        .collect::<Vec<_>>()
                        .join("\n"),
                )
            } else {
                None
            };

            if let Some(ref message) = detail_text {
                let style = if message.contains("\"ERROR\"")
                    || message.contains("\"level\":\"ERROR\"")
                {
                    Style::default().fg(Color::Red)
                } else if message.contains("\"WARN\"") || message.contains("\"level\":\"WARN\"") {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::White)
                };

                Paragraph::new(message.as_str())
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
                    self.focus = CwFocus::LogGroupList;
                    Action::Noop
                }
                CwFocus::QueryInput => {
                    self.focus = CwFocus::LogGroupList;
                    self.query_input.focused = false;
                    Action::Noop
                }
                CwFocus::EventDetail => {
                    self.focus = CwFocus::ResultsTable;
                    Action::Noop
                }
                CwFocus::ResultsTable => {
                    self.focus = CwFocus::LogGroupList;
                    Action::Noop
                }
            },
            KeyCode::Tab => {
                match self.focus {
                    CwFocus::LogGroupList | CwFocus::LogGroupFilter => {
                        self.log_group_filter.focused = false;
                        self.focus = CwFocus::QueryInput;
                        self.query_input.focused = true;
                    }
                    CwFocus::QueryInput => {
                        // Toggle search mode
                        self.search_mode = match self.search_mode {
                            SearchMode::QuickSearch => SearchMode::InsightsQuery,
                            SearchMode::InsightsQuery => SearchMode::QuickSearch,
                        };
                        self.query_input.label = match self.search_mode {
                            SearchMode::QuickSearch => "Filter pattern".into(),
                            SearchMode::InsightsQuery => "Insights query".into(),
                        };
                    }
                    CwFocus::ResultsTable | CwFocus::EventDetail => {
                        self.focus = CwFocus::LogGroupList;
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
                    && !self.loading =>
            {
                self.time_range_modal = Some(TimeRangeModal::open(&self.time_range));
                Action::Noop
            }
            // `/` in log group list → activate log group filter
            KeyCode::Char('/') if matches!(self.focus, CwFocus::LogGroupList) => {
                self.focus = CwFocus::LogGroupFilter;
                self.log_group_filter.focused = true;
                Action::Noop
            }
            // `/` elsewhere (except text inputs) → jump to query input
            KeyCode::Char('/')
                if !matches!(self.focus, CwFocus::QueryInput | CwFocus::LogGroupFilter) =>
            {
                self.focus = CwFocus::QueryInput;
                self.query_input.focused = true;
                Action::Noop
            }
            KeyCode::Enter => match self.focus {
                CwFocus::LogGroupFilter => {
                    // Accept filter and go back to list navigation
                    self.log_group_filter.focused = false;
                    self.focus = CwFocus::LogGroupList;
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
                    self.focus = CwFocus::QueryInput;
                    self.query_input.focused = true;
                    Action::Noop
                }
                CwFocus::QueryInput => {
                    let query = self.query_input.value.clone();
                    if !query.is_empty() {
                        self.query_history.push(query);
                    }
                    self.focus = CwFocus::ResultsTable;
                    self.query_input.focused = false;
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
                    CwFocus::QueryInput => {
                        self.query_input.handle_key(key);
                    }
                    CwFocus::ResultsTable | CwFocus::EventDetail => {
                        self.table.handle_key(key);
                    }
                }
                Action::Noop
            }
        }
    }

    fn render(&mut self, area: Rect, buf: &mut Buffer) {
        let outer = Block::default()
            .borders(Borders::ALL)
            .title(" CloudWatch Search ")
            .border_style(Style::default().fg(Color::Cyan));
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
            Span::styled(acct_label, Style::default().fg(Color::Yellow)),
            Span::styled(" │ ", Style::default().fg(Color::DarkGray)),
            Span::styled(region_label, Style::default().fg(Color::Cyan)),
        ]);
        Paragraph::new(scope_line).render(left_chunks[0], buf);

        // Log group filter input
        self.log_group_filter.render(left_chunks[1], buf);

        // Log group table (use filtered_indices)
        let lg_border_color =
            if matches!(self.focus, CwFocus::LogGroupList | CwFocus::LogGroupFilter) {
                Color::Green
            } else {
                Color::Cyan
            };
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
                Style::default().fg(Color::Green)
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
                .map(|h| Cell::from(h.as_str()).style(Style::default().bold().fg(Color::Cyan))),
        )
        .height(1);
        let lg_table = ratatui::widgets::Table::new(lg_rows, &self.log_group_table.column_widths)
            .header(lg_header)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {} ", lg_title))
                    .border_style(Style::default().fg(lg_border_color)),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::Indexed(236))
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");
        ratatui::widgets::StatefulWidget::render(
            lg_table,
            left_chunks[2],
            buf,
            &mut self.log_group_table.state,
        );

        // ── Right panel: mode + query + results + status ──
        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // Mode indicator
                Constraint::Length(3), // Query input
                Constraint::Min(5),    // Results
                Constraint::Length(2), // Status
            ])
            .split(panels[1]);

        // Mode indicator
        let mode_text = match self.search_mode {
            SearchMode::QuickSearch => "[Quick Search (FilterLogEvents)] Tab to switch mode",
            SearchMode::InsightsQuery => "[Insights Query (StartQuery)]    Tab to switch mode",
        };
        Paragraph::new(mode_text)
            .style(Style::default().fg(Color::Cyan))
            .render(right_chunks[0], buf);

        // Query input
        self.query_input.render(right_chunks[1], buf);

        // Results
        let result_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(right_chunks[2]);

        let use_insights =
            matches!(self.search_mode, SearchMode::InsightsQuery) && self.query_id.is_some();

        if use_insights {
            let rows = self.query_results.iter().map(|fields| {
                let ts = fields
                    .iter()
                    .find(|f| f.field == "@timestamp")
                    .map(|f| f.value.as_str())
                    .unwrap_or("-");
                let msg = fields
                    .iter()
                    .find(|f| f.field == "@message")
                    .map(|f| f.value.as_str())
                    .unwrap_or("-");
                let stream = fields
                    .iter()
                    .find(|f| f.field == "@logStream")
                    .map(|f| f.value.as_str())
                    .unwrap_or("-");

                let msg_style = if msg.contains("ERROR") {
                    Style::default().fg(Color::Red)
                } else if msg.contains("WARN") {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                };

                Row::new(vec![
                    Cell::from(ts.to_string()),
                    Cell::from(stream.to_string()),
                    Cell::from(msg.chars().take(200).collect::<String>()).style(msg_style),
                ])
            });
            self.table
                .render_with_rows(rows, "Insights Results", result_chunks[0], buf);
        } else {
            let rows = self.events.iter().map(|ev| {
                let ts = chrono::DateTime::from_timestamp_millis(ev.timestamp)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
                    .unwrap_or_else(|| ev.timestamp.to_string());

                let msg_style = if ev.message.contains("ERROR") {
                    Style::default().fg(Color::Red)
                } else if ev.message.contains("WARN") {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                };

                Row::new(vec![
                    Cell::from(ts),
                    Cell::from(ev.log_stream_name.as_deref().unwrap_or("-")),
                    Cell::from(ev.message.chars().take(200).collect::<String>()).style(msg_style),
                ])
            });
            self.table
                .render_with_rows(rows, "Results", result_chunks[0], buf);
        }

        // Event detail
        self.render_event_detail(result_chunks[1], buf);

        // Status bar
        let status = if self.loading {
            match &self.query_status {
                Some(qs) => format!("Query status: {:?}", qs),
                None => "Searching...".into(),
            }
        } else if let Some(ref err) = self.error {
            format!("Error: {}", err)
        } else {
            let count = if use_insights {
                self.query_results.len()
            } else {
                self.events.len()
            };
            format!(
                "{} results | range: {} | r: cycle | R: custom | Tab: switch panel | /: query | Enter: select/run | Esc: back",
                count,
                self.time_range.footer_label(),
            )
        };

        Paragraph::new(status)
            .style(if self.error.is_some() {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::Gray)
            })
            .render(right_chunks[3], buf);

        // Loading overlay (first load, no data yet)
        if self.loading && self.log_groups.is_empty() {
            self.loading_spinner.render_overlay(inner, buf);
        }

        // Scope transition overlay
        if let Some(ref t) = self.scope_transition {
            t.render(inner, buf);
        }

        // Custom-range modal (top-most overlay)
        if let Some(ref modal) = self.time_range_modal {
            modal.render(inner, buf);
        }
    }

    fn on_tick(&mut self) {
        if self.loading {
            self.loading_spinner.tick();
        }
        if let Some(ref mut t) = self.scope_transition {
            if !t.tick() {
                self.scope_transition = None;
            }
        }
    }

    fn on_enter(&mut self) -> Vec<Action> {
        self.query_input.focused = false;
        self.focus = CwFocus::LogGroupList;
        vec![Action::RefreshLogGroups]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
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
            allowed_os_users: vec![],
            max_session_seconds: None,
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
        assert!(!screen.loading);
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
        screen.focus = CwFocus::QueryInput;
        screen.search_mode = SearchMode::InsightsQuery;
        screen.query_input.value = "fields @timestamp".into();

        let action = screen.handle_key(key(KeyCode::Enter));
        assert!(matches!(action, Action::RunInsightsQuery));
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

        screen.set_events(vec![LogEvent {
            timestamp: 1000,
            message: "hello".into(),
            log_stream_name: None,
            ingestion_time: None,
            event_id: None,
        }]);

        assert_eq!(screen.events.len(), 1);
        assert!(screen.query_results.is_empty());
        assert!(!screen.loading);
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

        screen.set_loading();
        assert!(screen.loading);
        assert!(screen.error.is_none());

        screen.set_error("timeout".into());
        assert!(!screen.loading);
        assert_eq!(screen.error.as_deref(), Some("timeout"));
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
        assert_eq!(screen.time_range, TimeRange::Preset(TimeRangePreset::OneHour));
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
        screen.loading = true;

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
        assert!(screen.time_range_modal.is_none(), "modal should close on submit");
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
}
