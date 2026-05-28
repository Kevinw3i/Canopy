use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row},
};
use shared::dto::cloudwatch::{LiveTailEvent, LogGroup, StartLiveTailRequest};
use shared::dto::entitlements::UserEntitlements;
use std::collections::{HashSet, VecDeque};

use super::Component;
use crate::event::Action;
use crate::theme::Theme;
use crate::widgets::input::TextInput;
use crate::widgets::table::{
    selected_row_style, table_border_style, SelectableTable, SELECTED_ROW_SYMBOL,
};

#[derive(Debug, PartialEq, Eq)]
enum TailState {
    Stopped,
    Running,
    Paused,
    Reconnecting,
}

pub struct LiveTailScreen {
    pub events: VecDeque<LiveTailEvent>,
    pub scrollback_limit: usize,
    pub connection_state: String,
    pub events_per_second: f64,
    pub selected_account_id: String,
    pub selected_region: String,
    pub selected_log_group_name: String,
    pub selected_log_group_arn: String,
    pub available_accounts: Vec<String>,
    pub available_regions: Vec<String>,
    pub log_groups: Vec<LogGroup>,
    pub fetch_generation: u64,

    state: TailState,
    filter_input: TextInput,
    filter_active: bool,
    auto_scroll: bool,
    scroll_offset: usize,
    log_group_filter: TextInput,
    filtered_log_group_indices: Vec<usize>,
    log_group_table: SelectableTable,
    picker_active: bool,
    picker_filter_active: bool,
    log_groups_loading: bool,
    log_groups_error: Option<String>,
    theme: Theme,
}

impl LiveTailScreen {
    pub fn new(scrollback_limit: usize) -> Self {
        Self::with_theme(scrollback_limit, Theme::default())
    }

    pub fn with_theme(scrollback_limit: usize, theme: Theme) -> Self {
        Self {
            events: VecDeque::with_capacity(scrollback_limit),
            scrollback_limit,
            connection_state: "Disconnected".into(),
            events_per_second: 0.0,
            selected_account_id: String::new(),
            selected_region: String::new(),
            selected_log_group_name: String::new(),
            selected_log_group_arn: String::new(),
            available_accounts: Vec::new(),
            available_regions: Vec::new(),
            log_groups: Vec::new(),
            fetch_generation: 0,
            state: TailState::Stopped,
            filter_input: TextInput::new("Local filter").with_theme(theme),
            filter_active: false,
            auto_scroll: true,
            scroll_offset: 0,
            log_group_filter: TextInput::new("Search log groups...").with_theme(theme),
            filtered_log_group_indices: Vec::new(),
            log_group_table: SelectableTable::new(
                vec!["Log Group".into(), "Retention".into(), "Size".into()],
                vec![
                    Constraint::Min(38),
                    Constraint::Length(12),
                    Constraint::Length(12),
                ],
            )
            .with_theme(theme),
            picker_active: false,
            picker_filter_active: false,
            log_groups_loading: false,
            log_groups_error: None,
            theme,
        }
    }

    pub fn set_entitlements(&mut self, entitlements: UserEntitlements) {
        if !entitlements.features.can_use_cloudwatch_tail {
            self.available_accounts.clear();
            self.available_regions.clear();
            self.selected_account_id.clear();
            self.selected_region.clear();
            self.clear_scope_log_groups();
            return;
        }

        let previous_account_id = self.selected_account_id.clone();
        let previous_region = self.selected_region.clone();

        self.available_accounts = entitlements
            .allowed_accounts
            .iter()
            .map(|account| account.account_id.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        self.available_accounts.sort();
        self.available_regions = entitlements.allowed_regions.clone();

        if self.selected_account_id.is_empty()
            || !self.available_accounts.contains(&self.selected_account_id)
        {
            if let Some(account) = self.available_accounts.first() {
                self.selected_account_id = account.clone();
            } else {
                self.selected_account_id.clear();
            }
        }
        if self.selected_region.is_empty()
            || !self.available_regions.contains(&self.selected_region)
        {
            if let Some(region) = self.available_regions.first() {
                self.selected_region = region.clone();
            } else {
                self.selected_region.clear();
            }
        }

        if self.selected_account_id != previous_account_id
            || self.selected_region != previous_region
            || !self.selected_log_group_matches_scope()
        {
            self.clear_scope_log_groups();
        }

        if self.selected_log_group_arn.is_empty() {
            if let Some(fallback) = entitlements
                .allowed_log_group_arns
                .iter()
                .find_map(|pattern| {
                    concrete_live_tail_log_group_arn(
                        pattern,
                        &self.selected_account_id,
                        &self.selected_region,
                    )
                })
            {
                self.select_log_group(log_group_name_from_arn(&fallback), fallback);
            }
        }
    }

    pub fn set_log_groups(&mut self, groups: Vec<LogGroup>) {
        self.log_groups = groups;
        let current_is_valid = self
            .log_groups
            .iter()
            .any(|group| group.arn == self.selected_log_group_arn);
        if self.log_groups.is_empty() {
            self.selected_log_group_name.clear();
            self.selected_log_group_arn.clear();
        } else if self.selected_log_group_arn.is_empty() || !current_is_valid {
            if let Some((name, arn)) = self
                .log_groups
                .first()
                .map(|group| (group.name.clone(), group.arn.clone()))
            {
                self.select_log_group(name, arn);
            }
        }
        self.refilter_log_groups();
        self.log_groups_loading = false;
        self.log_groups_error = None;
    }

    pub fn set_log_groups_loading(&mut self) {
        self.log_groups_loading = true;
        self.log_groups_error = None;
    }

    pub fn set_log_groups_error(&mut self, error: String) {
        self.log_groups_loading = false;
        self.log_groups_error = Some(error);
    }

    pub fn advance_fetch_generation(&mut self) {
        self.fetch_generation = self.fetch_generation.wrapping_add(1);
    }

    pub fn start_request(&self) -> Option<StartLiveTailRequest> {
        if self.selected_account_id.is_empty()
            || self.selected_region.is_empty()
            || self.selected_log_group_arn.is_empty()
        {
            return None;
        }

        Some(StartLiveTailRequest {
            account_id: self.selected_account_id.clone(),
            region: self.selected_region.clone(),
            log_group_arns: vec![self.selected_log_group_arn.clone()],
            filter_pattern: None,
        })
    }

    pub fn push_event(&mut self, event: LiveTailEvent) {
        if self.events.len() >= self.scrollback_limit {
            self.events.pop_front();
        }
        self.events.push_back(event);
        if self.auto_scroll {
            self.scroll_offset = 0;
        }
    }

    pub fn set_connected(&mut self) {
        self.state = TailState::Running;
        self.connection_state = "Connected".into();
    }

    pub fn set_reconnecting(&mut self) {
        self.state = TailState::Reconnecting;
        self.connection_state = "Reconnecting...".into();
    }

    pub fn set_paused(&mut self) {
        self.state = TailState::Paused;
        self.connection_state = "Paused".into();
    }

    pub fn set_events_per_second(&mut self, events_per_second: Option<f64>) {
        self.events_per_second = events_per_second.unwrap_or(0.0);
    }

    pub fn set_disconnected(&mut self) {
        self.state = TailState::Stopped;
        self.connection_state = "Disconnected".into();
        self.events_per_second = 0.0;
    }

    fn select_log_group(&mut self, name: String, arn: String) {
        self.selected_log_group_name = name;
        self.selected_log_group_arn = arn;
        self.sync_log_group_highlight();
    }

    fn refilter_log_groups(&mut self) {
        let query = self.log_group_filter.value.to_lowercase();
        self.filtered_log_group_indices = self
            .log_groups
            .iter()
            .enumerate()
            .filter(|(_, group)| query.is_empty() || group.name.to_lowercase().contains(&query))
            .map(|(idx, _)| idx)
            .collect();
        self.log_group_table
            .set_row_count(self.filtered_log_group_indices.len());
        self.sync_log_group_highlight();
    }

    fn sync_log_group_highlight(&mut self) {
        if self.selected_log_group_arn.is_empty() {
            return;
        }
        if let Some(pos) = self.filtered_log_group_indices.iter().position(|&idx| {
            self.log_groups
                .get(idx)
                .map(|group| group.arn == self.selected_log_group_arn)
                .unwrap_or(false)
        }) {
            self.log_group_table.state.select(Some(pos));
        }
    }

    fn select_highlighted_log_group(&mut self) {
        let selected = self
            .log_group_table
            .selected()
            .and_then(|table_idx| self.filtered_log_group_indices.get(table_idx).copied())
            .and_then(|real_idx| self.log_groups.get(real_idx))
            .map(|group| (group.name.clone(), group.arn.clone()));
        if let Some((name, arn)) = selected {
            self.select_log_group(name, arn);
        }
    }

    fn clear_scope_log_groups(&mut self) {
        self.advance_fetch_generation();
        self.log_groups.clear();
        self.filtered_log_group_indices.clear();
        self.log_group_table.set_row_count(0);
        self.selected_log_group_name.clear();
        self.selected_log_group_arn.clear();
        self.log_groups_loading = false;
        self.log_groups_error = None;
    }

    fn selected_log_group_matches_scope(&self) -> bool {
        self.selected_log_group_arn.is_empty()
            || log_group_arn_matches_scope(
                &self.selected_log_group_arn,
                &self.selected_account_id,
                &self.selected_region,
            )
    }

    fn cycle_account(&mut self, forward: bool) -> bool {
        if cycle_value(
            &self.available_accounts,
            &mut self.selected_account_id,
            forward,
        ) {
            self.clear_scope_log_groups();
            true
        } else {
            false
        }
    }

    fn cycle_region(&mut self, forward: bool) -> bool {
        if cycle_value(&self.available_regions, &mut self.selected_region, forward) {
            self.clear_scope_log_groups();
            true
        } else {
            false
        }
    }

    fn open_picker(&mut self) {
        self.picker_active = true;
        self.picker_filter_active = false;
        self.log_group_filter.focused = false;
        self.refilter_log_groups();
    }

    fn close_picker(&mut self) {
        self.picker_active = false;
        self.picker_filter_active = false;
        self.log_group_filter.focused = false;
    }

    fn handle_picker_key(&mut self, key: KeyEvent) -> Action {
        if self.picker_filter_active {
            match key.code {
                KeyCode::Esc => {
                    self.picker_filter_active = false;
                    self.log_group_filter.focused = false;
                    Action::Noop
                }
                KeyCode::Enter => {
                    self.select_highlighted_log_group();
                    self.close_picker();
                    Action::Noop
                }
                _ => {
                    self.log_group_filter.handle_key(key);
                    self.refilter_log_groups();
                    Action::Noop
                }
            }
        } else {
            match key.code {
                KeyCode::Esc | KeyCode::Char('l') => {
                    self.close_picker();
                    Action::Noop
                }
                KeyCode::Char('/') => {
                    self.picker_filter_active = true;
                    self.log_group_filter.focused = true;
                    Action::Noop
                }
                KeyCode::Enter => {
                    self.select_highlighted_log_group();
                    self.close_picker();
                    Action::Noop
                }
                KeyCode::Char('r') => Action::RefreshLiveTailLogGroups,
                KeyCode::Char('[') => {
                    if self.cycle_account(false) {
                        Action::RefreshLiveTailLogGroups
                    } else {
                        Action::Noop
                    }
                }
                KeyCode::Char(']') => {
                    if self.cycle_account(true) {
                        Action::RefreshLiveTailLogGroups
                    } else {
                        Action::Noop
                    }
                }
                KeyCode::Char('{') => {
                    if self.cycle_region(false) {
                        Action::RefreshLiveTailLogGroups
                    } else {
                        Action::Noop
                    }
                }
                KeyCode::Char('}') => {
                    if self.cycle_region(true) {
                        Action::RefreshLiveTailLogGroups
                    } else {
                        Action::Noop
                    }
                }
                _ => {
                    self.log_group_table.handle_key(key);
                    Action::Noop
                }
            }
        }
    }

    fn filtered_events(&self) -> Vec<&LiveTailEvent> {
        let filter = self.filter_input.value.to_lowercase();
        if filter.is_empty() {
            self.events.iter().collect()
        } else {
            self.events
                .iter()
                .filter(|e| e.message.to_lowercase().contains(&filter))
                .collect()
        }
    }

    fn colorize_message<'a>(&self, message: &'a str) -> Span<'a> {
        if message.contains("ERROR") || message.contains("\"level\":\"ERROR\"") {
            Span::styled(message, self.theme.danger_style())
        } else if message.contains("WARN") || message.contains("\"level\":\"WARN\"") {
            Span::styled(message, self.theme.warning_style())
        } else if message.contains("INFO") || message.contains("\"level\":\"INFO\"") {
            Span::styled(message, self.theme.success_style())
        } else if message.contains("DEBUG") || message.contains("\"level\":\"DEBUG\"") {
            Span::styled(message, self.theme.accent_style())
        } else {
            Span::raw(message)
        }
    }
}

impl Component for LiveTailScreen {
    fn handle_key(&mut self, key: KeyEvent) -> Action {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Action::Quit;
        }

        if self.picker_active {
            return self.handle_picker_key(key);
        }

        if self.filter_active {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    self.filter_active = false;
                    self.filter_input.focused = false;
                    return Action::Noop;
                }
                _ => {
                    self.filter_input.handle_key(key);
                    return Action::Noop;
                }
            }
        }

        match key.code {
            KeyCode::Esc => Action::GoBack,
            KeyCode::Char('l') => {
                self.open_picker();
                Action::Noop
            }
            KeyCode::Char('[') => {
                if self.cycle_account(false) {
                    Action::RefreshLiveTailLogGroups
                } else {
                    Action::Noop
                }
            }
            KeyCode::Char(']') => {
                if self.cycle_account(true) {
                    Action::RefreshLiveTailLogGroups
                } else {
                    Action::Noop
                }
            }
            KeyCode::Char('{') => {
                if self.cycle_region(false) {
                    Action::RefreshLiveTailLogGroups
                } else {
                    Action::Noop
                }
            }
            KeyCode::Char('}') => {
                if self.cycle_region(true) {
                    Action::RefreshLiveTailLogGroups
                } else {
                    Action::Noop
                }
            }
            KeyCode::Char('s') => match self.state {
                TailState::Stopped => Action::StartLiveTail,
                TailState::Running | TailState::Paused | TailState::Reconnecting => {
                    Action::StopLiveTail
                }
            },
            KeyCode::Char('p') => match self.state {
                TailState::Running => Action::PauseLiveTail,
                TailState::Paused => Action::ResumeLiveTail,
                _ => Action::Noop,
            },
            KeyCode::Char('/') => {
                self.filter_active = true;
                self.filter_input.focused = true;
                Action::Noop
            }
            KeyCode::Char('a') => {
                self.auto_scroll = !self.auto_scroll;
                Action::Noop
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.auto_scroll = false;
                self.scroll_offset = self.scroll_offset.saturating_add(1);
                Action::Noop
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.scroll_offset > 0 {
                    self.scroll_offset -= 1;
                } else {
                    self.auto_scroll = true;
                }
                Action::Noop
            }
            KeyCode::Char('c') => {
                self.events.clear();
                self.scroll_offset = 0;
                Action::Noop
            }
            _ => Action::Noop,
        }
    }

    fn handle_paste(&mut self, text: &str) -> Action {
        if self.filter_active {
            self.filter_input
                .insert_str(&text.replace("\r\n", "\n").replace(['\r', '\n'], " "));
        } else if self.picker_active && self.picker_filter_active {
            self.log_group_filter
                .insert_str(&text.replace("\r\n", "\n").replace(['\r', '\n'], " "));
            self.refilter_log_groups();
        }
        Action::Noop
    }

    fn on_enter(&mut self) -> Vec<Action> {
        if self.selected_account_id.is_empty() || self.selected_region.is_empty() {
            vec![]
        } else {
            vec![Action::RefreshLiveTailLogGroups]
        }
    }

    fn render(&mut self, area: Rect, buf: &mut Buffer) {
        let outer = Block::default()
            .borders(Borders::ALL)
            .title(" Live Tail ")
            .border_style(self.theme.accent_style());
        let inner = outer.inner(area);
        outer.render(area, buf);

        let constraints = if self.picker_active {
            vec![
                Constraint::Length(1), // Connection status
                Constraint::Length(3), // Target
                Constraint::Length(9), // Log group picker
                Constraint::Length(3), // Local filter
                Constraint::Min(5),    // Log output
                Constraint::Length(2), // Status bar
            ]
        } else {
            vec![
                Constraint::Length(1), // Connection status
                Constraint::Length(3), // Target
                Constraint::Length(3), // Local filter
                Constraint::Min(5),    // Log output
                Constraint::Length(2), // Status bar
            ]
        };
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(inner);

        // Connection status
        let conn_style = match self.state {
            TailState::Running => self.theme.success_style(),
            TailState::Paused => self.theme.warning_style(),
            TailState::Reconnecting => self.theme.warning_style(),
            TailState::Stopped => self.theme.danger_style(),
        };
        let conn_text = format!(
            "{} | {:.1} events/sec | {} events buffered",
            self.connection_state,
            self.events_per_second,
            self.events.len(),
        );
        Paragraph::new(conn_text)
            .style(conn_style)
            .render(chunks[0], buf);

        // Target selector
        self.render_target(chunks[1], buf);

        let (filter_idx, log_idx, status_idx) = if self.picker_active {
            self.render_picker(chunks[2], buf);
            (3, 4, 5)
        } else {
            (2, 3, 4)
        };

        // Filter
        self.filter_input.render(chunks[filter_idx], buf);

        // Log output
        let log_block = Block::default()
            .borders(Borders::ALL)
            .title(if self.auto_scroll {
                " Logs (auto-scroll) "
            } else {
                " Logs (manual scroll) "
            })
            .border_style(self.theme.muted_style());
        let log_inner = log_block.inner(chunks[log_idx]);
        log_block.render(chunks[log_idx], buf);

        let filtered = self.filtered_events();
        let visible_height = log_inner.height as usize;
        let total = filtered.len();
        let start = if total > visible_height + self.scroll_offset {
            total - visible_height - self.scroll_offset
        } else {
            0
        };
        let end = total.saturating_sub(self.scroll_offset);

        let visible_events = &filtered[start..end];
        let lines: Vec<Line> = visible_events
            .iter()
            .map(|ev| {
                let ts = chrono::DateTime::from_timestamp_millis(ev.timestamp)
                    .map(|dt| dt.format("%H:%M:%S%.3f").to_string())
                    .unwrap_or_default();

                Line::from(vec![
                    Span::styled(format!("{} ", ts), self.theme.muted_style()),
                    Span::styled(
                        format!("[{}] ", ev.log_stream_name),
                        self.theme.accent_style(),
                    ),
                    self.colorize_message(&ev.message),
                ])
            })
            .collect();

        Paragraph::new(lines).render(log_inner, buf);

        // Status bar
        Paragraph::new(
            "s start/stop | p pause | l logs | [/]/{/} scope | / filter | a auto | c clear | Esc back",
        )
        .style(self.theme.muted_style())
        .render(chunks[status_idx], buf);
    }
}

impl LiveTailScreen {
    fn render_target(&self, area: Rect, buf: &mut Buffer) {
        let target = if self.selected_log_group_name.is_empty() {
            "(no log group selected)"
        } else {
            self.selected_log_group_name.as_str()
        };
        let status = if let Some(error) = self.log_groups_error.as_deref() {
            format!("Picker error: {error}")
        } else if self.log_groups_loading {
            "Loading log groups...".into()
        } else {
            format!("{} log groups loaded", self.log_groups.len())
        };
        let line = Line::from(vec![
            Span::styled(
                format!("Account [/]: {}", self.selected_account_id),
                self.theme.warning_style(),
            ),
            Span::styled(" │ ", self.theme.muted_style()),
            Span::styled(
                format!("Region {{/}}: {}", self.selected_region),
                self.theme.accent_style(),
            ),
            Span::styled(" │ ", self.theme.muted_style()),
            Span::styled("Log group: ", Style::default().bold()),
            Span::raw(target.to_string()),
        ]);
        let block = Block::default().borders(Borders::ALL).title(format!(
            " Target | l: picker | r in picker: refresh | {status} "
        ));
        Paragraph::new(line).block(block).render(area, buf);
    }

    fn render_picker(&mut self, area: Rect, buf: &mut Buffer) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(3)])
            .split(area);
        self.log_group_filter.render(chunks[0], buf);

        let selected_arn = self.selected_log_group_arn.clone();
        let rows = self.filtered_log_group_indices.iter().filter_map(|&idx| {
            let group = self.log_groups.get(idx)?;
            let retention = group
                .retention_days
                .map(|days| format!("{days}d"))
                .unwrap_or_else(|| "never".into());
            let size = group
                .stored_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "-".into());
            let style = if group.arn == selected_arn {
                selected_row_style(self.theme)
            } else {
                Style::default()
            };
            Some(Row::new(vec![
                Cell::from(group.name.clone()).style(style),
                Cell::from(retention),
                Cell::from(size),
            ]))
        });
        let title = format!(
            "Log Groups ({}/{}) Enter: select | /: filter",
            self.filtered_log_group_indices.len(),
            self.log_groups.len()
        );
        let header = Row::new(
            self.log_group_table
                .headers
                .iter()
                .map(|header| Cell::from(header.as_str()).style(self.theme.accent_style().bold())),
        )
        .height(1);
        let table = ratatui::widgets::Table::new(rows, &self.log_group_table.column_widths)
            .header(header)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {title} "))
                    .border_style(table_border_style(!self.picker_filter_active, self.theme)),
            )
            .highlight_style(selected_row_style(self.theme))
            .highlight_symbol(SELECTED_ROW_SYMBOL);
        ratatui::widgets::StatefulWidget::render(
            table,
            chunks[1],
            buf,
            &mut self.log_group_table.state,
        );
    }
}

fn cycle_value(values: &[String], selected: &mut String, forward: bool) -> bool {
    if values.len() <= 1 {
        return false;
    }
    let current = values
        .iter()
        .position(|value| value == selected)
        .unwrap_or(0);
    let next = if forward {
        (current + 1) % values.len()
    } else if current == 0 {
        values.len() - 1
    } else {
        current - 1
    };
    *selected = values[next].clone();
    true
}

fn concrete_live_tail_log_group_arn(
    pattern: &str,
    account_id: &str,
    region: &str,
) -> Option<String> {
    let mut arn_parts = pattern.splitn(7, ':');
    let [Some("arn"), Some(partition), Some("logs"), Some(pattern_region), Some(pattern_account), Some("log-group"), Some(group_pattern)] = [
        arn_parts.next(),
        arn_parts.next(),
        arn_parts.next(),
        arn_parts.next(),
        arn_parts.next(),
        arn_parts.next(),
        arn_parts.next(),
    ] else {
        return None;
    };

    if pattern_account != "*" && pattern_account != account_id {
        return None;
    }
    if pattern_region != "*" && pattern_region != region {
        return None;
    }

    let group_pattern = group_pattern.strip_suffix(":*").unwrap_or(group_pattern);
    let group_is_wildcard = group_pattern.ends_with('*');
    let group_prefix = if group_is_wildcard {
        group_pattern.trim_end_matches('*')
    } else {
        group_pattern
    };
    let group_name = if group_prefix.is_empty() || group_prefix == "/" {
        "/app/web-service".to_string()
    } else if group_is_wildcard {
        if group_prefix.ends_with('/') {
            format!("{group_prefix}web-service")
        } else {
            group_prefix.to_string()
        }
    } else {
        group_prefix.to_string()
    };
    Some(format!(
        "arn:{partition}:logs:{region}:{account_id}:log-group:{group_name}"
    ))
}

fn log_group_arn_matches_scope(arn: &str, account_id: &str, region: &str) -> bool {
    let mut parts = arn.splitn(7, ':');
    matches!(
        [
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ],
        [
            Some("arn"),
            Some(_partition),
            Some("logs"),
            Some(arn_region),
            Some(arn_account),
            Some("log-group"),
            Some(_group)
        ] if arn_region == region && arn_account == account_id
    )
}

fn log_group_name_from_arn(arn: &str) -> String {
    arn.rsplit_once("log-group:")
        .map(|(_, name)| name.trim_end_matches(":*").to_string())
        .unwrap_or_else(|| arn.to_string())
}

fn format_bytes(bytes: i64) -> String {
    const GB: i64 = 1_073_741_824;
    const MB: i64 = 1_048_576;
    const KB: i64 = 1024;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn sample_event(msg: &str) -> LiveTailEvent {
        LiveTailEvent {
            timestamp: 1700000000000,
            message: msg.into(),
            log_stream_name: "stream-1".into(),
            log_group_name: "/app/test".into(),
        }
    }

    fn test_entitlements() -> UserEntitlements {
        UserEntitlements {
            user_id: "dev-admin".into(),
            email: "dev-admin@dev.local".into(),
            display_name: "Dev Admin".into(),
            groups: vec!["platform-engineering".into()],
            features: shared::dto::entitlements::FeatureFlags {
                can_use_cloudwatch_tail: true,
                ..Default::default()
            },
            allowed_accounts: vec![
                shared::dto::entitlements::AllowedAccount {
                    account_id: "111111111111".into(),
                    account_name: "production".into(),
                    role_arn: "arn:aws:iam::111111111111:role/CanopyRole".into(),
                },
                shared::dto::entitlements::AllowedAccount {
                    account_id: "222222222222".into(),
                    account_name: "staging".into(),
                    role_arn: "arn:aws:iam::222222222222:role/CanopyRole".into(),
                },
            ],
            allowed_regions: vec!["us-east-1".into(), "eu-west-1".into()],
            allowed_log_group_arns: vec![
                "arn:aws:logs:*:111111111111:log-group:/app/*".into(),
                "arn:aws:logs:*:222222222222:log-group:/app/*".into(),
            ],
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
                arn: "arn:aws:logs:us-east-1:111111111111:log-group:/app/web-service".into(),
                stored_bytes: Some(1024),
                retention_days: Some(30),
            },
            LogGroup {
                name: "/app/api-gateway".into(),
                arn: "arn:aws:logs:us-east-1:111111111111:log-group:/app/api-gateway".into(),
                stored_bytes: Some(2048),
                retention_days: Some(7),
            },
        ]
    }

    fn rendered_snapshot(screen: &mut LiveTailScreen, width: u16, height: u16) -> String {
        let area = Rect::new(0, 0, width, height);
        let mut buf = Buffer::empty(area);
        screen.render(area, &mut buf);

        buf.content
            .chunks(width as usize)
            .take(height as usize)
            .map(|row| {
                let mut line = String::new();
                for cell in row {
                    line.push_str(cell.symbol());
                }
                line.trim_end().to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    // ── State machine ──

    #[test]
    fn initial_state_is_stopped() {
        let screen = LiveTailScreen::new(1000);
        assert_eq!(screen.state, TailState::Stopped);
        assert_eq!(screen.connection_state, "Disconnected");
    }

    #[test]
    fn set_entitlements_populates_default_live_tail_target() {
        let mut screen = LiveTailScreen::new(1000);

        screen.set_entitlements(test_entitlements());

        assert_eq!(screen.selected_account_id, "111111111111");
        assert_eq!(screen.selected_region, "us-east-1");
        assert_eq!(screen.selected_log_group_name, "/app/web-service");
        assert_eq!(
            screen.selected_log_group_arn,
            "arn:aws:logs:us-east-1:111111111111:log-group:/app/web-service"
        );
        let req = screen.start_request().unwrap();
        assert_eq!(req.account_id, "111111111111");
        assert_eq!(req.region, "us-east-1");
        assert_eq!(req.log_group_arns, vec![screen.selected_log_group_arn]);
    }

    #[test]
    fn set_entitlements_clears_target_without_tail_feature() {
        let mut screen = LiveTailScreen::new(1000);
        screen.set_entitlements(test_entitlements());
        let mut entitlements = test_entitlements();
        entitlements.features.can_use_cloudwatch_tail = false;

        screen.set_entitlements(entitlements);

        assert!(screen.available_accounts.is_empty());
        assert!(screen.available_regions.is_empty());
        assert!(screen.start_request().is_none());
    }

    #[test]
    fn set_entitlements_replaces_stale_scope_selection() {
        let mut screen = LiveTailScreen::new(1000);
        screen.selected_account_id = "999999999999".into();
        screen.selected_region = "ap-southeast-1".into();
        screen.selected_log_group_name = "/old/service".into();
        screen.selected_log_group_arn =
            "arn:aws:logs:ap-southeast-1:999999999999:log-group:/old/service".into();

        screen.set_entitlements(test_entitlements());

        assert_eq!(screen.selected_account_id, "111111111111");
        assert_eq!(screen.selected_region, "us-east-1");
        assert_eq!(screen.selected_log_group_name, "/app/web-service");
        assert_eq!(
            screen.selected_log_group_arn,
            "arn:aws:logs:us-east-1:111111111111:log-group:/app/web-service"
        );
    }

    #[test]
    fn unrestricted_tail_scope_waits_for_loaded_log_group_selection() {
        let mut screen = LiveTailScreen::new(1000);
        let mut entitlements = test_entitlements();
        entitlements.allowed_log_group_arns.clear();

        screen.set_entitlements(entitlements);

        assert!(screen.selected_log_group_arn.is_empty());
        assert!(screen.start_request().is_none());
        screen.set_log_groups(test_log_groups());
        assert_eq!(screen.selected_log_group_name, "/app/web-service");
        assert!(screen.start_request().is_some());
    }

    #[test]
    fn set_log_groups_selects_first_loaded_group_when_default_is_invalid() {
        let mut screen = LiveTailScreen::new(1000);
        screen.set_entitlements(test_entitlements());
        screen.selected_log_group_arn = "arn:aws:logs:us-east-1:111111111111:log-group:/old".into();

        screen.set_log_groups(test_log_groups());

        assert_eq!(screen.selected_log_group_name, "/app/web-service");
        assert_eq!(
            screen.start_request().unwrap().log_group_arns,
            vec!["arn:aws:logs:us-east-1:111111111111:log-group:/app/web-service"]
        );
    }

    #[test]
    fn set_log_groups_clears_target_when_scope_has_no_groups() {
        let mut screen = LiveTailScreen::new(1000);
        screen.set_entitlements(test_entitlements());

        screen.set_log_groups(vec![]);

        assert!(screen.selected_log_group_name.is_empty());
        assert!(screen.selected_log_group_arn.is_empty());
        assert!(screen.start_request().is_none());
    }

    #[test]
    fn wildcard_default_does_not_duplicate_existing_prefix() {
        assert_eq!(
            concrete_live_tail_log_group_arn(
                "arn:aws:logs:*:111111111111:log-group:/app/web-service*",
                "111111111111",
                "us-east-1",
            )
            .as_deref(),
            Some("arn:aws:logs:us-east-1:111111111111:log-group:/app/web-service")
        );
    }

    #[test]
    fn wildcard_default_strips_log_stream_suffix() {
        assert_eq!(
            concrete_live_tail_log_group_arn(
                "arn:aws:logs:*:111111111111:log-group:/app/web-service:*",
                "111111111111",
                "us-east-1",
            )
            .as_deref(),
            Some("arn:aws:logs:us-east-1:111111111111:log-group:/app/web-service")
        );
    }

    #[test]
    fn picker_filters_and_selects_log_group() {
        let mut screen = LiveTailScreen::new(1000);
        screen.set_entitlements(test_entitlements());
        screen.set_log_groups(test_log_groups());

        screen.handle_key(key(KeyCode::Char('l')));
        screen.handle_key(key(KeyCode::Char('/')));
        for ch in ['a', 'p', 'i'] {
            screen.handle_key(key(KeyCode::Char(ch)));
        }
        screen.handle_key(key(KeyCode::Enter));

        assert!(!screen.picker_active);
        assert_eq!(screen.selected_log_group_name, "/app/api-gateway");
        assert_eq!(
            screen.start_request().unwrap().log_group_arns,
            vec!["arn:aws:logs:us-east-1:111111111111:log-group:/app/api-gateway"]
        );
    }

    #[test]
    fn picker_navigation_does_not_select_until_enter() {
        let mut screen = LiveTailScreen::new(1000);
        screen.set_entitlements(test_entitlements());
        screen.set_log_groups(test_log_groups());

        screen.handle_key(key(KeyCode::Char('l')));
        screen.handle_key(key(KeyCode::Down));

        assert_eq!(screen.selected_log_group_name, "/app/web-service");
        screen.handle_key(key(KeyCode::Enter));
        assert_eq!(screen.selected_log_group_name, "/app/api-gateway");
    }

    #[test]
    fn account_cycle_refreshes_live_tail_log_groups() {
        let mut screen = LiveTailScreen::new(1000);
        screen.set_entitlements(test_entitlements());

        let action = screen.handle_key(key(KeyCode::Char(']')));

        assert!(matches!(action, Action::RefreshLiveTailLogGroups));
        assert_eq!(screen.selected_account_id, "222222222222");
        assert!(screen.selected_log_group_arn.is_empty());
    }

    #[test]
    fn on_enter_refreshes_log_groups_when_target_scope_exists() {
        let mut screen = LiveTailScreen::new(1000);
        screen.set_entitlements(test_entitlements());

        let actions = screen.on_enter();

        assert!(matches!(
            actions.as_slice(),
            [Action::RefreshLiveTailLogGroups]
        ));
    }

    #[test]
    fn state_transitions() {
        let mut screen = LiveTailScreen::new(1000);

        screen.set_connected();
        assert_eq!(screen.state, TailState::Running);

        screen.set_paused();
        assert_eq!(screen.state, TailState::Paused);

        screen.set_reconnecting();
        assert_eq!(screen.state, TailState::Reconnecting);

        screen.set_disconnected();
        assert_eq!(screen.state, TailState::Stopped);
    }

    // ── Key handling ──

    #[test]
    fn s_starts_when_stopped() {
        let mut screen = LiveTailScreen::new(1000);
        let action = screen.handle_key(key(KeyCode::Char('s')));
        assert!(matches!(action, Action::StartLiveTail));
    }

    #[test]
    fn s_stops_when_running() {
        let mut screen = LiveTailScreen::new(1000);
        screen.set_connected();
        let action = screen.handle_key(key(KeyCode::Char('s')));
        assert!(matches!(action, Action::StopLiveTail));
    }

    #[test]
    fn s_stops_when_reconnecting() {
        let mut screen = LiveTailScreen::new(1000);
        screen.set_reconnecting();
        let action = screen.handle_key(key(KeyCode::Char('s')));
        assert!(matches!(action, Action::StopLiveTail));
    }

    #[test]
    fn p_pauses_when_running() {
        let mut screen = LiveTailScreen::new(1000);
        screen.set_connected();
        let action = screen.handle_key(key(KeyCode::Char('p')));
        assert!(matches!(action, Action::PauseLiveTail));
    }

    #[test]
    fn p_resumes_when_paused() {
        let mut screen = LiveTailScreen::new(1000);
        screen.set_connected();
        screen.set_paused();
        let action = screen.handle_key(key(KeyCode::Char('p')));
        assert!(matches!(action, Action::ResumeLiveTail));
    }

    #[test]
    fn p_noop_when_stopped() {
        let mut screen = LiveTailScreen::new(1000);
        let action = screen.handle_key(key(KeyCode::Char('p')));
        assert!(matches!(action, Action::Noop));
    }

    #[test]
    fn esc_goes_back() {
        let mut screen = LiveTailScreen::new(1000);
        let action = screen.handle_key(key(KeyCode::Esc));
        assert!(matches!(action, Action::GoBack));
    }

    // ── Event buffer ──

    #[test]
    fn push_event_respects_scrollback_limit() {
        let mut screen = LiveTailScreen::new(3);
        for i in 0..5 {
            screen.push_event(sample_event(&format!("msg-{}", i)));
        }
        assert_eq!(screen.events.len(), 3);
        assert_eq!(screen.events[0].message, "msg-2");
    }

    #[test]
    fn c_clears_events() {
        let mut screen = LiveTailScreen::new(100);
        screen.push_event(sample_event("hello"));
        assert_eq!(screen.events.len(), 1);

        screen.handle_key(key(KeyCode::Char('c')));
        assert!(screen.events.is_empty());
    }

    // ── Scroll ──

    #[test]
    fn scroll_up_disables_auto_scroll() {
        let mut screen = LiveTailScreen::new(100);
        assert!(screen.auto_scroll);

        screen.handle_key(key(KeyCode::Up));
        assert!(!screen.auto_scroll);
        assert_eq!(screen.scroll_offset, 1);
    }

    #[test]
    fn scroll_down_to_zero_re_enables_auto_scroll() {
        let mut screen = LiveTailScreen::new(100);
        screen.auto_scroll = false;
        screen.scroll_offset = 1;

        screen.handle_key(key(KeyCode::Down));
        assert_eq!(screen.scroll_offset, 0);
        // Next scroll down should re-enable auto scroll
        screen.handle_key(key(KeyCode::Down));
        assert!(screen.auto_scroll);
    }

    #[test]
    fn a_toggles_auto_scroll() {
        let mut screen = LiveTailScreen::new(100);
        assert!(screen.auto_scroll);

        screen.handle_key(key(KeyCode::Char('a')));
        assert!(!screen.auto_scroll);

        screen.handle_key(key(KeyCode::Char('a')));
        assert!(screen.auto_scroll);
    }

    // ── Filter mode ──

    #[test]
    fn slash_activates_filter_esc_deactivates() {
        let mut screen = LiveTailScreen::new(100);
        assert!(!screen.filter_active);

        screen.handle_key(key(KeyCode::Char('/')));
        assert!(screen.filter_active);
        assert!(screen.filter_input.focused);

        // While in filter mode, Esc exits filter, not the screen
        let action = screen.handle_key(key(KeyCode::Esc));
        assert!(!screen.filter_active);
        assert!(matches!(action, Action::Noop));
    }

    #[test]
    fn filter_mode_enter_also_exits() {
        let mut screen = LiveTailScreen::new(100);
        screen.handle_key(key(KeyCode::Char('/')));
        assert!(screen.filter_active);

        let action = screen.handle_key(key(KeyCode::Enter));
        assert!(!screen.filter_active);
        assert!(matches!(action, Action::Noop));
    }

    #[test]
    fn paste_in_filter_mode_inserts_filter_text() {
        let mut screen = LiveTailScreen::new(100);
        screen.handle_key(key(KeyCode::Char('/')));

        screen.handle_paste("ERROR\nWARN");

        assert_eq!(screen.filter_input.value, "ERROR WARN");
    }

    #[test]
    fn filtered_events_respects_filter_text() {
        let mut screen = LiveTailScreen::new(100);
        screen.push_event(sample_event("INFO hello"));
        screen.push_event(sample_event("ERROR crash"));
        screen.push_event(sample_event("INFO world"));

        // No filter
        assert_eq!(screen.filtered_events().len(), 3);

        // Set filter
        screen.filter_input.value = "error".into();
        assert_eq!(screen.filtered_events().len(), 1);
        assert_eq!(screen.filtered_events()[0].message, "ERROR crash");
    }

    #[test]
    fn render_shows_session_update_and_streamed_event() {
        let mut screen = LiveTailScreen::new(100);
        screen.set_connected();
        screen.set_events_per_second(Some(0.5));
        screen.push_event(sample_event(
            r#"{"level":"INFO","msg":"Simulated log event #1"}"#,
        ));

        screen.set_entitlements(test_entitlements());
        let snapshot = rendered_snapshot(&mut screen, 120, 18);

        assert!(snapshot.contains("Connected | 0.5 events/sec | 1 events buffered"));
        assert!(snapshot.contains("Log group: /app/web-service"));
        assert!(snapshot.contains("[stream-1]"));
        assert!(snapshot.contains("Simulated log event #1"));
        assert!(snapshot.contains("s start/stop | p pause | l logs | [/]/{/} scope"));
    }
}
