use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Wrap},
};
use shared::dto::ec2::Ec2Instance;
use shared::dto::entitlements::UserEntitlements;

use super::{loading::LoadingIndicator, Component, ScopeTransition};
use crate::event::Action;
use crate::widgets::input::TextInput;
use crate::widgets::table::SelectableTable;

enum Ec2Focus {
    SearchBox,
    Table,
    DetailPanel,
    /// OS user selection popup before connecting
    OsUserSelect,
}

/// Pending connect action waiting for OS user selection
struct PendingConnect {
    instance_id: String,
    instance_name: Option<String>,
    account_id: String,
    region: String,
    /// Which connect method triggered this (Ssm, Ec2InstanceConnect, Ssh)
    method: shared::dto::ec2::ConnectMethod,
    /// Available OS users to choose from
    users: Vec<String>,
    /// Currently highlighted user index
    selected: usize,
}

struct ConnectDispatchTarget {
    instance_id: String,
    instance_name: Option<String>,
    account_id: String,
    region: String,
    os_user: Option<String>,
}

/// Which instances to show based on state
#[derive(Clone, Copy, PartialEq, Eq)]
enum StateFilter {
    All,     // Show everything
    Running, // Only running (not stopped)
    Stopped, // Only stopped
}

impl StateFilter {
    fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Running => "Running",
            Self::Stopped => "Stopped",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::All => Self::Running,
            Self::Running => Self::Stopped,
            Self::Stopped => Self::All,
        }
    }

    fn matches(self, state: &shared::dto::ec2::InstanceState) -> bool {
        match self {
            Self::All => true,
            Self::Running => *state == shared::dto::ec2::InstanceState::Running,
            Self::Stopped => *state == shared::dto::ec2::InstanceState::Stopped,
        }
    }
}

pub struct Ec2Screen {
    pub instances: Vec<Ec2Instance>,
    pub loading: bool,
    pub error: Option<String>,
    entitlements: Option<UserEntitlements>,
    pub search_input: TextInput,
    table: SelectableTable,
    focus: Ec2Focus,
    show_detail: bool,
    pending_connect: Option<PendingConnect>,
    state_filter: StateFilter,

    // Scope selection for account/region cycling
    pub selected_account_id: Option<String>,
    pub selected_region: Option<String>,
    pub available_accounts: Vec<String>,
    pub available_regions: Vec<String>,
    scope_transition: Option<ScopeTransition>,
    loading_spinner: LoadingIndicator,
    /// Monotonically increasing counter to detect stale async responses
    pub fetch_generation: u64,
}

impl Default for Ec2Screen {
    fn default() -> Self {
        Self::new()
    }
}

impl Ec2Screen {
    pub fn new() -> Self {
        Self {
            instances: Vec::new(),
            loading: false,
            error: None,
            entitlements: None,
            search_input: TextInput::new("Search (name, id, ip)"),
            table: SelectableTable::new(
                vec![
                    "Instance ID".into(),
                    "Name".into(),
                    "Private IP".into(),
                    "Public IP".into(),
                    "State".into(),
                    "Type".into(),
                    "SSM".into(),
                    "SSH".into(),
                    "Env".into(),
                ],
                vec![
                    Constraint::Length(21),
                    Constraint::Min(15),
                    Constraint::Length(15),
                    Constraint::Length(15),
                    Constraint::Length(10),
                    Constraint::Length(12),
                    Constraint::Length(5),
                    Constraint::Length(5),
                    Constraint::Length(12),
                ],
            ),
            focus: Ec2Focus::Table,
            show_detail: false,
            pending_connect: None,
            state_filter: StateFilter::All,
            selected_account_id: None,
            selected_region: None,
            available_accounts: Vec::new(),
            available_regions: Vec::new(),
            scope_transition: None,
            loading_spinner: LoadingIndicator::new("Loading EC2 instances..."),
            fetch_generation: 0,
        }
    }

    pub fn set_instances(&mut self, instances: Vec<Ec2Instance>) {
        self.instances = instances;
        self.apply_state_filter();
        self.loading = false;
        self.error = None;
    }

    /// Returns instances filtered by the current state filter
    fn filtered_instances(&self) -> Vec<&Ec2Instance> {
        self.instances
            .iter()
            .filter(|i| self.state_filter.matches(&i.state))
            .collect()
    }

    fn apply_state_filter(&mut self) {
        let count = self
            .instances
            .iter()
            .filter(|i| self.state_filter.matches(&i.state))
            .count();
        self.table.set_row_count(count);
    }

    pub fn set_entitlements(&mut self, ent: UserEntitlements) {
        // Populate available accounts (deduplicated, sorted)
        self.available_accounts = ent
            .allowed_accounts
            .iter()
            .map(|a| a.account_id.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        self.available_accounts.sort();
        self.available_regions = ent.allowed_regions.clone();

        // Default to All (None) for both account and region
        self.selected_account_id = None;
        self.selected_region = None;

        self.entitlements = Some(ent);
    }

    pub fn set_loading(&mut self) {
        self.loading = true;
        self.error = None;
        self.fetch_generation += 1;
    }

    pub fn set_error(&mut self, err: String) {
        self.loading = false;
        self.error = Some(err);
    }

    fn selected_instance(&self) -> Option<&Ec2Instance> {
        let filtered = self.filtered_instances();
        self.table.selected().and_then(|i| filtered.get(i).copied())
    }

    fn render_detail(&self, area: Rect, buf: &mut Buffer) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Instance Detail ")
            .border_style(Style::default().fg(Color::Yellow));
        let inner = block.inner(area);
        block.render(area, buf);

        if let Some(inst) = self.selected_instance() {
            let state_style = match inst.state {
                shared::dto::ec2::InstanceState::Running => Style::default().fg(Color::Green),
                shared::dto::ec2::InstanceState::Stopped => Style::default().fg(Color::Red),
                _ => Style::default().fg(Color::Yellow),
            };

            let mut lines = vec![
                Line::from(vec![
                    Span::styled("Instance ID: ", Style::default().bold()),
                    Span::styled(&inst.instance_id, Style::default().fg(Color::Yellow)),
                ]),
                Line::from(vec![
                    Span::styled("Name:        ", Style::default().bold()),
                    Span::styled(
                        inst.name.as_deref().unwrap_or("-"),
                        Style::default().fg(Color::White).bold(),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Account:     ", Style::default().bold()),
                    Span::raw(&inst.account_id),
                ]),
                Line::from(vec![
                    Span::styled("Region:      ", Style::default().bold()),
                    Span::raw(&inst.region),
                ]),
                Line::from(vec![
                    Span::styled("State:       ", Style::default().bold()),
                    Span::styled(inst.state.to_string(), state_style),
                ]),
                Line::from(vec![
                    Span::styled("Private IP:  ", Style::default().bold()),
                    Span::raw(inst.private_ip.as_deref().unwrap_or("-")),
                ]),
                Line::from(vec![
                    Span::styled("Public IP:   ", Style::default().bold()),
                    Span::raw(inst.public_ip.as_deref().unwrap_or("-")),
                ]),
                Line::from(vec![
                    Span::styled("Type:        ", Style::default().bold()),
                    Span::raw(&inst.instance_type),
                ]),
                Line::from(vec![
                    Span::styled("Platform:    ", Style::default().bold()),
                    Span::raw(inst.platform.as_deref().unwrap_or("-")),
                ]),
                Line::from(vec![
                    Span::styled("VPC:         ", Style::default().bold()),
                    Span::raw(inst.vpc_id.as_deref().unwrap_or("-")),
                ]),
                Line::from(vec![
                    Span::styled("Subnet:      ", Style::default().bold()),
                    Span::raw(inst.subnet_id.as_deref().unwrap_or("-")),
                ]),
                Line::from(vec![
                    Span::styled("IAM Role:    ", Style::default().bold()),
                    Span::raw(inst.iam_role.as_deref().unwrap_or("-")),
                ]),
                Line::from(vec![
                    Span::styled("Launch Time: ", Style::default().bold()),
                    Span::raw(inst.launch_time.as_deref().unwrap_or("-")),
                ]),
            ];

            // Tags
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Tags:", Style::default().bold())));
            for (k, v) in &inst.tags {
                lines.push(Line::from(format!("  {}: {}", k, v)));
            }

            // Security Groups
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Security Groups:",
                Style::default().bold(),
            )));
            for sg in &inst.security_groups {
                lines.push(Line::from(format!("  {}", sg)));
            }

            // ── Connect actions ──────────────────────────
            let is_running = inst.state == shared::dto::ec2::InstanceState::Running;
            let has_ssm = self
                .entitlements
                .as_ref()
                .map(|e| e.features.can_use_ssm)
                .unwrap_or(false);
            let has_eic = self
                .entitlements
                .as_ref()
                .map(|e| e.features.can_use_ec2_instance_connect)
                .unwrap_or(false);

            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Connect:",
                Style::default().bold().fg(Color::Cyan),
            )));

            if !is_running {
                lines.push(Line::from(Span::styled(
                    "  Instance is not running",
                    Style::default().fg(Color::Red),
                )));
            } else {
                // SSM
                if inst.ssm_managed && has_ssm {
                    lines.push(Line::from(vec![
                        Span::styled("  [s] ", Style::default().fg(Color::Green).bold()),
                        Span::styled("SSM Session Manager", Style::default().fg(Color::White)),
                        Span::styled(" - ready", Style::default().fg(Color::Green)),
                    ]));
                } else if inst.ssm_managed && !has_ssm {
                    lines.push(Line::from(vec![
                        Span::styled("  [s] ", Style::default().fg(Color::Gray)),
                        Span::styled("SSM Session Manager", Style::default().fg(Color::Gray)),
                        Span::styled(" - not authorized", Style::default().fg(Color::Red)),
                    ]));
                } else {
                    lines.push(Line::from(vec![
                        Span::styled("  [s] ", Style::default().fg(Color::Gray)),
                        Span::styled("SSM Session Manager", Style::default().fg(Color::Gray)),
                        Span::styled(
                            " - not available (no SSM agent)",
                            Style::default().fg(Color::Gray),
                        ),
                    ]));
                }

                // EC2 Instance Connect
                if inst.instance_connect_capable && has_eic {
                    lines.push(Line::from(vec![
                        Span::styled("  [e] ", Style::default().fg(Color::Green).bold()),
                        Span::styled(
                            "EC2 Instance Connect SSH",
                            Style::default().fg(Color::White),
                        ),
                        Span::styled(" - ready", Style::default().fg(Color::Green)),
                    ]));
                } else if inst.instance_connect_capable && !has_eic {
                    lines.push(Line::from(vec![
                        Span::styled("  [e] ", Style::default().fg(Color::Gray)),
                        Span::styled("EC2 Instance Connect SSH", Style::default().fg(Color::Gray)),
                        Span::styled(" - not authorized", Style::default().fg(Color::Red)),
                    ]));
                } else {
                    lines.push(Line::from(vec![
                        Span::styled("  [e] ", Style::default().fg(Color::Gray)),
                        Span::styled("EC2 Instance Connect SSH", Style::default().fg(Color::Gray)),
                        Span::styled(" - not available", Style::default().fg(Color::Gray)),
                    ]));
                }

                // Direct SSH
                let has_ip = inst.private_ip.is_some() || inst.public_ip.is_some();
                if has_ip && has_ssm {
                    let ip_display = inst
                        .public_ip
                        .as_deref()
                        .or(inst.private_ip.as_deref())
                        .unwrap_or("?");
                    lines.push(Line::from(vec![
                        Span::styled("  [c] ", Style::default().fg(Color::Green).bold()),
                        Span::styled("SSH (your key)", Style::default().fg(Color::White)),
                        Span::styled(
                            format!(" - {}", ip_display),
                            Style::default().fg(Color::Green),
                        ),
                    ]));
                } else if has_ip && !has_ssm {
                    lines.push(Line::from(vec![
                        Span::styled("  [c] ", Style::default().fg(Color::Gray)),
                        Span::styled("SSH (your key)", Style::default().fg(Color::Gray)),
                        Span::styled(" - not authorized", Style::default().fg(Color::Red)),
                    ]));
                } else {
                    lines.push(Line::from(vec![
                        Span::styled("  [c] ", Style::default().fg(Color::Gray)),
                        Span::styled("SSH (your key)", Style::default().fg(Color::Gray)),
                        Span::styled(" - no IP address", Style::default().fg(Color::Gray)),
                    ]));
                }

                if !inst.ssm_managed && !inst.instance_connect_capable && !has_ip {
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        "  No connect method available for this instance",
                        Style::default().fg(Color::Yellow),
                    )));
                }
            }

            Paragraph::new(lines)
                .wrap(Wrap { trim: true })
                .render(inner, buf);
        } else {
            Paragraph::new("No instance selected")
                .style(Style::default().fg(Color::Gray))
                .render(inner, buf);
        }
    }
}

impl Ec2Screen {
    /// Start the connect flow: if only one OS user, connect immediately.
    /// If multiple, show the user selection popup.
    fn start_connect(&mut self, method: shared::dto::ec2::ConnectMethod) -> Action {
        if self.loading {
            return Action::Noop;
        }
        let Some(inst) = self.selected_instance() else {
            return Action::Noop;
        };

        // Pre-flight checks
        if inst.state != shared::dto::ec2::InstanceState::Running {
            return Action::ShowError("Instance is not running".into());
        }
        match method {
            shared::dto::ec2::ConnectMethod::Ssm => {
                if !inst.ssm_managed {
                    return Action::ShowError("Instance is not SSM managed".into());
                }
            }
            shared::dto::ec2::ConnectMethod::Ec2InstanceConnect => {
                if !inst.instance_connect_capable {
                    return Action::ShowError(
                        "Instance does not support EC2 Instance Connect".into(),
                    );
                }
            }
            shared::dto::ec2::ConnectMethod::Ssh => {
                if inst.private_ip.is_none() && inst.public_ip.is_none() {
                    return Action::ShowError("Instance has no IP address".into());
                }
            }
        }

        let users: Vec<String> = self
            .entitlements
            .as_ref()
            .map(|e| e.allowed_os_users.clone())
            .unwrap_or_default();

        let instance_id = inst.instance_id.clone();
        let instance_name = inst.name.clone();
        let account_id = inst.account_id.clone();
        let region = inst.region.clone();

        if users.is_empty() {
            // No OS users configured — connect without one (SSM shell only)
            return self.dispatch_connect(
                method,
                ConnectDispatchTarget {
                    instance_id,
                    instance_name,
                    account_id,
                    region,
                    os_user: None,
                },
            );
        }

        if users.len() == 1 {
            // Only one choice — skip popup
            let user = users[0].clone();
            return self.dispatch_connect(
                method,
                ConnectDispatchTarget {
                    instance_id,
                    instance_name,
                    account_id,
                    region,
                    os_user: Some(user),
                },
            );
        }

        // Multiple users — show selection popup
        self.pending_connect = Some(PendingConnect {
            instance_id,
            instance_name,
            account_id,
            region,
            method,
            users,
            selected: 0,
        });
        self.focus = Ec2Focus::OsUserSelect;
        Action::Noop
    }

    /// Clear instance list and selection to prevent stale cross-scope actions.
    fn clear_instances(&mut self) {
        // Advance generation first so any in-flight response is rejected
        self.fetch_generation += 1;
        self.instances.clear();
        self.table.set_row_count(0);
        self.error = None;
        self.show_detail = false;
        self.focus = Ec2Focus::Table;
        self.pending_connect = None;
        self.search_input.clear();
    }

    /// Cycle account: None (All) → first → second → … → None (All)
    fn cycle_account(&mut self, forward: bool) -> bool {
        if self.available_accounts.is_empty() {
            return false;
        }
        let cur_idx = self
            .selected_account_id
            .as_ref()
            .and_then(|id| self.available_accounts.iter().position(|a| a == id));
        let next = if forward {
            match cur_idx {
                None => Some(0),
                Some(i) if i + 1 < self.available_accounts.len() => Some(i + 1),
                Some(_) => None,
            }
        } else {
            match cur_idx {
                None => Some(self.available_accounts.len() - 1),
                Some(0) => None,
                Some(i) => Some(i - 1),
            }
        };
        self.selected_account_id = next.map(|i| self.available_accounts[i].clone());
        self.clear_instances();
        true
    }

    /// Cycle region: None (All) → first → second → … → None (All)
    fn cycle_region(&mut self, forward: bool) -> bool {
        if self.available_regions.is_empty() {
            return false;
        }
        let cur_idx = self
            .selected_region
            .as_ref()
            .and_then(|id| self.available_regions.iter().position(|r| r == id));
        let next = if forward {
            match cur_idx {
                None => Some(0),
                Some(i) if i + 1 < self.available_regions.len() => Some(i + 1),
                Some(_) => None,
            }
        } else {
            match cur_idx {
                None => Some(self.available_regions.len() - 1),
                Some(0) => None,
                Some(i) => Some(i - 1),
            }
        };
        self.selected_region = next.map(|i| self.available_regions[i].clone());
        self.clear_instances();
        true
    }

    fn dispatch_connect(
        &self,
        method: shared::dto::ec2::ConnectMethod,
        target: ConnectDispatchTarget,
    ) -> Action {
        match method {
            shared::dto::ec2::ConnectMethod::Ssm => Action::ConnectSsm {
                instance_id: target.instance_id,
                instance_name: target.instance_name,
                account_id: target.account_id,
                region: target.region,
                os_user: target.os_user,
            },
            shared::dto::ec2::ConnectMethod::Ec2InstanceConnect => Action::ConnectEic {
                instance_id: target.instance_id,
                instance_name: target.instance_name,
                account_id: target.account_id,
                region: target.region,
                os_user: target.os_user,
            },
            shared::dto::ec2::ConnectMethod::Ssh => Action::ConnectSsh {
                instance_id: target.instance_id,
                instance_name: target.instance_name,
                account_id: target.account_id,
                region: target.region,
                os_user: target.os_user,
            },
        }
    }
}

impl Component for Ec2Screen {
    fn handle_key(&mut self, key: KeyEvent) -> Action {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Action::Quit;
        }

        // OS user selection popup intercepts all keys
        if matches!(self.focus, Ec2Focus::OsUserSelect) {
            if let Some(ref mut pending) = self.pending_connect {
                match key.code {
                    KeyCode::Esc => {
                        self.pending_connect = None;
                        self.focus = if self.show_detail {
                            Ec2Focus::DetailPanel
                        } else {
                            Ec2Focus::Table
                        };
                        return Action::Noop;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if pending.selected > 0 {
                            pending.selected -= 1;
                        }
                        return Action::Noop;
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if pending.selected < pending.users.len().saturating_sub(1) {
                            pending.selected += 1;
                        }
                        return Action::Noop;
                    }
                    KeyCode::Enter => {
                        let user = pending.users[pending.selected].clone();
                        let method = pending.method.clone();
                        let instance_id = pending.instance_id.clone();
                        let instance_name = pending.instance_name.clone();
                        let account_id = pending.account_id.clone();
                        let region = pending.region.clone();
                        self.pending_connect = None;
                        self.focus = if self.show_detail {
                            Ec2Focus::DetailPanel
                        } else {
                            Ec2Focus::Table
                        };
                        return self.dispatch_connect(
                            method,
                            ConnectDispatchTarget {
                                instance_id,
                                instance_name,
                                account_id,
                                region,
                                os_user: Some(user),
                            },
                        );
                    }
                    _ => return Action::Noop,
                }
            }
        }

        match key.code {
            KeyCode::Esc => {
                match self.focus {
                    Ec2Focus::SearchBox => {
                        self.focus = Ec2Focus::Table;
                        self.search_input.focused = false;
                    }
                    Ec2Focus::DetailPanel => {
                        self.show_detail = false;
                        self.focus = Ec2Focus::Table;
                    }
                    Ec2Focus::Table => return Action::GoBack,
                    Ec2Focus::OsUserSelect => {} // handled above
                }
                Action::Noop
            }
            KeyCode::Char('/') if !matches!(self.focus, Ec2Focus::SearchBox) => {
                self.focus = Ec2Focus::SearchBox;
                self.search_input.focused = true;
                Action::Noop
            }
            KeyCode::Enter => match self.focus {
                Ec2Focus::SearchBox => {
                    let query = self.search_input.value.clone();
                    self.focus = Ec2Focus::Table;
                    self.search_input.focused = false;
                    Action::SearchEc2(query)
                }
                Ec2Focus::Table => {
                    self.show_detail = !self.show_detail;
                    if self.show_detail {
                        self.focus = Ec2Focus::DetailPanel;
                    }
                    Action::Noop
                }
                Ec2Focus::DetailPanel | Ec2Focus::OsUserSelect => Action::Noop,
            },
            // `[` / `]` → cycle account
            KeyCode::Char('[') if !matches!(self.focus, Ec2Focus::SearchBox) => {
                if ScopeTransition::is_blocking(&self.scope_transition) {
                    return Action::Noop;
                }
                if self.cycle_account(false) {
                    let label = format!(
                        "Account → {}",
                        self.selected_account_id.as_deref().unwrap_or("All")
                    );
                    self.scope_transition = Some(ScopeTransition::new(label));
                    return Action::RefreshEc2;
                }
                Action::Noop
            }
            KeyCode::Char(']') if !matches!(self.focus, Ec2Focus::SearchBox) => {
                if ScopeTransition::is_blocking(&self.scope_transition) {
                    return Action::Noop;
                }
                if self.cycle_account(true) {
                    let label = format!(
                        "Account → {}",
                        self.selected_account_id.as_deref().unwrap_or("All")
                    );
                    self.scope_transition = Some(ScopeTransition::new(label));
                    return Action::RefreshEc2;
                }
                Action::Noop
            }
            // `{` / `}` → cycle region
            KeyCode::Char('{') if !matches!(self.focus, Ec2Focus::SearchBox) => {
                if ScopeTransition::is_blocking(&self.scope_transition) {
                    return Action::Noop;
                }
                if self.cycle_region(false) {
                    let label = format!(
                        "Region → {}",
                        self.selected_region.as_deref().unwrap_or("All")
                    );
                    self.scope_transition = Some(ScopeTransition::new(label));
                    return Action::RefreshEc2;
                }
                Action::Noop
            }
            KeyCode::Char('}') if !matches!(self.focus, Ec2Focus::SearchBox) => {
                if ScopeTransition::is_blocking(&self.scope_transition) {
                    return Action::Noop;
                }
                if self.cycle_region(true) {
                    let label = format!(
                        "Region → {}",
                        self.selected_region.as_deref().unwrap_or("All")
                    );
                    self.scope_transition = Some(ScopeTransition::new(label));
                    return Action::RefreshEc2;
                }
                Action::Noop
            }
            KeyCode::Char('r') if !matches!(self.focus, Ec2Focus::SearchBox) => Action::RefreshEc2,
            KeyCode::Char('f') if !matches!(self.focus, Ec2Focus::SearchBox) => {
                self.state_filter = self.state_filter.next();
                self.apply_state_filter();
                Action::Noop
            }
            KeyCode::Char('s') if !matches!(self.focus, Ec2Focus::SearchBox) => {
                self.start_connect(shared::dto::ec2::ConnectMethod::Ssm)
            }
            KeyCode::Char('e') if !matches!(self.focus, Ec2Focus::SearchBox) => {
                self.start_connect(shared::dto::ec2::ConnectMethod::Ec2InstanceConnect)
            }
            KeyCode::Char('c') if !matches!(self.focus, Ec2Focus::SearchBox) => {
                self.start_connect(shared::dto::ec2::ConnectMethod::Ssh)
            }
            _ => {
                match self.focus {
                    Ec2Focus::SearchBox => {
                        self.search_input.handle_key(key);
                    }
                    Ec2Focus::Table | Ec2Focus::DetailPanel => {
                        self.table.handle_key(key);
                    }
                    Ec2Focus::OsUserSelect => {} // handled above
                }
                Action::Noop
            }
        }
    }

    fn render(&mut self, area: Rect, buf: &mut Buffer) {
        let outer = Block::default()
            .borders(Borders::ALL)
            .title(" EC2 Inventory ")
            .border_style(Style::default().fg(Color::Cyan));
        let inner = outer.inner(area);
        outer.render(area, buf);

        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Search bar
                Constraint::Length(1), // Account/Region scope
                Constraint::Min(5),    // Table + detail
                Constraint::Length(2), // Status bar
            ])
            .split(inner);

        // Search bar
        self.search_input.render(main_chunks[0], buf);

        // Account/Region scope header
        let acct_display = self.selected_account_id.as_deref().unwrap_or("All");
        let region_display = self.selected_region.as_deref().unwrap_or("All");
        let acct_label = if self.available_accounts.len() > 1 {
            format!("Account [/]: {}", acct_display)
        } else {
            format!("Account: {}", acct_display)
        };
        let region_label = if self.available_regions.len() > 1 {
            format!("Region {{/}}: {}", region_display)
        } else {
            format!("Region: {}", region_display)
        };
        let scope_line = Line::from(vec![
            Span::styled(" ", Style::default()),
            Span::styled(acct_label, Style::default().fg(Color::Yellow)),
            Span::styled(" │ ", Style::default().fg(Color::DarkGray)),
            Span::styled(region_label, Style::default().fg(Color::Cyan)),
        ]);
        Paragraph::new(scope_line).render(main_chunks[1], buf);

        // Table + optional detail panel
        if self.show_detail {
            let h_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
                .split(main_chunks[2]);

            self.render_table(h_chunks[0], buf);
            self.render_detail(h_chunks[1], buf);
        } else {
            self.render_table(main_chunks[2], buf);
        }

        // Status bar
        let filtered_count = self.filtered_instances().len();
        let total_count = self.instances.len();
        let filter_label = self.state_filter.label();

        let count_display = if self.state_filter == StateFilter::All {
            format!("{} instances", total_count)
        } else {
            format!("{}/{} [{}]", filtered_count, total_count, filter_label)
        };

        let status = if self.loading {
            "Loading instances...".to_string()
        } else if let Some(ref err) = self.error {
            format!("Error: {}", err)
        } else if self.show_detail {
            format!(
                "{} | f: filter | s: SSM | e: EIC | c: SSH | r: refresh | Esc: close",
                count_display
            )
        } else {
            format!(
                "{} | f: filter | /: search | r: refresh | Enter: detail | Esc: back",
                count_display
            )
        };

        let status_style = if self.error.is_some() {
            Style::default().fg(Color::Red)
        } else if self.loading {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::Gray)
        };

        Paragraph::new(status)
            .style(status_style)
            .render(main_chunks[3], buf);

        // Loading overlay
        if self.loading && self.instances.is_empty() {
            self.loading_spinner.render_overlay(inner, buf);
        }

        // OS user selection popup (rendered on top)
        if let Some(ref pending) = self.pending_connect {
            self.render_os_user_popup(inner, buf, pending);
        }

        // Scope transition overlay
        if let Some(ref t) = self.scope_transition {
            t.render(inner, buf);
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
        vec![Action::RefreshEc2]
    }
}

impl Ec2Screen {
    fn render_os_user_popup(&self, area: Rect, buf: &mut Buffer, pending: &PendingConnect) {
        use ratatui::widgets::Clear;

        let method_name = match pending.method {
            shared::dto::ec2::ConnectMethod::Ssm => "SSM",
            shared::dto::ec2::ConnectMethod::Ec2InstanceConnect => "EC2 Instance Connect",
            shared::dto::ec2::ConnectMethod::Ssh => "SSH",
        };

        let popup_height = (pending.users.len() as u16 + 4).min(area.height.saturating_sub(4));
        let popup_width = 40u16.min(area.width.saturating_sub(4));
        let popup_area = Rect {
            x: area.x + (area.width.saturating_sub(popup_width)) / 2,
            y: area.y + (area.height.saturating_sub(popup_height)) / 2,
            width: popup_width,
            height: popup_height,
        };

        Clear.render(popup_area, buf);

        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} — Select User ", method_name))
            .border_style(Style::default().fg(Color::Cyan).bold());
        let inner = block.inner(popup_area);
        block.render(popup_area, buf);

        let mut lines = Vec::new();
        for (i, user) in pending.users.iter().enumerate() {
            let (prefix, style) = if i == pending.selected {
                (
                    ">> ",
                    Style::default()
                        .fg(Color::White)
                        .bg(Color::Indexed(24))
                        .bold(),
                )
            } else {
                ("   ", Style::default().fg(Color::White))
            };
            lines.push(Line::from(Span::styled(
                format!("{}{}", prefix, user),
                style,
            )));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "j/k: select | Enter: connect | Esc: cancel",
            Style::default().fg(Color::Gray),
        )));

        Paragraph::new(lines).render(inner, buf);
    }
}

#[cfg(test)]
impl Ec2Screen {
    fn test_focus(&self) -> &str {
        match self.focus {
            Ec2Focus::SearchBox => "SearchBox",
            Ec2Focus::Table => "Table",
            Ec2Focus::DetailPanel => "DetailPanel",
            Ec2Focus::OsUserSelect => "OsUserSelect",
        }
    }
}

impl Ec2Screen {
    fn render_table(&mut self, area: Rect, buf: &mut Buffer) {
        let filter = self.state_filter;
        let rows: Vec<_> = self
            .instances
            .iter()
            .filter(|i| filter.matches(&i.state))
            .map(|inst| {
                let state_style = match inst.state {
                    shared::dto::ec2::InstanceState::Running => Style::default().fg(Color::Green),
                    shared::dto::ec2::InstanceState::Stopped => Style::default().fg(Color::Red),
                    _ => Style::default().fg(Color::Yellow),
                };

                Row::new(vec![
                    Cell::from(inst.instance_id.as_str()).style(Style::default().fg(Color::Yellow)),
                    Cell::from(inst.name.as_deref().unwrap_or("-"))
                        .style(Style::default().fg(Color::White).bold()),
                    Cell::from(inst.private_ip.as_deref().unwrap_or("-"))
                        .style(Style::default().fg(Color::White)),
                    Cell::from(inst.public_ip.as_deref().unwrap_or("-"))
                        .style(Style::default().fg(Color::White)),
                    Cell::from(inst.state.to_string()).style(state_style),
                    Cell::from(inst.instance_type.as_str()).style(Style::default().fg(Color::Gray)),
                    Cell::from(if inst.ssm_managed { "Yes" } else { "No" }).style(
                        if inst.ssm_managed {
                            Style::default().fg(Color::Green)
                        } else {
                            Style::default().fg(Color::Gray)
                        },
                    ),
                    Cell::from(if inst.instance_connect_capable {
                        "Yes"
                    } else {
                        "No"
                    })
                    .style(if inst.instance_connect_capable {
                        Style::default().fg(Color::Green)
                    } else {
                        Style::default().fg(Color::Gray)
                    }),
                    Cell::from(inst.environment.as_deref().unwrap_or("-"))
                        .style(Style::default().fg(Color::Cyan)),
                ])
            })
            .collect();

        let title = if self.state_filter == StateFilter::All {
            "Instances".to_string()
        } else {
            format!("Instances [{}]", self.state_filter.label())
        };
        self.table
            .render_with_rows(rows.into_iter(), &title, area, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
    use shared::dto::entitlements::*;
    use std::collections::HashMap;

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
            email: "test@example.com".into(),
            display_name: "Test".into(),
            groups: vec!["ops".into()],
            features: FeatureFlags {
                can_view_ec2: true,
                can_use_cloudwatch_search: false,
                can_use_cloudwatch_tail: false,
                can_use_ssm: true,
                can_use_ec2_instance_connect: true,
                ..Default::default()
            },
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
            allowed_log_group_arns: vec![],
            instance_tag_selectors: vec![],
            excluded_tag_selectors: vec![],
            allowed_os_users: vec!["ec2-user".into(), "ubuntu".into()],
            max_session_seconds: None,
        }
    }

    fn running_instance(id: &str) -> Ec2Instance {
        Ec2Instance {
            instance_id: id.into(),
            account_id: "111".into(),
            region: "us-east-1".into(),
            name: Some(format!("server-{}", id)),
            private_ip: Some("10.0.0.1".into()),
            public_ip: None,
            state: shared::dto::ec2::InstanceState::Running,
            platform: None,
            instance_type: "t3.micro".into(),
            ssm_managed: true,
            instance_connect_capable: true,
            environment: Some("dev".into()),
            tags: HashMap::new(),
            launch_time: None,
            vpc_id: None,
            subnet_id: None,
            security_groups: vec![],
            iam_role: None,
        }
    }

    fn stopped_instance(id: &str) -> Ec2Instance {
        let mut inst = running_instance(id);
        inst.state = shared::dto::ec2::InstanceState::Stopped;
        inst.ssm_managed = false;
        inst
    }

    // ── Initial state ──

    #[test]
    fn initial_focus_is_table() {
        let screen = Ec2Screen::new();
        assert_eq!(screen.test_focus(), "Table");
        assert!(!screen.show_detail);
    }

    // ── Entitlements & scope ──

    #[test]
    fn set_entitlements_populates_scope() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(test_entitlements());

        assert_eq!(screen.available_accounts.len(), 2);
        assert_eq!(screen.available_regions.len(), 2);
        assert!(screen.selected_account_id.is_none()); // "All"
        assert!(screen.selected_region.is_none());
    }

    #[test]
    fn cycle_account_from_all() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(test_entitlements());

        // Forward: All → first account
        assert!(screen.cycle_account(true));
        assert_eq!(screen.selected_account_id.as_deref(), Some("111"));

        // Forward: 111 → 222
        assert!(screen.cycle_account(true));
        assert_eq!(screen.selected_account_id.as_deref(), Some("222"));

        // Forward: 222 → All
        assert!(screen.cycle_account(true));
        assert!(screen.selected_account_id.is_none());
    }

    #[test]
    fn cycle_account_backward() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(test_entitlements());

        // Backward: All → last account
        assert!(screen.cycle_account(false));
        assert_eq!(screen.selected_account_id.as_deref(), Some("222"));
    }

    #[test]
    fn cycle_clears_instances() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(test_entitlements());
        screen.set_instances(vec![running_instance("i-1")]);
        assert_eq!(screen.instances.len(), 1);

        screen.cycle_account(true);
        assert!(screen.instances.is_empty());
    }

    // ── State filter ──

    #[test]
    fn state_filter_cycles() {
        let mut screen = Ec2Screen::new();
        screen.set_instances(vec![running_instance("i-1"), stopped_instance("i-2")]);

        assert_eq!(screen.filtered_instances().len(), 2); // All

        screen.handle_key(key(KeyCode::Char('f')));
        assert_eq!(screen.filtered_instances().len(), 1); // Running only

        screen.handle_key(key(KeyCode::Char('f')));
        assert_eq!(screen.filtered_instances().len(), 1); // Stopped only

        screen.handle_key(key(KeyCode::Char('f')));
        assert_eq!(screen.filtered_instances().len(), 2); // All again
    }

    // ── Focus transitions ──

    #[test]
    fn slash_opens_search_esc_returns_to_table() {
        let mut screen = Ec2Screen::new();
        screen.handle_key(key(KeyCode::Char('/')));
        assert_eq!(screen.test_focus(), "SearchBox");
        assert!(screen.search_input.focused);

        screen.handle_key(key(KeyCode::Esc));
        assert_eq!(screen.test_focus(), "Table");
        assert!(!screen.search_input.focused);
    }

    #[test]
    fn enter_toggles_detail_panel() {
        let mut screen = Ec2Screen::new();
        screen.set_instances(vec![running_instance("i-1")]);

        screen.handle_key(key(KeyCode::Enter));
        assert!(screen.show_detail);
        assert_eq!(screen.test_focus(), "DetailPanel");

        // Esc from detail panel goes back to table
        screen.handle_key(key(KeyCode::Esc));
        assert!(!screen.show_detail);
        assert_eq!(screen.test_focus(), "Table");
    }

    #[test]
    fn enter_in_search_dispatches_search_action() {
        let mut screen = Ec2Screen::new();
        screen.handle_key(key(KeyCode::Char('/')));
        // Type something — the TextInput will capture it
        screen.search_input.value = "web-server".into();

        let action = screen.handle_key(key(KeyCode::Enter));
        assert!(matches!(action, Action::SearchEc2(ref q) if q == "web-server"));
        assert_eq!(screen.test_focus(), "Table");
    }

    // ── Key actions ──

    #[test]
    fn r_refreshes() {
        let mut screen = Ec2Screen::new();
        let action = screen.handle_key(key(KeyCode::Char('r')));
        assert!(matches!(action, Action::RefreshEc2));
    }

    #[test]
    fn esc_from_table_goes_back() {
        let mut screen = Ec2Screen::new();
        let action = screen.handle_key(key(KeyCode::Esc));
        assert!(matches!(action, Action::GoBack));
    }

    #[test]
    fn on_enter_returns_refresh() {
        let mut screen = Ec2Screen::new();
        let actions = screen.on_enter();
        assert!(actions.iter().any(|a| matches!(a, Action::RefreshEc2)));
    }

    // ── Generation counter ──

    #[test]
    fn set_loading_increments_generation() {
        let mut screen = Ec2Screen::new();
        let gen0 = screen.fetch_generation;
        screen.set_loading();
        assert_eq!(screen.fetch_generation, gen0 + 1);
        assert!(screen.loading);
    }

    #[test]
    fn clear_instances_increments_generation() {
        let mut screen = Ec2Screen::new();
        let gen0 = screen.fetch_generation;
        screen.clear_instances();
        assert_eq!(screen.fetch_generation, gen0 + 1);
    }
}
