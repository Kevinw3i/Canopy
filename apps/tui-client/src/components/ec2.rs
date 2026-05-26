use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Wrap},
};
use shared::dto::ec2::{Ec2Instance, Ec2PowerAction, InstanceState};
use shared::dto::ecs::EcsTask;
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
    /// ECS container picker before execute-command
    ContainerPicker,
    /// EC2 start/stop/reboot confirmation popup
    PowerConfirm,
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

struct PendingEcsExec {
    account_id: String,
    region: String,
    cluster_arn: String,
    task_arn: String,
    containers: Vec<String>,
    selected: usize,
}

struct PendingPowerAction {
    instance_id: String,
    instance_name: Option<String>,
    account_id: String,
    region: String,
    current_state: InstanceState,
    action: Ec2PowerAction,
    confirmation: TextInput,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InventoryView {
    Ec2,
    Ecs,
}

impl InventoryView {
    fn label(self) -> &'static str {
        match self {
            Self::Ec2 => "EC2",
            Self::Ecs => "ECS",
        }
    }
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
    pub tasks: Vec<EcsTask>,
    pub loading: bool,
    pub error: Option<String>,
    entitlements: Option<UserEntitlements>,
    pub search_input: TextInput,
    table: SelectableTable,
    ecs_table: SelectableTable,
    view: InventoryView,
    focus: Ec2Focus,
    show_detail: bool,
    pending_connect: Option<PendingConnect>,
    pending_ecs_exec: Option<PendingEcsExec>,
    pending_power: Option<PendingPowerAction>,
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
            tasks: Vec::new(),
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
            ecs_table: SelectableTable::new(
                vec![
                    "Cluster".into(),
                    "Family".into(),
                    "Task ID".into(),
                    "Launch".into(),
                    "Status".into(),
                    "Containers".into(),
                    "Account".into(),
                    "Region".into(),
                ],
                vec![
                    Constraint::Length(20),
                    Constraint::Min(14),
                    Constraint::Length(18),
                    Constraint::Length(8),
                    Constraint::Length(10),
                    Constraint::Length(24),
                    Constraint::Length(14),
                    Constraint::Length(14),
                ],
            ),
            view: InventoryView::Ec2,
            focus: Ec2Focus::Table,
            show_detail: false,
            pending_connect: None,
            pending_ecs_exec: None,
            pending_power: None,
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

    pub fn set_tasks(&mut self, tasks: Vec<EcsTask>) {
        self.tasks = tasks;
        self.apply_ecs_filter();
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
        if !ent.features.can_view_ec2 && ent.features.can_view_ecs {
            self.view = InventoryView::Ecs;
        }

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

    fn selected_task(&self) -> Option<&EcsTask> {
        let filtered = self.filtered_tasks();
        self.ecs_table
            .selected()
            .and_then(|i| filtered.get(i).copied())
    }

    fn filtered_tasks(&self) -> Vec<&EcsTask> {
        let query = self.search_input.value.trim().to_ascii_lowercase();
        if query.is_empty() {
            return self.tasks.iter().collect();
        }

        self.tasks
            .iter()
            .filter(|task| {
                task.cluster_name.to_ascii_lowercase().contains(&query)
                    || task
                        .family
                        .as_deref()
                        .unwrap_or_default()
                        .to_ascii_lowercase()
                        .contains(&query)
                    || task
                        .task_id
                        .as_deref()
                        .unwrap_or_default()
                        .to_ascii_lowercase()
                        .contains(&query)
                    || task
                        .containers
                        .iter()
                        .any(|container| container.name.to_ascii_lowercase().contains(&query))
            })
            .collect()
    }

    fn apply_ecs_filter(&mut self) {
        let count = self.filtered_tasks().len();
        self.ecs_table.set_row_count(count);
    }

    fn refresh_current_view_action(&self) -> Action {
        match self.view {
            InventoryView::Ec2 => Action::RefreshEc2,
            InventoryView::Ecs => Action::RefreshEcsTasks,
        }
    }

    fn search_label(&self) -> &'static str {
        match self.view {
            InventoryView::Ec2 => "Search (name, id, ip)",
            InventoryView::Ecs => "Search (cluster, family, task, container)",
        }
    }

    fn can_view_inventory(&self, view: InventoryView) -> bool {
        match self.entitlements.as_ref() {
            Some(ent) => match view {
                InventoryView::Ec2 => ent.features.can_view_ec2,
                InventoryView::Ecs => ent.features.can_view_ecs,
            },
            None => true,
        }
    }

    fn toggle_target(&self) -> InventoryView {
        match self.view {
            InventoryView::Ec2 => InventoryView::Ecs,
            InventoryView::Ecs => InventoryView::Ec2,
        }
    }

    fn toggle_hint(&self) -> Option<&'static str> {
        let target = self.toggle_target();
        self.can_view_inventory(target).then_some(target.label())
    }

    pub fn toggle_inventory_view(&mut self) -> Action {
        let target = self.toggle_target();
        if !self.can_view_inventory(target) {
            return Action::ShowError(format!("{} inventory is not authorized", target.label()));
        }

        self.view = target;
        self.sanitize_scope_for_current_view();
        self.clear_instances();
        match self.view {
            InventoryView::Ec2 => Action::RefreshEc2,
            InventoryView::Ecs => Action::RefreshEcsTasks,
        }
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
            let has_start = self.has_power_entitlement(Ec2PowerAction::Start);
            let has_stop = self.has_power_entitlement(Ec2PowerAction::Stop);
            let has_reboot = self.has_power_entitlement(Ec2PowerAction::Reboot);

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

            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Power:",
                Style::default().bold().fg(Color::Red),
            )));
            if has_start {
                let (label, style) = if inst.state == InstanceState::Stopped {
                    (" - ready", Style::default().fg(Color::Green))
                } else {
                    (" - requires stopped", Style::default().fg(Color::Gray))
                };
                lines.push(Line::from(vec![
                    Span::styled("  [S] ", Style::default().fg(Color::Green).bold()),
                    Span::styled("Start", Style::default().fg(Color::White)),
                    Span::styled(label, style),
                ]));
            } else {
                lines.push(Line::from(vec![
                    Span::styled("  [S] ", Style::default().fg(Color::Gray)),
                    Span::styled("Start", Style::default().fg(Color::Gray)),
                    Span::styled(" - not authorized", Style::default().fg(Color::Red)),
                ]));
            }

            if has_stop {
                let (label, style) = if inst.state == InstanceState::Running {
                    (" - ready", Style::default().fg(Color::Green))
                } else {
                    (" - requires running", Style::default().fg(Color::Gray))
                };
                lines.push(Line::from(vec![
                    Span::styled("  [X] ", Style::default().fg(Color::Red).bold()),
                    Span::styled("Stop", Style::default().fg(Color::White)),
                    Span::styled(label, style),
                ]));
            } else {
                lines.push(Line::from(vec![
                    Span::styled("  [X] ", Style::default().fg(Color::Gray)),
                    Span::styled("Stop", Style::default().fg(Color::Gray)),
                    Span::styled(" - not authorized", Style::default().fg(Color::Red)),
                ]));
            }

            if has_reboot {
                let (label, style) = if inst.state == InstanceState::Running {
                    (" - ready", Style::default().fg(Color::Green))
                } else {
                    (" - requires running", Style::default().fg(Color::Gray))
                };
                lines.push(Line::from(vec![
                    Span::styled("  [B] ", Style::default().fg(Color::Yellow).bold()),
                    Span::styled("Reboot", Style::default().fg(Color::White)),
                    Span::styled(label, style),
                ]));
            } else {
                lines.push(Line::from(vec![
                    Span::styled("  [B] ", Style::default().fg(Color::Gray)),
                    Span::styled("Reboot", Style::default().fg(Color::Gray)),
                    Span::styled(" - not authorized", Style::default().fg(Color::Red)),
                ]));
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

    fn has_power_entitlement(&self, action: Ec2PowerAction) -> bool {
        self.entitlements
            .as_ref()
            .map(|entitlements| match action {
                Ec2PowerAction::Start => entitlements.features.can_start_ec2,
                Ec2PowerAction::Stop => entitlements.features.can_stop_ec2,
                Ec2PowerAction::Reboot => entitlements.features.can_reboot_ec2,
            })
            .unwrap_or(false)
    }

    fn start_power_action(&mut self, action: Ec2PowerAction) -> Action {
        if self.loading {
            return Action::Noop;
        }
        let Some(inst) = self.selected_instance() else {
            return Action::Noop;
        };
        if !self.has_power_entitlement(action) {
            return Action::ShowError(format!("EC2 {} is not authorized for this user", action));
        }

        match action {
            Ec2PowerAction::Start if inst.state != InstanceState::Stopped => {
                return Action::ShowError("Start is only available for stopped instances".into());
            }
            Ec2PowerAction::Stop | Ec2PowerAction::Reboot
                if inst.state != InstanceState::Running =>
            {
                return Action::ShowError(format!(
                    "{} is only available for running instances",
                    action
                ));
            }
            _ => {}
        }

        let mut confirmation = TextInput::new("Type instance id to confirm");
        confirmation.focused = true;

        self.pending_power = Some(PendingPowerAction {
            instance_id: inst.instance_id.clone(),
            instance_name: inst.name.clone(),
            account_id: inst.account_id.clone(),
            region: inst.region.clone(),
            current_state: inst.state.clone(),
            action,
            confirmation,
        });
        self.focus = Ec2Focus::PowerConfirm;
        Action::Noop
    }

    /// Clear instance list and selection to prevent stale cross-scope actions.
    fn clear_instances(&mut self) {
        // Advance generation first so any in-flight response is rejected
        self.fetch_generation += 1;
        self.instances.clear();
        self.tasks.clear();
        self.table.set_row_count(0);
        self.ecs_table.set_row_count(0);
        self.loading = false;
        self.error = None;
        self.show_detail = false;
        self.focus = Ec2Focus::Table;
        self.pending_connect = None;
        self.pending_ecs_exec = None;
        self.pending_power = None;
        self.search_input.clear();
    }

    fn account_scope_options(&self) -> Vec<String> {
        match self.view {
            InventoryView::Ec2 => self.available_accounts.clone(),
            InventoryView::Ecs => self.entitlements.as_ref().map_or_else(Vec::new, |ent| {
                ecs_account_scope_options(ent, self.selected_region.as_deref())
            }),
        }
    }

    fn region_scope_options(&self) -> Vec<String> {
        match self.view {
            InventoryView::Ec2 => self.available_regions.clone(),
            InventoryView::Ecs => self.entitlements.as_ref().map_or_else(Vec::new, |ent| {
                ecs_region_scope_options(ent, self.selected_account_id.as_deref())
            }),
        }
    }

    fn sanitize_scope_for_current_view(&mut self) {
        match self.view {
            InventoryView::Ec2 => {
                if self
                    .selected_account_id
                    .as_ref()
                    .is_some_and(|account| !self.available_accounts.contains(account))
                {
                    self.selected_account_id = None;
                }
                if self
                    .selected_region
                    .as_ref()
                    .is_some_and(|region| !self.available_regions.contains(region))
                {
                    self.selected_region = None;
                }
            }
            InventoryView::Ecs => {
                let Some(entitlements) = self.entitlements.as_ref() else {
                    self.selected_account_id = None;
                    self.selected_region = None;
                    return;
                };

                let accounts = ecs_account_scope_options(entitlements, None);
                if self
                    .selected_account_id
                    .as_ref()
                    .is_some_and(|account| !accounts.contains(account))
                {
                    self.selected_account_id = None;
                }

                let regions = ecs_region_scope_options(entitlements, None);
                if self.selected_region.as_ref().is_some_and(|region| {
                    !regions.contains(region)
                        && !ecs_region_selection_matches(
                            entitlements,
                            self.selected_account_id.as_deref(),
                            region,
                        )
                }) {
                    self.selected_region = None;
                }

                if let (Some(account), Some(region)) = (
                    self.selected_account_id.as_deref(),
                    self.selected_region.as_deref(),
                ) {
                    if !ecs_scope_pair_matches(entitlements, account, region) {
                        self.selected_region = None;
                    }
                }
            }
        }
    }

    /// Cycle account: None (All) → first → second → … → None (All)
    fn cycle_account(&mut self, forward: bool) -> bool {
        let accounts = self.account_scope_options();
        if accounts.is_empty() {
            return false;
        }
        let cur_idx = self
            .selected_account_id
            .as_ref()
            .and_then(|id| accounts.iter().position(|a| a == id));
        let next = if forward {
            match cur_idx {
                None => Some(0),
                Some(i) if i + 1 < accounts.len() => Some(i + 1),
                Some(_) => None,
            }
        } else {
            match cur_idx {
                None => Some(accounts.len() - 1),
                Some(0) => None,
                Some(i) => Some(i - 1),
            }
        };
        self.selected_account_id = next.map(|i| accounts[i].clone());
        self.clear_instances();
        true
    }

    /// Cycle region: None (All) → first → second → … → None (All)
    fn cycle_region(&mut self, forward: bool) -> bool {
        let regions = self.region_scope_options();
        if regions.is_empty() {
            return false;
        }
        let cur_idx = self
            .selected_region
            .as_ref()
            .and_then(|id| regions.iter().position(|r| r == id));
        let next = if forward {
            match cur_idx {
                None => Some(0),
                Some(i) if i + 1 < regions.len() => Some(i + 1),
                Some(_) => None,
            }
        } else {
            match cur_idx {
                None => Some(regions.len() - 1),
                Some(0) => None,
                Some(i) => Some(i - 1),
            }
        };
        self.selected_region = next.map(|i| regions[i].clone());
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

    fn start_ecs_exec(&mut self) -> Action {
        if self.loading {
            return Action::Noop;
        }
        let Some(task) = self.selected_task() else {
            return Action::Noop;
        };
        if task.last_status != "RUNNING" {
            return Action::ShowError("Task is not running".into());
        }
        if !task.enable_execute_command {
            return Action::ShowError("ECS Exec is not enabled for this task".into());
        }
        let containers = ecs_exec_ready_container_names(task);
        if containers.is_empty() {
            return Action::ShowError("No containers are ready for ECS Exec".into());
        }

        self.pending_ecs_exec = Some(PendingEcsExec {
            account_id: task.account_id.clone(),
            region: task.region.clone(),
            cluster_arn: task.cluster_arn.clone(),
            task_arn: task.task_arn.clone(),
            containers,
            selected: 0,
        });
        self.focus = Ec2Focus::ContainerPicker;
        Action::Noop
    }
}

fn ecs_exec_ready_container_names(task: &EcsTask) -> Vec<String> {
    task.containers
        .iter()
        .filter(|container| {
            container.last_status == "RUNNING" && container.execute_command_agent_running
        })
        .map(|container| container.name.clone())
        .collect()
}

fn ecs_account_scope_options(
    entitlements: &UserEntitlements,
    selected_region: Option<&str>,
) -> Vec<String> {
    let mut accounts = std::collections::BTreeSet::new();
    for pattern in &entitlements.allowed_clusters {
        let Some((region, account)) = ecs_cluster_pattern_scope(pattern) else {
            continue;
        };
        if !ecs_region_part_matches_selection(region, selected_region) {
            continue;
        }
        if account != "*" && !account.is_empty() {
            accounts.insert(account.to_string());
        }
    }
    accounts.into_iter().collect()
}

fn ecs_region_scope_options(
    entitlements: &UserEntitlements,
    selected_account: Option<&str>,
) -> Vec<String> {
    let mut regions = std::collections::BTreeSet::new();
    for pattern in &entitlements.allowed_clusters {
        let Some((region, account)) = ecs_cluster_pattern_scope(pattern) else {
            continue;
        };
        if !ecs_account_part_matches_selection(account, selected_account) {
            continue;
        }
        if region != "*" && !region.is_empty() {
            regions.insert(region.to_string());
        }
    }
    regions.into_iter().collect()
}

fn ecs_scope_pair_matches(entitlements: &UserEntitlements, account: &str, region: &str) -> bool {
    entitlements.allowed_clusters.iter().any(|pattern| {
        ecs_cluster_pattern_scope(pattern).is_some_and(|(cluster_region, cluster_account)| {
            ecs_account_part_matches_selection(cluster_account, Some(account))
                && ecs_region_part_matches_selection(cluster_region, Some(region))
        })
    })
}

fn ecs_region_selection_matches(
    entitlements: &UserEntitlements,
    selected_account: Option<&str>,
    region: &str,
) -> bool {
    entitlements.allowed_clusters.iter().any(|pattern| {
        ecs_cluster_pattern_scope(pattern).is_some_and(|(cluster_region, cluster_account)| {
            ecs_region_part_matches_selection(cluster_region, Some(region))
                && ecs_account_part_matches_selection(cluster_account, selected_account)
        })
    })
}

fn ecs_cluster_pattern_scope(pattern: &str) -> Option<(&str, &str)> {
    let mut parts = pattern.split(':');
    match (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        (Some("arn"), Some(_partition), Some("ecs"), Some(region), Some(account)) => {
            Some((region, account))
        }
        _ => None,
    }
}

fn ecs_region_part_matches_selection(part: &str, selected: Option<&str>) -> bool {
    selected.is_none_or(|selected| part == "*" || part == selected)
}

fn ecs_account_part_matches_selection(part: &str, selected: Option<&str>) -> bool {
    selected.is_none_or(|selected| part != "*" && part == selected)
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

        if matches!(self.focus, Ec2Focus::ContainerPicker) {
            if let Some(ref mut pending) = self.pending_ecs_exec {
                match key.code {
                    KeyCode::Esc => {
                        self.pending_ecs_exec = None;
                        self.focus = Ec2Focus::Table;
                        return Action::Noop;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if pending.selected > 0 {
                            pending.selected -= 1;
                        }
                        return Action::Noop;
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if pending.selected < pending.containers.len().saturating_sub(1) {
                            pending.selected += 1;
                        }
                        return Action::Noop;
                    }
                    KeyCode::Enter => {
                        let can_exec = self
                            .entitlements
                            .as_ref()
                            .map(|e| e.features.can_use_ecs_exec)
                            .unwrap_or(false);
                        if !can_exec {
                            return Action::ShowError(
                                "ECS exec requires can_use_ecs_exec entitlement".into(),
                            );
                        }
                        let container_name = pending.containers[pending.selected].clone();
                        let account_id = pending.account_id.clone();
                        let region = pending.region.clone();
                        let cluster_arn = pending.cluster_arn.clone();
                        let task_arn = pending.task_arn.clone();
                        self.pending_ecs_exec = None;
                        self.focus = Ec2Focus::Table;
                        return Action::ConnectEcsExec {
                            account_id,
                            region,
                            cluster_arn,
                            task_arn,
                            container_name,
                        };
                    }
                    _ => return Action::Noop,
                }
            }
        }

        if matches!(self.focus, Ec2Focus::PowerConfirm) {
            if let Some(ref mut pending) = self.pending_power {
                match key.code {
                    KeyCode::Esc => {
                        self.pending_power = None;
                        self.focus = Ec2Focus::DetailPanel;
                        return Action::Noop;
                    }
                    KeyCode::Enter => {
                        if pending.confirmation.value != pending.instance_id {
                            pending.confirmation.clear();
                            return Action::ShowError(
                                "Confirmation must exactly match the instance id".into(),
                            );
                        }
                        let instance_id = pending.instance_id.clone();
                        let account_id = pending.account_id.clone();
                        let region = pending.region.clone();
                        let action = pending.action;
                        let confirmation_instance_id = pending.confirmation.value.clone();
                        self.pending_power = None;
                        self.focus = Ec2Focus::DetailPanel;
                        return Action::PowerEc2 {
                            instance_id,
                            account_id,
                            region,
                            action,
                            confirmation_instance_id,
                        };
                    }
                    _ => {
                        pending.confirmation.handle_key(key);
                        return Action::Noop;
                    }
                }
            }
        }

        match key.code {
            KeyCode::Char('e')
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && !matches!(self.focus, Ec2Focus::SearchBox) =>
            {
                self.toggle_inventory_view()
            }
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
                    Ec2Focus::OsUserSelect | Ec2Focus::ContainerPicker | Ec2Focus::PowerConfirm => {
                    } // handled above
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
                    match self.view {
                        InventoryView::Ec2 => Action::SearchEc2(query),
                        InventoryView::Ecs => {
                            self.apply_ecs_filter();
                            Action::Noop
                        }
                    }
                }
                Ec2Focus::Table if self.view == InventoryView::Ecs => self.start_ecs_exec(),
                Ec2Focus::Table => {
                    self.show_detail = !self.show_detail;
                    if self.show_detail {
                        self.focus = Ec2Focus::DetailPanel;
                    }
                    Action::Noop
                }
                Ec2Focus::DetailPanel
                | Ec2Focus::OsUserSelect
                | Ec2Focus::ContainerPicker
                | Ec2Focus::PowerConfirm => Action::Noop,
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
                    return self.refresh_current_view_action();
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
                    return self.refresh_current_view_action();
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
                    return self.refresh_current_view_action();
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
                    return self.refresh_current_view_action();
                }
                Action::Noop
            }
            KeyCode::Char('r') if !matches!(self.focus, Ec2Focus::SearchBox) => {
                self.refresh_current_view_action()
            }
            KeyCode::Char('f')
                if self.view == InventoryView::Ec2
                    && !matches!(self.focus, Ec2Focus::SearchBox) =>
            {
                self.state_filter = self.state_filter.next();
                self.apply_state_filter();
                Action::Noop
            }
            KeyCode::Char('s')
                if self.view == InventoryView::Ec2
                    && !matches!(self.focus, Ec2Focus::SearchBox) =>
            {
                self.start_connect(shared::dto::ec2::ConnectMethod::Ssm)
            }
            KeyCode::Char('e')
                if self.view == InventoryView::Ec2
                    && !matches!(self.focus, Ec2Focus::SearchBox) =>
            {
                self.start_connect(shared::dto::ec2::ConnectMethod::Ec2InstanceConnect)
            }
            KeyCode::Char('c')
                if self.view == InventoryView::Ec2
                    && !matches!(self.focus, Ec2Focus::SearchBox) =>
            {
                self.start_connect(shared::dto::ec2::ConnectMethod::Ssh)
            }
            KeyCode::Char('S')
                if self.view == InventoryView::Ec2
                    && matches!(self.focus, Ec2Focus::DetailPanel) =>
            {
                self.start_power_action(Ec2PowerAction::Start)
            }
            KeyCode::Char('X')
                if self.view == InventoryView::Ec2
                    && matches!(self.focus, Ec2Focus::DetailPanel) =>
            {
                self.start_power_action(Ec2PowerAction::Stop)
            }
            KeyCode::Char('B')
                if self.view == InventoryView::Ec2
                    && matches!(self.focus, Ec2Focus::DetailPanel) =>
            {
                self.start_power_action(Ec2PowerAction::Reboot)
            }
            _ => {
                match self.focus {
                    Ec2Focus::SearchBox => {
                        self.search_input.handle_key(key);
                    }
                    Ec2Focus::Table | Ec2Focus::DetailPanel => {
                        if self.view == InventoryView::Ecs {
                            self.ecs_table.handle_key(key);
                        } else {
                            self.table.handle_key(key);
                        }
                    }
                    Ec2Focus::OsUserSelect | Ec2Focus::ContainerPicker | Ec2Focus::PowerConfirm => {
                    } // handled above
                }
                Action::Noop
            }
        }
    }

    fn handle_paste(&mut self, text: &str) -> Action {
        if matches!(self.focus, Ec2Focus::SearchBox) {
            self.search_input
                .insert_str(&text.replace("\r\n", "\n").replace(['\r', '\n'], " "));
        } else if matches!(self.focus, Ec2Focus::PowerConfirm) {
            if let Some(ref mut pending) = self.pending_power {
                pending
                    .confirmation
                    .insert_str(&text.replace("\r\n", "\n").replace(['\r', '\n'], " "));
            }
        }
        Action::Noop
    }

    fn render(&mut self, area: Rect, buf: &mut Buffer) {
        let outer = Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} Inventory ", self.view.label()))
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
        self.search_input.label = self.search_label().to_string();
        self.search_input.render(main_chunks[0], buf);

        // Account/Region scope header
        let account_options = self.account_scope_options();
        let region_options = self.region_scope_options();
        let acct_display = self.selected_account_id.as_deref().unwrap_or("All");
        let region_display = self.selected_region.as_deref().unwrap_or("All");
        let acct_label = if account_options.len() > 1 {
            format!("Account [/]: {}", acct_display)
        } else {
            format!("Account: {}", acct_display)
        };
        let region_label = if region_options.len() > 1 {
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
        if self.show_detail && self.view == InventoryView::Ec2 {
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
        let total_count = match self.view {
            InventoryView::Ec2 => self.instances.len(),
            InventoryView::Ecs => self.tasks.len(),
        };
        let filter_label = self.state_filter.label();

        let count_display = if self.view == InventoryView::Ecs {
            if self.search_input.value.trim().is_empty() {
                format!("{} tasks", total_count)
            } else {
                let filtered_task_count = self.filtered_tasks().len();
                format!("{}/{} tasks", filtered_task_count, total_count)
            }
        } else if self.state_filter == StateFilter::All {
            format!("{} instances", total_count)
        } else {
            format!("{}/{} [{}]", filtered_count, total_count, filter_label)
        };

        let toggle_hint = self.toggle_hint();
        let status = if self.loading {
            format!("Loading {}...", self.view.label())
        } else if let Some(ref err) = self.error {
            format!("Error: {}", err)
        } else if self.view == InventoryView::Ecs {
            if let Some(target) = toggle_hint {
                format!(
                    "{} | Ctrl+E: {} | /: search | r: refresh | Enter: containers | Esc: back",
                    count_display, target
                )
            } else {
                format!(
                    "{} | /: search | r: refresh | Enter: containers | Esc: back",
                    count_display
                )
            }
        } else if self.show_detail {
            if let Some(target) = toggle_hint {
                format!(
                    "{} | Ctrl+E: {} | s/e/c: connect | S/X/B: power | r: refresh | Esc: close",
                    count_display, target
                )
            } else {
                format!(
                    "{} | s/e/c: connect | S/X/B: power | r: refresh | Esc: close",
                    count_display
                )
            }
        } else if let Some(target) = toggle_hint {
            format!(
                "{} | Ctrl+E: {} | f: filter | /: search | r: refresh | Enter: detail | Esc: back",
                count_display, target
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
        if self.loading
            && match self.view {
                InventoryView::Ec2 => self.instances.is_empty(),
                InventoryView::Ecs => self.tasks.is_empty(),
            }
        {
            self.loading_spinner.render_overlay(inner, buf);
        }

        // OS user selection popup (rendered on top)
        if let Some(ref pending) = self.pending_connect {
            self.render_os_user_popup(inner, buf, pending);
        }

        if let Some(ref pending) = self.pending_ecs_exec {
            self.render_container_picker(inner, buf, pending);
        }

        if let Some(ref pending) = self.pending_power {
            self.render_power_confirmation(inner, buf, pending);
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
        vec![self.refresh_current_view_action()]
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

    fn render_container_picker(&self, area: Rect, buf: &mut Buffer, pending: &PendingEcsExec) {
        use ratatui::widgets::Clear;

        let popup_height = (pending.containers.len() as u16 + 5).min(area.height.saturating_sub(4));
        let popup_width = 56u16.min(area.width.saturating_sub(4));
        let popup_area = Rect {
            x: area.x + (area.width.saturating_sub(popup_width)) / 2,
            y: area.y + (area.height.saturating_sub(popup_height)) / 2,
            width: popup_width,
            height: popup_height,
        };

        Clear.render(popup_area, buf);

        let block = Block::default()
            .borders(Borders::ALL)
            .title(" ECS Exec — Select Container ")
            .border_style(Style::default().fg(Color::Cyan).bold());
        let inner = block.inner(popup_area);
        block.render(popup_area, buf);

        let mut lines = Vec::with_capacity(pending.containers.len() + 3);
        let task_label = pending
            .task_arn
            .rsplit('/')
            .next()
            .unwrap_or(pending.task_arn.as_str());
        lines.push(Line::from(vec![
            Span::styled("Task: ", Style::default().fg(Color::Gray)),
            Span::styled(task_label, Style::default().fg(Color::Yellow)),
        ]));
        lines.push(Line::from(""));

        for (i, container) in pending.containers.iter().enumerate() {
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
                format!("{}{}", prefix, container),
                style,
            )));
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "j/k: select | Enter: exec | Esc: cancel",
            Style::default().fg(Color::Gray),
        )));

        Paragraph::new(lines).render(inner, buf);
    }

    fn render_power_confirmation(
        &self,
        area: Rect,
        buf: &mut Buffer,
        pending: &PendingPowerAction,
    ) {
        use ratatui::widgets::Clear;

        let popup_width = 72u16.min(area.width.saturating_sub(4));
        let popup_height = 14u16.min(area.height.saturating_sub(4));
        let popup_area = Rect {
            x: area.x + (area.width.saturating_sub(popup_width)) / 2,
            y: area.y + (area.height.saturating_sub(popup_height)) / 2,
            width: popup_width,
            height: popup_height,
        };

        Clear.render(popup_area, buf);

        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" EC2 {} — Confirm ", pending.action))
            .border_style(Style::default().fg(Color::Red).bold());
        let inner = block.inner(popup_area);
        block.render(popup_area, buf);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(8),
                Constraint::Length(3),
                Constraint::Length(1),
            ])
            .split(inner);

        let action_style = match pending.action {
            Ec2PowerAction::Start => Style::default().fg(Color::Green).bold(),
            Ec2PowerAction::Stop => Style::default().fg(Color::Red).bold(),
            Ec2PowerAction::Reboot => Style::default().fg(Color::Yellow).bold(),
        };
        let lines = vec![
            Line::from(vec![
                Span::styled("Action:   ", Style::default().fg(Color::Gray)),
                Span::styled(pending.action.to_string(), action_style),
            ]),
            Line::from(vec![
                Span::styled("Instance: ", Style::default().fg(Color::Gray)),
                Span::styled(&pending.instance_id, Style::default().fg(Color::Yellow)),
            ]),
            Line::from(vec![
                Span::styled("Name:     ", Style::default().fg(Color::Gray)),
                Span::raw(pending.instance_name.as_deref().unwrap_or("-")),
            ]),
            Line::from(vec![
                Span::styled("Scope:    ", Style::default().fg(Color::Gray)),
                Span::raw(format!("{} / {}", pending.account_id, pending.region)),
            ]),
            Line::from(vec![
                Span::styled("State:    ", Style::default().fg(Color::Gray)),
                Span::raw(pending.current_state.to_string()),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "Type the full instance id below. The typed value is never stored in audit logs.",
                Style::default().fg(Color::Red),
            )),
        ];

        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .render(chunks[0], buf);
        pending.confirmation.render(chunks[1], buf);
        Paragraph::new("Enter: submit | Esc: cancel")
            .style(Style::default().fg(Color::Gray))
            .render(chunks[2], buf);
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
            Ec2Focus::ContainerPicker => "ContainerPicker",
            Ec2Focus::PowerConfirm => "PowerConfirm",
        }
    }
}

impl Ec2Screen {
    fn render_table(&mut self, area: Rect, buf: &mut Buffer) {
        if self.view == InventoryView::Ecs {
            self.render_ecs_table(area, buf);
            return;
        }

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
        self.table.render_with_rows_focused(
            rows.into_iter(),
            &title,
            area,
            buf,
            matches!(self.focus, Ec2Focus::Table),
        );
    }

    fn render_ecs_table(&mut self, area: Rect, buf: &mut Buffer) {
        let tasks = self.filtered_tasks();
        let rows: Vec<_> = tasks
            .into_iter()
            .map(|task| {
                let status_style = if task.last_status == "RUNNING" {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::Yellow)
                };
                let containers = task
                    .containers
                    .iter()
                    .map(|container| {
                        if container.execute_command_agent_running {
                            container.name.clone()
                        } else {
                            format!("{}*", container.name)
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(",");

                Row::new(vec![
                    Cell::from(task.cluster_name.clone()).style(Style::default().fg(Color::Cyan)),
                    Cell::from(task.family.clone().unwrap_or_else(|| "-".into()))
                        .style(Style::default().fg(Color::White).bold()),
                    Cell::from(task.task_id.clone().unwrap_or_else(|| "-".into()))
                        .style(Style::default().fg(Color::Yellow)),
                    Cell::from(task.launch_type.clone()).style(Style::default().fg(Color::Gray)),
                    Cell::from(task.last_status.clone()).style(status_style),
                    Cell::from(containers).style(Style::default().fg(Color::White)),
                    Cell::from(task.account_id.clone()).style(Style::default().fg(Color::Gray)),
                    Cell::from(task.region.clone()).style(Style::default().fg(Color::Gray)),
                ])
            })
            .collect();

        self.ecs_table.render_with_rows_focused(
            rows.into_iter(),
            "ECS Tasks",
            area,
            buf,
            matches!(self.focus, Ec2Focus::Table),
        );
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

    fn rendered_text(screen: &mut Ec2Screen) -> String {
        let area = Rect::new(0, 0, 140, 40);
        let mut buf = Buffer::empty(area);
        screen.render(area, &mut buf);

        let mut out = String::new();
        for cell in &buf.content {
            out.push_str(cell.symbol());
        }
        out
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
            allowed_clusters: vec![],
            task_tag_selectors: vec![],
            excluded_task_tag_selectors: vec![],
            excluded_container_names: vec![],
            allow_broad_cluster_discovery: false,
            allowed_os_users: vec!["ec2-user".into(), "ubuntu".into()],
            max_session_seconds: None,
        }
    }

    fn ecs_entitlements(can_exec: bool) -> UserEntitlements {
        let mut ent = test_entitlements();
        ent.features.can_view_ecs = true;
        ent.features.can_use_ecs_exec = can_exec;
        ent.allowed_clusters = vec!["arn:aws:ecs:us-east-1:111:cluster/app".into()];
        ent
    }

    fn multi_scope_ecs_entitlements() -> UserEntitlements {
        let mut ent = ecs_entitlements(true);
        ent.allowed_clusters = vec![
            "arn:aws:ecs:us-east-1:111:cluster/app".into(),
            "arn:aws:ecs:eu-west-1:222:cluster/app".into(),
        ];
        ent
    }

    fn wildcard_region_ecs_entitlements() -> UserEntitlements {
        let mut ent = ecs_entitlements(true);
        ent.allowed_regions.clear();
        ent.allowed_clusters = vec!["arn:aws:ecs:*:111:cluster/app".into()];
        ent
    }

    fn wildcard_account_ecs_entitlements() -> UserEntitlements {
        let mut ent = ecs_entitlements(true);
        ent.allowed_clusters = vec!["arn:aws:ecs:us-east-1:*:cluster/app".into()];
        ent
    }

    fn power_entitlements() -> UserEntitlements {
        let mut ent = test_entitlements();
        ent.features.can_start_ec2 = true;
        ent.features.can_stop_ec2 = true;
        ent.features.can_reboot_ec2 = true;
        ent
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

    fn ecs_task(containers: Vec<&str>) -> EcsTask {
        ecs_task_with_containers(
            containers
                .into_iter()
                .map(|name| (name, "RUNNING", true))
                .collect(),
        )
    }

    fn ecs_task_with_containers(containers: Vec<(&str, &str, bool)>) -> EcsTask {
        EcsTask {
            task_arn: "arn:aws:ecs:us-east-1:111:task/app/abc123".into(),
            cluster_arn: "arn:aws:ecs:us-east-1:111:cluster/app".into(),
            cluster_name: "app".into(),
            account_id: "111".into(),
            region: "us-east-1".into(),
            family: Some("web".into()),
            task_id: Some("abc123".into()),
            launch_type: "FARGATE".into(),
            last_status: "RUNNING".into(),
            desired_status: "RUNNING".into(),
            enable_execute_command: true,
            containers: containers
                .into_iter()
                .map(|(name, last_status, execute_command_agent_running)| {
                    shared::dto::ecs::EcsContainer {
                        name: name.into(),
                        last_status: last_status.into(),
                        execute_command_agent_running,
                    }
                })
                .collect(),
            tags: HashMap::new(),
        }
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

    #[test]
    fn toggle_ecs_view_clears_state_and_refreshes_current_view() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(ecs_entitlements(true));
        screen.set_instances(vec![running_instance("i-1")]);
        screen.set_tasks(vec![ecs_task(vec!["app"])]);
        let generation = screen.fetch_generation;

        let action = screen.toggle_inventory_view();

        assert!(matches!(action, Action::RefreshEcsTasks));
        assert_eq!(screen.view, InventoryView::Ecs);
        assert!(screen.instances.is_empty());
        assert!(screen.tasks.is_empty());
        assert_eq!(screen.fetch_generation, generation + 1);
    }

    #[test]
    fn ecs_view_only_user_defaults_to_ecs_and_refreshes_tasks_on_enter() {
        let mut screen = Ec2Screen::new();
        let mut ent = ecs_entitlements(false);
        ent.features.can_view_ec2 = false;
        screen.set_entitlements(ent);

        assert_eq!(screen.view, InventoryView::Ecs);
        let actions = screen.on_enter();
        assert!(actions.iter().any(|a| matches!(a, Action::RefreshEcsTasks)));
    }

    #[test]
    fn ecs_view_only_user_cannot_toggle_to_ec2() {
        let mut screen = Ec2Screen::new();
        let mut ent = ecs_entitlements(false);
        ent.features.can_view_ec2 = false;
        screen.set_entitlements(ent);

        let action = screen.toggle_inventory_view();

        assert!(matches!(action, Action::ShowError(ref msg) if msg.contains("EC2")));
        assert_eq!(screen.view, InventoryView::Ecs);
        assert!(screen.toggle_hint().is_none());
    }

    #[test]
    fn ec2_view_only_user_cannot_toggle_to_ecs() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(test_entitlements());

        let action = screen.toggle_inventory_view();

        assert!(matches!(action, Action::ShowError(ref msg) if msg.contains("ECS")));
        assert_eq!(screen.view, InventoryView::Ec2);
        assert!(screen.toggle_hint().is_none());
    }

    #[test]
    fn status_hides_toggle_hint_without_target_entitlement() {
        let mut screen = Ec2Screen::new();
        let mut ent = ecs_entitlements(false);
        ent.features.can_view_ec2 = false;
        screen.set_entitlements(ent);

        let text = rendered_text(&mut screen);

        assert!(!text.contains("Ctrl+E:"));
        assert!(text.contains("/: search"));
        assert!(text.contains("Enter: containers"));
    }

    #[test]
    fn status_shows_toggle_hint_when_target_entitled() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(ecs_entitlements(true));

        let ec2_text = rendered_text(&mut screen);
        assert!(ec2_text.contains("Ctrl+E: ECS"));

        let action = screen.toggle_inventory_view();
        assert!(matches!(action, Action::RefreshEcsTasks));
        let ecs_text = rendered_text(&mut screen);
        assert!(ecs_text.contains("Ctrl+E: EC2"));
    }

    #[test]
    fn ecs_view_search_label_describes_task_fields() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(ecs_entitlements(true));
        screen.view = InventoryView::Ecs;

        let text = rendered_text(&mut screen);

        assert!(text.contains("Search (cluster, family, task, container)"));
        assert!(!text.contains("Search (name, id, ip)"));
    }

    #[test]
    fn ecs_view_status_counts_filtered_search_results() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(ecs_entitlements(true));
        screen.view = InventoryView::Ecs;
        let mut worker = ecs_task(vec!["worker"]);
        worker.cluster_name = "jobs".into();
        worker.family = Some("worker".into());
        worker.task_id = Some("def456".into());
        screen.set_tasks(vec![ecs_task(vec!["app"]), worker]);
        screen.search_input.value = "worker".into();
        screen.apply_ecs_filter();

        let text = rendered_text(&mut screen);

        assert!(text.contains("1/2 tasks"));
    }

    #[test]
    fn ecs_view_account_cycle_uses_ecs_cluster_accounts_only() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(ecs_entitlements(true));
        screen.view = InventoryView::Ecs;

        assert!(screen.cycle_account(true));
        assert_eq!(screen.selected_account_id.as_deref(), Some("111"));
        assert!(screen.cycle_account(true));
        assert!(screen.selected_account_id.is_none());
    }

    #[test]
    fn ecs_view_region_cycle_uses_ecs_cluster_regions_only() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(ecs_entitlements(true));
        screen.view = InventoryView::Ecs;

        assert!(screen.cycle_region(true));
        assert_eq!(screen.selected_region.as_deref(), Some("us-east-1"));
        assert!(screen.cycle_region(true));
        assert!(screen.selected_region.is_none());
    }

    #[test]
    fn ecs_view_account_cycle_respects_selected_region_pair() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(multi_scope_ecs_entitlements());
        screen.view = InventoryView::Ecs;
        screen.selected_region = Some("eu-west-1".into());

        assert!(screen.cycle_account(true));
        assert_eq!(screen.selected_account_id.as_deref(), Some("222"));
        assert!(screen.cycle_account(true));
        assert!(screen.selected_account_id.is_none());
    }

    #[test]
    fn ecs_view_account_cycle_accepts_wildcard_region_pattern() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(wildcard_region_ecs_entitlements());
        screen.view = InventoryView::Ecs;
        screen.selected_region = Some("ap-northeast-1".into());

        assert!(screen.cycle_account(true));
        assert_eq!(screen.selected_account_id.as_deref(), Some("111"));
    }

    #[test]
    fn ecs_view_account_cycle_does_not_expand_wildcard_account_pattern() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(wildcard_account_ecs_entitlements());
        screen.view = InventoryView::Ecs;
        screen.selected_region = Some("us-east-1".into());

        assert!(!screen.cycle_account(true));
        assert!(screen.selected_account_id.is_none());
    }

    #[test]
    fn ecs_view_region_cycle_respects_selected_account_pair() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(multi_scope_ecs_entitlements());
        screen.view = InventoryView::Ecs;
        screen.selected_account_id = Some("111".into());

        assert!(screen.cycle_region(true));
        assert_eq!(screen.selected_region.as_deref(), Some("us-east-1"));
        assert!(screen.cycle_region(true));
        assert!(screen.selected_region.is_none());
    }

    #[test]
    fn toggling_to_ecs_resets_ec2_only_scope_selection() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(ecs_entitlements(true));
        screen.selected_account_id = Some("222".into());
        screen.selected_region = Some("eu-west-1".into());

        let action = screen.toggle_inventory_view();

        assert!(matches!(action, Action::RefreshEcsTasks));
        assert_eq!(screen.view, InventoryView::Ecs);
        assert!(screen.selected_account_id.is_none());
        assert!(screen.selected_region.is_none());
    }

    #[test]
    fn toggling_to_ecs_resets_cross_pair_scope_selection() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(multi_scope_ecs_entitlements());
        screen.selected_account_id = Some("111".into());
        screen.selected_region = Some("eu-west-1".into());

        let action = screen.toggle_inventory_view();

        assert!(matches!(action, Action::RefreshEcsTasks));
        assert_eq!(screen.view, InventoryView::Ecs);
        assert_eq!(screen.selected_account_id.as_deref(), Some("111"));
        assert!(screen.selected_region.is_none());
    }

    #[test]
    fn toggling_to_ecs_keeps_region_selected_when_wildcard_region_authorizes_it() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(wildcard_region_ecs_entitlements());
        screen.selected_account_id = Some("111".into());
        screen.selected_region = Some("ap-northeast-1".into());

        let action = screen.toggle_inventory_view();

        assert!(matches!(action, Action::RefreshEcsTasks));
        assert_eq!(screen.view, InventoryView::Ecs);
        assert_eq!(screen.selected_account_id.as_deref(), Some("111"));
        assert_eq!(screen.selected_region.as_deref(), Some("ap-northeast-1"));
    }

    #[test]
    fn ecs_scope_pair_matches_wildcard_region_pattern() {
        let entitlements = wildcard_region_ecs_entitlements();

        assert!(ecs_scope_pair_matches(
            &entitlements,
            "111",
            "ap-northeast-1"
        ));
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

    #[test]
    fn container_picker_always_shown_even_for_one_container() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(ecs_entitlements(true));
        screen.view = InventoryView::Ecs;
        screen.set_tasks(vec![ecs_task(vec!["app"])]);

        let action = screen.handle_key(key(KeyCode::Enter));

        assert!(matches!(action, Action::Noop));
        assert_eq!(screen.test_focus(), "ContainerPicker");
        assert!(screen.pending_ecs_exec.is_some());
    }

    #[test]
    fn container_picker_escape_returns_to_ecs_table_without_dispatch() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(ecs_entitlements(true));
        screen.view = InventoryView::Ecs;
        screen.set_tasks(vec![ecs_task(vec!["app"])]);
        screen.handle_key(key(KeyCode::Enter));

        let action = screen.handle_key(key(KeyCode::Esc));

        assert!(matches!(action, Action::Noop));
        assert_eq!(screen.test_focus(), "Table");
        assert!(screen.pending_ecs_exec.is_none());
    }

    #[test]
    fn container_picker_connect_disabled_without_exec_entitlement() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(ecs_entitlements(false));
        screen.view = InventoryView::Ecs;
        screen.set_tasks(vec![ecs_task(vec!["app"])]);
        screen.handle_key(key(KeyCode::Enter));

        let action = screen.handle_key(key(KeyCode::Enter));

        assert!(matches!(action, Action::ShowError(ref msg) if msg.contains("can_use_ecs_exec")));
        assert!(screen.pending_ecs_exec.is_some());
    }

    #[test]
    fn container_picker_skips_containers_without_exec_agent() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(ecs_entitlements(true));
        screen.view = InventoryView::Ecs;
        screen.set_tasks(vec![ecs_task_with_containers(vec![
            ("app", "RUNNING", true),
            ("sidecar", "RUNNING", false),
            ("worker", "STOPPED", true),
        ])]);

        let action = screen.handle_key(key(KeyCode::Enter));

        assert!(matches!(action, Action::Noop));
        let pending = screen.pending_ecs_exec.as_ref().unwrap();
        assert_eq!(pending.containers, vec!["app"]);
    }

    #[test]
    fn container_picker_errors_when_no_container_is_exec_ready() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(ecs_entitlements(true));
        screen.view = InventoryView::Ecs;
        screen.set_tasks(vec![ecs_task_with_containers(vec![
            ("sidecar", "RUNNING", false),
            ("worker", "STOPPED", true),
        ])]);

        let action = screen.handle_key(key(KeyCode::Enter));

        assert!(
            matches!(action, Action::ShowError(ref msg) if msg.contains("No containers are ready"))
        );
        assert!(screen.pending_ecs_exec.is_none());
        assert_eq!(screen.test_focus(), "Table");
    }

    #[test]
    fn container_picker_enter_dispatches_selected_container() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(ecs_entitlements(true));
        screen.view = InventoryView::Ecs;
        screen.set_tasks(vec![ecs_task(vec!["app", "worker"])]);
        screen.handle_key(key(KeyCode::Enter));
        screen.handle_key(key(KeyCode::Down));

        let action = screen.handle_key(key(KeyCode::Enter));

        assert!(matches!(
            action,
            Action::ConnectEcsExec {
                ref container_name,
                ..
            } if container_name == "worker"
        ));
        assert!(screen.pending_ecs_exec.is_none());
        assert_eq!(screen.test_focus(), "Table");
    }

    #[test]
    fn power_key_opens_confirmation_from_detail_panel() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(power_entitlements());
        screen.set_instances(vec![running_instance("i-1")]);
        screen.handle_key(key(KeyCode::Enter));

        let action = screen.handle_key(key(KeyCode::Char('X')));

        assert!(matches!(action, Action::Noop));
        assert_eq!(screen.test_focus(), "PowerConfirm");
        assert!(matches!(
            screen.pending_power.as_ref().map(|pending| pending.action),
            Some(Ec2PowerAction::Stop)
        ));
    }

    #[test]
    fn power_confirmation_dispatches_exact_instance_id() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(power_entitlements());
        screen.set_instances(vec![running_instance("i-1")]);
        screen.handle_key(key(KeyCode::Enter));
        screen.handle_key(key(KeyCode::Char('B')));
        screen.handle_paste("i-1");

        let action = screen.handle_key(key(KeyCode::Enter));

        assert!(matches!(
            action,
            Action::PowerEc2 {
                ref instance_id,
                action: Ec2PowerAction::Reboot,
                ref confirmation_instance_id,
                ..
            } if instance_id == "i-1" && confirmation_instance_id == "i-1"
        ));
        assert!(screen.pending_power.is_none());
        assert_eq!(screen.test_focus(), "DetailPanel");
    }

    #[test]
    fn power_confirmation_rejects_mismatch_locally() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(power_entitlements());
        screen.set_instances(vec![stopped_instance("i-2")]);
        screen.handle_key(key(KeyCode::Enter));
        screen.handle_key(key(KeyCode::Char('S')));
        screen.handle_paste("wrong");

        let action = screen.handle_key(key(KeyCode::Enter));

        assert!(matches!(
            action,
            Action::ShowError(ref msg) if msg.contains("exactly match")
        ));
        assert!(screen.pending_power.is_some());
        assert_eq!(screen.test_focus(), "PowerConfirm");
    }

    #[test]
    fn power_start_requires_stopped_instance() {
        let mut screen = Ec2Screen::new();
        screen.set_entitlements(power_entitlements());
        screen.set_instances(vec![running_instance("i-1")]);
        screen.handle_key(key(KeyCode::Enter));

        let action = screen.handle_key(key(KeyCode::Char('S')));

        assert!(matches!(
            action,
            Action::ShowError(ref msg) if msg.contains("stopped")
        ));
        assert!(screen.pending_power.is_none());
    }

    #[test]
    fn paste_in_search_box_inserts_search_text() {
        let mut screen = Ec2Screen::new();
        screen.handle_key(key(KeyCode::Char('/')));

        screen.handle_paste("web\napi");

        assert_eq!(screen.search_input.value, "web api");
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
