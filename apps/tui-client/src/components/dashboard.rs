use crossterm::event::KeyEvent;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
};
use shared::dto::entitlements::UserEntitlements;

use super::Component;
use crate::event::{Action, Screen};
use crate::keybindings::{DashboardShortcut, KeyBindings};
use crate::theme::Theme;

struct MenuItem {
    shortcut: DashboardShortcut,
    label: &'static str,
    screen: Screen,
    enabled: bool,
    /// When true the item is completely hidden from the menu (used for
    /// beta features gated behind a feature flag).
    hidden: bool,
}

pub struct DashboardScreen {
    entitlements: Option<UserEntitlements>,
    selected: usize,
    items: Vec<MenuItem>,
    mcp_server_running: bool,
    mcp_pulse_tick: u8,
    live_tail_enabled: bool,
    pub public_ip: Option<String>,
    pub show_public_ip: bool,
    pub ip_fetch_generation: u64,
    keybindings: KeyBindings,
    theme: Theme,
}

impl DashboardScreen {
    pub fn new(
        enable_live_tail: bool,
        show_public_ip: bool,
        keybindings: KeyBindings,
        theme: Theme,
    ) -> Self {
        Self {
            entitlements: None,
            selected: 0,
            mcp_server_running: false,
            mcp_pulse_tick: 0,
            live_tail_enabled: enable_live_tail,
            public_ip: None,
            show_public_ip,
            ip_fetch_generation: 0,
            keybindings,
            theme,
            items: vec![
                MenuItem {
                    shortcut: DashboardShortcut::Inventory,
                    label: "Inventory",
                    screen: Screen::Ec2Inventory,
                    enabled: false,
                    hidden: false,
                },
                MenuItem {
                    shortcut: DashboardShortcut::CloudWatch,
                    label: "CloudWatch Search",
                    screen: Screen::CloudWatchSearch,
                    enabled: false,
                    hidden: false,
                },
                MenuItem {
                    shortcut: DashboardShortcut::LiveTail,
                    label: "Live Tail",
                    screen: Screen::LiveTail,
                    enabled: false,
                    hidden: !enable_live_tail,
                },
                MenuItem {
                    shortcut: DashboardShortcut::Access,
                    label: "Access / Identity",
                    screen: Screen::Access,
                    enabled: true,
                    hidden: false,
                },
                MenuItem {
                    shortcut: DashboardShortcut::Settings,
                    label: "Settings",
                    screen: Screen::Settings,
                    enabled: true,
                    hidden: false,
                },
                MenuItem {
                    shortcut: DashboardShortcut::Mcp,
                    label: "MCP / AI Tools",
                    screen: Screen::Mcp,
                    enabled: false,
                    hidden: false,
                },
            ],
        }
    }

    /// Returns only the items that are visible (not hidden by feature flags).
    fn visible_items(&self) -> Vec<&MenuItem> {
        self.items.iter().filter(|i| !i.hidden).collect()
    }

    pub fn set_entitlements(&mut self, ent: UserEntitlements) {
        self.items[0].enabled = ent.features.can_view_ec2 || ent.features.can_view_ecs;
        self.items[1].enabled = ent.features.can_use_cloudwatch_search;
        // Only enable live tail when the feature flag is on AND the user has
        // the entitlement.
        self.items[2].enabled = self.live_tail_enabled && ent.features.can_use_cloudwatch_tail;
        self.items[5].enabled = ent.features.can_use_mcp;
        self.entitlements = Some(ent);
    }

    pub fn set_mcp_server_running(&mut self, running: bool) {
        self.mcp_server_running = running;
        if !running {
            self.mcp_pulse_tick = 0;
        }
    }

    fn try_navigate(&self, item: &MenuItem) -> Action {
        if !item.enabled {
            return Action::ShowError(
                "Feature not available with your current entitlements".into(),
            );
        }
        if item.screen == Screen::LiveTail && !self.live_tail_enabled {
            return Action::ShowError("Live Tail — Coming Soon".into());
        }
        Action::NavigateTo(item.screen.clone())
    }

    fn menu_item_style(&self, item: &MenuItem, selected: bool) -> Style {
        if !item.enabled {
            return Style::default().fg(self.theme.muted);
        }

        if item.screen == Screen::Mcp && self.mcp_server_running {
            return self.mcp_running_style(selected);
        }

        if selected {
            return Style::default()
                .fg(self.theme.selected_fg)
                .bg(self.theme.selected_bg)
                .bold();
        }

        Style::default().fg(self.theme.text)
    }

    fn mcp_running_style(&self, selected: bool) -> Style {
        let bright = self.mcp_pulse_tick % 8 < 4;
        let fg = if bright {
            Color::LightGreen
        } else {
            Color::Green
        };

        if selected {
            Style::default().fg(fg).bg(self.theme.selected_bg).bold()
        } else {
            Style::default().fg(fg).bold()
        }
    }
}

impl Component for DashboardScreen {
    fn handle_key(&mut self, key: KeyEvent) -> Action {
        if self.keybindings.matches_any(&self.keybindings.quit, &key) {
            return Action::Quit;
        }
        if self.keybindings.matches_any(&self.keybindings.logout, &key) {
            return Action::Logout;
        }
        if self
            .keybindings
            .matches_any(&self.keybindings.dashboard_quit, &key)
        {
            return Action::Quit;
        }
        let visible: Vec<&MenuItem> = self.visible_items();

        if self
            .keybindings
            .matches_any(&self.keybindings.dashboard_up, &key)
        {
            if self.selected > 0 {
                self.selected -= 1;
            }
            return Action::Noop;
        }

        if self
            .keybindings
            .matches_any(&self.keybindings.dashboard_down, &key)
        {
            if self.selected < visible.len().saturating_sub(1) {
                self.selected += 1;
            }
            return Action::Noop;
        }

        if self
            .keybindings
            .matches_any(&self.keybindings.dashboard_select, &key)
        {
            if let Some(item) = visible.get(self.selected) {
                return self.try_navigate(item);
            }
            return Action::Noop;
        }

        if let Some(item) = visible.iter().find(|item| {
            self.keybindings
                .matches_dashboard_shortcut(item.shortcut, &key)
        }) {
            self.try_navigate(item)
        } else {
            Action::Noop
        }
    }

    fn render(&mut self, area: Rect, buf: &mut Buffer) {
        let outer = Block::default()
            .borders(Borders::ALL)
            .title(" Canopy - Dashboard ")
            .border_style(Style::default().fg(self.theme.accent));
        let inner = outer.inner(area);
        outer.render(area, buf);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // IP + Time bar
                Constraint::Length(1), // Spacer
                Constraint::Length(4), // Welcome
                Constraint::Length(1), // Spacer
                Constraint::Min(10),   // Menu
                Constraint::Length(2), // Help
            ])
            .split(inner);

        // Info bar (time + optional IP)
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let info_line = if self.show_public_ip {
            let ip_display = self.public_ip.as_deref().unwrap_or("fetching...");
            Line::from(vec![
                Span::styled(" IP: ", Style::default().fg(self.theme.muted)),
                Span::styled(ip_display, Style::default().fg(self.theme.warning)),
                Span::styled("  │  ", Style::default().fg(self.theme.muted)),
                Span::styled(&now, Style::default().fg(self.theme.accent)),
            ])
        } else {
            Line::from(vec![
                Span::styled(" ", Style::default()),
                Span::styled(&now, Style::default().fg(self.theme.accent)),
            ])
        };
        Paragraph::new(info_line).render(chunks[0], buf);

        // Welcome message
        let welcome_text = if let Some(ref ent) = self.entitlements {
            format!(
                "Welcome, {}\n{} | {} accounts | {} regions",
                ent.display_name,
                ent.groups.join(", "),
                ent.allowed_accounts.len(),
                ent.allowed_regions.len(),
            )
        } else {
            "Loading entitlements...".into()
        };

        Paragraph::new(welcome_text)
            .style(Style::default().fg(self.theme.accent))
            .wrap(Wrap { trim: true })
            .render(chunks[2], buf);

        // Menu items (only show visible items)
        let visible: Vec<&MenuItem> = self.visible_items();
        let menu_area = chunks[4];
        let item_height = 2u16;
        for (i, item) in visible.iter().enumerate() {
            let y = menu_area.y + (i as u16 * item_height);
            if y >= menu_area.y + menu_area.height {
                break;
            }

            let item_area = Rect {
                x: menu_area.x + 2,
                y,
                width: menu_area.width.saturating_sub(4),
                height: item_height,
            };

            let selected = i == self.selected;
            let style = self.menu_item_style(item, selected);
            let prefix = if selected { ">>" } else { "  " };

            let label = if item.screen == Screen::Ec2Inventory {
                inventory_label(self.entitlements.as_ref(), item.label)
            } else {
                item.label
            };
            let status = if item.enabled { "" } else { " (disabled)" };
            let key_label = KeyBindings::first_label(
                self.keybindings.dashboard_shortcut_bindings(item.shortcut),
            );
            let text = format!("{} [{}] {}{}", prefix, key_label, label, status);
            Paragraph::new(text).style(style).render(item_area, buf);
        }

        // Help bar
        let help = format!(
            "{}: logout | {}: quit | {}/{}: navigate | {}: select",
            KeyBindings::first_label(&self.keybindings.logout),
            KeyBindings::first_label(&self.keybindings.dashboard_quit),
            KeyBindings::first_label(&self.keybindings.dashboard_up),
            KeyBindings::first_label(&self.keybindings.dashboard_down),
            KeyBindings::first_label(&self.keybindings.dashboard_select)
        );
        Paragraph::new(help)
            .style(Style::default().fg(self.theme.muted))
            .render(chunks[5], buf);
    }

    fn on_enter(&mut self) -> Vec<Action> {
        if self.show_public_ip && self.public_ip.is_none() {
            vec![Action::FetchPublicIp]
        } else {
            vec![]
        }
    }

    fn on_tick(&mut self) {
        if self.mcp_server_running {
            self.mcp_pulse_tick = self.mcp_pulse_tick.wrapping_add(1);
        }
    }
}

fn inventory_label(
    entitlements: Option<&UserEntitlements>,
    fallback: &'static str,
) -> &'static str {
    match entitlements.map(|ent| (ent.features.can_view_ec2, ent.features.can_view_ecs)) {
        Some((true, true)) => "Inventory (EC2 + ECS)",
        Some((true, false)) => "Inventory (EC2)",
        Some((false, true)) => "Inventory (ECS)",
        _ => fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
    use shared::dto::entitlements::*;

    fn key(code: KeyCode) -> KeyEvent {
        key_with_modifiers(code, KeyModifiers::empty())
    }

    fn key_with_modifiers(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn test_entitlements(ec2: bool, cw: bool, tail: bool) -> UserEntitlements {
        UserEntitlements {
            user_id: "u1".into(),
            email: "test@example.com".into(),
            display_name: "Test User".into(),
            groups: vec!["ops".into()],
            features: FeatureFlags {
                can_view_ec2: ec2,
                can_use_cloudwatch_search: cw,
                can_use_cloudwatch_tail: tail,
                can_use_ssm: false,
                can_use_ec2_instance_connect: false,
                ..Default::default()
            },
            allowed_accounts: vec![AllowedAccount {
                account_id: "111111111111".into(),
                account_name: "dev".into(),
                role_arn: "arn:aws:iam::111111111111:role/ops".into(),
            }],
            allowed_regions: vec!["us-east-1".into()],
            allowed_log_group_arns: vec![],
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
        }
    }

    fn test_theme() -> Theme {
        Theme::default()
    }

    fn rendered_text(screen: &mut DashboardScreen) -> String {
        let area = Rect::new(0, 0, 100, 32);
        let mut buf = Buffer::empty(area);
        screen.render(area, &mut buf);

        let mut out = String::new();
        for cell in &buf.content {
            out.push_str(cell.symbol());
        }
        out
    }

    fn rendered_buffer(screen: &mut DashboardScreen) -> Buffer {
        let area = Rect::new(0, 0, 100, 32);
        let mut buf = Buffer::empty(area);
        screen.render(area, &mut buf);
        buf
    }

    #[test]
    fn initial_state_all_menu_items_except_access_settings_disabled() {
        let screen = DashboardScreen::new(false, false, KeyBindings::default(), test_theme());
        let visible = screen.visible_items();
        // Items: Inventory(disabled), CW(disabled), Access(enabled), Settings(enabled), MCP(disabled)
        // Live Tail is hidden when enable_live_tail=false
        assert_eq!(visible.len(), 5);
        assert!(!visible[0].enabled); // Inventory
        assert!(!visible[1].enabled); // CW
        assert!(visible[2].enabled); // Access
        assert!(visible[3].enabled); // Settings
        assert!(!visible[4].enabled); // MCP
    }

    #[test]
    fn set_entitlements_enables_ec2_and_cloudwatch() {
        let mut screen = DashboardScreen::new(false, false, KeyBindings::default(), test_theme());
        screen.set_entitlements(test_entitlements(true, true, false));

        let visible = screen.visible_items();
        assert!(visible[0].enabled); // EC2
        assert!(visible[1].enabled); // CW
    }

    #[test]
    fn set_entitlements_enables_inventory_for_ecs_view_only_user() {
        let mut screen = DashboardScreen::new(false, false, KeyBindings::default(), test_theme());
        let mut ent = test_entitlements(false, false, false);
        ent.features.can_view_ecs = true;
        screen.set_entitlements(ent);

        let visible = screen.visible_items();
        assert!(visible[0].enabled);
        let action = screen.handle_key(key(KeyCode::Char('1')));
        assert!(matches!(action, Action::NavigateTo(Screen::Ec2Inventory)));
    }

    #[test]
    fn dashboard_inventory_label_is_ecs_aware() {
        let mut both = DashboardScreen::new(false, false, KeyBindings::default(), test_theme());
        let mut both_ent = test_entitlements(true, false, false);
        both_ent.features.can_view_ecs = true;
        both.set_entitlements(both_ent);
        let both_text = rendered_text(&mut both);
        assert!(both_text.contains("Inventory (EC2 + ECS)"));
        assert!(!both_text.contains("EC2 Inventory"));

        let mut ecs_only = DashboardScreen::new(false, false, KeyBindings::default(), test_theme());
        let mut ecs_ent = test_entitlements(false, false, false);
        ecs_ent.features.can_view_ecs = true;
        ecs_only.set_entitlements(ecs_ent);
        let ecs_text = rendered_text(&mut ecs_only);
        assert!(ecs_text.contains("Inventory (ECS)"));
        assert!(!ecs_text.contains("EC2 Inventory"));

        let mut ec2_only = DashboardScreen::new(false, false, KeyBindings::default(), test_theme());
        ec2_only.set_entitlements(test_entitlements(true, false, false));
        let ec2_text = rendered_text(&mut ec2_only);
        assert!(ec2_text.contains("Inventory (EC2)"));
        assert!(!ec2_text.contains("EC2 Inventory"));
    }

    #[test]
    fn live_tail_hidden_when_feature_flag_off() {
        let screen = DashboardScreen::new(false, false, KeyBindings::default(), test_theme());
        let visible = screen.visible_items();
        assert!(visible.iter().all(|i| i.screen != Screen::LiveTail));
    }

    #[test]
    fn live_tail_visible_when_feature_flag_on() {
        let screen = DashboardScreen::new(true, false, KeyBindings::default(), test_theme());
        let visible = screen.visible_items();
        assert!(visible.iter().any(|i| i.screen == Screen::LiveTail));
    }

    #[test]
    fn live_tail_enabled_only_with_entitlement_and_flag() {
        let mut screen = DashboardScreen::new(true, false, KeyBindings::default(), test_theme());
        screen.set_entitlements(test_entitlements(false, false, true));

        let lt = screen
            .items
            .iter()
            .find(|i| i.screen == Screen::LiveTail)
            .unwrap();
        assert!(lt.enabled);
    }

    #[test]
    fn navigate_up_down_wraps_selection() {
        let mut screen = DashboardScreen::new(false, false, KeyBindings::default(), test_theme());
        assert_eq!(screen.selected, 0);

        screen.handle_key(key(KeyCode::Down));
        assert_eq!(screen.selected, 1);

        screen.handle_key(key(KeyCode::Char('j')));
        assert_eq!(screen.selected, 2);

        // Can't go past the last visible item
        screen.handle_key(key(KeyCode::Down));
        screen.handle_key(key(KeyCode::Down));
        screen.handle_key(key(KeyCode::Down));
        assert_eq!(screen.selected, screen.visible_items().len() - 1);

        screen.handle_key(key(KeyCode::Up));
        assert_eq!(screen.selected, screen.visible_items().len() - 2);

        // Can't go below 0
        screen.selected = 0;
        screen.handle_key(key(KeyCode::Up));
        assert_eq!(screen.selected, 0);
    }

    #[test]
    fn enter_on_disabled_item_shows_error() {
        let mut screen = DashboardScreen::new(false, false, KeyBindings::default(), test_theme());
        // selected=0 is EC2, disabled
        let action = screen.handle_key(key(KeyCode::Enter));
        assert!(matches!(action, Action::ShowError(_)));
    }

    #[test]
    fn enter_on_enabled_item_navigates() {
        let mut screen = DashboardScreen::new(false, false, KeyBindings::default(), test_theme());
        screen.set_entitlements(test_entitlements(true, false, false));

        // selected=0 is EC2, now enabled
        let action = screen.handle_key(key(KeyCode::Enter));
        assert!(matches!(action, Action::NavigateTo(Screen::Ec2Inventory)));
    }

    #[test]
    fn quick_nav_by_number() {
        let mut screen = DashboardScreen::new(false, false, KeyBindings::default(), test_theme());
        screen.set_entitlements(test_entitlements(true, true, false));

        let action = screen.handle_key(key(KeyCode::Char('2')));
        assert!(matches!(
            action,
            Action::NavigateTo(Screen::CloudWatchSearch)
        ));
    }

    #[test]
    fn custom_quick_nav_replaces_default_key() {
        let bindings = KeyBindings {
            dashboard_cloudwatch: vec!["c".into()],
            ..Default::default()
        };
        let mut screen = DashboardScreen::new(false, false, bindings, test_theme());
        screen.set_entitlements(test_entitlements(true, true, false));

        let default_action = screen.handle_key(key(KeyCode::Char('2')));
        assert!(matches!(default_action, Action::Noop));

        let custom_action = screen.handle_key(key(KeyCode::Char('c')));
        assert!(matches!(
            custom_action,
            Action::NavigateTo(Screen::CloudWatchSearch)
        ));
    }

    #[test]
    fn render_applies_configured_selection_theme() {
        let theme = Theme {
            selected_bg: Color::Blue,
            selected_fg: Color::LightYellow,
            ..Theme::default()
        };
        let mut screen = DashboardScreen::new(false, false, KeyBindings::default(), theme);
        let area = Rect::new(0, 0, 100, 32);
        let mut buf = Buffer::empty(area);
        screen.set_entitlements(test_entitlements(true, false, false));

        screen.render(area, &mut buf);

        let selected_cells = buf
            .content
            .iter()
            .filter(|cell| cell.symbol() != " " && cell.bg == Color::Blue)
            .count();
        assert!(selected_cells > 0);
        assert!(buf.content.iter().any(|cell| {
            cell.symbol() != " " && cell.bg == Color::Blue && cell.fg == Color::LightYellow
        }));
    }

    #[test]
    fn running_mcp_menu_item_uses_green_pulse_style() {
        let mut screen = DashboardScreen::new(false, false, KeyBindings::default(), test_theme());
        let mut ent = test_entitlements(false, false, false);
        ent.features.can_use_mcp = true;
        screen.set_entitlements(ent);
        screen.set_mcp_server_running(true);
        screen.selected = screen.visible_items().len() - 1;

        let bright = rendered_buffer(&mut screen);
        assert!(bright.content.iter().any(|cell| cell.symbol() != " "
            && cell.fg == Color::LightGreen
            && cell.bg == screen.theme.selected_bg));
        assert!(!bright
            .content
            .iter()
            .any(|cell| cell.symbol() != " " && cell.bg == Color::LightGreen));

        for _ in 0..4 {
            screen.on_tick();
        }

        let dim = rendered_buffer(&mut screen);
        assert!(dim.content.iter().any(|cell| cell.symbol() != " "
            && cell.fg == Color::Green
            && cell.bg == screen.theme.selected_bg));
        assert!(!dim
            .content
            .iter()
            .any(|cell| cell.symbol() != " " && cell.bg == Color::Indexed(22)));
    }

    #[test]
    fn stopping_mcp_resets_dashboard_pulse_style() {
        let mut screen = DashboardScreen::new(false, false, KeyBindings::default(), test_theme());
        let mut ent = test_entitlements(false, false, false);
        ent.features.can_use_mcp = true;
        screen.set_entitlements(ent);
        screen.set_mcp_server_running(true);
        screen.set_mcp_server_running(false);
        screen.selected = screen.visible_items().len() - 1;

        let buf = rendered_buffer(&mut screen);
        assert!(buf
            .content
            .iter()
            .any(|cell| cell.symbol() != " " && cell.bg == screen.theme.selected_bg));
        assert!(!buf
            .content
            .iter()
            .any(|cell| cell.symbol() != " " && cell.bg == Color::LightGreen));
    }

    #[test]
    fn q_quits() {
        let mut screen = DashboardScreen::new(false, false, KeyBindings::default(), test_theme());
        let action = screen.handle_key(key(KeyCode::Char('q')));
        assert!(matches!(action, Action::Quit));
    }

    #[test]
    fn ctrl_x_logs_out() {
        let mut screen = DashboardScreen::new(false, false, KeyBindings::default(), test_theme());
        let action = screen.handle_key(key_with_modifiers(
            KeyCode::Char('x'),
            KeyModifiers::CONTROL,
        ));
        assert!(matches!(action, Action::Logout));
    }

    #[test]
    fn plain_x_upper_x_and_tab_do_not_log_out() {
        let mut screen = DashboardScreen::new(false, false, KeyBindings::default(), test_theme());

        let plain_x = screen.handle_key(key(KeyCode::Char('x')));
        let upper_x = screen.handle_key(key(KeyCode::Char('X')));
        let tab = screen.handle_key(key(KeyCode::Tab));

        assert!(!matches!(plain_x, Action::Logout));
        assert!(!matches!(upper_x, Action::Logout));
        assert!(!matches!(tab, Action::Logout));
    }

    #[test]
    fn on_enter_fetches_ip_when_enabled() {
        let mut screen = DashboardScreen::new(false, true, KeyBindings::default(), test_theme());
        let actions = screen.on_enter();
        assert!(actions.iter().any(|a| matches!(a, Action::FetchPublicIp)));
    }

    #[test]
    fn on_enter_does_not_fetch_ip_when_disabled() {
        let mut screen = DashboardScreen::new(false, false, KeyBindings::default(), test_theme());
        let actions = screen.on_enter();
        assert!(actions.is_empty());
    }

    #[test]
    fn on_enter_does_not_refetch_ip_when_already_present() {
        let mut screen = DashboardScreen::new(false, true, KeyBindings::default(), test_theme());
        screen.public_ip = Some("1.2.3.4".into());
        let actions = screen.on_enter();
        assert!(actions.is_empty());
    }
}
