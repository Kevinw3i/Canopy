use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
};
use shared::dto::entitlements::UserEntitlements;

use super::Component;
use crate::event::{Action, Screen};

struct MenuItem {
    key: char,
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
    live_tail_enabled: bool,
    pub public_ip: Option<String>,
    pub show_public_ip: bool,
    pub ip_fetch_generation: u64,
}

impl DashboardScreen {
    pub fn new(enable_live_tail: bool, show_public_ip: bool) -> Self {
        Self {
            entitlements: None,
            selected: 0,
            live_tail_enabled: enable_live_tail,
            public_ip: None,
            show_public_ip,
            ip_fetch_generation: 0,
            items: vec![
                MenuItem {
                    key: '1',
                    label: "EC2 Inventory",
                    screen: Screen::Ec2Inventory,
                    enabled: false,
                    hidden: false,
                },
                MenuItem {
                    key: '2',
                    label: "CloudWatch Search",
                    screen: Screen::CloudWatchSearch,
                    enabled: false,
                    hidden: false,
                },
                MenuItem {
                    key: '3',
                    label: "Live Tail",
                    screen: Screen::LiveTail,
                    enabled: false,
                    hidden: !enable_live_tail,
                },
                MenuItem {
                    key: '4',
                    label: "Access / Identity",
                    screen: Screen::Access,
                    enabled: true,
                    hidden: false,
                },
                MenuItem {
                    key: '5',
                    label: "Settings",
                    screen: Screen::Settings,
                    enabled: true,
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
        self.items[0].enabled = ent.features.can_view_ec2;
        self.items[1].enabled = ent.features.can_use_cloudwatch_search;
        // Only enable live tail when the feature flag is on AND the user has
        // the entitlement.
        self.items[2].enabled = self.live_tail_enabled && ent.features.can_use_cloudwatch_tail;
        self.entitlements = Some(ent);
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
}

impl Component for DashboardScreen {
    fn handle_key(&mut self, key: KeyEvent) -> Action {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Action::Quit;
        }
        if key.code == KeyCode::Char('q') {
            return Action::Quit;
        }

        let visible: Vec<&MenuItem> = self.visible_items();

        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected > 0 {
                    self.selected -= 1;
                }
                Action::Noop
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected < visible.len().saturating_sub(1) {
                    self.selected += 1;
                }
                Action::Noop
            }
            KeyCode::Enter => {
                if let Some(item) = visible.get(self.selected) {
                    self.try_navigate(item)
                } else {
                    Action::Noop
                }
            }
            KeyCode::Char(c) => {
                if let Some(item) = visible.iter().find(|i| i.key == c) {
                    self.try_navigate(item)
                } else {
                    Action::Noop
                }
            }
            _ => Action::Noop,
        }
    }

    fn render(&mut self, area: Rect, buf: &mut Buffer) {
        let outer = Block::default()
            .borders(Borders::ALL)
            .title(" Canopy - Dashboard ")
            .border_style(Style::default().fg(Color::Cyan));
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
                Span::styled(" IP: ", Style::default().fg(Color::DarkGray)),
                Span::styled(ip_display, Style::default().fg(Color::Yellow)),
                Span::styled("  │  ", Style::default().fg(Color::DarkGray)),
                Span::styled(&now, Style::default().fg(Color::Cyan)),
            ])
        } else {
            Line::from(vec![
                Span::styled(" ", Style::default()),
                Span::styled(&now, Style::default().fg(Color::Cyan)),
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
            .style(Style::default().fg(Color::Cyan))
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

            let (style, prefix) = if !item.enabled {
                (Style::default().fg(Color::Gray), "  ")
            } else if i == self.selected {
                (
                    Style::default().fg(Color::White).bg(Color::Indexed(24)).bold(),
                    ">>",
                )
            } else {
                (Style::default().fg(Color::White), "  ")
            };

            let status = if item.enabled { "" } else { " (disabled)" };
            let text = format!("{} [{}] {}{}", prefix, item.key, item.label, status);
            Paragraph::new(text).style(style).render(item_area, buf);
        }

        // Help bar
        Paragraph::new("q: quit | j/k: navigate | Enter: select | 1-5: quick nav")
            .style(Style::default().fg(Color::Gray))
            .render(chunks[5], buf);
    }

    fn on_enter(&mut self) -> Vec<Action> {
        if self.show_public_ip && self.public_ip.is_none() {
            vec![Action::FetchPublicIp]
        } else {
            vec![]
        }
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
            allowed_os_users: vec![],
            max_session_seconds: None,
        }
    }

    #[test]
    fn initial_state_all_menu_items_except_access_settings_disabled() {
        let screen = DashboardScreen::new(false, false);
        let visible = screen.visible_items();
        // Items: EC2(disabled), CW(disabled), Access(enabled), Settings(enabled)
        // Live Tail is hidden when enable_live_tail=false
        assert_eq!(visible.len(), 4);
        assert!(!visible[0].enabled); // EC2
        assert!(!visible[1].enabled); // CW
        assert!(visible[2].enabled);  // Access
        assert!(visible[3].enabled);  // Settings
    }

    #[test]
    fn set_entitlements_enables_ec2_and_cloudwatch() {
        let mut screen = DashboardScreen::new(false, false);
        screen.set_entitlements(test_entitlements(true, true, false));

        let visible = screen.visible_items();
        assert!(visible[0].enabled);  // EC2
        assert!(visible[1].enabled);  // CW
    }

    #[test]
    fn live_tail_hidden_when_feature_flag_off() {
        let screen = DashboardScreen::new(false, false);
        let visible = screen.visible_items();
        assert!(visible.iter().all(|i| i.screen != Screen::LiveTail));
    }

    #[test]
    fn live_tail_visible_when_feature_flag_on() {
        let screen = DashboardScreen::new(true, false);
        let visible = screen.visible_items();
        assert!(visible.iter().any(|i| i.screen == Screen::LiveTail));
    }

    #[test]
    fn live_tail_enabled_only_with_entitlement_and_flag() {
        let mut screen = DashboardScreen::new(true, false);
        screen.set_entitlements(test_entitlements(false, false, true));

        let lt = screen.items.iter().find(|i| i.screen == Screen::LiveTail).unwrap();
        assert!(lt.enabled);
    }

    #[test]
    fn navigate_up_down_wraps_selection() {
        let mut screen = DashboardScreen::new(false, false);
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
        let mut screen = DashboardScreen::new(false, false);
        // selected=0 is EC2, disabled
        let action = screen.handle_key(key(KeyCode::Enter));
        assert!(matches!(action, Action::ShowError(_)));
    }

    #[test]
    fn enter_on_enabled_item_navigates() {
        let mut screen = DashboardScreen::new(false, false);
        screen.set_entitlements(test_entitlements(true, false, false));

        // selected=0 is EC2, now enabled
        let action = screen.handle_key(key(KeyCode::Enter));
        assert!(matches!(action, Action::NavigateTo(Screen::Ec2Inventory)));
    }

    #[test]
    fn quick_nav_by_number() {
        let mut screen = DashboardScreen::new(false, false);
        screen.set_entitlements(test_entitlements(true, true, false));

        let action = screen.handle_key(key(KeyCode::Char('2')));
        assert!(matches!(action, Action::NavigateTo(Screen::CloudWatchSearch)));
    }

    #[test]
    fn q_quits() {
        let mut screen = DashboardScreen::new(false, false);
        let action = screen.handle_key(key(KeyCode::Char('q')));
        assert!(matches!(action, Action::Quit));
    }

    #[test]
    fn on_enter_fetches_ip_when_enabled() {
        let mut screen = DashboardScreen::new(false, true);
        let actions = screen.on_enter();
        assert!(actions.iter().any(|a| matches!(a, Action::FetchPublicIp)));
    }

    #[test]
    fn on_enter_does_not_fetch_ip_when_disabled() {
        let mut screen = DashboardScreen::new(false, false);
        let actions = screen.on_enter();
        assert!(actions.is_empty());
    }

    #[test]
    fn on_enter_does_not_refetch_ip_when_already_present() {
        let mut screen = DashboardScreen::new(false, true);
        screen.public_ip = Some("1.2.3.4".into());
        let actions = screen.on_enter();
        assert!(actions.is_empty());
    }
}
