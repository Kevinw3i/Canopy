use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
};
use shared::dto::entitlements::UserEntitlements;

use super::Component;
use crate::event::Action;

#[derive(Default)]
pub struct AccessScreen {
    pub entitlements: Option<UserEntitlements>,
}

impl AccessScreen {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_entitlements(&mut self, ent: UserEntitlements) {
        self.entitlements = Some(ent);
    }
}

impl Component for AccessScreen {
    fn handle_key(&mut self, key: KeyEvent) -> Action {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Action::Quit;
        }
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => Action::GoBack,
            _ => Action::Noop,
        }
    }

    fn render(&mut self, area: Rect, buf: &mut Buffer) {
        let outer = Block::default()
            .borders(Borders::ALL)
            .title(" Access / Current Identity ")
            .border_style(Style::default().fg(Color::Cyan));
        let inner = outer.inner(area);
        outer.render(area, buf);

        let Some(ref ent) = self.entitlements else {
            Paragraph::new("Loading entitlements...")
                .style(Style::default().fg(Color::Yellow))
                .render(inner, buf);
            return;
        };

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(6), // Identity
                Constraint::Length(8), // Features
                Constraint::Length(6), // Accounts
                Constraint::Length(3), // Regions
                Constraint::Min(4),    // Log groups
                Constraint::Length(2), // Help
            ])
            .split(inner);

        // Identity section
        let identity_lines = vec![
            Line::from(vec![
                Span::styled("User ID:      ", Style::default().bold()),
                Span::raw(&ent.user_id),
            ]),
            Line::from(vec![
                Span::styled("Email:        ", Style::default().bold()),
                Span::raw(&ent.email),
            ]),
            Line::from(vec![
                Span::styled("Display Name: ", Style::default().bold()),
                Span::raw(&ent.display_name),
            ]),
            Line::from(vec![
                Span::styled("Groups:       ", Style::default().bold()),
                Span::raw(ent.groups.join(", ")),
            ]),
        ];
        let identity_block = Block::default()
            .borders(Borders::ALL)
            .title(" Identity ")
            .border_style(Style::default().fg(Color::Cyan));
        Paragraph::new(identity_lines)
            .block(identity_block)
            .render(chunks[0], buf);

        // Features section
        let feat = &ent.features;
        let check = |b: bool| if b { "Yes" } else { "No " };
        let feat_style = |b: bool| {
            if b {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Red)
            }
        };

        let feature_lines = vec![
            Line::from(vec![
                Span::styled("EC2 View:              ", Style::default().bold()),
                Span::styled(check(feat.can_view_ec2), feat_style(feat.can_view_ec2)),
            ]),
            Line::from(vec![
                Span::styled("CloudWatch Search:     ", Style::default().bold()),
                Span::styled(
                    check(feat.can_use_cloudwatch_search),
                    feat_style(feat.can_use_cloudwatch_search),
                ),
            ]),
            Line::from(vec![
                Span::styled("CloudWatch Live Tail:  ", Style::default().bold()),
                Span::styled(
                    check(feat.can_use_cloudwatch_tail),
                    feat_style(feat.can_use_cloudwatch_tail),
                ),
            ]),
            Line::from(vec![
                Span::styled("SSM Session Manager:   ", Style::default().bold()),
                Span::styled(check(feat.can_use_ssm), feat_style(feat.can_use_ssm)),
            ]),
            Line::from(vec![
                Span::styled("EC2 Instance Connect:  ", Style::default().bold()),
                Span::styled(
                    check(feat.can_use_ec2_instance_connect),
                    feat_style(feat.can_use_ec2_instance_connect),
                ),
            ]),
        ];
        let feature_block = Block::default()
            .borders(Borders::ALL)
            .title(" Feature Flags ")
            .border_style(Style::default().fg(Color::Cyan));
        Paragraph::new(feature_lines)
            .block(feature_block)
            .render(chunks[1], buf);

        // Accounts
        let account_lines: Vec<Line> = ent
            .allowed_accounts
            .iter()
            .map(|a| {
                Line::from(format!(
                    "  {} ({}) - {}",
                    a.account_id, a.account_name, a.role_arn
                ))
            })
            .collect();
        let accounts_block = Block::default()
            .borders(Borders::ALL)
            .title(format!(
                " Allowed Accounts ({}) ",
                ent.allowed_accounts.len()
            ))
            .border_style(Style::default().fg(Color::Cyan));
        Paragraph::new(account_lines)
            .block(accounts_block)
            .wrap(Wrap { trim: true })
            .render(chunks[2], buf);

        // Regions
        let regions_block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" Allowed Regions ({}) ", ent.allowed_regions.len()))
            .border_style(Style::default().fg(Color::Cyan));
        Paragraph::new(ent.allowed_regions.join(", "))
            .block(regions_block)
            .render(chunks[3], buf);

        // Log groups
        let lg_lines: Vec<Line> = ent
            .allowed_log_group_arns
            .iter()
            .map(|arn| Line::from(format!("  {}", arn)))
            .collect();
        let lg_block = Block::default()
            .borders(Borders::ALL)
            .title(format!(
                " Allowed Log Group Patterns ({}) ",
                ent.allowed_log_group_arns.len()
            ))
            .border_style(Style::default().fg(Color::Cyan));
        Paragraph::new(lg_lines)
            .block(lg_block)
            .wrap(Wrap { trim: true })
            .render(chunks[4], buf);

        // Help
        Paragraph::new("Esc/q: back")
            .style(Style::default().fg(Color::Gray))
            .render(chunks[5], buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState};
    use shared::dto::entitlements::{AllowedAccount, FeatureFlags};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn key_ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn sample_entitlements() -> UserEntitlements {
        UserEntitlements {
            user_id: "alice".into(),
            email: "alice@example.com".into(),
            display_name: "Alice".into(),
            groups: vec!["engineers".into(), "ops".into()],
            features: FeatureFlags {
                can_view_ec2: true,
                can_use_cloudwatch_search: true,
                can_use_cloudwatch_tail: false,
                can_use_ssm: true,
                can_use_ec2_instance_connect: false,
                ..Default::default()
            },
            allowed_accounts: vec![AllowedAccount {
                account_id: "111111111111".into(),
                account_name: "production".into(),
                role_arn: "arn:aws:iam::111111111111:role/CanopyRole".into(),
            }],
            allowed_regions: vec!["us-east-1".into(), "ap-northeast-1".into()],
            allowed_log_group_arns: vec!["arn:aws:logs:*:111111111111:log-group:/app/*".into()],
            max_session_seconds: None,
            instance_tag_selectors: vec![],
            excluded_tag_selectors: vec![],
            allowed_os_users: vec![],
            database_scopes: vec![],
        }
    }

    fn rendered(screen: &mut AccessScreen, area: Rect) -> String {
        let mut buf = Buffer::empty(area);
        screen.render(area, &mut buf);
        buf.content.iter().map(|c| c.symbol()).collect()
    }

    // ── Key handling ──

    #[test]
    fn esc_key_returns_go_back_action() {
        let mut screen = AccessScreen::new();
        assert!(matches!(
            screen.handle_key(key(KeyCode::Esc)),
            Action::GoBack
        ));
    }

    #[test]
    fn q_key_returns_go_back_action() {
        let mut screen = AccessScreen::new();
        assert!(matches!(
            screen.handle_key(key(KeyCode::Char('q'))),
            Action::GoBack
        ));
    }

    #[test]
    fn ctrl_c_returns_quit_action_even_on_access_screen() {
        // Global quit shortcut must still take precedence.
        let mut screen = AccessScreen::new();
        assert!(matches!(
            screen.handle_key(key_ctrl(KeyCode::Char('c'))),
            Action::Quit
        ));
    }

    #[test]
    fn unrelated_keys_return_noop() {
        let mut screen = AccessScreen::new();
        for code in [
            KeyCode::Char('a'),
            KeyCode::Char('z'),
            KeyCode::Up,
            KeyCode::Enter,
            KeyCode::Tab,
        ] {
            let action = screen.handle_key(key(code));
            assert!(
                matches!(action, Action::Noop),
                "{code:?} should be no-op, got {action:?}"
            );
        }
    }

    // ── Render: empty / null state ──

    #[test]
    fn render_without_entitlements_shows_loading_placeholder() {
        let mut screen = AccessScreen::new();
        let text = rendered(&mut screen, Rect::new(0, 0, 80, 24));

        assert!(
            text.contains("Loading entitlements..."),
            "expected placeholder before entitlements load"
        );
    }

    #[test]
    fn render_does_not_panic_in_short_area() {
        let mut screen = AccessScreen::new();
        screen.set_entitlements(sample_entitlements());

        // 1-row area is smaller than the layout demands; the
        // ratatui Layout::split must clamp gracefully.
        let mut buf = Buffer::empty(Rect::new(0, 0, 80, 1));
        screen.render(Rect::new(0, 0, 80, 1), &mut buf);
    }

    // ── Render: populated state ──

    #[test]
    fn render_with_entitlements_shows_user_identity_fields() {
        let mut screen = AccessScreen::new();
        screen.set_entitlements(sample_entitlements());

        let text = rendered(&mut screen, Rect::new(0, 0, 120, 40));

        assert!(text.contains("alice"), "user_id should appear");
        assert!(text.contains("alice@example.com"), "email should appear");
        assert!(text.contains("Alice"), "display name should appear");
        assert!(
            text.contains("engineers") && text.contains("ops"),
            "groups should appear"
        );
    }

    #[test]
    fn render_includes_all_feature_flag_labels() {
        let mut screen = AccessScreen::new();
        screen.set_entitlements(sample_entitlements());

        let text = rendered(&mut screen, Rect::new(0, 0, 120, 40));

        assert!(text.contains("EC2 View"));
        assert!(text.contains("CloudWatch Search"));
        assert!(text.contains("CloudWatch Live Tail"));
        assert!(text.contains("SSM Session Manager"));
        assert!(text.contains("EC2 Instance Connect"));
    }

    #[test]
    fn render_shows_account_count_in_title_and_account_details() {
        let mut screen = AccessScreen::new();
        screen.set_entitlements(sample_entitlements());

        let text = rendered(&mut screen, Rect::new(0, 0, 120, 40));

        assert!(text.contains("Allowed Accounts (1)"));
        assert!(text.contains("111111111111"));
        assert!(text.contains("production"));
    }

    #[test]
    fn render_shows_region_list_with_count() {
        let mut screen = AccessScreen::new();
        screen.set_entitlements(sample_entitlements());

        let text = rendered(&mut screen, Rect::new(0, 0, 120, 40));

        assert!(text.contains("us-east-1"));
        assert!(text.contains("ap-northeast-1"));
        assert!(text.contains("Allowed Regions (2)"));
    }

    #[test]
    fn render_with_empty_entitlement_lists_shows_zero_counts() {
        // Boundary: user has zero accounts / zero regions / zero log
        // groups. Titles should show (0); no panic.
        let mut empty = sample_entitlements();
        empty.allowed_accounts.clear();
        empty.allowed_regions.clear();
        empty.allowed_log_group_arns.clear();

        let mut screen = AccessScreen::new();
        screen.set_entitlements(empty);

        let text = rendered(&mut screen, Rect::new(0, 0, 120, 40));
        assert!(text.contains("Allowed Accounts (0)"));
        assert!(text.contains("Allowed Regions (0)"));
        assert!(text.contains("Allowed Log Group Patterns (0)"));
    }
}
