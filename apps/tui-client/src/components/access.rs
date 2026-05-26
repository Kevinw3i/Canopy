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
                Constraint::Length(6),  // Identity
                Constraint::Length(10), // Features
                Constraint::Length(6),  // Accounts
                Constraint::Length(3),  // Regions
                Constraint::Length(8),  // ECS scopes
                Constraint::Min(4),     // Log groups
                Constraint::Length(2),  // Help
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
            Line::from(vec![
                Span::styled("ECS Task View:         ", Style::default().bold()),
                Span::styled(check(feat.can_view_ecs), feat_style(feat.can_view_ecs)),
            ]),
            Line::from(vec![
                Span::styled("ECS Exec:              ", Style::default().bold()),
                Span::styled(
                    check(feat.can_use_ecs_exec),
                    feat_style(feat.can_use_ecs_exec),
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

        // ECS scopes
        let selector_summary = |selectors: &[shared::dto::entitlements::TagSelector]| -> String {
            if selectors.is_empty() {
                "-".into()
            } else {
                selectors
                    .iter()
                    .map(|selector| {
                        selector
                            .tags
                            .iter()
                            .map(|(key, values)| format!("{}=[{}]", key, values.join("|")))
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .collect::<Vec<_>>()
                    .join("; ")
            }
        };
        let ecs_lines = vec![
            Line::from(format!(
                "  allowed_clusters: {}",
                if ent.allowed_clusters.is_empty() {
                    "-".into()
                } else {
                    ent.allowed_clusters.join(", ")
                }
            )),
            Line::from(format!(
                "  task_tag_selectors: {}",
                selector_summary(&ent.task_tag_selectors)
            )),
            Line::from(format!(
                "  excluded_task_tag_selectors: {}",
                selector_summary(&ent.excluded_task_tag_selectors)
            )),
            Line::from(format!(
                "  excluded_container_names: {}",
                if ent.excluded_container_names.is_empty() {
                    "-".into()
                } else {
                    ent.excluded_container_names.join(", ")
                }
            )),
            Line::from(format!(
                "  allow_broad_cluster_discovery: {}",
                if ent.allow_broad_cluster_discovery {
                    "true"
                } else {
                    "false"
                }
            )),
        ];
        let ecs_block = Block::default()
            .borders(Borders::ALL)
            .title(" ECS Scope ")
            .border_style(Style::default().fg(Color::Cyan));
        Paragraph::new(ecs_lines)
            .block(ecs_block)
            .wrap(Wrap { trim: true })
            .render(chunks[4], buf);

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
            .render(chunks[5], buf);

        // Help
        Paragraph::new("Esc/q: back")
            .style(Style::default().fg(Color::Gray))
            .render(chunks[6], buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::dto::entitlements::{AllowedAccount, FeatureFlags, TagSelector};
    use std::collections::HashMap;

    fn rendered_text(screen: &mut AccessScreen) -> String {
        let area = Rect::new(0, 0, 140, 40);
        let mut buf = Buffer::empty(area);
        screen.render(area, &mut buf);

        let mut out = String::new();
        for cell in &buf.content {
            out.push_str(cell.symbol());
        }
        out
    }

    #[test]
    fn render_includes_ecs_permissions_and_scope() {
        let mut screen = AccessScreen::new();
        screen.set_entitlements(UserEntitlements {
            user_id: "u1".into(),
            email: "u1@example.com".into(),
            display_name: "User".into(),
            groups: vec!["platform".into()],
            features: FeatureFlags {
                can_view_ecs: true,
                can_use_ecs_exec: false,
                ..Default::default()
            },
            allowed_accounts: vec![AllowedAccount {
                account_id: "111".into(),
                account_name: "prod".into(),
                role_arn: "arn:aws:iam::111:role/CanopyRole".into(),
            }],
            allowed_regions: vec!["us-east-1".into()],
            allowed_log_group_arns: vec![],
            instance_tag_selectors: vec![],
            excluded_tag_selectors: vec![],
            allowed_clusters: vec!["arn:aws:ecs:us-east-1:111:cluster/prod-*".into()],
            task_tag_selectors: vec![TagSelector {
                tags: HashMap::from([("Environment".into(), vec!["production".into()])]),
            }],
            excluded_task_tag_selectors: vec![TagSelector {
                tags: HashMap::from([("CanopyDeny".into(), vec!["true".into()])]),
            }],
            excluded_container_names: vec!["envoy".into()],
            allow_broad_cluster_discovery: false,
            allowed_os_users: vec![],
            max_session_seconds: None,
        });

        let text = rendered_text(&mut screen);

        assert!(text.contains("ECS Task View"));
        assert!(text.contains("ECS Exec"));
        assert!(text.contains("arn:aws:ecs:us-east-1:111:cluster/prod-*"));
        assert!(text.contains("Environment=[production]"));
        assert!(text.contains("CanopyDeny=[true]"));
        assert!(text.contains("envoy"));
        assert!(text.contains("allow_broad_cluster_discovery: false"));
    }
}
