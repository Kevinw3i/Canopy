use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyBindings {
    #[serde(default = "default_quit")]
    pub quit: Vec<String>,
    #[serde(default = "default_logout")]
    pub logout: Vec<String>,
    #[serde(default = "default_dashboard_up")]
    pub dashboard_up: Vec<String>,
    #[serde(default = "default_dashboard_down")]
    pub dashboard_down: Vec<String>,
    #[serde(default = "default_dashboard_select")]
    pub dashboard_select: Vec<String>,
    #[serde(default = "default_dashboard_quit")]
    pub dashboard_quit: Vec<String>,
    #[serde(default = "default_dashboard_inventory")]
    pub dashboard_inventory: Vec<String>,
    #[serde(default = "default_dashboard_cloudwatch")]
    pub dashboard_cloudwatch: Vec<String>,
    #[serde(default = "default_dashboard_live_tail")]
    pub dashboard_live_tail: Vec<String>,
    #[serde(default = "default_dashboard_access")]
    pub dashboard_access: Vec<String>,
    #[serde(default = "default_dashboard_settings")]
    pub dashboard_settings: Vec<String>,
    #[serde(default = "default_dashboard_mcp")]
    pub dashboard_mcp: Vec<String>,
    #[serde(default = "default_settings_back")]
    pub settings_back: Vec<String>,
    #[serde(default = "default_settings_change_password")]
    pub settings_change_password: Vec<String>,
}

impl Default for KeyBindings {
    fn default() -> Self {
        Self {
            quit: default_quit(),
            logout: default_logout(),
            dashboard_up: default_dashboard_up(),
            dashboard_down: default_dashboard_down(),
            dashboard_select: default_dashboard_select(),
            dashboard_quit: default_dashboard_quit(),
            dashboard_inventory: default_dashboard_inventory(),
            dashboard_cloudwatch: default_dashboard_cloudwatch(),
            dashboard_live_tail: default_dashboard_live_tail(),
            dashboard_access: default_dashboard_access(),
            dashboard_settings: default_dashboard_settings(),
            dashboard_mcp: default_dashboard_mcp(),
            settings_back: default_settings_back(),
            settings_change_password: default_settings_change_password(),
        }
    }
}

fn keys<const N: usize>(items: [&str; N]) -> Vec<String> {
    items.into_iter().map(str::to_string).collect()
}

fn default_quit() -> Vec<String> {
    keys(["ctrl+c"])
}
fn default_logout() -> Vec<String> {
    keys(["ctrl+x"])
}
fn default_dashboard_up() -> Vec<String> {
    keys(["up", "k"])
}
fn default_dashboard_down() -> Vec<String> {
    keys(["down", "j"])
}
fn default_dashboard_select() -> Vec<String> {
    keys(["enter"])
}
fn default_dashboard_quit() -> Vec<String> {
    keys(["q"])
}
fn default_dashboard_inventory() -> Vec<String> {
    keys(["1"])
}
fn default_dashboard_cloudwatch() -> Vec<String> {
    keys(["2"])
}
fn default_dashboard_live_tail() -> Vec<String> {
    keys(["3"])
}
fn default_dashboard_access() -> Vec<String> {
    keys(["4"])
}
fn default_dashboard_settings() -> Vec<String> {
    keys(["5"])
}
fn default_dashboard_mcp() -> Vec<String> {
    keys(["6"])
}
fn default_settings_back() -> Vec<String> {
    keys(["esc", "q"])
}
fn default_settings_change_password() -> Vec<String> {
    keys(["p"])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardShortcut {
    Inventory,
    CloudWatch,
    LiveTail,
    Access,
    Settings,
    Mcp,
}

impl KeyBindings {
    pub fn validate(&self) -> anyhow::Result<()> {
        for (name, bindings) in self.all_named_bindings() {
            if bindings.is_empty() {
                anyhow::bail!("keybindings.{name} must not be empty");
            }
            for binding in bindings {
                if ParsedBinding::parse(binding).is_none() {
                    anyhow::bail!("invalid keybindings.{name} entry: '{binding}'");
                }
            }
        }
        Ok(())
    }

    pub fn matches_any(&self, bindings: &[String], key: &KeyEvent) -> bool {
        bindings
            .iter()
            .filter_map(|binding| ParsedBinding::parse(binding))
            .any(|binding| binding.matches(key))
    }

    pub fn matches_dashboard_shortcut(&self, shortcut: DashboardShortcut, key: &KeyEvent) -> bool {
        self.matches_any(self.dashboard_shortcut_bindings(shortcut), key)
    }

    pub fn dashboard_shortcut_bindings(&self, shortcut: DashboardShortcut) -> &[String] {
        match shortcut {
            DashboardShortcut::Inventory => &self.dashboard_inventory,
            DashboardShortcut::CloudWatch => &self.dashboard_cloudwatch,
            DashboardShortcut::LiveTail => &self.dashboard_live_tail,
            DashboardShortcut::Access => &self.dashboard_access,
            DashboardShortcut::Settings => &self.dashboard_settings,
            DashboardShortcut::Mcp => &self.dashboard_mcp,
        }
    }

    pub fn display_bindings(bindings: &[String]) -> String {
        if bindings.is_empty() {
            "disabled".into()
        } else {
            bindings.join(", ")
        }
    }

    pub fn first_label(bindings: &[String]) -> String {
        bindings
            .first()
            .cloned()
            .unwrap_or_else(|| "disabled".into())
    }

    pub fn settings_rows(&self) -> Vec<(&'static str, String)> {
        vec![
            ("Quit", Self::display_bindings(&self.quit)),
            ("Logout", Self::display_bindings(&self.logout)),
            ("Dashboard up", Self::display_bindings(&self.dashboard_up)),
            (
                "Dashboard down",
                Self::display_bindings(&self.dashboard_down),
            ),
            (
                "Dashboard select",
                Self::display_bindings(&self.dashboard_select),
            ),
            (
                "Dashboard quit",
                Self::display_bindings(&self.dashboard_quit),
            ),
            (
                "Inventory",
                Self::display_bindings(&self.dashboard_inventory),
            ),
            (
                "CloudWatch",
                Self::display_bindings(&self.dashboard_cloudwatch),
            ),
            (
                "Live Tail",
                Self::display_bindings(&self.dashboard_live_tail),
            ),
            ("Access", Self::display_bindings(&self.dashboard_access)),
            ("Settings", Self::display_bindings(&self.dashboard_settings)),
            ("MCP", Self::display_bindings(&self.dashboard_mcp)),
            ("Settings back", Self::display_bindings(&self.settings_back)),
            (
                "Change password",
                Self::display_bindings(&self.settings_change_password),
            ),
        ]
    }

    fn all_named_bindings(&self) -> [(&'static str, &[String]); 14] {
        [
            ("quit", &self.quit),
            ("logout", &self.logout),
            ("dashboard_up", &self.dashboard_up),
            ("dashboard_down", &self.dashboard_down),
            ("dashboard_select", &self.dashboard_select),
            ("dashboard_quit", &self.dashboard_quit),
            ("dashboard_inventory", &self.dashboard_inventory),
            ("dashboard_cloudwatch", &self.dashboard_cloudwatch),
            ("dashboard_live_tail", &self.dashboard_live_tail),
            ("dashboard_access", &self.dashboard_access),
            ("dashboard_settings", &self.dashboard_settings),
            ("dashboard_mcp", &self.dashboard_mcp),
            ("settings_back", &self.settings_back),
            ("settings_change_password", &self.settings_change_password),
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedBinding {
    modifiers: KeyModifiers,
    code: ParsedKeyCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedKeyCode {
    Char(char),
    Enter,
    Esc,
    Up,
    Down,
    Left,
    Right,
    Tab,
    BackTab,
    F(u8),
}

impl ParsedBinding {
    fn parse(input: &str) -> Option<Self> {
        let mut modifiers = KeyModifiers::empty();
        let mut key_code = None;

        for raw_part in input.split('+') {
            let part = raw_part.trim();
            if part.is_empty() {
                return None;
            }
            let lower = part.to_ascii_lowercase();
            match lower.as_str() {
                "ctrl" | "control" => modifiers |= KeyModifiers::CONTROL,
                "alt" | "option" => modifiers |= KeyModifiers::ALT,
                "shift" => modifiers |= KeyModifiers::SHIFT,
                _ if key_code.is_none() => {
                    key_code = Some(parse_key_code(part)?);
                }
                _ => return None,
            }
        }

        Some(Self {
            modifiers,
            code: key_code?,
        })
    }

    fn matches(self, key: &KeyEvent) -> bool {
        key.modifiers == self.modifiers
            && match (self.code, key.code) {
                (ParsedKeyCode::Char(expected), KeyCode::Char(actual)) => expected == actual,
                (ParsedKeyCode::Enter, KeyCode::Enter) => true,
                (ParsedKeyCode::Esc, KeyCode::Esc) => true,
                (ParsedKeyCode::Up, KeyCode::Up) => true,
                (ParsedKeyCode::Down, KeyCode::Down) => true,
                (ParsedKeyCode::Left, KeyCode::Left) => true,
                (ParsedKeyCode::Right, KeyCode::Right) => true,
                (ParsedKeyCode::Tab, KeyCode::Tab) => true,
                (ParsedKeyCode::BackTab, KeyCode::BackTab) => true,
                (ParsedKeyCode::F(expected), KeyCode::F(actual)) => expected == actual,
                _ => false,
            }
    }
}

fn parse_key_code(input: &str) -> Option<ParsedKeyCode> {
    let lower = input.to_ascii_lowercase();
    match lower.as_str() {
        "enter" => Some(ParsedKeyCode::Enter),
        "esc" | "escape" => Some(ParsedKeyCode::Esc),
        "up" => Some(ParsedKeyCode::Up),
        "down" => Some(ParsedKeyCode::Down),
        "left" => Some(ParsedKeyCode::Left),
        "right" => Some(ParsedKeyCode::Right),
        "tab" => Some(ParsedKeyCode::Tab),
        "backtab" | "shift+tab" => Some(ParsedKeyCode::BackTab),
        "space" => Some(ParsedKeyCode::Char(' ')),
        value
            if value
                .strip_prefix('f')
                .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit())) =>
        {
            value
                .strip_prefix('f')
                .and_then(|n| n.parse::<u8>().ok())
                .filter(|n| (1..=12).contains(n))
                .map(ParsedKeyCode::F)
        }
        value if value.chars().count() == 1 => input.chars().next().map(ParsedKeyCode::Char),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState};

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    #[test]
    fn default_bindings_match_existing_dashboard_keys() {
        let bindings = KeyBindings::default();
        assert!(bindings.matches_any(
            &bindings.dashboard_up,
            &key(KeyCode::Char('k'), KeyModifiers::NONE)
        ));
        assert!(bindings.matches_any(
            &bindings.dashboard_down,
            &key(KeyCode::Down, KeyModifiers::NONE)
        ));
        assert!(bindings.matches_any(
            &bindings.dashboard_select,
            &key(KeyCode::Enter, KeyModifiers::NONE)
        ));
        assert!(bindings.matches_any(
            &bindings.logout,
            &key(KeyCode::Char('x'), KeyModifiers::CONTROL)
        ));
    }

    #[test]
    fn custom_char_binding_matches_exactly() {
        let bindings = KeyBindings {
            dashboard_inventory: keys(["f"]),
            ..Default::default()
        };
        assert!(bindings.matches_dashboard_shortcut(
            DashboardShortcut::Inventory,
            &key(KeyCode::Char('f'), KeyModifiers::NONE)
        ));
        assert!(!bindings.matches_dashboard_shortcut(
            DashboardShortcut::Inventory,
            &key(KeyCode::Char('1'), KeyModifiers::NONE)
        ));
    }

    #[test]
    fn validate_rejects_invalid_entries() {
        let bindings = KeyBindings {
            dashboard_up: keys(["cmd+k"]),
            ..Default::default()
        };
        assert!(bindings.validate().is_err());
    }
}
