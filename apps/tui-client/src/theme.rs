use ratatui::style::{Color, Modifier, Style};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThemeConfig {
    #[serde(default = "default_preset")]
    pub preset: String,
    #[serde(default)]
    pub accent: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub muted: Option<String>,
    #[serde(default)]
    pub selected_bg: Option<String>,
    #[serde(default)]
    pub selected_fg: Option<String>,
    #[serde(default)]
    pub success: Option<String>,
    #[serde(default)]
    pub warning: Option<String>,
    #[serde(default)]
    pub danger: Option<String>,
}

impl Default for ThemeConfig {
    fn default() -> Self {
        Self {
            preset: default_preset(),
            accent: None,
            text: None,
            muted: None,
            selected_bg: None,
            selected_fg: None,
            success: None,
            warning: None,
            danger: None,
        }
    }
}

fn default_preset() -> String {
    "default".into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub accent: Color,
    pub text: Color,
    pub muted: Color,
    pub selected_bg: Color,
    pub selected_fg: Color,
    pub success: Color,
    pub warning: Color,
    pub danger: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            accent: Color::Cyan,
            text: Color::White,
            muted: Color::Gray,
            selected_bg: Color::Indexed(24),
            selected_fg: Color::White,
            success: Color::Green,
            warning: Color::Yellow,
            danger: Color::Red,
        }
    }
}

impl Theme {
    pub fn accent_style(self) -> Style {
        Style::default().fg(self.accent)
    }

    pub fn text_style(self) -> Style {
        Style::default().fg(self.text)
    }

    pub fn muted_style(self) -> Style {
        Style::default().fg(self.muted)
    }

    pub fn selected_style(self) -> Style {
        self.selected_plain_style()
    }

    pub fn selected_plain_style(self) -> Style {
        Style::default()
            .fg(self.selected_fg)
            .bg(self.selected_bg)
            .add_modifier(Modifier::BOLD)
    }

    pub fn focused_border_style(self) -> Style {
        Style::default()
            .fg(self.warning)
            .add_modifier(Modifier::BOLD)
    }

    pub fn success_style(self) -> Style {
        Style::default().fg(self.success)
    }

    pub fn warning_style(self) -> Style {
        Style::default().fg(self.warning)
    }

    pub fn danger_style(self) -> Style {
        Style::default().fg(self.danger)
    }

    pub fn cursor_style(self) -> Style {
        Style::default().fg(self.selected_fg).bg(self.selected_bg)
    }
}

impl ThemeConfig {
    pub fn resolve(&self) -> anyhow::Result<Theme> {
        let mut theme = match self.preset.trim().to_ascii_lowercase().as_str() {
            "default" => Theme::default(),
            "mono" => Theme {
                accent: Color::White,
                text: Color::White,
                muted: Color::Gray,
                selected_bg: Color::White,
                selected_fg: Color::Black,
                success: Color::White,
                warning: Color::White,
                danger: Color::White,
            },
            "high_contrast" | "high-contrast" => Theme {
                accent: Color::Yellow,
                text: Color::White,
                muted: Color::White,
                selected_bg: Color::Yellow,
                selected_fg: Color::Black,
                success: Color::LightGreen,
                warning: Color::LightYellow,
                danger: Color::LightRed,
            },
            other => anyhow::bail!("invalid theme.preset: '{other}'"),
        };

        apply_color("accent", &self.accent, &mut theme.accent)?;
        apply_color("text", &self.text, &mut theme.text)?;
        apply_color("muted", &self.muted, &mut theme.muted)?;
        apply_color("selected_bg", &self.selected_bg, &mut theme.selected_bg)?;
        apply_color("selected_fg", &self.selected_fg, &mut theme.selected_fg)?;
        apply_color("success", &self.success, &mut theme.success)?;
        apply_color("warning", &self.warning, &mut theme.warning)?;
        apply_color("danger", &self.danger, &mut theme.danger)?;

        Ok(theme)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        self.resolve().map(|_| ())
    }
}

fn apply_color(name: &str, value: &Option<String>, target: &mut Color) -> anyhow::Result<()> {
    if let Some(value) = value {
        *target =
            parse_color(value).ok_or_else(|| anyhow::anyhow!("invalid theme.{name}: '{value}'"))?;
    }
    Ok(())
}

fn parse_color(value: &str) -> Option<Color> {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();
    match lower.as_str() {
        "black" => Some(Color::Black),
        "red" => Some(Color::Red),
        "green" => Some(Color::Green),
        "yellow" => Some(Color::Yellow),
        "blue" => Some(Color::Blue),
        "magenta" => Some(Color::Magenta),
        "cyan" => Some(Color::Cyan),
        "gray" | "grey" => Some(Color::Gray),
        "dark_gray" | "darkgray" | "dark-grey" | "dark_grey" => Some(Color::DarkGray),
        "white" => Some(Color::White),
        "light_red" | "lightred" => Some(Color::LightRed),
        "light_green" | "lightgreen" => Some(Color::LightGreen),
        "light_yellow" | "lightyellow" => Some(Color::LightYellow),
        "light_blue" | "lightblue" => Some(Color::LightBlue),
        "light_magenta" | "lightmagenta" => Some(Color::LightMagenta),
        "light_cyan" | "lightcyan" => Some(Color::LightCyan),
        value if value.starts_with("indexed:") => value
            .strip_prefix("indexed:")
            .and_then(|n| n.parse::<u8>().ok())
            .map(Color::Indexed),
        value if value.starts_with("ansi:") => value
            .strip_prefix("ansi:")
            .and_then(|n| n.parse::<u8>().ok())
            .map(Color::Indexed),
        value if value.starts_with('#') => parse_hex_color(value),
        _ => None,
    }
}

fn parse_hex_color(value: &str) -> Option<Color> {
    let hex = value.strip_prefix('#')?;
    if hex.len() != 6 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
    let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
    let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
    Some(Color::Rgb(r, g, b))
}

pub fn color_label(color: Color) -> String {
    match color {
        Color::Black => "black".into(),
        Color::Red => "red".into(),
        Color::Green => "green".into(),
        Color::Yellow => "yellow".into(),
        Color::Blue => "blue".into(),
        Color::Magenta => "magenta".into(),
        Color::Cyan => "cyan".into(),
        Color::Gray => "gray".into(),
        Color::DarkGray => "dark_gray".into(),
        Color::White => "white".into(),
        Color::LightRed => "light_red".into(),
        Color::LightGreen => "light_green".into(),
        Color::LightYellow => "light_yellow".into(),
        Color::LightBlue => "light_blue".into(),
        Color::LightMagenta => "light_magenta".into(),
        Color::LightCyan => "light_cyan".into(),
        Color::Indexed(index) => format!("indexed:{index}"),
        Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
        Color::Reset => "reset".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_theme_resolves() {
        let theme = ThemeConfig::default().resolve().unwrap();
        assert_eq!(theme.accent, Color::Cyan);
        assert_eq!(theme.selected_bg, Color::Indexed(24));
    }

    #[test]
    fn high_contrast_preset_resolves() {
        let config = ThemeConfig {
            preset: "high_contrast".into(),
            ..Default::default()
        };
        let theme = config.resolve().unwrap();
        assert_eq!(theme.accent, Color::Yellow);
        assert_eq!(theme.selected_fg, Color::Black);
    }

    #[test]
    fn color_overrides_support_names_indexed_and_hex() {
        let config = ThemeConfig {
            accent: Some("#336699".into()),
            selected_bg: Some("indexed:42".into()),
            danger: Some("light_red".into()),
            ..Default::default()
        };
        let theme = config.resolve().unwrap();
        assert_eq!(theme.accent, Color::Rgb(0x33, 0x66, 0x99));
        assert_eq!(theme.selected_bg, Color::Indexed(42));
        assert_eq!(theme.danger, Color::LightRed);
    }

    #[test]
    fn invalid_color_rejects_config() {
        let config = ThemeConfig {
            accent: Some("not-a-color".into()),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }
}
