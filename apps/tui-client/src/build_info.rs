pub fn version() -> &'static str {
    option_env!("CANOPY_TUI_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
}

pub fn user_agent() -> String {
    format!("canopy-tui/{}", version())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_uses_canopy_build_version_when_cargo_received_it() {
        if let Ok(expected) = std::env::var("CANOPY_BUILD_VERSION") {
            assert_eq!(version(), expected);
        } else {
            assert_eq!(version(), env!("CARGO_PKG_VERSION"));
        }
    }

    #[test]
    fn user_agent_uses_embedded_version() {
        assert_eq!(user_agent(), format!("canopy-tui/{}", version()));
    }
}
