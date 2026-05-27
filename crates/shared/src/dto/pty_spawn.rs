use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Command specification for TUI PTY sessions.
///
/// EC2 connect, ECS Exec, and future shell-like integrations convert their
/// route-specific response DTOs into this shared shape before spawning the local
/// terminal wrapper.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PtySpawnSpec {
    pub command: String,
    pub args: Vec<String>,
    pub env_vars: HashMap<String, String>,
    /// Maximum session duration in seconds. None = no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_session_seconds: Option<u64>,
}
