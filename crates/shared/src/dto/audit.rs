use serde::{Deserialize, Serialize};

/// Audit JSON-lines event.
///
/// Keep this enum and event shape in sync with `docs/AUDIT-SCHEMA.md`.
///
/// Schema evolution is additive: new fields should be optional and skipped
/// when absent so flexible downstream consumers keep working. Strict log
/// shippers or Athena-style tables still need a schema migration when new
/// fields are added.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub timestamp: String,
    pub actor: String,
    pub action: AuditAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Resource identifier. EC2 connect uses an instance id; CloudWatch routes
    /// use a log group ARN/name or session/query id when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_resource: Option<String>,
    /// Human-readable label for `target_resource` when one is known.
    ///
    /// For EC2 connect events this is the instance Name tag. Other event types
    /// usually omit it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_resource_name: Option<String>,
    pub outcome: AuditOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    Login,
    Logout,
    Ec2List,
    Ec2Connect,
    /// Start / Stop / Reboot a single instance. Power-action specifics
    /// (start vs stop vs reboot) live in the `power_action` metadata
    /// field rather than encoding three separate audit actions, which
    /// keeps downstream consumers and Athena schemas simpler.
    Ec2Power,
    CloudwatchSearch,
    CloudwatchInsightsQuery,
    CloudwatchLiveTailStart,
    CloudwatchLiveTailStop,
    LogGroupList,
    EntitlementsView,
    /// Local MCP session lifecycle registration. This is separate from
    /// `login` because the user is already authenticated; the event records
    /// whether an MCP session can be opened for that authenticated actor.
    McpSessionRegister,
    /// MCP guidance delivery / sync lifecycle. Metadata records the guidance
    /// id and version so data-access tools can prove the required guidance was
    /// issued before use.
    McpGuidanceSync,
    /// MCP database scope discovery. Scope details stay in metadata; secrets
    /// and connection internals must not be exposed in the response or audit.
    McpDatabaseScopeList,
    /// MCP database data access. The operation details, including raw SQL,
    /// scope, EXPLAIN result, and rejection reason, live in metadata rather
    /// than being split across read/write action variants.
    /// Raw SQL may contain PII or secrets typed by the user; treat audit output
    /// as sensitive and redact at downstream audit/SIEM boundaries as needed.
    McpDatabaseQuery,
}

impl AuditAction {
    pub fn wire_name(&self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Logout => "logout",
            Self::Ec2List => "ec2_list",
            Self::Ec2Connect => "ec2_connect",
            Self::Ec2Power => "ec2_power",
            Self::CloudwatchSearch => "cloudwatch_search",
            Self::CloudwatchInsightsQuery => "cloudwatch_insights_query",
            Self::CloudwatchLiveTailStart => "cloudwatch_live_tail_start",
            Self::CloudwatchLiveTailStop => "cloudwatch_live_tail_stop",
            Self::LogGroupList => "log_group_list",
            Self::EntitlementsView => "entitlements_view",
            Self::McpSessionRegister => "mcp_session_register",
            Self::McpGuidanceSync => "mcp_guidance_sync",
            Self::McpDatabaseScopeList => "mcp_database_scope_list",
            Self::McpDatabaseQuery => "mcp_database_query",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Failure,
    Denied,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn audit_action_serializes_snake_case() {
        for action in [
            AuditAction::Login,
            AuditAction::Logout,
            AuditAction::Ec2List,
            AuditAction::Ec2Connect,
            AuditAction::Ec2Power,
            AuditAction::CloudwatchSearch,
            AuditAction::CloudwatchInsightsQuery,
            AuditAction::CloudwatchLiveTailStart,
            AuditAction::CloudwatchLiveTailStop,
            AuditAction::LogGroupList,
            AuditAction::EntitlementsView,
            AuditAction::McpSessionRegister,
            AuditAction::McpGuidanceSync,
            AuditAction::McpDatabaseScopeList,
            AuditAction::McpDatabaseQuery,
        ] {
            let json = serde_json::to_value(&action).unwrap();
            assert_eq!(json, serde_json::Value::String(action.wire_name().into()));
        }
    }

    #[test]
    fn audit_action_deserializes_snake_case() {
        let val: AuditAction = serde_json::from_value(json!("log_group_list")).unwrap();
        assert!(matches!(val, AuditAction::LogGroupList));
    }

    #[test]
    fn audit_action_ec2_power_roundtrip() {
        // The wire form must be `ec2_power` (not `ec2-power` or
        // separate `ec2_start` / `ec2_stop` / `ec2_reboot`). The
        // start/stop/reboot distinction is carried in `metadata.power_action`.
        let json = serde_json::to_value(AuditAction::Ec2Power).unwrap();
        assert_eq!(json, "ec2_power");
        assert_eq!(AuditAction::Ec2Power.wire_name(), "ec2_power");

        let back: AuditAction = serde_json::from_value(json).unwrap();
        assert!(matches!(back, AuditAction::Ec2Power));
    }

    #[test]
    fn audit_action_mcp_roundtrip() {
        for (action, expected) in [
            (AuditAction::McpSessionRegister, "mcp_session_register"),
            (AuditAction::McpGuidanceSync, "mcp_guidance_sync"),
            (AuditAction::McpDatabaseScopeList, "mcp_database_scope_list"),
            (AuditAction::McpDatabaseQuery, "mcp_database_query"),
        ] {
            let json = serde_json::to_value(&action).unwrap();
            assert_eq!(json, expected);
            assert_eq!(action.wire_name(), expected);

            let back: AuditAction = serde_json::from_value(json).unwrap();
            assert_eq!(
                serde_json::to_string(&back).unwrap(),
                serde_json::to_string(&action).unwrap()
            );
        }
    }

    #[test]
    fn audit_outcome_roundtrip() {
        for outcome in [
            AuditOutcome::Success,
            AuditOutcome::Failure,
            AuditOutcome::Denied,
        ] {
            let json = serde_json::to_value(&outcome).unwrap();
            let back: AuditOutcome = serde_json::from_value(json).unwrap();
            assert_eq!(
                serde_json::to_string(&outcome).unwrap(),
                serde_json::to_string(&back).unwrap()
            );
        }
    }

    #[test]
    fn audit_event_omits_none_fields() {
        let event = AuditEvent {
            event_id: "e1".into(),
            timestamp: "2025-01-01T00:00:00Z".into(),
            actor: "alice".into(),
            action: AuditAction::Login,
            account_id: None,
            region: None,
            target_resource: None,
            target_resource_name: None,
            outcome: AuditOutcome::Success,
            error_message: None,
            metadata: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("account_id"));
        assert!(!json.contains("region"));
        assert!(!json.contains("target_resource"));
        assert!(!json.contains("target_resource_name"));
        assert!(!json.contains("error_message"));
        assert!(!json.contains("metadata"));
    }

    #[test]
    fn audit_event_full_roundtrip() {
        let event = AuditEvent {
            event_id: "e1".into(),
            timestamp: "2025-01-01T00:00:00Z".into(),
            actor: "bob".into(),
            action: AuditAction::Ec2List,
            account_id: Some("123".into()),
            region: Some("us-east-1".into()),
            target_resource: Some("i-abc".into()),
            target_resource_name: Some("web-01".into()),
            outcome: AuditOutcome::Denied,
            error_message: Some("forbidden".into()),
            metadata: Some(json!({"key": "value"})),
        };
        let json = serde_json::to_value(&event).unwrap();
        let back: AuditEvent = serde_json::from_value(json).unwrap();
        assert_eq!(back.actor, "bob");
        assert_eq!(back.account_id.as_deref(), Some("123"));
        assert_eq!(back.target_resource_name.as_deref(), Some("web-01"));
    }
}
