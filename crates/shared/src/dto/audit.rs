use serde::{Deserialize, Serialize};

/// Audit JSON-lines event.
///
/// Keep this enum and event shape in sync with `docs/en/AUDIT-SCHEMA.md`.
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
    /// List ECS tasks visible through Canopy's ECS inventory view.
    /// Cluster filters, returned counts, and broad-discovery context live in
    /// metadata so list and exec events stay forensically distinct.
    EcsTaskList,
    /// Start an ECS Exec shell into a task container. The task ARN is the
    /// target resource; cluster/container details and validation outcomes live
    /// in metadata.
    EcsExec,
    EntitlementsView,
    /// Local MCP session lifecycle registration. This is separate from
    /// `login` because the user is already authenticated; the event records
    /// whether an MCP session can be opened for that authenticated actor.
    McpSessionRegister,
    /// MCP guidance delivery / sync lifecycle. Metadata records the guidance
    /// id and version so data-access tools can prove the required guidance was
    /// issued before use.
    McpGuidanceSync,
    /// MCP CloudWatch discovery. The operation lists authorized log groups
    /// only; CloudWatch data access stays behind later MCP phases.
    McpCloudwatchDiscovery,
    /// MCP CloudWatch data-access preflight. No AWS data read happens here;
    /// success means the server issued a scoped preflight token.
    McpCloudwatchPreflight,
    /// MCP CloudWatch FilterLogEvents data access.
    McpCloudwatchSearch,
    /// MCP CloudWatch Logs Insights start/poll data access.
    McpCloudwatchInsights,
    /// MCP database scope discovery. Scope details stay in metadata; secrets
    /// and connection internals must not be exposed in the response or audit.
    McpDatabaseScopeList,
    /// MCP database data access. The operation details, including raw SQL,
    /// scope, EXPLAIN result, and rejection reason, live in metadata rather
    /// than being split across read/write action variants.
    /// Raw SQL may contain PII or secrets typed by the user; treat audit output
    /// as sensitive and redact at downstream audit/SIEM boundaries as needed.
    McpDatabaseQuery,
    /// Start or confirm local TOTP factor enrollment. Secret material and
    /// verification codes must never be placed in metadata.
    MfaTotpEnroll,
    /// Verify a local TOTP factor for a step-up challenge. Verification codes
    /// must never be placed in metadata.
    MfaTotpVerify,
    /// Generate local MFA recovery codes. Plaintext recovery codes must never
    /// be placed in metadata.
    MfaRecoveryCodesGenerate,
    /// Verify and consume one local MFA recovery code for a step-up challenge.
    /// Plaintext recovery codes must never be placed in metadata.
    MfaRecoveryCodeVerify,
    /// Enroll a local WebAuthn/passkey factor. Browser credential payloads must
    /// never be placed in metadata.
    #[serde(rename = "mfa_webauthn_enroll")]
    MfaWebAuthnEnroll,
    /// Verify a local WebAuthn/passkey factor for a step-up challenge. Browser
    /// assertion payloads must never be placed in metadata.
    #[serde(rename = "mfa_webauthn_verify")]
    MfaWebAuthnVerify,
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
            Self::EcsTaskList => "ecs_task_list",
            Self::EcsExec => "ecs_exec",
            Self::EntitlementsView => "entitlements_view",
            Self::McpSessionRegister => "mcp_session_register",
            Self::McpGuidanceSync => "mcp_guidance_sync",
            Self::McpCloudwatchDiscovery => "mcp_cloudwatch_discovery",
            Self::McpCloudwatchPreflight => "mcp_cloudwatch_preflight",
            Self::McpCloudwatchSearch => "mcp_cloudwatch_search",
            Self::McpCloudwatchInsights => "mcp_cloudwatch_insights",
            Self::McpDatabaseScopeList => "mcp_database_scope_list",
            Self::McpDatabaseQuery => "mcp_database_query",
            Self::MfaTotpEnroll => "mfa_totp_enroll",
            Self::MfaTotpVerify => "mfa_totp_verify",
            Self::MfaRecoveryCodesGenerate => "mfa_recovery_codes_generate",
            Self::MfaRecoveryCodeVerify => "mfa_recovery_code_verify",
            Self::MfaWebAuthnEnroll => "mfa_webauthn_enroll",
            Self::MfaWebAuthnVerify => "mfa_webauthn_verify",
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
            AuditAction::EcsTaskList,
            AuditAction::EcsExec,
            AuditAction::EntitlementsView,
            AuditAction::McpSessionRegister,
            AuditAction::McpGuidanceSync,
            AuditAction::McpCloudwatchDiscovery,
            AuditAction::McpCloudwatchPreflight,
            AuditAction::McpCloudwatchSearch,
            AuditAction::McpCloudwatchInsights,
            AuditAction::McpDatabaseScopeList,
            AuditAction::McpDatabaseQuery,
            AuditAction::MfaTotpEnroll,
            AuditAction::MfaTotpVerify,
            AuditAction::MfaRecoveryCodesGenerate,
            AuditAction::MfaRecoveryCodeVerify,
            AuditAction::MfaWebAuthnEnroll,
            AuditAction::MfaWebAuthnVerify,
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
    fn audit_action_ecs_task_list_roundtrip() {
        let json = serde_json::to_value(AuditAction::EcsTaskList).unwrap();
        assert_eq!(json, "ecs_task_list");
        assert_eq!(AuditAction::EcsTaskList.wire_name(), "ecs_task_list");

        let back: AuditAction = serde_json::from_value(json).unwrap();
        assert!(matches!(back, AuditAction::EcsTaskList));
    }

    #[test]
    fn audit_action_ecs_exec_roundtrip() {
        let json = serde_json::to_value(AuditAction::EcsExec).unwrap();
        assert_eq!(json, "ecs_exec");
        assert_eq!(AuditAction::EcsExec.wire_name(), "ecs_exec");

        let back: AuditAction = serde_json::from_value(json).unwrap();
        assert!(matches!(back, AuditAction::EcsExec));
    }

    #[test]
    fn audit_action_mfa_totp_enroll_roundtrip() {
        let json = serde_json::to_value(AuditAction::MfaTotpEnroll).unwrap();
        assert_eq!(json, "mfa_totp_enroll");
        assert_eq!(AuditAction::MfaTotpEnroll.wire_name(), "mfa_totp_enroll");

        let back: AuditAction = serde_json::from_value(json).unwrap();
        assert!(matches!(back, AuditAction::MfaTotpEnroll));
    }

    #[test]
    fn audit_action_mfa_totp_verify_roundtrip() {
        let json = serde_json::to_value(AuditAction::MfaTotpVerify).unwrap();
        assert_eq!(json, "mfa_totp_verify");
        assert_eq!(AuditAction::MfaTotpVerify.wire_name(), "mfa_totp_verify");

        let back: AuditAction = serde_json::from_value(json).unwrap();
        assert!(matches!(back, AuditAction::MfaTotpVerify));
    }

    #[test]
    fn audit_action_mfa_recovery_codes_generate_roundtrip() {
        let json = serde_json::to_value(AuditAction::MfaRecoveryCodesGenerate).unwrap();
        assert_eq!(json, "mfa_recovery_codes_generate");
        assert_eq!(
            AuditAction::MfaRecoveryCodesGenerate.wire_name(),
            "mfa_recovery_codes_generate"
        );

        let back: AuditAction = serde_json::from_value(json).unwrap();
        assert!(matches!(back, AuditAction::MfaRecoveryCodesGenerate));
    }

    #[test]
    fn audit_action_mfa_recovery_code_verify_roundtrip() {
        let json = serde_json::to_value(AuditAction::MfaRecoveryCodeVerify).unwrap();
        assert_eq!(json, "mfa_recovery_code_verify");
        assert_eq!(
            AuditAction::MfaRecoveryCodeVerify.wire_name(),
            "mfa_recovery_code_verify"
        );

        let back: AuditAction = serde_json::from_value(json).unwrap();
        assert!(matches!(back, AuditAction::MfaRecoveryCodeVerify));
    }

    #[test]
    fn audit_action_mfa_webauthn_enroll_roundtrip() {
        let json = serde_json::to_value(AuditAction::MfaWebAuthnEnroll).unwrap();
        assert_eq!(json, "mfa_webauthn_enroll");
        assert_eq!(
            AuditAction::MfaWebAuthnEnroll.wire_name(),
            "mfa_webauthn_enroll"
        );

        let back: AuditAction = serde_json::from_value(json).unwrap();
        assert!(matches!(back, AuditAction::MfaWebAuthnEnroll));
    }

    #[test]
    fn audit_action_mfa_webauthn_verify_roundtrip() {
        let json = serde_json::to_value(AuditAction::MfaWebAuthnVerify).unwrap();
        assert_eq!(json, "mfa_webauthn_verify");
        assert_eq!(
            AuditAction::MfaWebAuthnVerify.wire_name(),
            "mfa_webauthn_verify"
        );

        let back: AuditAction = serde_json::from_value(json).unwrap();
        assert!(matches!(back, AuditAction::MfaWebAuthnVerify));
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
