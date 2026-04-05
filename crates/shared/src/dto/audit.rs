use serde::{Deserialize, Serialize};

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_resource: Option<String>,
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
    CloudwatchSearch,
    CloudwatchInsightsQuery,
    CloudwatchLiveTailStart,
    CloudwatchLiveTailStop,
    LogGroupList,
    EntitlementsView,
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
        let json = serde_json::to_value(AuditAction::Ec2Connect).unwrap();
        assert_eq!(json, "ec2_connect");

        let json = serde_json::to_value(AuditAction::CloudwatchLiveTailStart).unwrap();
        assert_eq!(json, "cloudwatch_live_tail_start");
    }

    #[test]
    fn audit_action_deserializes_snake_case() {
        let val: AuditAction = serde_json::from_value(json!("log_group_list")).unwrap();
        assert!(matches!(val, AuditAction::LogGroupList));
    }

    #[test]
    fn audit_outcome_roundtrip() {
        for outcome in [AuditOutcome::Success, AuditOutcome::Failure, AuditOutcome::Denied] {
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
            outcome: AuditOutcome::Success,
            error_message: None,
            metadata: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("account_id"));
        assert!(!json.contains("region"));
        assert!(!json.contains("target_resource"));
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
            outcome: AuditOutcome::Denied,
            error_message: Some("forbidden".into()),
            metadata: Some(json!({"key": "value"})),
        };
        let json = serde_json::to_value(&event).unwrap();
        let back: AuditEvent = serde_json::from_value(json).unwrap();
        assert_eq!(back.actor, "bob");
        assert_eq!(back.account_id.as_deref(), Some("123"));
    }
}
