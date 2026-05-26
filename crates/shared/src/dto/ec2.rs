use crate::dto::pty_spawn::PtySpawnSpec;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ec2ListRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_filter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_filter: Option<Vec<InstanceState>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag_filters: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
    #[serde(default = "default_page_size")]
    pub page_size: u32,
}

fn default_page_size() -> u32 {
    50
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ec2ListResponse {
    pub instances: Vec<Ec2Instance>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
    pub total_count: usize,
    /// Scopes (account/region) that failed during fan-out fetch.
    /// Empty when all scopes succeeded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum InstanceState {
    Pending,
    Running,
    ShuttingDown,
    Terminated,
    Stopping,
    Stopped,
}

impl std::fmt::Display for InstanceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::ShuttingDown => write!(f, "shutting-down"),
            Self::Terminated => write!(f, "terminated"),
            Self::Stopping => write!(f, "stopping"),
            Self::Stopped => write!(f, "stopped"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ec2Instance {
    pub instance_id: String,
    pub account_id: String,
    pub region: String,
    pub name: Option<String>,
    pub private_ip: Option<String>,
    pub public_ip: Option<String>,
    pub state: InstanceState,
    pub platform: Option<String>,
    pub instance_type: String,
    pub ssm_managed: bool,
    pub instance_connect_capable: bool,
    pub environment: Option<String>,
    pub tags: HashMap<String, String>,
    pub launch_time: Option<String>,
    pub vpc_id: Option<String>,
    pub subnet_id: Option<String>,
    pub security_groups: Vec<String>,
    pub iam_role: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ec2InstanceDetail {
    #[serde(flatten)]
    pub instance: Ec2Instance,
    pub block_devices: Vec<BlockDevice>,
    pub network_interfaces: Vec<NetworkInterface>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockDevice {
    pub device_name: String,
    pub volume_id: String,
    pub size_gb: i32,
    pub volume_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub interface_id: String,
    pub private_ip: String,
    pub public_ip: Option<String>,
    pub subnet_id: String,
}

/// Connect to an instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub instance_id: String,
    pub account_id: String,
    pub region: String,
    pub method: ConnectMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_user: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectMethod {
    Ssm,
    Ec2InstanceConnect,
    /// Direct SSH using the operator's own key (~/.ssh/id_rsa etc.)
    /// Connects to the instance's private or public IP.
    Ssh,
}

/// Temporary credentials from STS AssumeRole, injected into the spawned CLI process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssumedRoleCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectResponse {
    pub authorized: bool,
    pub command: String,
    pub args: Vec<String>,
    pub env_vars: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Maximum session duration in seconds. None = no limit.
    /// The TUI enforces this by killing the spawned process after the timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_session_seconds: Option<u64>,
}

impl From<ConnectResponse> for PtySpawnSpec {
    fn from(resp: ConnectResponse) -> Self {
        Self {
            command: resp.command,
            args: resp.args,
            env_vars: resp.env_vars,
            max_session_seconds: resp.max_session_seconds,
        }
    }
}

// ── Power actions (start / stop / reboot) ──────────────────────────────

/// Power-action verb for an EC2 instance.
///
/// Serialized as snake_case to match the rest of the shared API enums and stay
/// future-proof for multi-word actions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Ec2PowerAction {
    Start,
    Stop,
    Reboot,
}

impl std::fmt::Display for Ec2PowerAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Start => write!(f, "start"),
            Self::Stop => write!(f, "stop"),
            Self::Reboot => write!(f, "reboot"),
        }
    }
}

/// Request a power action against a single EC2 instance.
///
/// `confirmation_instance_id` is a UX safeguard, NOT an authentication
/// boundary. The TUI prompts the user to type the full instance id before
/// sending; the control-plane string-equals it against `instance_id` and
/// rejects with 400 on mismatch. Audit metadata records only
/// `confirmation_present: true` — the typed value itself is never stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ec2PowerRequest {
    pub instance_id: String,
    pub account_id: String,
    pub region: String,
    pub action: Ec2PowerAction,
    /// User-typed confirmation string. Server requires this to equal
    /// `instance_id`.
    pub confirmation_instance_id: String,
}

/// Response for a successful power action.
///
/// `previous_state` is the instance state observed via DescribeInstances
/// immediately before the AWS power call. `requested_state` is whatever
/// AWS reported in the StartInstances/StopInstances/RebootInstances
/// response (typically a transient state like `pending` / `stopping`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ec2PowerResponse {
    pub instance_id: String,
    pub action: Ec2PowerAction,
    pub previous_state: InstanceState,
    pub requested_state: InstanceState,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn instance_state_kebab_case() {
        assert_eq!(
            serde_json::to_value(InstanceState::Running).unwrap(),
            "running"
        );
        assert_eq!(
            serde_json::to_value(InstanceState::ShuttingDown).unwrap(),
            "shutting-down"
        );

        let val: InstanceState = serde_json::from_value(json!("shutting-down")).unwrap();
        assert_eq!(val, InstanceState::ShuttingDown);
    }

    #[test]
    fn connect_method_snake_case() {
        assert_eq!(serde_json::to_value(ConnectMethod::Ssm).unwrap(), "ssm");
        assert_eq!(
            serde_json::to_value(ConnectMethod::Ec2InstanceConnect).unwrap(),
            "ec2_instance_connect"
        );
        assert_eq!(serde_json::to_value(ConnectMethod::Ssh).unwrap(), "ssh");
    }

    #[test]
    fn ec2_list_request_default_page_size() {
        let json = json!({});
        let req: Ec2ListRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.page_size, 50);
        assert!(req.account_id.is_none());
    }

    #[test]
    fn ec2_list_response_omits_empty_failed_scopes() {
        let resp = Ec2ListResponse {
            instances: vec![],
            next_token: None,
            total_count: 0,
            failed_scopes: vec![],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("failed_scopes"));
        assert!(!json.contains("next_token"));
    }

    #[test]
    fn ec2_instance_roundtrip() {
        let inst = Ec2Instance {
            instance_id: "i-abc123".into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            name: Some("web-1".into()),
            private_ip: Some("10.0.0.1".into()),
            public_ip: None,
            state: InstanceState::Running,
            platform: Some("linux".into()),
            instance_type: "t3.micro".into(),
            ssm_managed: true,
            instance_connect_capable: false,
            environment: Some("production".into()),
            tags: HashMap::from([("env".into(), "prod".into())]),
            launch_time: Some("2025-01-01T00:00:00Z".into()),
            vpc_id: Some("vpc-123".into()),
            subnet_id: Some("subnet-456".into()),
            security_groups: vec!["sg-789".into()],
            iam_role: Some("role-abc".into()),
        };
        let json = serde_json::to_value(&inst).unwrap();
        let back: Ec2Instance = serde_json::from_value(json).unwrap();
        assert_eq!(back.instance_id, "i-abc123");
        assert_eq!(back.state, InstanceState::Running);
        assert!(back.ssm_managed);
    }

    #[test]
    fn ec2_instance_detail_flattens() {
        let inst = Ec2Instance {
            instance_id: "i-x".into(),
            account_id: "111".into(),
            region: "us-east-1".into(),
            name: None,
            private_ip: None,
            public_ip: None,
            state: InstanceState::Stopped,
            platform: None,
            instance_type: "t3.nano".into(),
            ssm_managed: false,
            instance_connect_capable: false,
            environment: None,
            tags: HashMap::new(),
            launch_time: None,
            vpc_id: None,
            subnet_id: None,
            security_groups: vec![],
            iam_role: None,
        };
        let detail = Ec2InstanceDetail {
            instance: inst,
            block_devices: vec![BlockDevice {
                device_name: "/dev/xvda".into(),
                volume_id: "vol-1".into(),
                size_gb: 8,
                volume_type: "gp3".into(),
            }],
            network_interfaces: vec![],
        };
        let json = serde_json::to_value(&detail).unwrap();
        // Flattened: instance_id at top level
        assert_eq!(json["instance_id"], "i-x");
        assert_eq!(json["block_devices"][0]["device_name"], "/dev/xvda");
    }

    #[test]
    fn connect_response_omits_optional_fields() {
        let resp = ConnectResponse {
            authorized: true,
            command: "aws".into(),
            args: vec!["ssm".into()],
            env_vars: HashMap::new(),
            error: None,
            max_session_seconds: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("error"));
        assert!(!json.contains("max_session_seconds"));
    }

    // ── Power-action tests ─────────────────────────────────────────────

    #[test]
    fn ec2_power_action_snake_case_serde() {
        assert_eq!(
            serde_json::to_value(Ec2PowerAction::Start).unwrap(),
            "start"
        );
        assert_eq!(serde_json::to_value(Ec2PowerAction::Stop).unwrap(), "stop");
        assert_eq!(
            serde_json::to_value(Ec2PowerAction::Reboot).unwrap(),
            "reboot"
        );

        let parsed: Ec2PowerAction = serde_json::from_value(json!("reboot")).unwrap();
        assert_eq!(parsed, Ec2PowerAction::Reboot);
    }

    #[test]
    fn ec2_power_action_display_matches_serde() {
        assert_eq!(Ec2PowerAction::Start.to_string(), "start");
        assert_eq!(Ec2PowerAction::Stop.to_string(), "stop");
        assert_eq!(Ec2PowerAction::Reboot.to_string(), "reboot");
    }

    #[test]
    fn ec2_power_request_requires_confirmation_field() {
        // Missing `confirmation_instance_id` must fail to deserialize —
        // ensures the server can rely on its presence for the safeguard.
        let json = json!({
            "instance_id": "i-abc",
            "account_id": "111111111111",
            "region": "us-east-1",
            "action": "stop",
        });
        let err = serde_json::from_value::<Ec2PowerRequest>(json).unwrap_err();
        assert!(
            err.to_string().contains("confirmation_instance_id"),
            "expected error to mention missing field, got: {err}"
        );
    }

    #[test]
    fn ec2_power_request_roundtrip() {
        let req = Ec2PowerRequest {
            instance_id: "i-abc".into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            action: Ec2PowerAction::Start,
            confirmation_instance_id: "i-abc".into(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["action"], "start");
        let back: Ec2PowerRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back.instance_id, "i-abc");
        assert_eq!(back.confirmation_instance_id, "i-abc");
        assert_eq!(back.action, Ec2PowerAction::Start);
    }

    #[test]
    fn ec2_power_response_roundtrip() {
        let resp = Ec2PowerResponse {
            instance_id: "i-abc".into(),
            action: Ec2PowerAction::Stop,
            previous_state: InstanceState::Running,
            requested_state: InstanceState::Stopping,
            message: "Stop initiated".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["previous_state"], "running");
        assert_eq!(json["requested_state"], "stopping");
        assert_eq!(json["action"], "stop");
        let back: Ec2PowerResponse = serde_json::from_value(json).unwrap();
        assert_eq!(back.previous_state, InstanceState::Running);
        assert_eq!(back.requested_state, InstanceState::Stopping);
        assert_eq!(back.action, Ec2PowerAction::Stop);
    }
}
