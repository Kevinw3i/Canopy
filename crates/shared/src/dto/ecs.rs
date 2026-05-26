use crate::dto::pty_spawn::PtySpawnSpec;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const DEV_MOCK_CLUSTER_NAME: &str = "dev-mock-cluster";

fn default_page_size() -> u32 {
    50
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EcsTasksRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Optional cluster filter. `"*"` is rejected by the control-plane.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
    #[serde(default = "default_page_size")]
    pub page_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EcsTasksResponse {
    pub tasks: Vec<EcsTask>,
    pub total_count: usize,
    pub truncated: bool,
    /// Scopes or clusters that failed during fan-out fetch.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EcsTask {
    pub task_arn: String,
    pub cluster_arn: String,
    pub cluster_name: String,
    pub account_id: String,
    pub region: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    pub launch_type: String,
    pub last_status: String,
    pub desired_status: String,
    pub enable_execute_command: bool,
    pub containers: Vec<EcsContainer>,
    pub tags: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EcsContainer {
    pub name: String,
    pub last_status: String,
    pub execute_command_agent_running: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EcsExecRequest {
    pub account_id: String,
    pub region: String,
    pub cluster_arn: String,
    pub task_arn: String,
    pub container_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EcsExecResponse {
    pub command: String,
    pub args: Vec<String>,
    pub env_vars: HashMap<String, String>,
    /// Maximum session duration in seconds. None = no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_session_seconds: Option<u64>,
}

impl From<EcsExecResponse> for PtySpawnSpec {
    fn from(resp: EcsExecResponse) -> Self {
        Self {
            command: resp.command,
            args: resp.args,
            env_vars: resp.env_vars,
            max_session_seconds: resp.max_session_seconds,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ecs_tasks_request_default_page_size() {
        let req: EcsTasksRequest = serde_json::from_value(json!({})).unwrap();
        assert_eq!(req.page_size, 50);
        assert!(req.account_id.is_none());
        assert!(req.cluster.is_none());
    }

    #[test]
    fn ecs_exec_request_requires_container_name() {
        let err = serde_json::from_value::<EcsExecRequest>(json!({
            "account_id": "111111111111",
            "region": "us-east-1",
            "cluster_arn": "arn:aws:ecs:us-east-1:111111111111:cluster/prod-app",
            "task_arn": "arn:aws:ecs:us-east-1:111111111111:task/prod-app/abc"
        }))
        .unwrap_err();
        assert!(err.to_string().contains("container_name"));
    }

    #[test]
    fn ecs_exec_response_converts_to_pty_spawn_spec() {
        let resp = EcsExecResponse {
            command: "aws".into(),
            args: vec!["ecs".into(), "execute-command".into()],
            env_vars: HashMap::from([("AWS_DEFAULT_REGION".into(), "us-east-1".into())]),
            max_session_seconds: Some(3600),
        };
        let spec: PtySpawnSpec = resp.into();
        assert_eq!(spec.command, "aws");
        assert_eq!(spec.args[0], "ecs");
        assert_eq!(spec.max_session_seconds, Some(3600));
    }

    #[test]
    fn ecs_tasks_response_omits_empty_failed_scopes() {
        let resp = EcsTasksResponse {
            tasks: vec![],
            total_count: 0,
            truncated: false,
            failed_scopes: vec![],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("failed_scopes"));
        assert!(!json.contains("next_cursor"));
    }
}
