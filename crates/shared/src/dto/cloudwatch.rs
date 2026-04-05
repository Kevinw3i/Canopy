use serde::{Deserialize, Serialize};

/// List available log groups for this user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogGroupsRequest {
    pub account_id: String,
    pub region: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogGroupsResponse {
    pub log_groups: Vec<LogGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogGroup {
    pub name: String,
    pub arn: String,
    pub stored_bytes: Option<i64>,
    pub retention_days: Option<i32>,
}

/// Quick search via FilterLogEvents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterLogEventsRequest {
    pub account_id: String,
    pub region: String,
    pub log_group_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_pattern: Option<String>,
    pub start_time: i64,
    pub end_time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i32,
}

fn default_limit() -> i32 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterLogEventsResponse {
    pub events: Vec<LogEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub timestamp: i64,
    pub message: String,
    pub log_stream_name: Option<String>,
    pub ingestion_time: Option<i64>,
    pub event_id: Option<String>,
}

/// Start a Logs Insights query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartInsightsQueryRequest {
    pub account_id: String,
    pub region: String,
    pub log_group_names: Vec<String>,
    pub query_string: String,
    pub start_time: i64,
    pub end_time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartInsightsQueryResponse {
    pub query_id: String,
}

/// Get query results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetQueryResultsRequest {
    pub account_id: String,
    pub region: String,
    pub query_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetQueryResultsResponse {
    pub status: QueryStatus,
    pub results: Vec<Vec<QueryResultField>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statistics: Option<QueryStatistics>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum QueryStatus {
    Scheduled,
    Running,
    Complete,
    Failed,
    Cancelled,
    Timeout,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResultField {
    pub field: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryStatistics {
    pub records_matched: f64,
    pub records_scanned: f64,
    pub bytes_scanned: f64,
}

/// Live tail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartLiveTailRequest {
    pub account_id: String,
    pub region: String,
    pub log_group_arns: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveTailEvent {
    pub timestamp: i64,
    pub message: String,
    pub log_stream_name: String,
    pub log_group_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum LiveTailMessage {
    #[serde(rename = "event")]
    Event(LiveTailEvent),
    #[serde(rename = "session_start")]
    SessionStart { session_id: String },
    #[serde(rename = "session_update")]
    SessionUpdate {
        session_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        events_per_second: Option<f64>,
    },
    #[serde(rename = "error")]
    Error { message: String },
}

/// Saved query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedQuery {
    pub id: String,
    pub name: String,
    pub query_string: String,
    pub log_group_names: Vec<String>,
    pub account_id: String,
    pub region: String,
    pub created_at: String,
}

/// Query history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryHistoryEntry {
    pub query_string: String,
    pub log_group_names: Vec<String>,
    pub account_id: String,
    pub region: String,
    pub executed_at: String,
    pub status: QueryStatus,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn query_status_pascal_case() {
        assert_eq!(serde_json::to_value(QueryStatus::Complete).unwrap(), "Complete");
        assert_eq!(serde_json::to_value(QueryStatus::Running).unwrap(), "Running");

        let val: QueryStatus = serde_json::from_value(json!("Failed")).unwrap();
        assert_eq!(val, QueryStatus::Failed);
    }

    #[test]
    fn filter_log_events_request_default_limit() {
        let json = json!({
            "account_id": "111",
            "region": "us-east-1",
            "log_group_name": "/app/web",
            "start_time": 0,
            "end_time": 999
        });
        let req: FilterLogEventsRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.limit, 100);
        assert!(req.filter_pattern.is_none());
        assert!(req.next_token.is_none());
    }

    #[test]
    fn log_groups_request_omits_none_prefix() {
        let req = LogGroupsRequest {
            account_id: "111".into(),
            region: "us-east-1".into(),
            prefix: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("prefix"));
    }

    #[test]
    fn live_tail_message_tagged_enum() {
        let msg = LiveTailMessage::Event(LiveTailEvent {
            timestamp: 123,
            message: "hello".into(),
            log_stream_name: "stream-1".into(),
            log_group_name: "/app/web".into(),
        });
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "event");
        assert_eq!(json["message"], "hello");
    }

    #[test]
    fn live_tail_session_start() {
        let msg = LiveTailMessage::SessionStart {
            session_id: "s1".into(),
        };
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "session_start");
        assert_eq!(json["session_id"], "s1");
    }

    #[test]
    fn live_tail_error() {
        let json = json!({"type": "error", "message": "timeout"});
        let msg: LiveTailMessage = serde_json::from_value(json).unwrap();
        match msg {
            LiveTailMessage::Error { message } => assert_eq!(message, "timeout"),
            _ => panic!("expected Error variant"),
        }
    }

    #[test]
    fn get_query_results_response_omits_none_statistics() {
        let resp = GetQueryResultsResponse {
            status: QueryStatus::Complete,
            results: vec![],
            statistics: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("statistics"));
    }

    #[test]
    fn query_statistics_roundtrip() {
        let stats = QueryStatistics {
            records_matched: 42.0,
            records_scanned: 1000.0,
            bytes_scanned: 524288.0,
        };
        let json = serde_json::to_value(&stats).unwrap();
        let back: QueryStatistics = serde_json::from_value(json).unwrap();
        assert_eq!(back.records_matched, 42.0);
    }
}
