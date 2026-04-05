use shared::dto::cloudwatch::*;

/// Poll a CloudWatch Logs Insights query until complete.
/// Returns intermediate states for the caller to relay to the UI.
pub struct QueryPoller {
    pub query_id: String,
    pub poll_interval: std::time::Duration,
    pub max_polls: usize,
}

impl QueryPoller {
    pub fn new(query_id: String) -> Self {
        Self {
            query_id,
            poll_interval: std::time::Duration::from_secs(1),
            max_polls: 120, // 2 minutes max
        }
    }

    /// Determine if the query is in a terminal state
    pub fn is_terminal(status: &QueryStatus) -> bool {
        matches!(
            status,
            QueryStatus::Complete
                | QueryStatus::Failed
                | QueryStatus::Cancelled
                | QueryStatus::Timeout
        )
    }
}

/// Mock log events for development
pub fn mock_log_events() -> Vec<LogEvent> {
    let base_ts = chrono::Utc::now().timestamp_millis();
    vec![
        LogEvent {
            timestamp: base_ts - 5000,
            message: r#"{"level":"INFO","msg":"Request received","path":"/api/v1/users","method":"GET","request_id":"abc-123"}"#.into(),
            log_stream_name: Some("web-prod-01/application".into()),
            ingestion_time: Some(base_ts - 4900),
            event_id: Some("ev-001".into()),
        },
        LogEvent {
            timestamp: base_ts - 4000,
            message: r#"{"level":"INFO","msg":"Database query completed","duration_ms":45,"query":"SELECT * FROM users"}"#.into(),
            log_stream_name: Some("web-prod-01/application".into()),
            ingestion_time: Some(base_ts - 3900),
            event_id: Some("ev-002".into()),
        },
        LogEvent {
            timestamp: base_ts - 3000,
            message: r#"{"level":"WARN","msg":"Slow response detected","path":"/api/v1/reports","duration_ms":2500}"#.into(),
            log_stream_name: Some("api-prod-01/application".into()),
            ingestion_time: Some(base_ts - 2900),
            event_id: Some("ev-003".into()),
        },
        LogEvent {
            timestamp: base_ts - 2000,
            message: r#"{"level":"ERROR","msg":"Connection refused","target":"redis:6379","retry_count":3}"#.into(),
            log_stream_name: Some("worker-prod-01/application".into()),
            ingestion_time: Some(base_ts - 1900),
            event_id: Some("ev-004".into()),
        },
        LogEvent {
            timestamp: base_ts - 1000,
            message: r#"{"level":"INFO","msg":"Health check passed","service":"web","status":"healthy"}"#.into(),
            log_stream_name: Some("web-prod-01/application".into()),
            ingestion_time: Some(base_ts - 900),
            event_id: Some("ev-005".into()),
        },
    ]
}

/// Mock log groups for development
pub fn mock_log_groups() -> Vec<LogGroup> {
    vec![
        LogGroup {
            name: "/app/web-service".into(),
            arn: "arn:aws:logs:us-east-1:111111111111:log-group:/app/web-service".into(),
            stored_bytes: Some(1_073_741_824),
            retention_days: Some(30),
        },
        LogGroup {
            name: "/app/api-service".into(),
            arn: "arn:aws:logs:us-east-1:111111111111:log-group:/app/api-service".into(),
            stored_bytes: Some(2_147_483_648),
            retention_days: Some(90),
        },
        LogGroup {
            name: "/app/worker".into(),
            arn: "arn:aws:logs:us-east-1:111111111111:log-group:/app/worker".into(),
            stored_bytes: Some(536_870_912),
            retention_days: Some(14),
        },
        LogGroup {
            name: "/app/web-service".into(),
            arn: "arn:aws:logs:us-east-1:222222222222:log-group:/app/web-service".into(),
            stored_bytes: Some(268_435_456),
            retention_days: Some(30),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_poller_terminal_states() {
        assert!(QueryPoller::is_terminal(&QueryStatus::Complete));
        assert!(QueryPoller::is_terminal(&QueryStatus::Failed));
        assert!(QueryPoller::is_terminal(&QueryStatus::Cancelled));
        assert!(QueryPoller::is_terminal(&QueryStatus::Timeout));
        assert!(!QueryPoller::is_terminal(&QueryStatus::Running));
        assert!(!QueryPoller::is_terminal(&QueryStatus::Scheduled));
    }

    #[test]
    fn test_mock_log_events_not_empty() {
        let events = mock_log_events();
        assert!(!events.is_empty());
        // Events should be in descending timestamp order (most recent last)
        for window in events.windows(2) {
            assert!(window[0].timestamp <= window[1].timestamp);
        }
    }

    #[test]
    fn test_query_poller_new_defaults() {
        let poller = QueryPoller::new("qid-123".into());
        assert_eq!(poller.query_id, "qid-123");
        assert_eq!(poller.poll_interval, std::time::Duration::from_secs(1));
        assert_eq!(poller.max_polls, 120);
    }

    #[test]
    fn test_mock_log_groups_count_and_fields() {
        let groups = mock_log_groups();
        assert_eq!(groups.len(), 4);
        for g in &groups {
            assert!(!g.name.is_empty());
            assert!(!g.arn.is_empty());
            assert!(g.stored_bytes.is_some());
        }
    }

    #[test]
    fn test_mock_log_groups_two_accounts() {
        let groups = mock_log_groups();
        let acct_111: Vec<_> = groups.iter().filter(|g| g.arn.contains("111111111111")).collect();
        let acct_222: Vec<_> = groups.iter().filter(|g| g.arn.contains("222222222222")).collect();
        assert_eq!(acct_111.len(), 3);
        assert_eq!(acct_222.len(), 1);
    }

    #[test]
    fn test_mock_log_events_all_have_stream_and_id() {
        let events = mock_log_events();
        for ev in &events {
            assert!(ev.log_stream_name.is_some(), "missing log_stream_name");
            assert!(ev.event_id.is_some(), "missing event_id");
        }
    }

    #[test]
    fn test_mock_log_events_contain_all_levels() {
        let events = mock_log_events();
        let messages: String = events.iter().map(|e| e.message.as_str()).collect::<Vec<_>>().join(" ");
        assert!(messages.contains("INFO"));
        assert!(messages.contains("WARN"));
        assert!(messages.contains("ERROR"));
    }
}
