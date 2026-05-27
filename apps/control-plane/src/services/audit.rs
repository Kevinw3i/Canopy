use shared::dto::audit::{AuditAction, AuditEvent, AuditOutcome};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Mutex;
use uuid::Uuid;

use crate::config::{AuditExportConfig, AuditS3ExportConfig};
use crate::services::auth::Claims;
use aws_config::SdkConfig;
use axum::http::{header::USER_AGENT, HeaderMap};
use chrono::Datelike;
use shared::headers;
use tokio::sync::mpsc;

const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// Audit service — logs all user actions for compliance.
/// When durable logging is configured, `log_event` returns Err on write
/// failure so callers can fail-closed on privileged operations.
pub struct AuditService {
    writer: Option<Mutex<std::io::BufWriter<std::fs::File>>>,
    exporter: Option<AuditExporter>,
    sink_failed: std::sync::atomic::AtomicBool,
}

impl Default for AuditService {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditService {
    pub fn new() -> Self {
        Self {
            writer: None,
            exporter: None,
            sink_failed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn with_file(path: &str) -> anyhow::Result<Self> {
        let path = PathBuf::from(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(&path)?;
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        tracing::info!(path = %path.display(), "Audit log file opened");
        Ok(Self {
            writer: Some(Mutex::new(std::io::BufWriter::new(file))),
            exporter: None,
            sink_failed: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub fn from_config(
        audit_log: Option<&str>,
        export_config: &AuditExportConfig,
        aws_config: &SdkConfig,
    ) -> anyhow::Result<Self> {
        export_config.validate()?;

        let mut service = if let Some(log_path) = audit_log {
            Self::with_file(log_path)?
        } else {
            Self::new()
        };

        if export_config.is_enabled() {
            service.exporter = Some(AuditExporter::spawn(
                export_config.clone(),
                aws_config.clone(),
            ));
        }

        Ok(service)
    }

    pub fn event(
        &self,
        actor: &str,
        action: AuditAction,
        outcome: AuditOutcome,
    ) -> AuditEventBuilder<'_> {
        AuditEventBuilder::new(self, actor, action, outcome)
    }

    fn write_event(&self, event: AuditEvent) -> Result<(), &'static str> {
        // Always emit structured tracing
        tracing::info!(
            audit_event = %serde_json::to_string(&event).unwrap_or_default(),
            actor = %event.actor,
            action = ?event.action,
            outcome = ?event.outcome,
            "audit"
        );

        // Persist to durable log file if configured.
        if let Some(ref writer) = self.writer {
            match writer.lock() {
                Ok(mut w) => {
                    if let Ok(json) = serde_json::to_string(&event) {
                        if let Err(e) = writeln!(w, "{}", json) {
                            tracing::error!(error = %e, "AUDIT SINK FAILURE: write");
                            self.sink_failed
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                            return Err("Audit write failed");
                        }
                        if let Err(e) = w.flush() {
                            tracing::error!(error = %e, "AUDIT SINK FAILURE: flush");
                            self.sink_failed
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                            return Err("Audit flush failed");
                        }
                        self.sink_failed
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "AUDIT SINK FAILURE: lock");
                    self.sink_failed
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    return Err("Audit lock poisoned");
                }
            }
        }

        if let Some(exporter) = &self.exporter {
            exporter.enqueue(event)?;
        }

        Ok(())
    }

    /// Check whether the audit sink can likely accept writes.
    /// This is optimistic: a previously failed sink is allowed to retry
    /// so transient I/O errors (disk full, permission blip) can recover
    /// without restarting the process. The actual write in `commit_or_fail()`
    /// is still fail-closed — callers must propagate its errors.
    pub fn is_healthy(&self) -> bool {
        match &self.writer {
            None => self
                .exporter
                .as_ref()
                .map(|exporter| exporter.is_healthy())
                .unwrap_or(true),
            Some(mutex) => {
                !mutex.is_poisoned()
                    && self
                        .exporter
                        .as_ref()
                        .map(|exporter| exporter.is_healthy())
                        .unwrap_or(true)
            }
        }
    }
}

#[derive(Clone)]
struct AuditExporter {
    sender: mpsc::Sender<AuditEvent>,
}

impl AuditExporter {
    fn spawn(config: AuditExportConfig, aws_config: SdkConfig) -> Self {
        let queue_size = config.queue_size.max(1);
        let (sender, receiver) = mpsc::channel(queue_size);
        tokio::spawn(async move {
            AuditExportWorker::new(config, aws_config)
                .run(receiver)
                .await;
        });
        Self { sender }
    }

    fn enqueue(&self, event: AuditEvent) -> Result<(), &'static str> {
        match self.sender.try_send(event) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err("Audit export queue full"),
            Err(mpsc::error::TrySendError::Closed(_)) => Err("Audit export worker stopped"),
        }
    }

    fn is_healthy(&self) -> bool {
        !self.sender.is_closed()
    }
}

struct AuditExportWorker {
    cloudwatch_logs: Option<AuditCloudWatchLogsSink>,
    s3: Option<AuditS3Sink>,
}

impl AuditExportWorker {
    fn new(config: AuditExportConfig, aws_config: SdkConfig) -> Self {
        let cloudwatch_logs = config
            .cloudwatch_logs
            .map(|sink| AuditCloudWatchLogsSink::new(sink, &aws_config));
        let s3 = config.s3.map(|sink| AuditS3Sink::new(sink, &aws_config));
        Self {
            cloudwatch_logs,
            s3,
        }
    }

    async fn run(self, mut receiver: mpsc::Receiver<AuditEvent>) {
        if let Some(sink) = &self.cloudwatch_logs {
            if let Err(error) = sink.ensure_log_stream().await {
                tracing::error!(error = %error, "audit CloudWatch Logs stream setup failed");
            }
        }

        while let Some(event) = receiver.recv().await {
            let json = match serde_json::to_string(&event) {
                Ok(json) => json,
                Err(error) => {
                    tracing::error!(error = %error, "audit export serialization failed");
                    continue;
                }
            };

            if let Some(sink) = &self.cloudwatch_logs {
                if let Err(error) = sink.export(&event, json.clone()).await {
                    tracing::error!(error = %error, "audit CloudWatch Logs export failed");
                }
            }

            if let Some(sink) = &self.s3 {
                if let Err(error) = sink.export(&event, json.clone()).await {
                    tracing::error!(error = %error, "audit S3 export failed");
                }
            }
        }
    }
}

struct AuditCloudWatchLogsSink {
    client: aws_sdk_cloudwatchlogs::Client,
    log_group_name: String,
    log_stream_name: String,
    create_log_stream: bool,
}

impl AuditCloudWatchLogsSink {
    fn new(config: crate::config::AuditCloudWatchLogsExportConfig, aws_config: &SdkConfig) -> Self {
        Self {
            client: aws_sdk_cloudwatchlogs::Client::new(aws_config),
            log_group_name: config.log_group_name,
            log_stream_name: config.log_stream_name,
            create_log_stream: config.create_log_stream,
        }
    }

    async fn ensure_log_stream(&self) -> anyhow::Result<()> {
        if !self.create_log_stream {
            return Ok(());
        }

        let output = self
            .client
            .describe_log_streams()
            .log_group_name(&self.log_group_name)
            .log_stream_name_prefix(&self.log_stream_name)
            .limit(1)
            .send()
            .await?;

        let exists = output
            .log_streams()
            .iter()
            .any(|stream| stream.log_stream_name() == Some(self.log_stream_name.as_str()));
        if exists {
            return Ok(());
        }

        self.client
            .create_log_stream()
            .log_group_name(&self.log_group_name)
            .log_stream_name(&self.log_stream_name)
            .send()
            .await?;
        Ok(())
    }

    async fn export(&self, event: &AuditEvent, json: String) -> anyhow::Result<()> {
        let input = aws_sdk_cloudwatchlogs::types::InputLogEvent::builder()
            .timestamp(audit_timestamp_millis(event))
            .message(json)
            .build()?;

        self.client
            .put_log_events()
            .log_group_name(&self.log_group_name)
            .log_stream_name(&self.log_stream_name)
            .log_events(input)
            .send()
            .await?;
        Ok(())
    }
}

struct AuditS3Sink {
    client: aws_sdk_s3::Client,
    bucket: String,
    prefix: String,
}

impl AuditS3Sink {
    fn new(config: AuditS3ExportConfig, aws_config: &SdkConfig) -> Self {
        Self {
            client: aws_sdk_s3::Client::new(aws_config),
            bucket: config.bucket,
            prefix: normalized_s3_prefix(&config.prefix),
        }
    }

    async fn export(&self, event: &AuditEvent, json: String) -> anyhow::Result<()> {
        let key = audit_s3_key(&self.prefix, event);
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_type("application/json")
            .body(aws_sdk_s3::primitives::ByteStream::from(json.into_bytes()))
            .send()
            .await?;
        Ok(())
    }
}

fn audit_timestamp_millis(event: &AuditEvent) -> i64 {
    chrono::DateTime::parse_from_rfc3339(&event.timestamp)
        .map(|timestamp| timestamp.timestamp_millis())
        .unwrap_or_else(|_| chrono::Utc::now().timestamp_millis())
}

fn normalized_s3_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim().trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}/")
    }
}

fn audit_s3_key(prefix: &str, event: &AuditEvent) -> String {
    let timestamp = chrono::DateTime::parse_from_rfc3339(&event.timestamp)
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());
    format!(
        "{}{:04}/{:02}/{:02}/{}-{}.json",
        prefix,
        timestamp.year(),
        timestamp.month(),
        timestamp.day(),
        timestamp.format("%Y%m%dT%H%M%S%.3fZ"),
        event.event_id
    )
}

pub struct AuditEventBuilder<'a> {
    service: &'a AuditService,
    actor: String,
    action: AuditAction,
    outcome: AuditOutcome,
    account_id: Option<String>,
    region: Option<String>,
    target_resource: Option<String>,
    target_resource_name: Option<String>,
    error_message: Option<String>,
    metadata: Option<serde_json::Value>,
}

impl<'a> AuditEventBuilder<'a> {
    fn new(
        service: &'a AuditService,
        actor: &str,
        action: AuditAction,
        outcome: AuditOutcome,
    ) -> Self {
        Self {
            service,
            actor: actor.to_string(),
            action,
            outcome,
            account_id: None,
            region: None,
            target_resource: None,
            target_resource_name: None,
            error_message: None,
            metadata: None,
        }
    }

    pub fn account(mut self, account_id: Option<&str>) -> Self {
        self.account_id = normalized_optional_string(account_id);
        self
    }

    pub fn region(mut self, region: Option<&str>) -> Self {
        self.region = normalized_optional_string(region);
        self
    }

    pub fn target(mut self, target_resource: Option<&str>) -> Self {
        self.target_resource = normalized_optional_string(target_resource);
        self
    }

    pub fn target_name(mut self, target_resource_name: Option<&str>) -> Self {
        self.target_resource_name = normalized_optional_string(target_resource_name);
        self
    }

    pub fn error(mut self, error_message: Option<&str>) -> Self {
        self.error_message = normalized_optional_string(error_message);
        self
    }

    pub fn metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub fn optional_metadata(mut self, metadata: Option<serde_json::Value>) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn commit_or_fail(self) -> Result<(), &'static str> {
        self.service.write_event(self.build())
    }

    pub fn commit_best_effort(self) {
        let actor = self.actor.clone();
        let action = self.action.clone();
        let outcome = self.outcome.clone();
        if let Err(e) = self.commit_or_fail() {
            tracing::error!(
                error = %e,
                actor = %actor,
                action = ?action,
                outcome = ?outcome,
                "audit write failed"
            );
        }
    }

    fn build(self) -> AuditEvent {
        AuditEvent {
            event_id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            actor: self.actor,
            action: self.action,
            account_id: self.account_id,
            region: self.region,
            target_resource: self.target_resource,
            target_resource_name: self.target_resource_name,
            outcome: self.outcome,
            error_message: self.error_message,
            metadata: self.metadata,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditRequestContext {
    actor_email: Option<String>,
    actor_email_verified: bool,
    client_ip: Option<String>,
    user_agent: Option<String>,
    tui_version: Option<String>,
}

impl AuditRequestContext {
    /// Request metadata is client/proxy supplied and untrusted. It is useful
    /// for forensic context only and must never drive authorization decisions.
    ///
    /// Query strings and filter patterns are intentionally recorded in full per
    /// audit requirements. Treat audit logs as sensitive because they can
    /// contain user-entered literals.
    pub fn from_headers_and_claims(headers: &HeaderMap, claims: &Claims) -> Self {
        Self {
            actor_email: non_empty(claims.email.as_str()),
            actor_email_verified: claims.email_verified,
            client_ip: forwarded_for_client_ip(headers),
            user_agent: header_string(headers, USER_AGENT.as_str()),
            tui_version: header_string(headers, headers::CANOPY_TUI_VERSION),
        }
    }

    pub fn metadata(&self, details: serde_json::Value) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        insert_opt(&mut map, "actor_email", self.actor_email.as_deref());
        map.insert(
            "actor_email_verified".into(),
            serde_json::Value::Bool(self.actor_email_verified),
        );
        insert_opt(&mut map, "client_ip", self.client_ip.as_deref());
        insert_opt(&mut map, "user_agent", self.user_agent.as_deref());
        insert_opt(&mut map, "tui_version", self.tui_version.as_deref());

        match details {
            serde_json::Value::Object(details) => {
                for (key, value) in details {
                    if !value.is_null() {
                        map.insert(key, value);
                    }
                }
            }
            serde_json::Value::Null => {}
            other => {
                map.insert("details".into(), other);
            }
        }

        serde_json::Value::Object(map)
    }
}

fn header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(non_empty)
}

fn forwarded_for_client_ip(headers: &HeaderMap) -> Option<String> {
    // Best effort only: in the current ALB/Fargate path this is proxy supplied,
    // not authenticated identity. Prefer the rightmost non-empty hop because
    // ALB appends to X-Forwarded-For; never use this value for enforcement.
    headers
        .get(X_FORWARDED_FOR)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .split(',')
                .map(str::trim)
                .rev()
                .find(|part| !part.is_empty())
                .map(str::to_string)
        })
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalized_optional_string(value: Option<&str>) -> Option<String> {
    value.and_then(non_empty)
}

fn insert_opt(
    map: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: Option<&str>,
) {
    if let Some(value) = value {
        map.insert(key.into(), serde_json::Value::String(value.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::dto::audit::{AuditAction, AuditOutcome};

    #[test]
    fn test_no_file_always_ok() {
        let svc = AuditService::new();
        assert!(svc.is_healthy());
        let result = svc
            .event("alice", AuditAction::Login, AuditOutcome::Success)
            .commit_or_fail();
        assert!(result.is_ok());
    }

    #[test]
    fn test_with_file_writes_and_healthy() {
        let dir = std::env::temp_dir().join(format!("canopy-audit-test-{}", std::process::id()));
        let path = dir.join("audit.jsonl");
        let path_str = path.to_str().unwrap();

        let svc = AuditService::with_file(path_str).unwrap();
        assert!(svc.is_healthy());

        let result = svc
            .event("bob", AuditAction::Ec2List, AuditOutcome::Success)
            .account(Some("123456789012"))
            .region(Some("us-east-1"))
            .commit_or_fail();
        assert!(result.is_ok());

        // Verify file has content
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("bob"));
        assert!(content.contains("ec2_list"));

        // Verify permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_with_file_records_failure_events() {
        let dir = std::env::temp_dir().join(format!("canopy-audit-fail-{}", std::process::id()));
        let path = dir.join("audit.jsonl");
        let path_str = path.to_str().unwrap();

        let svc = AuditService::with_file(path_str).unwrap();
        let result = svc
            .event("eve", AuditAction::Ec2Connect, AuditOutcome::Denied)
            .account(Some("111111111111"))
            .region(Some("eu-west-1"))
            .target(Some("i-0abc123"))
            .error(Some("Access denied by entitlements"))
            .commit_or_fail();
        assert!(result.is_ok());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("denied"));
        assert!(content.contains("Access denied by entitlements"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_multiple_sequential_writes() {
        let dir = std::env::temp_dir().join(format!("canopy-audit-multi-{}", std::process::id()));
        let path = dir.join("audit.jsonl");
        let path_str = path.to_str().unwrap();

        let svc = AuditService::with_file(path_str).unwrap();
        for i in 0..5 {
            svc.event(
                &format!("user-{}", i),
                AuditAction::Ec2List,
                AuditOutcome::Success,
            )
            .account(Some("111"))
            .commit_or_fail()
            .unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 5, "expected 5 JSONL lines");
        for (i, line) in lines.iter().enumerate() {
            assert!(line.contains(&format!("user-{}", i)));
            // Each line should be valid JSON
            let _: serde_json::Value = serde_json::from_str(line).unwrap();
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_all_audit_actions_serialize() {
        let dir = std::env::temp_dir().join(format!("canopy-audit-actions-{}", std::process::id()));
        let path = dir.join("audit.jsonl");
        let path_str = path.to_str().unwrap();

        let svc = AuditService::with_file(path_str).unwrap();
        let actions = [
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
        ];
        for action in &actions {
            svc.event("test", action.clone(), AuditOutcome::Success)
                .commit_or_fail()
                .unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), actions.len());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_event_contains_uuid_and_timestamp() {
        let dir = std::env::temp_dir().join(format!("canopy-audit-uuid-{}", std::process::id()));
        let path = dir.join("audit.jsonl");
        let path_str = path.to_str().unwrap();

        let svc = AuditService::with_file(path_str).unwrap();
        svc.event("alice", AuditAction::Login, AuditOutcome::Success)
            .commit_or_fail()
            .unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let event: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

        // event_id should be a valid UUID
        let event_id = event["event_id"].as_str().unwrap();
        assert!(
            uuid::Uuid::parse_str(event_id).is_ok(),
            "invalid UUID: {}",
            event_id
        );

        // timestamp should be RFC3339
        let ts = event["timestamp"].as_str().unwrap();
        assert!(
            chrono::DateTime::parse_from_rfc3339(ts).is_ok(),
            "invalid timestamp: {}",
            ts
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_with_file_invalid_path_returns_err() {
        let result = AuditService::with_file("/nonexistent/deeply/nested/path/audit.jsonl");
        assert!(result.is_err());
    }

    #[test]
    fn test_metadata_field_persisted() {
        let dir = std::env::temp_dir().join(format!("canopy-audit-meta-{}", std::process::id()));
        let path = dir.join("audit.jsonl");
        let path_str = path.to_str().unwrap();

        let svc = AuditService::with_file(path_str).unwrap();
        // log_event doesn't expose metadata directly, but we can verify the
        // event structure includes the field (as null when not set)
        svc.event("alice", AuditAction::Login, AuditOutcome::Success)
            .commit_or_fail()
            .unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let event: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        // metadata should be absent (serde skip_serializing_if = None)
        // or null — either is acceptable
        assert!(event.get("metadata").is_none() || event["metadata"].is_null());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_audit_builder_metadata_persists_object() {
        let dir =
            std::env::temp_dir().join(format!("canopy-audit-meta-object-{}", std::process::id()));
        let path = dir.join("audit.jsonl");
        let path_str = path.to_str().unwrap();

        let svc = AuditService::with_file(path_str).unwrap();
        svc.event(
            "alice-sub",
            AuditAction::CloudwatchSearch,
            AuditOutcome::Success,
        )
        .account(Some("111"))
        .region(Some("us-east-1"))
        .target(Some("/app/web"))
        .metadata(serde_json::json!({
            "actor_email": "alice@example.com",
            "filter_pattern": "ERROR"
        }))
        .commit_or_fail()
        .unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let event: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(event["metadata"]["actor_email"], "alice@example.com");
        assert_eq!(event["metadata"]["filter_pattern"], "ERROR");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_log_event_with_target_name_persists_top_level_field() {
        let dir =
            std::env::temp_dir().join(format!("canopy-audit-target-name-{}", std::process::id()));
        let path = dir.join("audit.jsonl");
        let path_str = path.to_str().unwrap();

        let svc = AuditService::with_file(path_str).unwrap();
        svc.event("alice-sub", AuditAction::Ec2Connect, AuditOutcome::Success)
            .account(Some("111"))
            .region(Some("us-east-1"))
            .target(Some("i-abc"))
            .target_name(Some("web-01"))
            .commit_or_fail()
            .unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let event: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(event["target_resource"], "i-abc");
        assert_eq!(event["target_resource_name"], "web-01");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_audit_builder_omits_empty_target_name() {
        let dir = std::env::temp_dir().join(format!(
            "canopy-audit-empty-target-name-{}",
            std::process::id()
        ));
        let path = dir.join("audit.jsonl");
        let path_str = path.to_str().unwrap();

        let svc = AuditService::with_file(path_str).unwrap();
        svc.event("alice-sub", AuditAction::Ec2Connect, AuditOutcome::Success)
            .target(Some("i-abc"))
            .target_name(Some(""))
            .commit_or_fail()
            .unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let event: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(event["target_resource"], "i-abc");
        assert!(event.get("target_resource_name").is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_audit_builder_omits_empty_target_but_keeps_target_name() {
        let dir =
            std::env::temp_dir().join(format!("canopy-audit-empty-target-{}", std::process::id()));
        let path = dir.join("audit.jsonl");
        let path_str = path.to_str().unwrap();

        let svc = AuditService::with_file(path_str).unwrap();
        svc.event("alice-sub", AuditAction::Ec2Connect, AuditOutcome::Success)
            .target(Some(""))
            .target_name(Some("web-01"))
            .commit_or_fail()
            .unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let event: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert!(event.get("target_resource").is_none());
        assert_eq!(event["target_resource_name"], "web-01");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_audit_builder_optional_metadata_none_overrides_metadata() {
        let dir = std::env::temp_dir().join(format!(
            "canopy-audit-metadata-override-{}",
            std::process::id()
        ));
        let path = dir.join("audit.jsonl");
        let path_str = path.to_str().unwrap();

        let svc = AuditService::with_file(path_str).unwrap();
        svc.event("alice-sub", AuditAction::Login, AuditOutcome::Success)
            .metadata(serde_json::json!({"actor_email": "alice@example.com"}))
            .optional_metadata(None)
            .commit_or_fail()
            .unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let event: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert!(event.get("metadata").is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_audit_request_context_extracts_headers_and_email() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "203.0.113.10, 10.0.0.1".parse().unwrap());
        headers.insert("User-Agent", "canopy-tui/0.1.0".parse().unwrap());
        headers.insert("X-Canopy-TUI-Version", "0.1.0".parse().unwrap());
        let claims = Claims {
            sub: "sub-123".into(),
            email: "alice@example.com".into(),
            name: "Alice".into(),
            groups: vec![],
            exp: 1,
            iat: 0,
            jti: "test-token".into(),
            email_verified: true,
        };

        let ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);
        let metadata = ctx.metadata(serde_json::json!({
            "query_string": "fields @timestamp | limit 20",
            "null_field": null
        }));

        assert_eq!(metadata["actor_email"], "alice@example.com");
        assert_eq!(metadata["actor_email_verified"], true);
        assert_eq!(metadata["client_ip"], "10.0.0.1");
        assert_eq!(metadata["user_agent"], "canopy-tui/0.1.0");
        assert_eq!(metadata["tui_version"], "0.1.0");
        assert_eq!(metadata["query_string"], "fields @timestamp | limit 20");
        assert!(metadata.get("null_field").is_none());
    }

    #[test]
    fn test_audit_request_context_uses_rightmost_forwarded_for_hop() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Forwarded-For",
            "198.51.100.7, 203.0.113.10, 10.0.0.1".parse().unwrap(),
        );
        let claims = Claims {
            sub: "sub-123".into(),
            email: "alice@example.com".into(),
            name: "Alice".into(),
            groups: vec![],
            exp: 1,
            iat: 0,
            jti: "test-token".into(),
            email_verified: true,
        };

        let ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);
        let metadata = ctx.metadata(serde_json::json!({}));

        assert_eq!(metadata["client_ip"], "10.0.0.1");
    }

    #[test]
    fn test_audit_request_context_preserves_ipv6_forwarded_for_hop() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Forwarded-For",
            "2001:db8::1, [2001:db8::2]:443".parse().unwrap(),
        );
        let claims = Claims {
            sub: "sub-123".into(),
            email: "alice@example.com".into(),
            name: "Alice".into(),
            groups: vec![],
            exp: 1,
            iat: 0,
            jti: "test-token".into(),
            email_verified: true,
        };

        let ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);
        let metadata = ctx.metadata(serde_json::json!({}));

        assert_eq!(metadata["client_ip"], "[2001:db8::2]:443");
    }

    #[test]
    fn test_audit_request_context_omits_missing_or_empty_forwarded_for() {
        let claims = Claims {
            sub: "sub-123".into(),
            email: "alice@example.com".into(),
            name: "Alice".into(),
            groups: vec![],
            exp: 1,
            iat: 0,
            jti: "test-token".into(),
            email_verified: false,
        };

        let headers = HeaderMap::new();
        let ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);
        let metadata = ctx.metadata(serde_json::json!({}));
        assert!(metadata.get("client_ip").is_none());

        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", " , ".parse().unwrap());
        let ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);
        let metadata = ctx.metadata(serde_json::json!({}));

        assert!(metadata.get("client_ip").is_none());
        assert_eq!(metadata["actor_email_verified"], false);
    }

    #[test]
    fn test_is_healthy_true_without_writer() {
        let svc = AuditService::new();
        assert!(svc.is_healthy());
    }

    #[test]
    fn audit_s3_key_partitions_by_utc_date_and_normalizes_prefix() {
        let event = AuditEvent {
            event_id: "evt-123".into(),
            timestamp: "2026-05-27T03:04:05.678Z".into(),
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

        let prefix = normalized_s3_prefix("/prod/audit/");
        assert_eq!(prefix, "prod/audit/");
        assert_eq!(
            audit_s3_key(&prefix, &event),
            "prod/audit/2026/05/27/20260527T030405.678Z-evt-123.json"
        );
    }

    #[test]
    fn test_sink_failed_false_after_successful_write() {
        let dir = std::env::temp_dir().join(format!("canopy-audit-sink-{}", std::process::id()));
        let path = dir.join("audit.jsonl");
        let path_str = path.to_str().unwrap();

        let svc = AuditService::with_file(path_str).unwrap();
        svc.event("test", AuditAction::Login, AuditOutcome::Success)
            .commit_or_fail()
            .unwrap();
        assert!(
            !svc.sink_failed.load(std::sync::atomic::Ordering::Relaxed),
            "sink_failed should be false after successful write"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
