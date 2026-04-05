use shared::dto::audit::{AuditAction, AuditEvent, AuditOutcome};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Mutex;
use uuid::Uuid;

/// Audit service — logs all user actions for compliance.
/// When durable logging is configured, `log_event` returns Err on write
/// failure so callers can fail-closed on privileged operations.
pub struct AuditService {
    writer: Option<Mutex<std::io::BufWriter<std::fs::File>>>,
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
            sink_failed: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Log an audit event. Returns `Err` if durable audit is configured
    /// and the write fails — callers MUST propagate this to block the
    /// response when the audit trail cannot be maintained.
    #[allow(clippy::too_many_arguments)]
    pub fn log_event(
        &self,
        actor: &str,
        action: AuditAction,
        outcome: AuditOutcome,
        account_id: Option<&str>,
        region: Option<&str>,
        target_resource: Option<&str>,
        error_message: Option<&str>,
    ) -> Result<(), &'static str> {
        let event = AuditEvent {
            event_id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            actor: actor.to_string(),
            action,
            account_id: account_id.map(String::from),
            region: region.map(String::from),
            target_resource: target_resource.map(String::from),
            outcome,
            error_message: error_message.map(String::from),
            metadata: None,
        };

        // Always emit structured tracing
        tracing::info!(
            audit_event = %serde_json::to_string(&event).unwrap_or_default(),
            actor = %event.actor,
            action = ?event.action,
            outcome = ?event.outcome,
            "audit"
        );

        // Persist to durable log file if configured
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
        Ok(())
    }

    /// Check whether the audit sink can likely accept writes.
    /// This is optimistic: a previously failed sink is allowed to retry
    /// so transient I/O errors (disk full, permission blip) can recover
    /// without restarting the process. The actual write in `log_event()`
    /// is still fail-closed — callers must propagate its errors.
    pub fn is_healthy(&self) -> bool {
        match &self.writer {
            None => true,
            Some(mutex) => !mutex.is_poisoned(),
        }
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
        let result = svc.log_event(
            "alice",
            AuditAction::Login,
            AuditOutcome::Success,
            None,
            None,
            None,
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_with_file_writes_and_healthy() {
        let dir = std::env::temp_dir().join(format!("canopy-audit-test-{}", std::process::id()));
        let path = dir.join("audit.jsonl");
        let path_str = path.to_str().unwrap();

        let svc = AuditService::with_file(path_str).unwrap();
        assert!(svc.is_healthy());

        let result = svc.log_event(
            "bob",
            AuditAction::Ec2List,
            AuditOutcome::Success,
            Some("123456789012"),
            Some("us-east-1"),
            None,
            None,
        );
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
        let result = svc.log_event(
            "eve",
            AuditAction::Ec2Connect,
            AuditOutcome::Denied,
            Some("111111111111"),
            Some("eu-west-1"),
            Some("i-0abc123"),
            Some("Access denied by entitlements"),
        );
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
            svc.log_event(
                &format!("user-{}", i),
                AuditAction::Ec2List,
                AuditOutcome::Success,
                Some("111"),
                None,
                None,
                None,
            )
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
            AuditAction::CloudwatchSearch,
            AuditAction::CloudwatchInsightsQuery,
            AuditAction::CloudwatchLiveTailStart,
            AuditAction::CloudwatchLiveTailStop,
            AuditAction::LogGroupList,
            AuditAction::EntitlementsView,
        ];
        for action in &actions {
            svc.log_event(
                "test",
                action.clone(),
                AuditOutcome::Success,
                None,
                None,
                None,
                None,
            )
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
        svc.log_event(
            "alice",
            AuditAction::Login,
            AuditOutcome::Success,
            None,
            None,
            None,
            None,
        )
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
        svc.log_event(
            "alice",
            AuditAction::Login,
            AuditOutcome::Success,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let event: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        // metadata should be absent (serde skip_serializing_if = None)
        // or null — either is acceptable
        assert!(event.get("metadata").is_none() || event["metadata"].is_null());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_is_healthy_true_without_writer() {
        let svc = AuditService::new();
        assert!(svc.is_healthy());
    }

    #[test]
    fn test_sink_failed_false_after_successful_write() {
        let dir = std::env::temp_dir().join(format!("canopy-audit-sink-{}", std::process::id()));
        let path = dir.join("audit.jsonl");
        let path_str = path.to_str().unwrap();

        let svc = AuditService::with_file(path_str).unwrap();
        svc.log_event(
            "test",
            AuditAction::Login,
            AuditOutcome::Success,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(
            !svc.sink_failed.load(std::sync::atomic::Ordering::Relaxed),
            "sink_failed should be false after successful write"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
