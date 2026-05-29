use crate::services::McpSessionRecord;
use async_trait::async_trait;
use aws_sdk_dynamodb::operation::update_item::UpdateItemError;
use aws_sdk_dynamodb::types::AttributeValue;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, thiserror::Error)]
pub enum McpSessionStoreError {
    #[error("MCP session store backend error: {0}")]
    Backend(String),
    #[error("MCP session store record is invalid: {0}")]
    InvalidRecord(String),
}

#[async_trait]
pub trait McpSessionStore: Send + Sync {
    async fn sweep_expired(&self, now: DateTime<Utc>) -> Result<(), McpSessionStoreError>;

    async fn create_session(
        &self,
        session_id: String,
        record: McpSessionRecord,
    ) -> Result<(), McpSessionStoreError>;

    async fn get_session(
        &self,
        session_id: &str,
    ) -> Result<Option<McpSessionRecord>, McpSessionStoreError>;

    async fn mark_guidance_delivered(
        &self,
        session_id: &str,
        actor: &str,
        local_secret_generation: &str,
        guidance_key: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, McpSessionStoreError>;
}

#[derive(Debug, Default)]
pub struct MemoryMcpSessionStore {
    sessions: DashMap<String, McpSessionRecord>,
}

impl MemoryMcpSessionStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl McpSessionStore for MemoryMcpSessionStore {
    async fn sweep_expired(&self, now: DateTime<Utc>) -> Result<(), McpSessionStoreError> {
        self.sessions.retain(|_, record| record.expires_at >= now);
        Ok(())
    }

    async fn create_session(
        &self,
        session_id: String,
        record: McpSessionRecord,
    ) -> Result<(), McpSessionStoreError> {
        // Match the DynamoDB store's `attribute_not_exists(session_id)`
        // semantics: registration always mints a fresh UUID, so an existing id
        // is an anomaly and must not silently overwrite a live session (the
        // previous `insert` was last-write-wins, diverging from DynamoDB).
        use dashmap::mapref::entry::Entry;
        match self.sessions.entry(session_id) {
            Entry::Occupied(existing) => Err(McpSessionStoreError::Backend(format!(
                "session_id already exists: {}",
                existing.key()
            ))),
            Entry::Vacant(slot) => {
                slot.insert(record);
                Ok(())
            }
        }
    }

    async fn get_session(
        &self,
        session_id: &str,
    ) -> Result<Option<McpSessionRecord>, McpSessionStoreError> {
        Ok(self.sessions.get(session_id).map(|record| record.clone()))
    }

    async fn mark_guidance_delivered(
        &self,
        session_id: &str,
        actor: &str,
        local_secret_generation: &str,
        guidance_key: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, McpSessionStoreError> {
        let Some(mut record) = self.sessions.get_mut(session_id) else {
            return Ok(false);
        };
        if record.actor != actor
            || record.local_secret_generation != local_secret_generation
            || record.is_expired_at(now)
        {
            return Ok(false);
        }
        record.guidance_delivered.insert(guidance_key.to_string());
        record.updated_at = now;
        Ok(true)
    }
}

/// DynamoDB TTL attribute (session expiry as epoch seconds). MUST stay in sync
/// with `ttl.attribute_name` in infra/mcp_sessions.tf — if they diverge,
/// DynamoDB TTL silently never fires and expired sessions accumulate forever.
/// The same attribute also backs the `mark_guidance_delivered` conditional
/// expiry check, so both uses share this single definition.
const TTL_ATTRIBUTE: &str = "expires_at_epoch";

#[derive(Debug, Clone)]
pub struct DynamoMcpSessionStore {
    client: aws_sdk_dynamodb::Client,
    table_name: String,
}

impl DynamoMcpSessionStore {
    pub fn new(client: aws_sdk_dynamodb::Client, table_name: impl Into<String>) -> Self {
        Self {
            client,
            table_name: table_name.into(),
        }
    }

    fn record_to_item(
        session_id: String,
        record: McpSessionRecord,
    ) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::new();
        item.insert("session_id".into(), AttributeValue::S(session_id));
        item.insert("actor".into(), AttributeValue::S(record.actor));
        item.insert("actor_email".into(), AttributeValue::S(record.actor_email));
        item.insert(
            "local_secret_generation".into(),
            AttributeValue::S(record.local_secret_generation),
        );
        item.insert(
            "forwarding_key".into(),
            AttributeValue::S(record.forwarding_key),
        );
        item.insert(
            "protocol_version".into(),
            AttributeValue::S(record.protocol_version),
        );
        item.insert("client_name".into(), AttributeValue::S(record.client_name));
        item.insert(
            "client_version".into(),
            AttributeValue::S(record.client_version),
        );
        item.insert(
            "product_phase".into(),
            AttributeValue::S(record.product_phase),
        );
        if !record.guidance_delivered.is_empty() {
            item.insert(
                "guidance_delivered".into(),
                AttributeValue::Ss(record.guidance_delivered.into_iter().collect()),
            );
        }
        item.insert(
            "expires_at".into(),
            AttributeValue::S(record.expires_at.to_rfc3339()),
        );
        item.insert(
            TTL_ATTRIBUTE.into(),
            AttributeValue::N(record.expires_at.timestamp().to_string()),
        );
        item.insert(
            "created_at".into(),
            AttributeValue::S(record.created_at.to_rfc3339()),
        );
        item.insert(
            "updated_at".into(),
            AttributeValue::S(record.updated_at.to_rfc3339()),
        );
        item
    }

    fn item_to_record(
        item: &HashMap<String, AttributeValue>,
    ) -> Result<McpSessionRecord, McpSessionStoreError> {
        let guidance_delivered = match item.get("guidance_delivered") {
            Some(AttributeValue::Ss(values)) => values.iter().cloned().collect(),
            None => BTreeSet::new(),
            _ => {
                return Err(McpSessionStoreError::InvalidRecord(
                    "guidance_delivered must be a string set".into(),
                ))
            }
        };
        Ok(McpSessionRecord {
            actor: required_s(item, "actor")?,
            actor_email: required_s_allow_empty(item, "actor_email")?,
            local_secret_generation: required_s(item, "local_secret_generation")?,
            forwarding_key: required_s(item, "forwarding_key")?,
            protocol_version: required_s(item, "protocol_version")?,
            client_name: required_s(item, "client_name")?,
            client_version: required_s(item, "client_version")?,
            product_phase: required_s(item, "product_phase")?,
            guidance_delivered,
            expires_at: required_time(item, "expires_at")?,
            created_at: required_time(item, "created_at")?,
            updated_at: required_time(item, "updated_at")?,
        })
    }
}

fn required_s_allow_empty(
    item: &HashMap<String, AttributeValue>,
    key: &str,
) -> Result<String, McpSessionStoreError> {
    match item.get(key) {
        Some(AttributeValue::S(value)) => Ok(value.clone()),
        _ => Err(McpSessionStoreError::InvalidRecord(format!(
            "{key} must be a string"
        ))),
    }
}

fn required_s(
    item: &HashMap<String, AttributeValue>,
    key: &str,
) -> Result<String, McpSessionStoreError> {
    match item.get(key) {
        Some(AttributeValue::S(value)) if !value.is_empty() => Ok(value.clone()),
        _ => Err(McpSessionStoreError::InvalidRecord(format!(
            "{key} must be a non-empty string"
        ))),
    }
}

fn required_time(
    item: &HashMap<String, AttributeValue>,
    key: &str,
) -> Result<DateTime<Utc>, McpSessionStoreError> {
    DateTime::parse_from_rfc3339(&required_s(item, key)?)
        .map(|ts| ts.with_timezone(&Utc))
        .map_err(|_| McpSessionStoreError::InvalidRecord(format!("{key} must be RFC3339")))
}

/// Log a DynamoDB store failure and wrap it as a `Backend` error. The route
/// layer maps every store error to a generic 503 and drops the detail, and
/// store errors are deliberately not written as `Denied` audit events — so
/// without this log an outage of the authorization-gating store (throttling,
/// IAM denial, table missing) would be invisible server-side.
fn dynamo_backend_error(operation: &str, err: impl std::fmt::Debug) -> McpSessionStoreError {
    tracing::warn!(
        operation = operation,
        error = ?err,
        "DynamoDB MCP session store operation failed"
    );
    McpSessionStoreError::Backend(format!("{err:?}"))
}

#[async_trait]
impl McpSessionStore for DynamoMcpSessionStore {
    async fn sweep_expired(&self, _now: DateTime<Utc>) -> Result<(), McpSessionStoreError> {
        // DynamoDB TTL performs cleanup asynchronously. Authorization still
        // checks expires_at on every read, so TTL lag cannot extend access.
        Ok(())
    }

    async fn create_session(
        &self,
        session_id: String,
        record: McpSessionRecord,
    ) -> Result<(), McpSessionStoreError> {
        self.client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(Self::record_to_item(session_id, record)))
            .condition_expression("attribute_not_exists(session_id)")
            .send()
            .await
            .map_err(|err| dynamo_backend_error("create_session", err))?;
        Ok(())
    }

    async fn get_session(
        &self,
        session_id: &str,
    ) -> Result<Option<McpSessionRecord>, McpSessionStoreError> {
        let output = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key("session_id", AttributeValue::S(session_id.to_string()))
            .consistent_read(true)
            .send()
            .await
            .map_err(|err| dynamo_backend_error("get_session", err))?;
        output.item().map(Self::item_to_record).transpose()
    }

    async fn mark_guidance_delivered(
        &self,
        session_id: &str,
        actor: &str,
        local_secret_generation: &str,
        guidance_key: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, McpSessionStoreError> {
        let result = self
            .client
            .update_item()
            .table_name(&self.table_name)
            .key("session_id", AttributeValue::S(session_id.to_string()))
            .update_expression("SET updated_at = :updated_at ADD guidance_delivered :guidance")
            .condition_expression(format!(
                "actor = :actor AND local_secret_generation = :generation AND {TTL_ATTRIBUTE} >= :now_epoch"
            ))
            .expression_attribute_values(":updated_at", AttributeValue::S(now.to_rfc3339()))
            .expression_attribute_values(":guidance", AttributeValue::Ss(vec![guidance_key.to_string()]))
            .expression_attribute_values(":actor", AttributeValue::S(actor.to_string()))
            .expression_attribute_values(
                ":generation",
                AttributeValue::S(local_secret_generation.to_string()),
            )
            .expression_attribute_values(":now_epoch", AttributeValue::N(now.timestamp().to_string()))
            .send()
            .await;

        match result {
            Ok(_) => Ok(true),
            // A conditional-check failure means the session was concurrently
            // removed/expired or the actor/generation no longer match — this is
            // the fail-closed `Ok(false)` path. Detect it via the typed service
            // error: `SdkError`'s `Display` only renders the literal "service
            // error", so the previous `err.to_string().contains(..)` never
            // matched and turned every benign conflict into a backend error
            // (503 instead of 409). This mirrors the typed-error convention
            // already used in routes/mcp.rs and routes/cloudwatch.rs.
            Err(err)
                if err
                    .as_service_error()
                    .is_some_and(UpdateItemError::is_conditional_check_failed_exception) =>
            {
                Ok(false)
            }
            Err(err) => Err(dynamo_backend_error("mark_guidance_delivered", err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn record(now: DateTime<Utc>) -> McpSessionRecord {
        McpSessionRecord {
            actor: "actor-1".into(),
            actor_email: "actor@example.com".into(),
            local_secret_generation: "lsg_1".into(),
            forwarding_key: "forwarding".into(),
            protocol_version: "2025-06-18".into(),
            client_name: "test".into(),
            client_version: "0.1.0".into(),
            product_phase: "phase_3_data_tools".into(),
            guidance_delivered: BTreeSet::new(),
            expires_at: now + Duration::hours(8),
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn memory_store_create_get_update_and_sweep() {
        let store = MemoryMcpSessionStore::new();
        let now = Utc::now();
        store
            .create_session("mcp_test".into(), record(now))
            .await
            .unwrap();
        assert!(store.get_session("mcp_test").await.unwrap().is_some());

        let updated = store
            .mark_guidance_delivered("mcp_test", "actor-1", "lsg_1", "security@v1", now)
            .await
            .unwrap();
        assert!(updated);
        let session = store.get_session("mcp_test").await.unwrap().unwrap();
        assert!(session.guidance_delivered.contains("security@v1"));

        store.sweep_expired(now + Duration::hours(9)).await.unwrap();
        assert!(store.get_session("mcp_test").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn memory_store_mark_guidance_fails_closed_on_mismatch_or_expiry() {
        let store = MemoryMcpSessionStore::new();
        let now = Utc::now();
        store
            .create_session("mcp_test".into(), record(now))
            .await
            .unwrap();

        assert!(!store
            .mark_guidance_delivered("mcp_test", "other", "lsg_1", "security@v1", now)
            .await
            .unwrap());
        assert!(!store
            .mark_guidance_delivered("mcp_test", "actor-1", "bad", "security@v1", now)
            .await
            .unwrap());
        assert!(!store
            .mark_guidance_delivered(
                "mcp_test",
                "actor-1",
                "lsg_1",
                "security@v1",
                now + Duration::hours(9),
            )
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn memory_store_create_rejects_duplicate_session_id() {
        // create_session must not overwrite an existing id — this matches the
        // DynamoDB store's `attribute_not_exists(session_id)` guard. (The old
        // `insert` was last-write-wins, which diverged from DynamoDB and could
        // silently clobber a live session if an id ever recurred.)
        let store = MemoryMcpSessionStore::new();
        let now = Utc::now();
        store
            .create_session("mcp_dup".into(), record(now))
            .await
            .unwrap();
        assert!(
            store
                .create_session("mcp_dup".into(), record(now))
                .await
                .is_err(),
            "a duplicate session_id must be rejected, not silently overwritten"
        );
    }

    #[test]
    fn dynamo_item_roundtrip_preserves_session_fields() {
        let now = Utc::now();
        let mut original = record(now);
        original.guidance_delivered.insert("security@v1".into());
        let item = DynamoMcpSessionStore::record_to_item("mcp_test".into(), original.clone());
        let parsed = DynamoMcpSessionStore::item_to_record(&item).unwrap();
        // Assert EVERY field round-trips, so a mistyped attribute key or a
        // dropped field in record_to_item/item_to_record is caught — such bugs
        // only surface on the DynamoDB backend, never in the memory store.
        assert_eq!(parsed.actor, original.actor);
        assert_eq!(parsed.actor_email, original.actor_email);
        assert_eq!(
            parsed.local_secret_generation,
            original.local_secret_generation
        );
        assert_eq!(parsed.forwarding_key, original.forwarding_key);
        assert_eq!(parsed.protocol_version, original.protocol_version);
        assert_eq!(parsed.client_name, original.client_name);
        assert_eq!(parsed.client_version, original.client_version);
        assert_eq!(parsed.product_phase, original.product_phase);
        assert_eq!(parsed.guidance_delivered, original.guidance_delivered);
        assert_eq!(
            parsed.expires_at.timestamp(),
            original.expires_at.timestamp()
        );
        assert_eq!(
            parsed.created_at.timestamp(),
            original.created_at.timestamp()
        );
        assert_eq!(
            parsed.updated_at.timestamp(),
            original.updated_at.timestamp()
        );
    }

    #[test]
    fn dynamo_item_rejects_missing_required_fields() {
        let item = HashMap::new();
        let err = DynamoMcpSessionStore::item_to_record(&item)
            .unwrap_err()
            .to_string();
        assert!(err.contains("actor"));
    }

    #[test]
    fn dynamo_item_with_empty_required_field_fails_to_decode() {
        // Round-trip asymmetry: record_to_item writes an empty string without
        // complaint, but item_to_record (required_s) rejects it. This is the
        // reason register_session must reject empty client-supplied fields up
        // front — otherwise a session would persist to DynamoDB yet be
        // permanently undecodable on every subsequent read (a 503 loop until
        // TTL), while the in-memory store would keep working. Guarding at
        // registration keeps both backends behaving identically.
        let now = Utc::now();
        let mut original = record(now);
        original.client_name = String::new();
        let item = DynamoMcpSessionStore::record_to_item("mcp_test".into(), original);
        let err = DynamoMcpSessionStore::item_to_record(&item)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("client_name"),
            "empty client_name must fail to decode, got: {err}"
        );
    }
}
