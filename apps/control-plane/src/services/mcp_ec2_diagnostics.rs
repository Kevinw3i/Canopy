use async_trait::async_trait;
use aws_sdk_dynamodb::operation::update_item::UpdateItemError;
use aws_sdk_dynamodb::types::AttributeValue;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use shared::dto::mcp::{McpEc2DiagnosticCommandStatus, McpEc2DiagnosticCommandType};
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum McpEc2DiagnosticCommandStoreError {
    #[error("MCP EC2 diagnostic command store backend error: {0}")]
    Backend(String),
    #[error("MCP EC2 diagnostic command store record is invalid: {0}")]
    InvalidRecord(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpEc2DiagnosticCommandRecord {
    pub actor: String,
    pub actor_email: String,
    pub mcp_session_id: String,
    pub local_secret_generation: String,
    pub instance_id: String,
    pub account_id: String,
    pub region: String,
    pub command_type: McpEc2DiagnosticCommandType,
    pub allowlist_rule_id: String,
    pub command_scope_id: String,
    pub status: McpEc2DiagnosticCommandStatus,
    pub aws_ssm_command_id: Option<String>,
    pub submitted_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub output_byte_count: u64,
    pub dropped_byte_count: u64,
    pub output_sequence_start: u64,
    pub output_sequence_end: u64,
    pub exit_status: Option<i32>,
    pub truncated: bool,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl McpEc2DiagnosticCommandRecord {
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.timestamp() < now.timestamp()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpEc2DiagnosticCommandCompletion {
    pub status: McpEc2DiagnosticCommandStatus,
    pub completed_at: DateTime<Utc>,
    pub output_byte_count: u64,
    pub dropped_byte_count: u64,
    pub output_sequence_start: u64,
    pub output_sequence_end: u64,
    pub exit_status: Option<i32>,
    pub truncated: bool,
}

impl McpEc2DiagnosticCommandCompletion {
    fn validate(&self) -> Result<(), McpEc2DiagnosticCommandStoreError> {
        match self.status {
            McpEc2DiagnosticCommandStatus::Succeeded
            | McpEc2DiagnosticCommandStatus::Failed
            | McpEc2DiagnosticCommandStatus::Expired => Ok(()),
            McpEc2DiagnosticCommandStatus::Queued | McpEc2DiagnosticCommandStatus::Running => {
                Err(McpEc2DiagnosticCommandStoreError::InvalidRecord(
                    "completion status must be terminal".into(),
                ))
            }
        }
    }
}

#[async_trait]
pub trait McpEc2DiagnosticCommandStore: Send + Sync {
    async fn sweep_expired(
        &self,
        now: DateTime<Utc>,
    ) -> Result<(), McpEc2DiagnosticCommandStoreError>;

    async fn create_command(
        &self,
        command_id: String,
        record: McpEc2DiagnosticCommandRecord,
    ) -> Result<(), McpEc2DiagnosticCommandStoreError>;

    async fn get_command(
        &self,
        command_id: &str,
    ) -> Result<Option<McpEc2DiagnosticCommandRecord>, McpEc2DiagnosticCommandStoreError>;

    async fn get_owned_command(
        &self,
        command_id: &str,
        actor: &str,
        mcp_session_id: &str,
        local_secret_generation: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<McpEc2DiagnosticCommandRecord>, McpEc2DiagnosticCommandStoreError>;

    async fn mark_dispatched(
        &self,
        command_id: &str,
        actor: &str,
        mcp_session_id: &str,
        local_secret_generation: &str,
        aws_ssm_command_id: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, McpEc2DiagnosticCommandStoreError>;

    async fn mark_terminal(
        &self,
        command_id: &str,
        actor: &str,
        mcp_session_id: &str,
        local_secret_generation: &str,
        completion: McpEc2DiagnosticCommandCompletion,
        now: DateTime<Utc>,
    ) -> Result<bool, McpEc2DiagnosticCommandStoreError>;
}

#[derive(Debug, Default)]
pub struct MemoryMcpEc2DiagnosticCommandStore {
    commands: DashMap<String, McpEc2DiagnosticCommandRecord>,
}

impl MemoryMcpEc2DiagnosticCommandStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl McpEc2DiagnosticCommandStore for MemoryMcpEc2DiagnosticCommandStore {
    async fn sweep_expired(
        &self,
        now: DateTime<Utc>,
    ) -> Result<(), McpEc2DiagnosticCommandStoreError> {
        self.commands.retain(|_, record| record.expires_at >= now);
        Ok(())
    }

    async fn create_command(
        &self,
        command_id: String,
        record: McpEc2DiagnosticCommandRecord,
    ) -> Result<(), McpEc2DiagnosticCommandStoreError> {
        use dashmap::mapref::entry::Entry;
        match self.commands.entry(command_id) {
            Entry::Occupied(existing) => Err(McpEc2DiagnosticCommandStoreError::Backend(format!(
                "mcp_ec2_command_id already exists: {}",
                existing.key()
            ))),
            Entry::Vacant(slot) => {
                slot.insert(record);
                Ok(())
            }
        }
    }

    async fn get_command(
        &self,
        command_id: &str,
    ) -> Result<Option<McpEc2DiagnosticCommandRecord>, McpEc2DiagnosticCommandStoreError> {
        Ok(self.commands.get(command_id).map(|record| record.clone()))
    }

    async fn get_owned_command(
        &self,
        command_id: &str,
        actor: &str,
        mcp_session_id: &str,
        local_secret_generation: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<McpEc2DiagnosticCommandRecord>, McpEc2DiagnosticCommandStoreError> {
        let Some(record) = self.commands.get(command_id).map(|record| record.clone()) else {
            return Ok(None);
        };
        if record.actor != actor
            || record.mcp_session_id != mcp_session_id
            || record.local_secret_generation != local_secret_generation
            || record.is_expired_at(now)
        {
            return Ok(None);
        }
        Ok(Some(record))
    }

    async fn mark_dispatched(
        &self,
        command_id: &str,
        actor: &str,
        mcp_session_id: &str,
        local_secret_generation: &str,
        aws_ssm_command_id: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, McpEc2DiagnosticCommandStoreError> {
        let Some(mut record) = self.commands.get_mut(command_id) else {
            return Ok(false);
        };
        if record.actor != actor
            || record.mcp_session_id != mcp_session_id
            || record.local_secret_generation != local_secret_generation
            || record.is_expired_at(now)
            || record.status != McpEc2DiagnosticCommandStatus::Queued
            || record.aws_ssm_command_id.is_some()
        {
            return Ok(false);
        }
        record.aws_ssm_command_id = Some(aws_ssm_command_id.to_string());
        record.status = McpEc2DiagnosticCommandStatus::Running;
        record.updated_at = now;
        Ok(true)
    }

    async fn mark_terminal(
        &self,
        command_id: &str,
        actor: &str,
        mcp_session_id: &str,
        local_secret_generation: &str,
        completion: McpEc2DiagnosticCommandCompletion,
        now: DateTime<Utc>,
    ) -> Result<bool, McpEc2DiagnosticCommandStoreError> {
        completion.validate()?;
        let Some(mut record) = self.commands.get_mut(command_id) else {
            return Ok(false);
        };
        if record.actor != actor
            || record.mcp_session_id != mcp_session_id
            || record.local_secret_generation != local_secret_generation
            || record.is_expired_at(now)
            || record.status != McpEc2DiagnosticCommandStatus::Running
            || record.aws_ssm_command_id.is_none()
            || record.completed_at.is_some()
        {
            return Ok(false);
        }
        record.status = completion.status;
        record.completed_at = Some(completion.completed_at);
        record.output_byte_count = completion.output_byte_count;
        record.dropped_byte_count = completion.dropped_byte_count;
        record.output_sequence_start = completion.output_sequence_start;
        record.output_sequence_end = completion.output_sequence_end;
        record.exit_status = completion.exit_status;
        record.truncated = completion.truncated;
        record.updated_at = now;
        Ok(true)
    }
}

/// DynamoDB TTL attribute (command record expiry as epoch seconds). MUST stay
/// in sync with `ttl.attribute_name` in
/// infra/mcp_ec2_diagnostic_commands.tf.
const TTL_ATTRIBUTE: &str = "expires_at_epoch";

#[derive(Debug, Clone)]
pub struct DynamoMcpEc2DiagnosticCommandStore {
    client: aws_sdk_dynamodb::Client,
    table_name: String,
}

impl DynamoMcpEc2DiagnosticCommandStore {
    pub fn new(client: aws_sdk_dynamodb::Client, table_name: impl Into<String>) -> Self {
        Self {
            client,
            table_name: table_name.into(),
        }
    }

    fn record_to_item(
        command_id: String,
        record: McpEc2DiagnosticCommandRecord,
    ) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::new();
        item.insert("mcp_ec2_command_id".into(), AttributeValue::S(command_id));
        item.insert("actor".into(), AttributeValue::S(record.actor));
        item.insert("actor_email".into(), AttributeValue::S(record.actor_email));
        item.insert(
            "mcp_session_id".into(),
            AttributeValue::S(record.mcp_session_id),
        );
        item.insert(
            "local_secret_generation".into(),
            AttributeValue::S(record.local_secret_generation),
        );
        item.insert("instance_id".into(), AttributeValue::S(record.instance_id));
        item.insert("account_id".into(), AttributeValue::S(record.account_id));
        item.insert("region".into(), AttributeValue::S(record.region));
        item.insert(
            "command_type".into(),
            AttributeValue::S(command_type_to_s(&record.command_type).into()),
        );
        item.insert(
            "allowlist_rule_id".into(),
            AttributeValue::S(record.allowlist_rule_id),
        );
        item.insert(
            "command_scope_id".into(),
            AttributeValue::S(record.command_scope_id),
        );
        item.insert(
            "status".into(),
            AttributeValue::S(status_to_s(&record.status).into()),
        );
        if let Some(value) = record.aws_ssm_command_id {
            item.insert("aws_ssm_command_id".into(), AttributeValue::S(value));
        }
        item.insert(
            "submitted_at".into(),
            AttributeValue::S(record.submitted_at.to_rfc3339()),
        );
        if let Some(value) = record.completed_at {
            item.insert("completed_at".into(), AttributeValue::S(value.to_rfc3339()));
        }
        item.insert(
            "output_byte_count".into(),
            AttributeValue::N(record.output_byte_count.to_string()),
        );
        item.insert(
            "dropped_byte_count".into(),
            AttributeValue::N(record.dropped_byte_count.to_string()),
        );
        item.insert(
            "output_sequence_start".into(),
            AttributeValue::N(record.output_sequence_start.to_string()),
        );
        item.insert(
            "output_sequence_end".into(),
            AttributeValue::N(record.output_sequence_end.to_string()),
        );
        if let Some(value) = record.exit_status {
            item.insert("exit_status".into(), AttributeValue::N(value.to_string()));
        }
        item.insert("truncated".into(), AttributeValue::Bool(record.truncated));
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
    ) -> Result<McpEc2DiagnosticCommandRecord, McpEc2DiagnosticCommandStoreError> {
        Ok(McpEc2DiagnosticCommandRecord {
            actor: required_s(item, "actor")?,
            actor_email: required_s_allow_empty(item, "actor_email")?,
            mcp_session_id: required_s(item, "mcp_session_id")?,
            local_secret_generation: required_s(item, "local_secret_generation")?,
            instance_id: required_s(item, "instance_id")?,
            account_id: required_s(item, "account_id")?,
            region: required_s(item, "region")?,
            command_type: command_type_from_s(&required_s(item, "command_type")?)?,
            allowlist_rule_id: required_s(item, "allowlist_rule_id")?,
            command_scope_id: required_s(item, "command_scope_id")?,
            status: status_from_s(&required_s(item, "status")?)?,
            aws_ssm_command_id: optional_s(item, "aws_ssm_command_id")?,
            submitted_at: required_time(item, "submitted_at")?,
            completed_at: optional_time(item, "completed_at")?,
            output_byte_count: required_u64(item, "output_byte_count")?,
            dropped_byte_count: required_u64(item, "dropped_byte_count")?,
            output_sequence_start: required_u64(item, "output_sequence_start")?,
            output_sequence_end: required_u64(item, "output_sequence_end")?,
            exit_status: optional_i32(item, "exit_status")?,
            truncated: required_bool(item, "truncated")?,
            expires_at: required_time(item, "expires_at")?,
            created_at: required_time(item, "created_at")?,
            updated_at: required_time(item, "updated_at")?,
        })
    }
}

fn required_s_allow_empty(
    item: &HashMap<String, AttributeValue>,
    key: &str,
) -> Result<String, McpEc2DiagnosticCommandStoreError> {
    match item.get(key) {
        Some(AttributeValue::S(value)) => Ok(value.clone()),
        _ => Err(McpEc2DiagnosticCommandStoreError::InvalidRecord(format!(
            "{key} must be a string"
        ))),
    }
}

fn required_s(
    item: &HashMap<String, AttributeValue>,
    key: &str,
) -> Result<String, McpEc2DiagnosticCommandStoreError> {
    match item.get(key) {
        Some(AttributeValue::S(value)) if !value.is_empty() => Ok(value.clone()),
        _ => Err(McpEc2DiagnosticCommandStoreError::InvalidRecord(format!(
            "{key} must be a non-empty string"
        ))),
    }
}

fn optional_s(
    item: &HashMap<String, AttributeValue>,
    key: &str,
) -> Result<Option<String>, McpEc2DiagnosticCommandStoreError> {
    match item.get(key) {
        Some(AttributeValue::S(value)) if !value.is_empty() => Ok(Some(value.clone())),
        None => Ok(None),
        _ => Err(McpEc2DiagnosticCommandStoreError::InvalidRecord(format!(
            "{key} must be a non-empty string when present"
        ))),
    }
}

fn required_u64(
    item: &HashMap<String, AttributeValue>,
    key: &str,
) -> Result<u64, McpEc2DiagnosticCommandStoreError> {
    match item.get(key) {
        Some(AttributeValue::N(value)) => value.parse().map_err(|_| {
            McpEc2DiagnosticCommandStoreError::InvalidRecord(format!("{key} must be u64"))
        }),
        _ => Err(McpEc2DiagnosticCommandStoreError::InvalidRecord(format!(
            "{key} must be u64"
        ))),
    }
}

fn optional_i32(
    item: &HashMap<String, AttributeValue>,
    key: &str,
) -> Result<Option<i32>, McpEc2DiagnosticCommandStoreError> {
    match item.get(key) {
        Some(AttributeValue::N(value)) => value.parse().map(Some).map_err(|_| {
            McpEc2DiagnosticCommandStoreError::InvalidRecord(format!("{key} must be i32"))
        }),
        None => Ok(None),
        _ => Err(McpEc2DiagnosticCommandStoreError::InvalidRecord(format!(
            "{key} must be i32 when present"
        ))),
    }
}

fn required_bool(
    item: &HashMap<String, AttributeValue>,
    key: &str,
) -> Result<bool, McpEc2DiagnosticCommandStoreError> {
    match item.get(key) {
        Some(AttributeValue::Bool(value)) => Ok(*value),
        _ => Err(McpEc2DiagnosticCommandStoreError::InvalidRecord(format!(
            "{key} must be bool"
        ))),
    }
}

fn required_time(
    item: &HashMap<String, AttributeValue>,
    key: &str,
) -> Result<DateTime<Utc>, McpEc2DiagnosticCommandStoreError> {
    DateTime::parse_from_rfc3339(&required_s(item, key)?)
        .map(|ts| ts.with_timezone(&Utc))
        .map_err(|_| {
            McpEc2DiagnosticCommandStoreError::InvalidRecord(format!("{key} must be RFC3339"))
        })
}

fn optional_time(
    item: &HashMap<String, AttributeValue>,
    key: &str,
) -> Result<Option<DateTime<Utc>>, McpEc2DiagnosticCommandStoreError> {
    match optional_s(item, key)? {
        Some(value) => DateTime::parse_from_rfc3339(&value)
            .map(|ts| Some(ts.with_timezone(&Utc)))
            .map_err(|_| {
                McpEc2DiagnosticCommandStoreError::InvalidRecord(format!("{key} must be RFC3339"))
            }),
        None => Ok(None),
    }
}

fn status_to_s(status: &McpEc2DiagnosticCommandStatus) -> &'static str {
    match status {
        McpEc2DiagnosticCommandStatus::Queued => "queued",
        McpEc2DiagnosticCommandStatus::Running => "running",
        McpEc2DiagnosticCommandStatus::Succeeded => "succeeded",
        McpEc2DiagnosticCommandStatus::Failed => "failed",
        McpEc2DiagnosticCommandStatus::Expired => "expired",
    }
}

fn status_from_s(
    status: &str,
) -> Result<McpEc2DiagnosticCommandStatus, McpEc2DiagnosticCommandStoreError> {
    match status {
        "queued" => Ok(McpEc2DiagnosticCommandStatus::Queued),
        "running" => Ok(McpEc2DiagnosticCommandStatus::Running),
        "succeeded" => Ok(McpEc2DiagnosticCommandStatus::Succeeded),
        "failed" => Ok(McpEc2DiagnosticCommandStatus::Failed),
        "expired" => Ok(McpEc2DiagnosticCommandStatus::Expired),
        _ => Err(McpEc2DiagnosticCommandStoreError::InvalidRecord(
            "status must be a known EC2 diagnostic command status".into(),
        )),
    }
}

fn command_type_to_s(command_type: &McpEc2DiagnosticCommandType) -> &'static str {
    match command_type {
        McpEc2DiagnosticCommandType::TailLog => "tail_log",
        McpEc2DiagnosticCommandType::GrepLog => "grep_log",
        McpEc2DiagnosticCommandType::JournalctlUnit => "journalctl_unit",
        McpEc2DiagnosticCommandType::HttpHead => "http_head",
        McpEc2DiagnosticCommandType::TcpProbe => "tcp_probe",
        McpEc2DiagnosticCommandType::DnsLookup => "dns_lookup",
    }
}

fn command_type_from_s(
    command_type: &str,
) -> Result<McpEc2DiagnosticCommandType, McpEc2DiagnosticCommandStoreError> {
    match command_type {
        "tail_log" => Ok(McpEc2DiagnosticCommandType::TailLog),
        "grep_log" => Ok(McpEc2DiagnosticCommandType::GrepLog),
        "journalctl_unit" => Ok(McpEc2DiagnosticCommandType::JournalctlUnit),
        "http_head" => Ok(McpEc2DiagnosticCommandType::HttpHead),
        "tcp_probe" => Ok(McpEc2DiagnosticCommandType::TcpProbe),
        "dns_lookup" => Ok(McpEc2DiagnosticCommandType::DnsLookup),
        _ => Err(McpEc2DiagnosticCommandStoreError::InvalidRecord(
            "command_type must be a known EC2 diagnostic command type".into(),
        )),
    }
}

fn dynamo_backend_error(
    operation: &str,
    err: impl std::fmt::Debug,
) -> McpEc2DiagnosticCommandStoreError {
    tracing::warn!(
        operation = operation,
        error = ?err,
        "DynamoDB MCP EC2 diagnostic command store operation failed"
    );
    McpEc2DiagnosticCommandStoreError::Backend(format!("{err:?}"))
}

#[async_trait]
impl McpEc2DiagnosticCommandStore for DynamoMcpEc2DiagnosticCommandStore {
    async fn sweep_expired(
        &self,
        _now: DateTime<Utc>,
    ) -> Result<(), McpEc2DiagnosticCommandStoreError> {
        // DynamoDB TTL performs cleanup asynchronously. Read and update gates
        // still check expires_at, so TTL lag cannot extend result access.
        Ok(())
    }

    async fn create_command(
        &self,
        command_id: String,
        record: McpEc2DiagnosticCommandRecord,
    ) -> Result<(), McpEc2DiagnosticCommandStoreError> {
        self.client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(Self::record_to_item(command_id, record)))
            .condition_expression("attribute_not_exists(mcp_ec2_command_id)")
            .send()
            .await
            .map_err(|err| dynamo_backend_error("create_ec2_diagnostic_command", err))?;
        Ok(())
    }

    async fn get_command(
        &self,
        command_id: &str,
    ) -> Result<Option<McpEc2DiagnosticCommandRecord>, McpEc2DiagnosticCommandStoreError> {
        let output = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key(
                "mcp_ec2_command_id",
                AttributeValue::S(command_id.to_string()),
            )
            .consistent_read(true)
            .send()
            .await
            .map_err(|err| dynamo_backend_error("get_ec2_diagnostic_command", err))?;
        output.item().map(Self::item_to_record).transpose()
    }

    async fn get_owned_command(
        &self,
        command_id: &str,
        actor: &str,
        mcp_session_id: &str,
        local_secret_generation: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<McpEc2DiagnosticCommandRecord>, McpEc2DiagnosticCommandStoreError> {
        let Some(record) = self.get_command(command_id).await? else {
            return Ok(None);
        };
        if record.actor != actor
            || record.mcp_session_id != mcp_session_id
            || record.local_secret_generation != local_secret_generation
            || record.is_expired_at(now)
        {
            return Ok(None);
        }
        Ok(Some(record))
    }

    async fn mark_dispatched(
        &self,
        command_id: &str,
        actor: &str,
        mcp_session_id: &str,
        local_secret_generation: &str,
        aws_ssm_command_id: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, McpEc2DiagnosticCommandStoreError> {
        let result = self
            .client
            .update_item()
            .table_name(&self.table_name)
            .key("mcp_ec2_command_id", AttributeValue::S(command_id.to_string()))
            .update_expression(
                "SET aws_ssm_command_id = :aws_ssm_command_id, #status = :running, updated_at = :updated_at",
            )
            .condition_expression(format!(
                "actor = :actor AND mcp_session_id = :mcp_session_id \
                 AND local_secret_generation = :generation \
                 AND {TTL_ATTRIBUTE} >= :now_epoch \
                 AND #status = :queued \
                 AND attribute_not_exists(aws_ssm_command_id)"
            ))
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(
                ":aws_ssm_command_id",
                AttributeValue::S(aws_ssm_command_id.to_string()),
            )
            .expression_attribute_values(":running", AttributeValue::S("running".into()))
            .expression_attribute_values(":updated_at", AttributeValue::S(now.to_rfc3339()))
            .expression_attribute_values(":actor", AttributeValue::S(actor.to_string()))
            .expression_attribute_values(
                ":mcp_session_id",
                AttributeValue::S(mcp_session_id.to_string()),
            )
            .expression_attribute_values(
                ":generation",
                AttributeValue::S(local_secret_generation.to_string()),
            )
            .expression_attribute_values(":now_epoch", AttributeValue::N(now.timestamp().to_string()))
            .expression_attribute_values(":queued", AttributeValue::S("queued".into()))
            .send()
            .await;

        match result {
            Ok(_) => Ok(true),
            Err(err)
                if err
                    .as_service_error()
                    .is_some_and(UpdateItemError::is_conditional_check_failed_exception) =>
            {
                Ok(false)
            }
            Err(err) => Err(dynamo_backend_error("mark_ec2_diagnostic_dispatched", err)),
        }
    }

    async fn mark_terminal(
        &self,
        command_id: &str,
        actor: &str,
        mcp_session_id: &str,
        local_secret_generation: &str,
        completion: McpEc2DiagnosticCommandCompletion,
        now: DateTime<Utc>,
    ) -> Result<bool, McpEc2DiagnosticCommandStoreError> {
        completion.validate()?;
        let update_expression = if completion.exit_status.is_some() {
            "SET #status = :status, completed_at = :completed_at, \
             output_byte_count = :output_byte_count, dropped_byte_count = :dropped_byte_count, \
             output_sequence_start = :output_sequence_start, output_sequence_end = :output_sequence_end, \
             exit_status = :exit_status, truncated = :truncated, updated_at = :updated_at"
        } else {
            "SET #status = :status, completed_at = :completed_at, \
             output_byte_count = :output_byte_count, dropped_byte_count = :dropped_byte_count, \
             output_sequence_start = :output_sequence_start, output_sequence_end = :output_sequence_end, \
             truncated = :truncated, updated_at = :updated_at"
        };
        let mut request = self
            .client
            .update_item()
            .table_name(&self.table_name)
            .key(
                "mcp_ec2_command_id",
                AttributeValue::S(command_id.to_string()),
            )
            .update_expression(update_expression)
            .condition_expression(format!(
                "actor = :actor AND mcp_session_id = :mcp_session_id \
                 AND local_secret_generation = :generation \
                 AND {TTL_ATTRIBUTE} >= :now_epoch \
                 AND #status = :running \
                 AND attribute_exists(aws_ssm_command_id) \
                 AND attribute_not_exists(completed_at)"
            ))
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(
                ":status",
                AttributeValue::S(status_to_s(&completion.status).into()),
            )
            .expression_attribute_values(
                ":completed_at",
                AttributeValue::S(completion.completed_at.to_rfc3339()),
            )
            .expression_attribute_values(
                ":output_byte_count",
                AttributeValue::N(completion.output_byte_count.to_string()),
            )
            .expression_attribute_values(
                ":dropped_byte_count",
                AttributeValue::N(completion.dropped_byte_count.to_string()),
            )
            .expression_attribute_values(
                ":output_sequence_start",
                AttributeValue::N(completion.output_sequence_start.to_string()),
            )
            .expression_attribute_values(
                ":output_sequence_end",
                AttributeValue::N(completion.output_sequence_end.to_string()),
            )
            .expression_attribute_values(":truncated", AttributeValue::Bool(completion.truncated))
            .expression_attribute_values(":updated_at", AttributeValue::S(now.to_rfc3339()))
            .expression_attribute_values(":actor", AttributeValue::S(actor.to_string()))
            .expression_attribute_values(
                ":mcp_session_id",
                AttributeValue::S(mcp_session_id.to_string()),
            )
            .expression_attribute_values(
                ":generation",
                AttributeValue::S(local_secret_generation.to_string()),
            )
            .expression_attribute_values(
                ":now_epoch",
                AttributeValue::N(now.timestamp().to_string()),
            )
            .expression_attribute_values(":running", AttributeValue::S("running".into()));
        if let Some(exit_status) = completion.exit_status {
            request = request.expression_attribute_values(
                ":exit_status",
                AttributeValue::N(exit_status.to_string()),
            );
        }
        let result = request.send().await;

        match result {
            Ok(_) => Ok(true),
            Err(err)
                if err
                    .as_service_error()
                    .is_some_and(UpdateItemError::is_conditional_check_failed_exception) =>
            {
                Ok(false)
            }
            Err(err) => Err(dynamo_backend_error("mark_ec2_diagnostic_terminal", err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn record(now: DateTime<Utc>) -> McpEc2DiagnosticCommandRecord {
        McpEc2DiagnosticCommandRecord {
            actor: "actor-1".into(),
            actor_email: "actor@example.com".into(),
            mcp_session_id: "mcp-session-1".into(),
            local_secret_generation: "lsg_1".into(),
            instance_id: "i-0123456789abcdef0".into(),
            account_id: "123456789012".into(),
            region: "ap-northeast-1".into(),
            command_type: McpEc2DiagnosticCommandType::TailLog,
            allowlist_rule_id: "rule-1".into(),
            command_scope_id: "scope-1".into(),
            status: McpEc2DiagnosticCommandStatus::Queued,
            aws_ssm_command_id: None,
            submitted_at: now,
            completed_at: None,
            output_byte_count: 0,
            dropped_byte_count: 0,
            output_sequence_start: 0,
            output_sequence_end: 0,
            exit_status: None,
            truncated: false,
            expires_at: now + Duration::minutes(15),
            created_at: now,
            updated_at: now,
        }
    }

    fn completion(now: DateTime<Utc>) -> McpEc2DiagnosticCommandCompletion {
        McpEc2DiagnosticCommandCompletion {
            status: McpEc2DiagnosticCommandStatus::Succeeded,
            completed_at: now,
            output_byte_count: 42,
            dropped_byte_count: 0,
            output_sequence_start: 0,
            output_sequence_end: 42,
            exit_status: Some(0),
            truncated: false,
        }
    }

    #[tokio::test]
    async fn memory_store_create_get_dispatch_complete_and_sweep() {
        let store = MemoryMcpEc2DiagnosticCommandStore::new();
        let now = Utc::now();
        store
            .create_command("cmd-1".into(), record(now))
            .await
            .unwrap();

        let owned = store
            .get_owned_command("cmd-1", "actor-1", "mcp-session-1", "lsg_1", now)
            .await
            .unwrap();
        assert!(owned.is_some());

        assert!(store
            .mark_dispatched(
                "cmd-1",
                "actor-1",
                "mcp-session-1",
                "lsg_1",
                "ssm-command-1",
                now + Duration::seconds(1),
            )
            .await
            .unwrap());
        let dispatched = store.get_command("cmd-1").await.unwrap().unwrap();
        assert_eq!(dispatched.status, McpEc2DiagnosticCommandStatus::Running);
        assert_eq!(
            dispatched.aws_ssm_command_id.as_deref(),
            Some("ssm-command-1")
        );

        assert!(store
            .mark_terminal(
                "cmd-1",
                "actor-1",
                "mcp-session-1",
                "lsg_1",
                completion(now + Duration::seconds(2)),
                now + Duration::seconds(2),
            )
            .await
            .unwrap());
        let completed = store.get_command("cmd-1").await.unwrap().unwrap();
        assert_eq!(completed.status, McpEc2DiagnosticCommandStatus::Succeeded);
        assert_eq!(completed.output_byte_count, 42);
        assert_eq!(completed.exit_status, Some(0));

        store
            .sweep_expired(now + Duration::minutes(16))
            .await
            .unwrap();
        assert!(store.get_command("cmd-1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn memory_store_fails_closed_on_owner_mismatch_or_expiry() {
        let store = MemoryMcpEc2DiagnosticCommandStore::new();
        let now = Utc::now();
        store
            .create_command("cmd-1".into(), record(now))
            .await
            .unwrap();

        assert!(store
            .get_owned_command("cmd-1", "other", "mcp-session-1", "lsg_1", now)
            .await
            .unwrap()
            .is_none());
        assert!(!store
            .mark_dispatched(
                "cmd-1",
                "actor-1",
                "other-session",
                "lsg_1",
                "ssm-command-1",
                now,
            )
            .await
            .unwrap());
        assert!(!store
            .mark_dispatched(
                "cmd-1",
                "actor-1",
                "mcp-session-1",
                "lsg_1",
                "ssm-command-1",
                now + Duration::minutes(16),
            )
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn memory_store_rejects_duplicate_command_id() {
        let store = MemoryMcpEc2DiagnosticCommandStore::new();
        let now = Utc::now();
        store
            .create_command("cmd-dup".into(), record(now))
            .await
            .unwrap();
        assert!(store
            .create_command("cmd-dup".into(), record(now))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn memory_store_rejects_non_terminal_completion_status() {
        let store = MemoryMcpEc2DiagnosticCommandStore::new();
        let now = Utc::now();
        store
            .create_command("cmd-1".into(), record(now))
            .await
            .unwrap();
        let mut completion = completion(now);
        completion.status = McpEc2DiagnosticCommandStatus::Running;
        let err = store
            .mark_terminal(
                "cmd-1",
                "actor-1",
                "mcp-session-1",
                "lsg_1",
                completion,
                now,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("terminal"));
    }

    #[tokio::test]
    async fn memory_store_rejects_completion_before_dispatch() {
        let store = MemoryMcpEc2DiagnosticCommandStore::new();
        let now = Utc::now();
        store
            .create_command("cmd-1".into(), record(now))
            .await
            .unwrap();

        assert!(!store
            .mark_terminal(
                "cmd-1",
                "actor-1",
                "mcp-session-1",
                "lsg_1",
                completion(now + Duration::seconds(1)),
                now + Duration::seconds(1),
            )
            .await
            .unwrap());
    }

    #[test]
    fn dynamo_item_roundtrip_preserves_command_record_fields() {
        let now = Utc::now();
        let mut original = record(now);
        original.status = McpEc2DiagnosticCommandStatus::Succeeded;
        original.aws_ssm_command_id = Some("ssm-command-1".into());
        original.completed_at = Some(now + Duration::seconds(2));
        original.output_byte_count = 128;
        original.dropped_byte_count = 8;
        original.output_sequence_start = 10;
        original.output_sequence_end = 138;
        original.exit_status = Some(1);
        original.truncated = true;

        let item =
            DynamoMcpEc2DiagnosticCommandStore::record_to_item("cmd-1".into(), original.clone());
        let parsed = DynamoMcpEc2DiagnosticCommandStore::item_to_record(&item).unwrap();

        assert_eq!(parsed, original);
        assert_eq!(
            item.get(TTL_ATTRIBUTE),
            Some(&AttributeValue::N(
                original.expires_at.timestamp().to_string()
            ))
        );
    }

    #[test]
    fn dynamo_item_rejects_missing_required_fields() {
        let item = HashMap::new();
        let err = DynamoMcpEc2DiagnosticCommandStore::item_to_record(&item)
            .unwrap_err()
            .to_string();
        assert!(err.contains("actor"));
    }

    #[test]
    fn dynamo_item_rejects_unknown_status() {
        let now = Utc::now();
        let mut item =
            DynamoMcpEc2DiagnosticCommandStore::record_to_item("cmd-1".into(), record(now));
        item.insert("status".into(), AttributeValue::S("shell_ready".into()));
        let err = DynamoMcpEc2DiagnosticCommandStore::item_to_record(&item)
            .unwrap_err()
            .to_string();
        assert!(err.contains("status"));
    }
}
