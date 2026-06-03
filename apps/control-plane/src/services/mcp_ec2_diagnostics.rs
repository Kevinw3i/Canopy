use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use async_trait::async_trait;
use aws_sdk_dynamodb::operation::update_item::UpdateItemError;
use aws_sdk_dynamodb::types::AttributeValue;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shared::dto::mcp::{
    McpEc2DiagnosticCommand, McpEc2DiagnosticCommandStatus, McpEc2DiagnosticCommandType,
};
use std::collections::{BTreeMap, HashMap};

use crate::config::McpConfig;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpEc2DiagnosticCommandStoreClaim {
    command_id: String,
    actor: String,
    mcp_session_id: String,
    local_secret_generation: String,
    aws_ssm_command_id: String,
    claimed_at: DateTime<Utc>,
}

impl McpEc2DiagnosticCommandStoreClaim {
    fn new(
        command_id: &str,
        actor: &str,
        mcp_session_id: &str,
        local_secret_generation: &str,
        aws_ssm_command_id: &str,
        claimed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            command_id: command_id.to_string(),
            actor: actor.to_string(),
            mcp_session_id: mcp_session_id.to_string(),
            local_secret_generation: local_secret_generation.to_string(),
            aws_ssm_command_id: aws_ssm_command_id.to_string(),
            claimed_at,
        }
    }

    pub fn command_id(&self) -> &str {
        &self.command_id
    }

    pub fn aws_ssm_command_id(&self) -> &str {
        &self.aws_ssm_command_id
    }

    pub fn claimed_at(&self) -> DateTime<Utc> {
        self.claimed_at
    }
}

pub const MCP_EC2_COMMAND_SPEC_REF_PREFIX: &str = "canopy-ec2-spec:v1:";
pub const MCP_EC2_COMMAND_SPEC_REF_MAX_LEN: usize = 4036;
pub const MCP_EC2_COMMAND_SPEC_HELPER_VERSION: &str = "2026-06-04.1";
pub const MCP_EC2_DIAGNOSTIC_SSM_DOCUMENT_NAME: &str = "Canopy-Ec2Diagnostics";
pub const MCP_EC2_COMMAND_SPEC_REF_MAX_TTL_SECONDS: i64 = 900;
pub const MCP_EC2_DIAGNOSTIC_SSM_TIMEOUT_SECONDS: i32 = 120;
pub const MCP_EC2_DIAGNOSTIC_SSM_MAX_CONCURRENCY: &str = "1";
pub const MCP_EC2_DIAGNOSTIC_SSM_MAX_ERRORS: &str = "0";
const MCP_EC2_COMMAND_SPEC_REF_NONCE_LEN: usize = 16;
const MCP_EC2_COMMAND_SPEC_REF_CIPHERTEXT_MAX_LEN: usize = 4000;
const MCP_EC2_COMMAND_SPEC_REF_MAX_CLOCK_SKEW_SECONDS: i64 = 60;
const MCP_EC2_COMMAND_SPEC_REF_AAD: &[u8] = b"canopy:mcp:ec2-diagnostics:command-spec-ref:v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum McpEc2DiagnosticCommandSpecRefError {
    #[error("MCP EC2 diagnostic command spec key material is empty")]
    EmptyKey,
    #[error("MCP EC2 diagnostic command spec serialization failed")]
    Serialize,
    #[error("MCP EC2 diagnostic command spec encryption failed")]
    Encrypt,
    #[error("MCP EC2 diagnostic command spec reference exceeds the SSM parameter limit")]
    TooLarge,
    #[error("MCP EC2 diagnostic command spec reference format is invalid")]
    InvalidFormat,
    #[error("MCP EC2 diagnostic command spec reference encoding is invalid")]
    InvalidEncoding,
    #[error("MCP EC2 diagnostic command spec reference nonce is invalid")]
    InvalidNonce,
    #[error("MCP EC2 diagnostic command spec reference authentication failed")]
    AuthenticationFailed,
    #[error("MCP EC2 diagnostic command spec deserialization failed")]
    Deserialize,
    #[error("MCP EC2 diagnostic command spec version is unsupported")]
    UnsupportedVersion,
    #[error("MCP EC2 diagnostic command spec binding mismatch: {0}")]
    BindingMismatch(&'static str),
    #[error("MCP EC2 diagnostic command spec reference is expired")]
    Expired,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpEc2DiagnosticCommandSpecRefPayload {
    pub version: u8,
    pub helper_version: String,
    pub mcp_ec2_command_id: String,
    pub actor: String,
    pub mcp_session_id: String,
    pub local_secret_generation: String,
    pub instance_id: String,
    pub account_id: String,
    pub region: String,
    pub command_type: McpEc2DiagnosticCommandType,
    pub command: McpEc2DiagnosticCommand,
    pub one_time_command_store_claim_required: bool,
    pub allowlist_rule_id: String,
    pub command_scope_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub struct McpEc2DiagnosticCommandSpecRefBinding<'a> {
    pub helper_version: &'a str,
    pub mcp_ec2_command_id: &'a str,
    pub actor: &'a str,
    pub mcp_session_id: &'a str,
    pub local_secret_generation: &'a str,
    pub instance_id: &'a str,
    pub account_id: &'a str,
    pub region: &'a str,
    pub allowlist_rule_id: &'a str,
    pub command_scope_id: &'a str,
    pub command_store_claim: &'a McpEc2DiagnosticCommandStoreClaim,
    pub now: DateTime<Utc>,
}

impl std::fmt::Debug for McpEc2DiagnosticCommandSpecRefPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpEc2DiagnosticCommandSpecRefPayload")
            .field("version", &self.version)
            .field("helper_version", &self.helper_version)
            .field("mcp_ec2_command_id", &self.mcp_ec2_command_id)
            .field("actor", &self.actor)
            .field("mcp_session_id", &self.mcp_session_id)
            .field("local_secret_generation", &self.local_secret_generation)
            .field("instance_id", &self.instance_id)
            .field("account_id", &self.account_id)
            .field("region", &self.region)
            .field("command_type", &self.command_type)
            .field("command", &"[redacted]")
            .field(
                "one_time_command_store_claim_required",
                &self.one_time_command_store_claim_required,
            )
            .field("allowlist_rule_id", &self.allowlist_rule_id)
            .field("command_scope_id", &self.command_scope_id)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl McpEc2DiagnosticCommandSpecRefPayload {
    pub fn validate_binding(
        &self,
        binding: &McpEc2DiagnosticCommandSpecRefBinding<'_>,
    ) -> Result<(), McpEc2DiagnosticCommandSpecRefError> {
        self.validate_common(binding.now)?;
        if self.helper_version != binding.helper_version {
            return Err(McpEc2DiagnosticCommandSpecRefError::BindingMismatch(
                "helper_version",
            ));
        }
        if self.mcp_ec2_command_id != binding.mcp_ec2_command_id {
            return Err(McpEc2DiagnosticCommandSpecRefError::BindingMismatch(
                "mcp_ec2_command_id",
            ));
        }
        if self.actor != binding.actor {
            return Err(McpEc2DiagnosticCommandSpecRefError::BindingMismatch(
                "actor",
            ));
        }
        if self.mcp_session_id != binding.mcp_session_id {
            return Err(McpEc2DiagnosticCommandSpecRefError::BindingMismatch(
                "mcp_session_id",
            ));
        }
        if self.local_secret_generation != binding.local_secret_generation {
            return Err(McpEc2DiagnosticCommandSpecRefError::BindingMismatch(
                "local_secret_generation",
            ));
        }
        if self.instance_id != binding.instance_id {
            return Err(McpEc2DiagnosticCommandSpecRefError::BindingMismatch(
                "instance_id",
            ));
        }
        if self.account_id != binding.account_id {
            return Err(McpEc2DiagnosticCommandSpecRefError::BindingMismatch(
                "account_id",
            ));
        }
        if self.region != binding.region {
            return Err(McpEc2DiagnosticCommandSpecRefError::BindingMismatch(
                "region",
            ));
        }
        if self.allowlist_rule_id != binding.allowlist_rule_id {
            return Err(McpEc2DiagnosticCommandSpecRefError::BindingMismatch(
                "allowlist_rule_id",
            ));
        }
        if self.command_scope_id != binding.command_scope_id {
            return Err(McpEc2DiagnosticCommandSpecRefError::BindingMismatch(
                "command_scope_id",
            ));
        }
        if self.mcp_ec2_command_id != binding.command_store_claim.command_id
            || self.actor != binding.command_store_claim.actor
            || self.mcp_session_id != binding.command_store_claim.mcp_session_id
            || self.local_secret_generation != binding.command_store_claim.local_secret_generation
            || binding.command_store_claim.claimed_at.timestamp() < self.issued_at.timestamp()
            || binding.command_store_claim.claimed_at.timestamp() > self.expires_at.timestamp()
            || binding.command_store_claim.claimed_at.timestamp()
                > (binding.now
                    + chrono::Duration::seconds(MCP_EC2_COMMAND_SPEC_REF_MAX_CLOCK_SKEW_SECONDS))
                .timestamp()
        {
            return Err(McpEc2DiagnosticCommandSpecRefError::BindingMismatch(
                "one_time_command_store_claim",
            ));
        }
        Ok(())
    }

    fn validate_common(
        &self,
        now: DateTime<Utc>,
    ) -> Result<(), McpEc2DiagnosticCommandSpecRefError> {
        if self.version != 1 || self.helper_version != MCP_EC2_COMMAND_SPEC_HELPER_VERSION {
            return Err(McpEc2DiagnosticCommandSpecRefError::UnsupportedVersion);
        }
        if self.command_type != mcp_ec2_command_type_for_spec_ref(&self.command) {
            return Err(McpEc2DiagnosticCommandSpecRefError::BindingMismatch(
                "command_type",
            ));
        }
        if !self.one_time_command_store_claim_required {
            return Err(McpEc2DiagnosticCommandSpecRefError::BindingMismatch(
                "one_time_command_store_claim",
            ));
        }
        if self.expires_at.timestamp() <= self.issued_at.timestamp() {
            return Err(McpEc2DiagnosticCommandSpecRefError::BindingMismatch(
                "expires_at",
            ));
        }
        if self.expires_at.timestamp() - self.issued_at.timestamp()
            > MCP_EC2_COMMAND_SPEC_REF_MAX_TTL_SECONDS
        {
            return Err(McpEc2DiagnosticCommandSpecRefError::BindingMismatch("ttl"));
        }
        if self.issued_at.timestamp()
            > (now + chrono::Duration::seconds(MCP_EC2_COMMAND_SPEC_REF_MAX_CLOCK_SKEW_SECONDS))
                .timestamp()
        {
            return Err(McpEc2DiagnosticCommandSpecRefError::BindingMismatch(
                "issued_at",
            ));
        }
        if self.expires_at.timestamp() < now.timestamp() {
            return Err(McpEc2DiagnosticCommandSpecRefError::Expired);
        }
        Ok(())
    }
}

pub fn seal_mcp_ec2_diagnostic_command_spec_ref(
    key_material: &str,
    payload: &McpEc2DiagnosticCommandSpecRefPayload,
    now: DateTime<Utc>,
) -> Result<String, McpEc2DiagnosticCommandSpecRefError> {
    payload.validate_common(now)?;
    let cipher = mcp_ec2_command_spec_ref_cipher(key_material)?;
    let plaintext =
        serde_json::to_vec(payload).map_err(|_| McpEc2DiagnosticCommandSpecRefError::Serialize)?;
    let mut nonce_bytes = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            aes_gcm::aead::Payload {
                msg: plaintext.as_slice(),
                aad: MCP_EC2_COMMAND_SPEC_REF_AAD,
            },
        )
        .map_err(|_| McpEc2DiagnosticCommandSpecRefError::Encrypt)?;
    let command_spec_ref = format!(
        "{}{}.{}",
        MCP_EC2_COMMAND_SPEC_REF_PREFIX,
        URL_SAFE_NO_PAD.encode(nonce_bytes),
        URL_SAFE_NO_PAD.encode(ciphertext),
    );
    if !mcp_ec2_command_spec_ref_shape_is_allowed(&command_spec_ref) {
        return Err(McpEc2DiagnosticCommandSpecRefError::TooLarge);
    }
    Ok(command_spec_ref)
}

pub fn open_mcp_ec2_diagnostic_command_spec_ref(
    key_material: &str,
    command_spec_ref: &str,
    binding: &McpEc2DiagnosticCommandSpecRefBinding<'_>,
) -> Result<McpEc2DiagnosticCommandSpecRefPayload, McpEc2DiagnosticCommandSpecRefError> {
    let payload =
        open_mcp_ec2_diagnostic_command_spec_ref_unchecked(key_material, command_spec_ref)?;
    payload.validate_binding(binding)?;
    Ok(payload)
}

#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedMcpEc2DiagnosticCommandSpecRef {
    command_spec_ref: String,
    helper_version: String,
    mcp_ec2_command_id: String,
    instance_id: String,
}

impl VerifiedMcpEc2DiagnosticCommandSpecRef {
    pub fn as_str(&self) -> &str {
        &self.command_spec_ref
    }

    pub fn helper_version(&self) -> &str {
        &self.helper_version
    }

    pub fn mcp_ec2_command_id(&self) -> &str {
        &self.mcp_ec2_command_id
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }
}

impl std::fmt::Debug for VerifiedMcpEc2DiagnosticCommandSpecRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedMcpEc2DiagnosticCommandSpecRef")
            .field("len", &self.command_spec_ref.len())
            .finish()
    }
}

pub fn verify_mcp_ec2_diagnostic_command_spec_ref(
    key_material: &str,
    command_spec_ref: &str,
    binding: &McpEc2DiagnosticCommandSpecRefBinding<'_>,
) -> Result<VerifiedMcpEc2DiagnosticCommandSpecRef, McpEc2DiagnosticCommandSpecRefError> {
    let payload =
        open_mcp_ec2_diagnostic_command_spec_ref(key_material, command_spec_ref, binding)?;
    Ok(VerifiedMcpEc2DiagnosticCommandSpecRef {
        command_spec_ref: command_spec_ref.to_string(),
        helper_version: payload.helper_version,
        mcp_ec2_command_id: payload.mcp_ec2_command_id,
        instance_id: payload.instance_id,
    })
}

fn open_mcp_ec2_diagnostic_command_spec_ref_unchecked(
    key_material: &str,
    command_spec_ref: &str,
) -> Result<McpEc2DiagnosticCommandSpecRefPayload, McpEc2DiagnosticCommandSpecRefError> {
    let cipher = mcp_ec2_command_spec_ref_cipher(key_material)?;
    if !mcp_ec2_command_spec_ref_shape_is_allowed(command_spec_ref) {
        return Err(McpEc2DiagnosticCommandSpecRefError::InvalidFormat);
    }
    let encoded = command_spec_ref
        .strip_prefix(MCP_EC2_COMMAND_SPEC_REF_PREFIX)
        .ok_or(McpEc2DiagnosticCommandSpecRefError::InvalidFormat)?;
    let (nonce_encoded, ciphertext_encoded) = encoded
        .split_once('.')
        .ok_or(McpEc2DiagnosticCommandSpecRefError::InvalidFormat)?;
    let nonce_bytes = URL_SAFE_NO_PAD
        .decode(nonce_encoded.as_bytes())
        .map_err(|_| McpEc2DiagnosticCommandSpecRefError::InvalidEncoding)?;
    if nonce_bytes.len() != 12 {
        return Err(McpEc2DiagnosticCommandSpecRefError::InvalidNonce);
    }
    let ciphertext = URL_SAFE_NO_PAD
        .decode(ciphertext_encoded.as_bytes())
        .map_err(|_| McpEc2DiagnosticCommandSpecRefError::InvalidEncoding)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            aes_gcm::aead::Payload {
                msg: ciphertext.as_slice(),
                aad: MCP_EC2_COMMAND_SPEC_REF_AAD,
            },
        )
        .map_err(|_| McpEc2DiagnosticCommandSpecRefError::AuthenticationFailed)?;
    let payload: McpEc2DiagnosticCommandSpecRefPayload = serde_json::from_slice(&plaintext)
        .map_err(|_| McpEc2DiagnosticCommandSpecRefError::Deserialize)?;
    if payload.version != 1 || payload.helper_version != MCP_EC2_COMMAND_SPEC_HELPER_VERSION {
        return Err(McpEc2DiagnosticCommandSpecRefError::UnsupportedVersion);
    }
    if payload.command_type != mcp_ec2_command_type_for_spec_ref(&payload.command) {
        return Err(McpEc2DiagnosticCommandSpecRefError::BindingMismatch(
            "command_type",
        ));
    }
    Ok(payload)
}

fn mcp_ec2_command_spec_ref_shape_is_allowed(command_spec_ref: &str) -> bool {
    if command_spec_ref.len() > MCP_EC2_COMMAND_SPEC_REF_MAX_LEN {
        return false;
    }
    let Some(encoded) = command_spec_ref.strip_prefix(MCP_EC2_COMMAND_SPEC_REF_PREFIX) else {
        return false;
    };
    let Some((nonce, ciphertext)) = encoded.split_once('.') else {
        return false;
    };
    nonce.len() == MCP_EC2_COMMAND_SPEC_REF_NONCE_LEN
        && (64..=MCP_EC2_COMMAND_SPEC_REF_CIPHERTEXT_MAX_LEN).contains(&ciphertext.len())
        && nonce.bytes().all(is_base64url_byte)
        && ciphertext.bytes().all(is_base64url_byte)
}

fn is_base64url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum McpEc2DiagnosticDispatchError {
    #[error("MCP EC2 diagnostics SSM dispatch is not configured")]
    DispatchNotConfigured,
    #[error("MCP EC2 diagnostics SSM document version must be pinned")]
    UnpinnedDocumentVersion,
    #[error("MCP EC2 diagnostics SSM dispatch input is invalid: {0}")]
    InvalidInput(&'static str),
}

#[derive(Clone, PartialEq, Eq)]
pub struct McpEc2DiagnosticSsmDispatchRequest {
    document_name: String,
    document_version: String,
    instance_id: String,
    timeout_seconds: i32,
    parameters: BTreeMap<String, Vec<String>>,
    cloudwatch_output_enabled: bool,
    s3_output_enabled: bool,
}

impl std::fmt::Debug for McpEc2DiagnosticSsmDispatchRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpEc2DiagnosticSsmDispatchRequest")
            .field("document_name", &self.document_name)
            .field("document_version", &self.document_version)
            .field("instance_id", &self.instance_id)
            .field("timeout_seconds", &self.timeout_seconds)
            .field(
                "parameter_keys",
                &self.parameters.keys().collect::<Vec<_>>(),
            )
            .field("cloudwatch_output_enabled", &self.cloudwatch_output_enabled)
            .field("s3_output_enabled", &self.s3_output_enabled)
            .finish()
    }
}

impl McpEc2DiagnosticSsmDispatchRequest {
    pub fn document_name(&self) -> &str {
        &self.document_name
    }

    pub fn document_version(&self) -> &str {
        &self.document_version
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub fn timeout_seconds(&self) -> i32 {
        self.timeout_seconds
    }

    pub fn parameter_keys(&self) -> Vec<&str> {
        self.parameters.keys().map(String::as_str).collect()
    }

    fn parameters(&self) -> &BTreeMap<String, Vec<String>> {
        &self.parameters
    }

    pub fn cloudwatch_output_enabled(&self) -> bool {
        self.cloudwatch_output_enabled
    }

    pub fn s3_output_enabled(&self) -> bool {
        self.s3_output_enabled
    }

    pub fn helper_version(&self) -> Option<&str> {
        self.parameters
            .get("helperVersion")
            .and_then(|values| values.first())
            .map(String::as_str)
    }

    fn command_spec_ref(&self) -> Option<&str> {
        self.parameters
            .get("commandSpecRef")
            .and_then(|values| values.first())
            .map(String::as_str)
    }
}

pub fn build_mcp_ec2_diagnostic_ssm_dispatch_request(
    config: &McpConfig,
    mcp_ec2_command_id: &str,
    instance_id: &str,
    command_spec_ref: &VerifiedMcpEc2DiagnosticCommandSpecRef,
) -> Result<McpEc2DiagnosticSsmDispatchRequest, McpEc2DiagnosticDispatchError> {
    let document_name = config
        .ec2_diagnostic_ssm_document_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(McpEc2DiagnosticDispatchError::DispatchNotConfigured)?;
    if document_name != MCP_EC2_DIAGNOSTIC_SSM_DOCUMENT_NAME {
        return Err(McpEc2DiagnosticDispatchError::InvalidInput("document_name"));
    }
    let document_version = config
        .ec2_diagnostic_ssm_document_version
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(McpEc2DiagnosticDispatchError::DispatchNotConfigured)?;
    if !mcp_ec2_dispatch_document_version_is_pinned(document_version) {
        return Err(McpEc2DiagnosticDispatchError::UnpinnedDocumentVersion);
    }
    if !mcp_ec2_command_id_shape_is_allowed(mcp_ec2_command_id) {
        return Err(McpEc2DiagnosticDispatchError::InvalidInput(
            "mcp_ec2_command_id",
        ));
    }
    if mcp_ec2_command_id != command_spec_ref.mcp_ec2_command_id() {
        return Err(McpEc2DiagnosticDispatchError::InvalidInput(
            "mcp_ec2_command_id",
        ));
    }
    if !mcp_ec2_instance_id_shape_is_allowed(instance_id) {
        return Err(McpEc2DiagnosticDispatchError::InvalidInput("instance_id"));
    }
    if instance_id != command_spec_ref.instance_id() {
        return Err(McpEc2DiagnosticDispatchError::InvalidInput("instance_id"));
    }
    if !mcp_ec2_command_spec_ref_shape_is_allowed(command_spec_ref.as_str()) {
        return Err(McpEc2DiagnosticDispatchError::InvalidInput(
            "command_spec_ref",
        ));
    }

    let helper_version = match config.ec2_diagnostic_helper_version.as_deref() {
        Some(value) => {
            let trimmed = value.trim();
            if trimmed != MCP_EC2_COMMAND_SPEC_HELPER_VERSION {
                return Err(McpEc2DiagnosticDispatchError::InvalidInput(
                    "helper_version",
                ));
            }
            trimmed
        }
        None => MCP_EC2_COMMAND_SPEC_HELPER_VERSION,
    };
    if !mcp_ec2_helper_version_shape_is_allowed(helper_version) {
        return Err(McpEc2DiagnosticDispatchError::InvalidInput(
            "helper_version",
        ));
    }
    if helper_version != command_spec_ref.helper_version() {
        return Err(McpEc2DiagnosticDispatchError::InvalidInput(
            "helper_version",
        ));
    }
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "mcpEc2CommandId".into(),
        vec![mcp_ec2_command_id.to_string()],
    );
    parameters.insert(
        "commandSpecRef".into(),
        vec![command_spec_ref.as_str().to_string()],
    );
    parameters.insert("helperVersion".into(), vec![helper_version.to_string()]);

    Ok(McpEc2DiagnosticSsmDispatchRequest {
        document_name: document_name.to_string(),
        document_version: document_version.to_string(),
        instance_id: instance_id.to_string(),
        timeout_seconds: MCP_EC2_DIAGNOSTIC_SSM_TIMEOUT_SECONDS,
        parameters,
        cloudwatch_output_enabled: false,
        s3_output_enabled: false,
    })
}

#[derive(Clone, PartialEq, Eq)]
pub struct McpEc2DiagnosticSsmSendCommandInput {
    document_name: String,
    document_version: String,
    instance_ids: Vec<String>,
    timeout_seconds: i32,
    parameters: BTreeMap<String, Vec<String>>,
    max_concurrency: String,
    max_errors: String,
    cloudwatch_output_enabled: bool,
    s3_output_enabled: bool,
}

impl std::fmt::Debug for McpEc2DiagnosticSsmSendCommandInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpEc2DiagnosticSsmSendCommandInput")
            .field("document_name", &self.document_name)
            .field("document_version", &self.document_version)
            .field("instance_ids", &self.instance_ids)
            .field("timeout_seconds", &self.timeout_seconds)
            .field(
                "parameter_keys",
                &self.parameters.keys().collect::<Vec<_>>(),
            )
            .field("max_concurrency", &self.max_concurrency)
            .field("max_errors", &self.max_errors)
            .field("cloudwatch_output_enabled", &self.cloudwatch_output_enabled)
            .field("s3_output_enabled", &self.s3_output_enabled)
            .finish()
    }
}

impl McpEc2DiagnosticSsmSendCommandInput {
    pub fn document_name(&self) -> &str {
        &self.document_name
    }

    pub fn document_version(&self) -> &str {
        &self.document_version
    }

    pub fn instance_ids(&self) -> &[String] {
        &self.instance_ids
    }

    pub fn timeout_seconds(&self) -> i32 {
        self.timeout_seconds
    }

    pub fn parameter_keys(&self) -> Vec<&str> {
        self.parameters.keys().map(String::as_str).collect()
    }

    pub fn max_concurrency(&self) -> &str {
        &self.max_concurrency
    }

    pub fn max_errors(&self) -> &str {
        &self.max_errors
    }

    pub fn cloudwatch_output_enabled(&self) -> bool {
        self.cloudwatch_output_enabled
    }

    pub fn s3_output_enabled(&self) -> bool {
        self.s3_output_enabled
    }

    fn parameters_for_aws(&self) -> &BTreeMap<String, Vec<String>> {
        &self.parameters
    }
}

pub fn build_mcp_ec2_diagnostic_ssm_send_command_input(
    request: &McpEc2DiagnosticSsmDispatchRequest,
) -> Result<McpEc2DiagnosticSsmSendCommandInput, McpEc2DiagnosticDispatchError> {
    if request.cloudwatch_output_enabled() {
        return Err(McpEc2DiagnosticDispatchError::InvalidInput(
            "cloudwatch_output",
        ));
    }
    if request.s3_output_enabled() {
        return Err(McpEc2DiagnosticDispatchError::InvalidInput("s3_output"));
    }
    let expected_parameter_keys = ["commandSpecRef", "helperVersion", "mcpEc2CommandId"];
    if request
        .parameters()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>()
        != expected_parameter_keys
    {
        return Err(McpEc2DiagnosticDispatchError::InvalidInput("parameters"));
    }
    for values in request.parameters().values() {
        if values.len() != 1 || values[0].trim().is_empty() {
            return Err(McpEc2DiagnosticDispatchError::InvalidInput("parameters"));
        }
    }

    Ok(McpEc2DiagnosticSsmSendCommandInput {
        document_name: request.document_name().to_string(),
        document_version: request.document_version().to_string(),
        instance_ids: vec![request.instance_id().to_string()],
        timeout_seconds: request.timeout_seconds(),
        parameters: request.parameters().clone(),
        max_concurrency: MCP_EC2_DIAGNOSTIC_SSM_MAX_CONCURRENCY.into(),
        max_errors: MCP_EC2_DIAGNOSTIC_SSM_MAX_ERRORS.into(),
        cloudwatch_output_enabled: false,
        s3_output_enabled: false,
    })
}

fn build_mcp_ec2_diagnostic_aws_send_command(
    client: &aws_sdk_ssm::Client,
    input: &McpEc2DiagnosticSsmSendCommandInput,
) -> aws_sdk_ssm::operation::send_command::builders::SendCommandFluentBuilder {
    let mut builder = client
        .send_command()
        .document_name(input.document_name())
        .document_version(input.document_version())
        .timeout_seconds(input.timeout_seconds())
        .max_concurrency(input.max_concurrency())
        .max_errors(input.max_errors())
        .cloud_watch_output_config(
            aws_sdk_ssm::types::CloudWatchOutputConfig::builder()
                .cloud_watch_output_enabled(input.cloudwatch_output_enabled())
                .build(),
        );
    for instance_id in input.instance_ids() {
        builder = builder.instance_ids(instance_id.clone());
    }
    for (key, values) in input.parameters_for_aws() {
        builder = builder.parameters(key.clone(), values.clone());
    }
    builder
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum McpEc2DiagnosticSsmDispatcherError {
    #[error("MCP EC2 diagnostics SSM dispatch backend error")]
    Backend,
    #[error("MCP EC2 diagnostics SSM dispatch returned no command id")]
    MissingCommandId,
}

#[async_trait]
pub trait McpEc2DiagnosticSsmDispatcher: Send + Sync {
    async fn dispatch(
        &self,
        input: &McpEc2DiagnosticSsmSendCommandInput,
    ) -> Result<String, McpEc2DiagnosticSsmDispatcherError>;
}

pub struct AwsMcpEc2DiagnosticSsmDispatcher {
    client: aws_sdk_ssm::Client,
}

impl AwsMcpEc2DiagnosticSsmDispatcher {
    pub fn new(client: aws_sdk_ssm::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl McpEc2DiagnosticSsmDispatcher for AwsMcpEc2DiagnosticSsmDispatcher {
    async fn dispatch(
        &self,
        input: &McpEc2DiagnosticSsmSendCommandInput,
    ) -> Result<String, McpEc2DiagnosticSsmDispatcherError> {
        let response = build_mcp_ec2_diagnostic_aws_send_command(&self.client, input)
            .send()
            .await
            .map_err(|_| McpEc2DiagnosticSsmDispatcherError::Backend)?;
        response
            .command()
            .and_then(|command| command.command_id())
            .map(str::to_string)
            .ok_or(McpEc2DiagnosticSsmDispatcherError::MissingCommandId)
    }
}

fn mcp_ec2_dispatch_document_version_is_pinned(version: &str) -> bool {
    !version.is_empty()
        && version != "$LATEST"
        && version != "$DEFAULT"
        && version.bytes().all(|byte| byte.is_ascii_digit())
        && version != "0"
}

fn mcp_ec2_command_id_shape_is_allowed(command_id: &str) -> bool {
    let bytes = command_id.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
}

fn mcp_ec2_instance_id_shape_is_allowed(instance_id: &str) -> bool {
    let Some(hex) = instance_id.strip_prefix("i-") else {
        return false;
    };
    matches!(hex.len(), 8 | 17) && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn mcp_ec2_helper_version_shape_is_allowed(version: &str) -> bool {
    let Some((date, suffix)) = version.split_once('.') else {
        return mcp_ec2_is_yyyy_mm_dd(version);
    };
    mcp_ec2_is_yyyy_mm_dd(date)
        && !suffix.is_empty()
        && suffix.bytes().all(|byte| byte.is_ascii_digit())
}

fn mcp_ec2_is_yyyy_mm_dd(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[8..10].iter().all(u8::is_ascii_digit)
}

fn mcp_ec2_command_spec_ref_cipher(
    key_material: &str,
) -> Result<Aes256Gcm, McpEc2DiagnosticCommandSpecRefError> {
    if key_material.is_empty() {
        return Err(McpEc2DiagnosticCommandSpecRefError::EmptyKey);
    }
    let digest = Sha256::digest(key_material.as_bytes());
    Aes256Gcm::new_from_slice(&digest).map_err(|_| McpEc2DiagnosticCommandSpecRefError::Encrypt)
}

fn mcp_ec2_command_type_for_spec_ref(
    command: &McpEc2DiagnosticCommand,
) -> McpEc2DiagnosticCommandType {
    match command {
        McpEc2DiagnosticCommand::TailLog { .. } => McpEc2DiagnosticCommandType::TailLog,
        McpEc2DiagnosticCommand::GrepLog { .. } => McpEc2DiagnosticCommandType::GrepLog,
        McpEc2DiagnosticCommand::JournalctlUnit { .. } => {
            McpEc2DiagnosticCommandType::JournalctlUnit
        }
        McpEc2DiagnosticCommand::HttpHead { .. } => McpEc2DiagnosticCommandType::HttpHead,
        McpEc2DiagnosticCommand::TcpProbe { .. } => McpEc2DiagnosticCommandType::TcpProbe,
        McpEc2DiagnosticCommand::DnsLookup { .. } => McpEc2DiagnosticCommandType::DnsLookup,
    }
}

pub const MCP_EC2_UNTRUSTED_OUTPUT_BEGIN: &str = "-----BEGIN CANOPY UNTRUSTED REMOTE OUTPUT-----";
pub const MCP_EC2_UNTRUSTED_OUTPUT_END: &str = "-----END CANOPY UNTRUSTED REMOTE OUTPUT-----";
const MCP_EC2_REDACTED: &str = "[REDACTED]";
const MCP_EC2_REDACTED_PRIVATE_KEY: &str = "[REDACTED PRIVATE KEY]";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpEc2DiagnosticFormattedOutput {
    pub output_text: String,
    pub output_bytes: u64,
    pub dropped_bytes: u64,
    pub truncated: bool,
}

pub fn format_mcp_ec2_diagnostic_output(
    remote_output_text: &str,
    max_output_text_bytes: usize,
) -> McpEc2DiagnosticFormattedOutput {
    let sanitized = strip_terminal_control_sequences(remote_output_text);
    let redacted = redact_mcp_ec2_sensitive_output(&sanitized);
    let prefixed = prefix_untrusted_lines(&redacted);
    let boundary_overhead =
        MCP_EC2_UNTRUSTED_OUTPUT_BEGIN.len() + 1 + MCP_EC2_UNTRUSTED_OUTPUT_END.len() + 1;
    let body_budget = max_output_text_bytes.saturating_sub(boundary_overhead);
    let (mut body, dropped_bytes) = truncate_utf8(&prefixed, body_budget);
    if !body.is_empty() && !body.ends_with('\n') {
        body.push('\n');
    }

    let output_text =
        format!("{MCP_EC2_UNTRUSTED_OUTPUT_BEGIN}\n{body}{MCP_EC2_UNTRUSTED_OUTPUT_END}");
    McpEc2DiagnosticFormattedOutput {
        output_bytes: output_text.len() as u64,
        dropped_bytes: dropped_bytes as u64,
        truncated: dropped_bytes > 0,
        output_text,
    }
}

fn prefix_untrusted_lines(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }

    let mut output = String::new();
    for line in input.split('\n') {
        output.push_str("| ");
        output.push_str(line);
        output.push('\n');
    }
    output
}

fn truncate_utf8(input: &str, max_bytes: usize) -> (String, usize) {
    if input.len() <= max_bytes {
        return (input.to_string(), 0);
    }
    let mut end = max_bytes.min(input.len());
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    (input[..end].to_string(), input.len() - end)
}

fn strip_terminal_control_sequences(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            consume_escape_sequence(&mut chars);
            continue;
        }

        if ch == '\r' {
            if matches!(chars.peek(), Some('\n')) {
                continue;
            }
            output.push('\n');
            continue;
        }

        if ch.is_control() && ch != '\n' && ch != '\t' {
            continue;
        }

        output.push(ch);
    }

    output
}

fn consume_escape_sequence<I>(chars: &mut std::iter::Peekable<I>)
where
    I: Iterator<Item = char>,
{
    let Some(kind) = chars.next() else {
        return;
    };

    match kind {
        '[' => {
            for ch in chars.by_ref() {
                if ('\u{40}'..='\u{7e}').contains(&ch) {
                    break;
                }
            }
        }
        ']' => consume_until_string_terminator(chars),
        'P' | 'X' | '^' | '_' => consume_until_string_terminator(chars),
        _ => {}
    }
}

fn consume_until_string_terminator<I>(chars: &mut std::iter::Peekable<I>)
where
    I: Iterator<Item = char>,
{
    while let Some(ch) = chars.next() {
        if ch == '\u{7}' {
            break;
        }
        if ch == '\x1b' && matches!(chars.peek(), Some('\\')) {
            chars.next();
            break;
        }
    }
}

fn redact_mcp_ec2_sensitive_output(input: &str) -> String {
    let mut lines = Vec::new();
    let mut in_private_key = false;

    for line in input.split('\n') {
        let lower = line.to_ascii_lowercase();
        let starts_private_key =
            lower.contains("-----begin ") && lower.contains("private key-----");
        let ends_private_key = lower.contains("-----end ") && lower.contains("private key-----");

        if starts_private_key {
            lines.push(MCP_EC2_REDACTED_PRIVATE_KEY.to_string());
            in_private_key = !ends_private_key;
            continue;
        }
        if in_private_key {
            if ends_private_key {
                in_private_key = false;
            }
            continue;
        }

        lines.push(redact_sensitive_line(line));
    }

    lines.join("\n")
}

fn redact_sensitive_line(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    if lower.contains("authorization:")
        || lower.contains("set-cookie:")
        || lower.contains("cookie:")
        || contains_sensitive_assignment(&lower)
    {
        return MCP_EC2_REDACTED.to_string();
    }

    let line = redact_bearer_tokens(line);
    redact_aws_access_key_tokens(&line)
}

fn contains_sensitive_assignment(lower_line: &str) -> bool {
    for key in [
        "password",
        "passwd",
        "api_key",
        "apikey",
        "client_secret",
        "secret_key",
        "session_token",
        "aws_access_key_id",
        "aws_secret_access_key",
    ] {
        let mut search_from = 0;
        while let Some(relative) = lower_line[search_from..].find(key) {
            let start = search_from + relative;
            let after = lower_line[start + key.len()..].trim_start();
            if after.starts_with('=') || after.starts_with(':') {
                return true;
            }
            search_from = start + key.len();
        }
    }
    false
}

fn redact_bearer_tokens(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    let mut output = String::new();
    let mut search_from = 0;
    let marker = "bearer ";

    while let Some(relative) = lower[search_from..].find(marker) {
        let start = search_from + relative;
        let token_start = start + marker.len();
        output.push_str(&line[search_from..token_start]);

        let token_end = line[token_start..]
            .find(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | ';'))
            .map(|end| token_start + end)
            .unwrap_or_else(|| line.len());
        output.push_str(MCP_EC2_REDACTED);
        search_from = token_end;
    }

    output.push_str(&line[search_from..]);
    output
}

fn redact_aws_access_key_tokens(line: &str) -> String {
    let mut output = String::new();
    let mut token = String::new();

    for ch in line.chars() {
        if ch.is_ascii_alphanumeric() {
            token.push(ch);
            continue;
        }

        flush_redactable_token(&mut output, &mut token);
        output.push(ch);
    }

    flush_redactable_token(&mut output, &mut token);
    output
}

fn flush_redactable_token(output: &mut String, token: &mut String) {
    if token.is_empty() {
        return;
    }
    if is_aws_access_key_id(token) {
        output.push_str(MCP_EC2_REDACTED);
    } else {
        output.push_str(token);
    }
    token.clear();
}

fn is_aws_access_key_id(token: &str) -> bool {
    token.len() == 20
        && (token.starts_with("AKIA") || token.starts_with("ASIA"))
        && token
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
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
    ) -> Result<Option<McpEc2DiagnosticCommandStoreClaim>, McpEc2DiagnosticCommandStoreError>;

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
    ) -> Result<Option<McpEc2DiagnosticCommandStoreClaim>, McpEc2DiagnosticCommandStoreError> {
        let Some(mut record) = self.commands.get_mut(command_id) else {
            return Ok(None);
        };
        if record.actor != actor
            || record.mcp_session_id != mcp_session_id
            || record.local_secret_generation != local_secret_generation
            || record.is_expired_at(now)
            || record.status != McpEc2DiagnosticCommandStatus::Queued
            || record.aws_ssm_command_id.is_some()
        {
            return Ok(None);
        }
        record.aws_ssm_command_id = Some(aws_ssm_command_id.to_string());
        record.status = McpEc2DiagnosticCommandStatus::Running;
        record.updated_at = now;
        Ok(Some(McpEc2DiagnosticCommandStoreClaim::new(
            command_id,
            actor,
            mcp_session_id,
            local_secret_generation,
            aws_ssm_command_id,
            now,
        )))
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
    ) -> Result<Option<McpEc2DiagnosticCommandStoreClaim>, McpEc2DiagnosticCommandStoreError> {
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
            Ok(_) => Ok(Some(McpEc2DiagnosticCommandStoreClaim::new(
                command_id,
                actor,
                mcp_session_id,
                local_secret_generation,
                aws_ssm_command_id,
                now,
            ))),
            Err(err)
                if err
                    .as_service_error()
                    .is_some_and(UpdateItemError::is_conditional_check_failed_exception) =>
            {
                Ok(None)
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

    fn spec_ref_payload(now: DateTime<Utc>) -> McpEc2DiagnosticCommandSpecRefPayload {
        McpEc2DiagnosticCommandSpecRefPayload {
            version: 1,
            helper_version: MCP_EC2_COMMAND_SPEC_HELPER_VERSION.into(),
            mcp_ec2_command_id: "mcp-ec2-cmd-1".into(),
            actor: "actor-1".into(),
            mcp_session_id: "mcp-session-1".into(),
            local_secret_generation: "lsg_1".into(),
            instance_id: "i-0123456789abcdef0".into(),
            account_id: "123456789012".into(),
            region: "ap-northeast-1".into(),
            command_type: McpEc2DiagnosticCommandType::GrepLog,
            command: McpEc2DiagnosticCommand::GrepLog {
                path: "/tmp/canopy-safe/app.log".into(),
                literal_pattern: "request-id".into(),
                case_insensitive: true,
                max_matches: 10,
            },
            one_time_command_store_claim_required: true,
            allowlist_rule_id: "allow-app-log-v1".into(),
            command_scope_id: "app-log-grep".into(),
            issued_at: now,
            expires_at: now + Duration::minutes(5),
        }
    }

    fn spec_ref_claim(now: DateTime<Utc>) -> McpEc2DiagnosticCommandStoreClaim {
        McpEc2DiagnosticCommandStoreClaim::new(
            "mcp-ec2-cmd-1",
            "actor-1",
            "mcp-session-1",
            "lsg_1",
            "ssm-command-1",
            now,
        )
    }

    fn spec_ref_binding<'a>(
        now: DateTime<Utc>,
        claim: &'a McpEc2DiagnosticCommandStoreClaim,
    ) -> McpEc2DiagnosticCommandSpecRefBinding<'a> {
        McpEc2DiagnosticCommandSpecRefBinding {
            helper_version: MCP_EC2_COMMAND_SPEC_HELPER_VERSION,
            mcp_ec2_command_id: "mcp-ec2-cmd-1",
            actor: "actor-1",
            mcp_session_id: "mcp-session-1",
            local_secret_generation: "lsg_1",
            instance_id: "i-0123456789abcdef0",
            account_id: "123456789012",
            region: "ap-northeast-1",
            allowlist_rule_id: "allow-app-log-v1",
            command_scope_id: "app-log-grep",
            command_store_claim: claim,
            now,
        }
    }

    fn ssm_dispatch_config() -> McpConfig {
        let mut config = McpConfig::default();
        config.ec2_diagnostic_ssm_document_name = Some("Canopy-Ec2Diagnostics".into());
        config.ec2_diagnostic_ssm_document_version = Some("7".into());
        config.ec2_diagnostic_helper_version = Some(MCP_EC2_COMMAND_SPEC_HELPER_VERSION.into());
        config
    }

    #[test]
    fn command_spec_ref_round_trips_without_exposing_command_fields() {
        let now = Utc::now();
        let payload = spec_ref_payload(now);
        let claim = spec_ref_claim(now);

        let command_spec_ref =
            seal_mcp_ec2_diagnostic_command_spec_ref("spec-ref-key", &payload, now).unwrap();

        assert!(command_spec_ref.starts_with(MCP_EC2_COMMAND_SPEC_REF_PREFIX));
        assert!(command_spec_ref.len() <= MCP_EC2_COMMAND_SPEC_REF_MAX_LEN);
        assert!(mcp_ec2_command_spec_ref_shape_is_allowed(&command_spec_ref));
        assert_eq!(
            MCP_EC2_COMMAND_SPEC_REF_MAX_LEN,
            MCP_EC2_COMMAND_SPEC_REF_PREFIX.len()
                + MCP_EC2_COMMAND_SPEC_REF_NONCE_LEN
                + 1
                + MCP_EC2_COMMAND_SPEC_REF_CIPHERTEXT_MAX_LEN
        );
        assert!(!command_spec_ref.contains("/tmp/canopy-safe/app.log"));
        assert!(!command_spec_ref.contains("request-id"));
        assert!(!command_spec_ref.contains("grep_log"));
        assert!(!format!("{payload:?}").contains("/tmp/canopy-safe/app.log"));
        assert!(!format!("{payload:?}").contains("request-id"));

        let opened = open_mcp_ec2_diagnostic_command_spec_ref(
            "spec-ref-key",
            &command_spec_ref,
            &spec_ref_binding(now, &claim),
        )
        .unwrap();
        assert_eq!(opened, payload);
    }

    #[test]
    fn command_spec_ref_rejects_tampering_wrong_key_and_binding_mismatch() {
        let now = Utc::now();
        let payload = spec_ref_payload(now);
        let claim = spec_ref_claim(now);
        let command_spec_ref =
            seal_mcp_ec2_diagnostic_command_spec_ref("spec-ref-key", &payload, now).unwrap();

        assert_eq!(
            open_mcp_ec2_diagnostic_command_spec_ref(
                "wrong-key",
                &command_spec_ref,
                &spec_ref_binding(now, &claim)
            )
            .unwrap_err(),
            McpEc2DiagnosticCommandSpecRefError::AuthenticationFailed
        );

        let mut tampered = command_spec_ref.clone();
        let ciphertext_start =
            MCP_EC2_COMMAND_SPEC_REF_PREFIX.len() + MCP_EC2_COMMAND_SPEC_REF_NONCE_LEN + 1;
        let replacement = if tampered.as_bytes()[ciphertext_start] == b'A' {
            'B'
        } else {
            'A'
        };
        tampered.replace_range(
            ciphertext_start..ciphertext_start + 1,
            &replacement.to_string(),
        );
        assert_eq!(
            open_mcp_ec2_diagnostic_command_spec_ref(
                "spec-ref-key",
                &tampered,
                &spec_ref_binding(now, &claim)
            )
            .unwrap_err(),
            McpEc2DiagnosticCommandSpecRefError::AuthenticationFailed
        );

        let wrong_target = McpEc2DiagnosticCommandSpecRefBinding {
            instance_id: "i-11111111111111111",
            ..spec_ref_binding(now, &claim)
        };
        assert_eq!(
            payload.validate_binding(&wrong_target).unwrap_err(),
            McpEc2DiagnosticCommandSpecRefError::BindingMismatch("instance_id")
        );

        let wrong_scope = McpEc2DiagnosticCommandSpecRefBinding {
            command_scope_id: "different-scope",
            ..spec_ref_binding(now, &claim)
        };
        assert_eq!(
            payload.validate_binding(&wrong_scope).unwrap_err(),
            McpEc2DiagnosticCommandSpecRefError::BindingMismatch("command_scope_id")
        );

        let wrong_claim = McpEc2DiagnosticCommandStoreClaim::new(
            "mcp-ec2-cmd-1",
            "actor-1",
            "other-session",
            "lsg_1",
            "ssm-command-1",
            now,
        );
        let wrong_claim_binding = spec_ref_binding(now, &wrong_claim);
        assert_eq!(
            open_mcp_ec2_diagnostic_command_spec_ref(
                "spec-ref-key",
                &command_spec_ref,
                &wrong_claim_binding
            )
            .unwrap_err(),
            McpEc2DiagnosticCommandSpecRefError::BindingMismatch("one_time_command_store_claim")
        );

        let expired = McpEc2DiagnosticCommandSpecRefBinding {
            now: now + Duration::minutes(10),
            ..spec_ref_binding(now, &claim)
        };
        assert_eq!(
            payload.validate_binding(&expired).unwrap_err(),
            McpEc2DiagnosticCommandSpecRefError::Expired
        );
    }

    #[test]
    fn command_spec_ref_seal_rejects_invalid_lifetime_and_unclaimed_payloads() {
        let now = Utc::now();

        let mut not_claim_required = spec_ref_payload(now);
        not_claim_required.one_time_command_store_claim_required = false;
        assert_eq!(
            seal_mcp_ec2_diagnostic_command_spec_ref("spec-ref-key", &not_claim_required, now)
                .unwrap_err(),
            McpEc2DiagnosticCommandSpecRefError::BindingMismatch("one_time_command_store_claim")
        );

        let mut expires_before_issued = spec_ref_payload(now);
        expires_before_issued.expires_at = now;
        assert_eq!(
            seal_mcp_ec2_diagnostic_command_spec_ref("spec-ref-key", &expires_before_issued, now)
                .unwrap_err(),
            McpEc2DiagnosticCommandSpecRefError::BindingMismatch("expires_at")
        );

        let mut too_long_ttl = spec_ref_payload(now);
        too_long_ttl.expires_at =
            now + Duration::seconds(MCP_EC2_COMMAND_SPEC_REF_MAX_TTL_SECONDS + 1);
        assert_eq!(
            seal_mcp_ec2_diagnostic_command_spec_ref("spec-ref-key", &too_long_ttl, now)
                .unwrap_err(),
            McpEc2DiagnosticCommandSpecRefError::BindingMismatch("ttl")
        );

        let mut issued_in_future = spec_ref_payload(now);
        issued_in_future.issued_at = now + Duration::minutes(2);
        issued_in_future.expires_at = issued_in_future.issued_at + Duration::minutes(1);
        assert_eq!(
            seal_mcp_ec2_diagnostic_command_spec_ref("spec-ref-key", &issued_in_future, now)
                .unwrap_err(),
            McpEc2DiagnosticCommandSpecRefError::BindingMismatch("issued_at")
        );
    }

    #[test]
    fn command_spec_ref_verification_blocks_shape_valid_untrusted_refs_before_dispatch() {
        let now = Utc::now();
        let payload = spec_ref_payload(now);
        let claim = spec_ref_claim(now);
        let binding = spec_ref_binding(now, &claim);
        let command_spec_ref =
            seal_mcp_ec2_diagnostic_command_spec_ref("spec-ref-key", &payload, now).unwrap();

        let shape_valid_untrusted = format!(
            "{}{}.{}",
            MCP_EC2_COMMAND_SPEC_REF_PREFIX,
            "A".repeat(MCP_EC2_COMMAND_SPEC_REF_NONCE_LEN),
            "A".repeat(64)
        );
        assert!(mcp_ec2_command_spec_ref_shape_is_allowed(
            &shape_valid_untrusted
        ));
        assert_eq!(
            verify_mcp_ec2_diagnostic_command_spec_ref(
                "spec-ref-key",
                &shape_valid_untrusted,
                &binding,
            )
            .unwrap_err(),
            McpEc2DiagnosticCommandSpecRefError::AuthenticationFailed
        );

        let wrong_target = McpEc2DiagnosticCommandSpecRefBinding {
            instance_id: "i-11111111111111111",
            ..spec_ref_binding(now, &claim)
        };
        assert_eq!(
            verify_mcp_ec2_diagnostic_command_spec_ref(
                "spec-ref-key",
                &command_spec_ref,
                &wrong_target,
            )
            .unwrap_err(),
            McpEc2DiagnosticCommandSpecRefError::BindingMismatch("instance_id")
        );

        let verified =
            verify_mcp_ec2_diagnostic_command_spec_ref("spec-ref-key", &command_spec_ref, &binding)
                .unwrap();
        assert_eq!(verified.as_str(), command_spec_ref.as_str());
        assert_eq!(verified.mcp_ec2_command_id(), "mcp-ec2-cmd-1");
        assert_eq!(verified.instance_id(), "i-0123456789abcdef0");
        assert_eq!(
            verified.helper_version(),
            MCP_EC2_COMMAND_SPEC_HELPER_VERSION
        );
        assert!(!format!("{verified:?}").contains(&command_spec_ref));
        assert!(!format!("{verified:?}").contains("/tmp/canopy-safe/app.log"));
    }

    #[test]
    fn ssm_dispatch_request_uses_only_opaque_parameters_and_disabled_output_sinks() {
        let now = Utc::now();
        let payload = spec_ref_payload(now);
        let claim = spec_ref_claim(now);
        let command_spec_ref =
            seal_mcp_ec2_diagnostic_command_spec_ref("spec-ref-key", &payload, now).unwrap();
        let verified_command_spec_ref = verify_mcp_ec2_diagnostic_command_spec_ref(
            "spec-ref-key",
            &command_spec_ref,
            &spec_ref_binding(now, &claim),
        )
        .unwrap();
        let request = build_mcp_ec2_diagnostic_ssm_dispatch_request(
            &ssm_dispatch_config(),
            "mcp-ec2-cmd-1",
            "i-0123456789abcdef0",
            &verified_command_spec_ref,
        )
        .unwrap();

        assert_eq!(request.document_name(), "Canopy-Ec2Diagnostics");
        assert_eq!(request.document_version(), "7");
        assert_eq!(request.instance_id(), "i-0123456789abcdef0");
        assert_eq!(
            request.timeout_seconds(),
            MCP_EC2_DIAGNOSTIC_SSM_TIMEOUT_SECONDS
        );
        assert_eq!(
            request.parameters().keys().cloned().collect::<Vec<_>>(),
            vec!["commandSpecRef", "helperVersion", "mcpEc2CommandId"]
        );
        assert_eq!(request.command_spec_ref(), Some(command_spec_ref.as_str()));
        assert_eq!(
            request.helper_version(),
            Some(MCP_EC2_COMMAND_SPEC_HELPER_VERSION)
        );
        assert!(!request.cloudwatch_output_enabled());
        assert!(!request.s3_output_enabled());

        let parameters = format!("{:?}", request.parameters());
        assert!(!parameters.contains("/tmp/canopy-safe/app.log"));
        assert!(!parameters.contains("request-id"));
        assert!(!parameters.contains("grep_log"));

        let request_debug = format!("{request:?}");
        assert!(!request_debug.contains(&command_spec_ref));
        assert!(!request_debug.contains("/tmp/canopy-safe/app.log"));
        assert!(!request_debug.contains("request-id"));
        assert!(!request_debug.contains("grep_log"));
    }

    #[test]
    fn ssm_dispatch_request_fails_closed_without_pinned_config_or_valid_ref() {
        let now = Utc::now();
        let payload = spec_ref_payload(now);
        let claim = spec_ref_claim(now);
        let command_spec_ref =
            seal_mcp_ec2_diagnostic_command_spec_ref("spec-ref-key", &payload, now).unwrap();
        let verified_command_spec_ref = verify_mcp_ec2_diagnostic_command_spec_ref(
            "spec-ref-key",
            &command_spec_ref,
            &spec_ref_binding(now, &claim),
        )
        .unwrap();

        assert_eq!(
            build_mcp_ec2_diagnostic_ssm_dispatch_request(
                &McpConfig::default(),
                "mcp-ec2-cmd-1",
                "i-0123456789abcdef0",
                &verified_command_spec_ref,
            )
            .unwrap_err(),
            McpEc2DiagnosticDispatchError::DispatchNotConfigured
        );

        let mut unpinned = ssm_dispatch_config();
        unpinned.ec2_diagnostic_ssm_document_version = Some("$LATEST".into());
        assert_eq!(
            build_mcp_ec2_diagnostic_ssm_dispatch_request(
                &unpinned,
                "mcp-ec2-cmd-1",
                "i-0123456789abcdef0",
                &verified_command_spec_ref,
            )
            .unwrap_err(),
            McpEc2DiagnosticDispatchError::UnpinnedDocumentVersion
        );

        let mut wrong_document = ssm_dispatch_config();
        wrong_document.ec2_diagnostic_ssm_document_name = Some("OtherDocument".into());
        assert_eq!(
            build_mcp_ec2_diagnostic_ssm_dispatch_request(
                &wrong_document,
                "mcp-ec2-cmd-1",
                "i-0123456789abcdef0",
                &verified_command_spec_ref,
            )
            .unwrap_err(),
            McpEc2DiagnosticDispatchError::InvalidInput("document_name")
        );

        let mut invalid_helper = ssm_dispatch_config();
        invalid_helper.ec2_diagnostic_helper_version = Some("latest".into());
        assert_eq!(
            build_mcp_ec2_diagnostic_ssm_dispatch_request(
                &invalid_helper,
                "mcp-ec2-cmd-1",
                "i-0123456789abcdef0",
                &verified_command_spec_ref,
            )
            .unwrap_err(),
            McpEc2DiagnosticDispatchError::InvalidInput("helper_version")
        );

        let mut blank_helper = ssm_dispatch_config();
        blank_helper.ec2_diagnostic_helper_version = Some("   ".into());
        assert_eq!(
            build_mcp_ec2_diagnostic_ssm_dispatch_request(
                &blank_helper,
                "mcp-ec2-cmd-1",
                "i-0123456789abcdef0",
                &verified_command_spec_ref,
            )
            .unwrap_err(),
            McpEc2DiagnosticDispatchError::InvalidInput("helper_version")
        );

        let mut mismatched_helper = ssm_dispatch_config();
        mismatched_helper.ec2_diagnostic_helper_version = Some("2026-06-04.2".into());
        assert_eq!(
            build_mcp_ec2_diagnostic_ssm_dispatch_request(
                &mismatched_helper,
                "mcp-ec2-cmd-1",
                "i-0123456789abcdef0",
                &verified_command_spec_ref,
            )
            .unwrap_err(),
            McpEc2DiagnosticDispatchError::InvalidInput("helper_version")
        );

        assert_eq!(
            build_mcp_ec2_diagnostic_ssm_dispatch_request(
                &ssm_dispatch_config(),
                "/tmp/canopy-safe/app.log",
                "i-0123456789abcdef0",
                &verified_command_spec_ref,
            )
            .unwrap_err(),
            McpEc2DiagnosticDispatchError::InvalidInput("mcp_ec2_command_id")
        );

        assert_eq!(
            build_mcp_ec2_diagnostic_ssm_dispatch_request(
                &ssm_dispatch_config(),
                "mcp-ec2-cmd-1",
                "/tmp/canopy-safe/app.log",
                &verified_command_spec_ref,
            )
            .unwrap_err(),
            McpEc2DiagnosticDispatchError::InvalidInput("instance_id")
        );
    }

    #[test]
    fn ssm_dispatch_request_rejects_verified_ref_target_mismatch() {
        let now = Utc::now();
        let payload = spec_ref_payload(now);
        let claim = spec_ref_claim(now);
        let command_spec_ref =
            seal_mcp_ec2_diagnostic_command_spec_ref("spec-ref-key", &payload, now).unwrap();
        let verified_command_spec_ref = verify_mcp_ec2_diagnostic_command_spec_ref(
            "spec-ref-key",
            &command_spec_ref,
            &spec_ref_binding(now, &claim),
        )
        .unwrap();

        assert_eq!(
            build_mcp_ec2_diagnostic_ssm_dispatch_request(
                &ssm_dispatch_config(),
                "mcp-ec2-cmd-2",
                "i-0123456789abcdef0",
                &verified_command_spec_ref,
            )
            .unwrap_err(),
            McpEc2DiagnosticDispatchError::InvalidInput("mcp_ec2_command_id")
        );

        assert_eq!(
            build_mcp_ec2_diagnostic_ssm_dispatch_request(
                &ssm_dispatch_config(),
                "mcp-ec2-cmd-1",
                "i-11111111111111111",
                &verified_command_spec_ref,
            )
            .unwrap_err(),
            McpEc2DiagnosticDispatchError::InvalidInput("instance_id")
        );
    }

    #[test]
    fn ssm_send_command_input_maps_to_single_target_pinned_document_and_disabled_sinks() {
        let now = Utc::now();
        let payload = spec_ref_payload(now);
        let claim = spec_ref_claim(now);
        let command_spec_ref =
            seal_mcp_ec2_diagnostic_command_spec_ref("spec-ref-key", &payload, now).unwrap();
        let verified_command_spec_ref = verify_mcp_ec2_diagnostic_command_spec_ref(
            "spec-ref-key",
            &command_spec_ref,
            &spec_ref_binding(now, &claim),
        )
        .unwrap();
        let dispatch_request = build_mcp_ec2_diagnostic_ssm_dispatch_request(
            &ssm_dispatch_config(),
            "mcp-ec2-cmd-1",
            "i-0123456789abcdef0",
            &verified_command_spec_ref,
        )
        .unwrap();
        let input = build_mcp_ec2_diagnostic_ssm_send_command_input(&dispatch_request).unwrap();

        assert_eq!(input.document_name(), "Canopy-Ec2Diagnostics");
        assert_eq!(input.document_version(), "7");
        assert_eq!(input.instance_ids(), &["i-0123456789abcdef0".to_string()]);
        assert_eq!(
            input.timeout_seconds(),
            MCP_EC2_DIAGNOSTIC_SSM_TIMEOUT_SECONDS
        );
        assert_eq!(
            input.parameter_keys(),
            vec!["commandSpecRef", "helperVersion", "mcpEc2CommandId"]
        );
        assert_eq!(
            input.max_concurrency(),
            MCP_EC2_DIAGNOSTIC_SSM_MAX_CONCURRENCY
        );
        assert_eq!(input.max_errors(), MCP_EC2_DIAGNOSTIC_SSM_MAX_ERRORS);
        assert!(!input.cloudwatch_output_enabled());
        assert!(!input.s3_output_enabled());

        let input_debug = format!("{input:?}");
        assert!(!input_debug.contains(&command_spec_ref));
        assert!(!input_debug.contains("/tmp/canopy-safe/app.log"));
        assert!(!input_debug.contains("request-id"));
        assert!(!input_debug.contains("grep_log"));

        let sdk_config = aws_config::SdkConfig::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new("ap-northeast-1"))
            .build();
        let client = aws_sdk_ssm::Client::new(&sdk_config);
        let builder = build_mcp_ec2_diagnostic_aws_send_command(&client, &input);
        let aws_input = builder.as_input();

        assert_eq!(
            aws_input.get_document_name().as_deref(),
            Some("Canopy-Ec2Diagnostics")
        );
        assert_eq!(aws_input.get_document_version().as_deref(), Some("7"));
        assert_eq!(
            aws_input.get_instance_ids().as_ref().unwrap(),
            &vec!["i-0123456789abcdef0".to_string()]
        );
        assert!(aws_input.get_targets().is_none());
        assert_eq!(
            aws_input.get_timeout_seconds(),
            &Some(MCP_EC2_DIAGNOSTIC_SSM_TIMEOUT_SECONDS)
        );
        assert_eq!(
            aws_input.get_max_concurrency().as_deref(),
            Some(MCP_EC2_DIAGNOSTIC_SSM_MAX_CONCURRENCY)
        );
        assert_eq!(
            aws_input.get_max_errors().as_deref(),
            Some(MCP_EC2_DIAGNOSTIC_SSM_MAX_ERRORS)
        );
        assert!(aws_input.get_output_s3_region().is_none());
        assert!(aws_input.get_output_s3_bucket_name().is_none());
        assert!(aws_input.get_output_s3_key_prefix().is_none());
        let cloudwatch_config = aws_input.get_cloud_watch_output_config().as_ref().unwrap();
        assert!(!cloudwatch_config.cloud_watch_output_enabled());
        assert!(cloudwatch_config.cloud_watch_log_group_name().is_none());

        let parameters = aws_input.get_parameters().as_ref().unwrap();
        let mut keys = parameters.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["commandSpecRef", "helperVersion", "mcpEc2CommandId"]
        );
        let parameters_debug = format!("{parameters:?}");
        assert!(!parameters_debug.contains("/tmp/canopy-safe/app.log"));
        assert!(!parameters_debug.contains("request-id"));
        assert!(!parameters_debug.contains("grep_log"));
    }

    #[test]
    fn formatter_wraps_prefixes_strips_controls_and_redacts_sensitive_output() {
        let raw = format!(
            "\x1b[31mERROR\x1b[0m\r\n{} {}\n{}super-secret\naws_access_key_id={}\n{}\nbody\n-----END PRIVATE KEY-----",
            concat!("Author", "ization:"),
            concat!("Bearer", " eyJhbGciOiJIUzI1NiJ9.payload.signature"),
            concat!("pass", "word="),
            concat!("AKIA", "IOSFODNN7EXAMPLE"),
            concat!("-----BEGIN ", "PRIVATE KEY-----"),
        );

        let formatted = format_mcp_ec2_diagnostic_output(&raw, 4096);

        assert!(!formatted.truncated);
        assert_eq!(formatted.dropped_bytes, 0);
        assert!(formatted
            .output_text
            .starts_with(MCP_EC2_UNTRUSTED_OUTPUT_BEGIN));
        assert!(formatted
            .output_text
            .ends_with(MCP_EC2_UNTRUSTED_OUTPUT_END));
        assert!(formatted.output_text.contains("| ERROR"));
        assert!(formatted.output_text.contains("| [REDACTED]"));
        assert!(formatted.output_text.contains("| [REDACTED PRIVATE KEY]"));
        assert!(!formatted.output_text.contains('\x1b'));
        assert!(!formatted.output_text.contains("super-secret"));
        assert!(!formatted.output_text.contains("eyJhbGci"));
        assert!(!formatted.output_text.contains("AKIA"));
        assert!(!formatted.output_text.contains("PRIVATE KEY-----\n| body"));

        for line in formatted.output_text.lines().skip(1) {
            if line == MCP_EC2_UNTRUSTED_OUTPUT_END {
                break;
            }
            assert!(
                line.starts_with("| "),
                "remote output line must be visibly marked untrusted: {line:?}"
            );
        }
    }

    #[test]
    fn formatter_truncates_without_splitting_utf8() {
        let raw = "ok αβγ\n".repeat(64);
        let budget = MCP_EC2_UNTRUSTED_OUTPUT_BEGIN.len() + MCP_EC2_UNTRUSTED_OUTPUT_END.len() + 32;

        let formatted = format_mcp_ec2_diagnostic_output(&raw, budget);

        assert!(formatted.truncated);
        assert!(formatted.dropped_bytes > 0);
        assert!(formatted
            .output_text
            .is_char_boundary(formatted.output_text.len()));
        assert!(formatted
            .output_text
            .starts_with(MCP_EC2_UNTRUSTED_OUTPUT_BEGIN));
        assert!(formatted
            .output_text
            .ends_with(MCP_EC2_UNTRUSTED_OUTPUT_END));
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

        let claim = store
            .mark_dispatched(
                "cmd-1",
                "actor-1",
                "mcp-session-1",
                "lsg_1",
                "ssm-command-1",
                now + Duration::seconds(1),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claim.command_id(), "cmd-1");
        assert_eq!(claim.aws_ssm_command_id(), "ssm-command-1");
        assert_eq!(claim.claimed_at(), now + Duration::seconds(1));
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
        assert!(store
            .mark_dispatched(
                "cmd-1",
                "actor-1",
                "other-session",
                "lsg_1",
                "ssm-command-1",
                now,
            )
            .await
            .unwrap()
            .is_none());
        assert!(store
            .mark_dispatched(
                "cmd-1",
                "actor-1",
                "mcp-session-1",
                "lsg_1",
                "ssm-command-1",
                now + Duration::minutes(16),
            )
            .await
            .unwrap()
            .is_none());
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
