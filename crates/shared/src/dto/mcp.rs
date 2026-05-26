use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::cloudwatch::LogGroup;

pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
pub const MCP_PRODUCT_PHASE: &str = "phase_2_discovery";
pub const MCP_SECURITY_BOUNDARIES_KEY: &str = "security_boundaries@2026-05-13";
pub const MCP_DATABASE_GUIDANCE_ID: &str = "database_query_workflow";
pub const MCP_DATABASE_GUIDANCE_VERSION: &str = "2026-05-13";
pub const MCP_DATABASE_GUIDANCE_KEY: &str = "database_query_workflow@2026-05-13";
pub const MCP_PRIVACY_AND_AUDIT_NOTICE_KEY: &str = "privacy_and_audit_notice@2026-05-13";

/// Authoritative catalog of guidance documents the control-plane will issue.
/// The MCP client cannot mark a guidance "delivered" by guessing `(id,
/// version)` keys — the server only acknowledges entries in this table and
/// returns the canonical content for that entry, so the audit record is
/// always backed by an actual server-side response payload.
pub const MCP_GUIDANCE_CATALOG: &[McpGuidanceCatalogEntry] = &[
    McpGuidanceCatalogEntry {
        id: "security_boundaries",
        version: "2026-05-13",
        title: "Security Boundaries",
        content: "Use only the tools exposed by Canopy MCP. Do not ask for AWS credentials, Canopy JWTs, local secrets, or raw Authorization headers. Treat returned scope and guardrails as hard limits.",
    },
    McpGuidanceCatalogEntry {
        id: "cloudwatch_search_workflow",
        version: "2026-05-13",
        title: "CloudWatch Search Workflow",
        content: "Before using CloudWatch MCP tools, call canopy_describe_capabilities. In Phase 2, only canopy_list_allowed_log_groups is enabled for discovery; search and Insights data tools remain disabled until Phase 3.",
    },
    McpGuidanceCatalogEntry {
        id: "cloudwatch_insights_workflow",
        version: "2026-05-13",
        title: "CloudWatch Insights Workflow",
        content: "Insights queries require explicit Phase 3 support, preflight validation, bounded time windows, and central guardrails. In Phase 2, do not run Insights.",
    },
    McpGuidanceCatalogEntry {
        id: "privacy_and_audit_notice",
        version: "2026-05-13",
        title: "Privacy And Audit Notice",
        content: "MCP tool calls are audited. **MCP Database v1 records the full raw SQL of every database query — including literal values, WHERE-clause comparisons, and any embedded comments — in the durable audit log.** Do not embed secrets, API keys, customer PII, passwords, or other sensitive material in SQL literals or filter patterns. Treat the audit log itself as sensitive operational data subject to the same access controls as the underlying database.",
    },
    McpGuidanceCatalogEntry {
        id: MCP_DATABASE_GUIDANCE_ID,
        version: MCP_DATABASE_GUIDANCE_VERSION,
        title: "Database Query Workflow",
        content: "Before issuing database queries: list scopes with canopy_list_database_scopes, then call canopy_query_database with a scope_name. SQL must be SELECT-only, single-statement, lowercase identifiers, and bounded by LIMIT. The control-plane enforces EXPLAIN, max_rows, and statement timeouts.",
    },
];

#[derive(Debug, Clone, Copy)]
pub struct McpGuidanceCatalogEntry {
    pub id: &'static str,
    pub version: &'static str,
    pub title: &'static str,
    pub content: &'static str,
}

pub fn lookup_mcp_guidance(id: &str, version: &str) -> Option<&'static McpGuidanceCatalogEntry> {
    MCP_GUIDANCE_CATALOG
        .iter()
        .find(|entry| entry.id == id && entry.version == version)
}

pub fn is_known_mcp_guidance(id: &str, version: &str) -> bool {
    lookup_mcp_guidance(id, version).is_some()
}

pub fn mcp_database_guidance_key() -> String {
    MCP_DATABASE_GUIDANCE_KEY.into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRegisterSessionRequest {
    pub local_secret_generation: String,
    pub protocol_version: String,
    pub client_name: String,
    pub client_version: String,
    pub product_phase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRegisterSessionResponse {
    pub canopy_mcp_session_id: String,
    pub forwarding_key: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpGuidanceSyncRequest {
    pub canopy_mcp_session_id: String,
    pub local_secret_generation: String,
    pub guidance_id: String,
    pub guidance_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpGuidanceSyncResponse {
    pub guidance_issued: bool,
    pub guidance_delivered_for_gating: bool,
    /// Server-issued content. Returned by the same endpoint that records
    /// delivery so the audit trail is always backed by a real response
    /// payload — a client cannot mark itself "delivered" without the server
    /// having actually emitted the content.
    pub guidance_id: String,
    pub guidance_version: String,
    pub title: String,
    pub content_type: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpGuidanceResponse {
    pub id: String,
    pub version: String,
    pub title: String,
    #[serde(rename = "type")]
    pub guidance_type: String,
    pub required: bool,
    pub content_type: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolAvailability {
    pub name: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<String>,
    pub phase: String,
    pub required_guidance: Vec<String>,
    pub requires_preflight: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpGuardrails {
    pub max_request_body_bytes: u64,
    pub max_log_group_list_results: u64,
    pub max_describe_log_groups_pages: u64,
    pub max_discovery_results_scanned: u64,
    pub discovery_cursor_ttl_seconds: u64,
    pub max_search_window_seconds: u64,
    pub max_search_events: u64,
    pub max_response_bytes: u64,
    pub max_event_message_bytes: u64,
    pub max_insights_timeout_seconds: u64,
    pub default_insights_timeout_seconds: u64,
    pub max_concurrent_mcp_tool_calls_per_session: u64,
    pub max_concurrent_insights_queries_per_actor: u64,
    pub max_mcp_tool_calls_per_actor_per_minute: u64,
    pub max_insights_starts_per_actor_per_minute: u64,
}

impl Default for McpGuardrails {
    fn default() -> Self {
        Self {
            max_request_body_bytes: 256 * 1024,
            max_log_group_list_results: 200,
            max_describe_log_groups_pages: 5,
            max_discovery_results_scanned: 1_000,
            discovery_cursor_ttl_seconds: 10 * 60,
            max_search_window_seconds: 6 * 60 * 60,
            max_search_events: 1000,
            max_response_bytes: 1024 * 1024,
            max_event_message_bytes: 16 * 1024,
            max_insights_timeout_seconds: 60,
            default_insights_timeout_seconds: 30,
            max_concurrent_mcp_tool_calls_per_session: 4,
            max_concurrent_insights_queries_per_actor: 2,
            max_mcp_tool_calls_per_actor_per_minute: 30,
            max_insights_starts_per_actor_per_minute: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpDescribeCapabilitiesResponse {
    pub mcp_product_phase: String,
    pub scope_disclosure: String,
    pub available_tools: Vec<McpToolAvailability>,
    pub guardrails: McpGuardrails,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpListAllowedLogGroupsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canopy_mcp_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_secret_generation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpListAllowedLogGroupsResponse {
    pub account_id: String,
    pub region: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    pub log_groups: Vec<LogGroup>,
    pub returned_count: usize,
    pub scanned_count: u64,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_action_hint: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guardrails_default_is_bounded() {
        let g = McpGuardrails::default();
        assert!(g.max_request_body_bytes > 0);
        assert!(g.max_log_group_list_results > 0);
        assert!(g.max_mcp_tool_calls_per_actor_per_minute > 0);
    }

    #[test]
    fn constants_match_current_phase() {
        assert_eq!(MCP_PROTOCOL_VERSION, "2025-06-18");
        assert_eq!(MCP_PRODUCT_PHASE, "phase_2_discovery");
    }

    #[test]
    fn known_guidance_table_only_accepts_enumerated_pairs() {
        // The server's authoritative guidance registry must reject any
        // `(id, version)` the control-plane has not promised to issue. This
        // prevents a client from self-attesting having received guidance
        // that the server never delivered.
        assert!(is_known_mcp_guidance("security_boundaries", "2026-05-13"));
        assert!(is_known_mcp_guidance(
            MCP_DATABASE_GUIDANCE_ID,
            MCP_DATABASE_GUIDANCE_VERSION
        ));
        assert!(!is_known_mcp_guidance("security_boundaries", "9999-12-31"));
        assert!(!is_known_mcp_guidance("i_made_this_up", "2026-05-13"));
    }

    #[test]
    fn catalog_returns_server_owned_content_not_just_keys() {
        // The catalog must carry actual content so the control-plane can
        // return it from `sync_guidance`. A client cannot mark guidance
        // delivered without the server having emitted this content.
        let entry =
            lookup_mcp_guidance(MCP_DATABASE_GUIDANCE_ID, MCP_DATABASE_GUIDANCE_VERSION).unwrap();
        assert_eq!(entry.id, MCP_DATABASE_GUIDANCE_ID);
        assert_eq!(entry.version, MCP_DATABASE_GUIDANCE_VERSION);
        assert!(!entry.title.is_empty());
        assert!(
            !entry.content.is_empty(),
            "guidance catalog must carry content, not just keys"
        );
    }
}
