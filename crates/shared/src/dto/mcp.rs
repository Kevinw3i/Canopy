use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::cloudwatch::{LogEvent, LogGroup, QueryResultField, QueryStatistics, QueryStatus};
use super::entitlements::McpBusinessScope;

pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
pub const MCP_PRODUCT_PHASE: &str = "phase_3_data_tools";
pub const MCP_SECURITY_BOUNDARIES_KEY: &str = "security_boundaries@2026-05-13";
pub const MCP_CLOUDWATCH_SEARCH_GUIDANCE_ID: &str = "cloudwatch_search_workflow";
pub const MCP_CLOUDWATCH_SEARCH_GUIDANCE_VERSION: &str = "2026-05-13";
pub const MCP_CLOUDWATCH_SEARCH_GUIDANCE_KEY: &str = "cloudwatch_search_workflow@2026-05-13";
pub const MCP_CLOUDWATCH_INSIGHTS_GUIDANCE_ID: &str = "cloudwatch_insights_workflow";
pub const MCP_CLOUDWATCH_INSIGHTS_GUIDANCE_VERSION: &str = "2026-05-13";
pub const MCP_CLOUDWATCH_INSIGHTS_GUIDANCE_KEY: &str = "cloudwatch_insights_workflow@2026-05-13";
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
        content: include_str!("mcp_guidance/security_boundaries.md"),
    },
    McpGuidanceCatalogEntry {
        id: MCP_CLOUDWATCH_SEARCH_GUIDANCE_ID,
        version: MCP_CLOUDWATCH_SEARCH_GUIDANCE_VERSION,
        title: "CloudWatch Search Workflow",
        content: include_str!("mcp_guidance/cloudwatch_search_workflow.md"),
    },
    McpGuidanceCatalogEntry {
        id: MCP_CLOUDWATCH_INSIGHTS_GUIDANCE_ID,
        version: MCP_CLOUDWATCH_INSIGHTS_GUIDANCE_VERSION,
        title: "CloudWatch Insights Workflow",
        content: include_str!("mcp_guidance/cloudwatch_insights_workflow.md"),
    },
    McpGuidanceCatalogEntry {
        id: "privacy_and_audit_notice",
        version: "2026-05-13",
        title: "Privacy And Audit Notice",
        content: include_str!("mcp_guidance/privacy_and_audit_notice.md"),
    },
    McpGuidanceCatalogEntry {
        id: MCP_DATABASE_GUIDANCE_ID,
        version: MCP_DATABASE_GUIDANCE_VERSION,
        title: "Database Query Workflow",
        content: include_str!("mcp_guidance/database_query_workflow.md"),
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

pub fn lookup_mcp_guidance_by_id(id: &str) -> Option<&'static McpGuidanceCatalogEntry> {
    MCP_GUIDANCE_CATALOG.iter().find(|entry| entry.id == id)
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
    pub preflight_token_ttl_seconds: u64,
    pub search_cursor_ttl_seconds: u64,
    pub insights_query_token_ttl_seconds: u64,
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
            preflight_token_ttl_seconds: 5 * 60,
            search_cursor_ttl_seconds: 10 * 60,
            insights_query_token_ttl_seconds: 15 * 60,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub business_scopes: Vec<McpBusinessScope>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpCloudwatchPreflightRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canopy_mcp_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_secret_generation: Option<String>,
    pub tool_name: String,
    pub account_id: String,
    pub region: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_group_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub log_group_names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_string: Option<String>,
    pub start_time: i64,
    pub end_time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpCloudwatchPreflightResponse {
    pub tool_name: String,
    pub account_id: String,
    pub region: String,
    pub log_group_names: Vec<String>,
    pub preflight_token: String,
    pub expires_at: DateTime<Utc>,
    pub guardrails: McpGuardrails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpSearchLogsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canopy_mcp_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_secret_generation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preflight_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpSearchLogsResponse {
    pub account_id: String,
    pub region: String,
    pub log_group_name: String,
    pub events: Vec<LogEvent>,
    pub returned_count: usize,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_action_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRunInsightsQueryRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canopy_mcp_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_secret_generation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preflight_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRunInsightsQueryResponse {
    pub account_id: String,
    pub region: String,
    pub log_group_names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_token: Option<String>,
    pub status: QueryStatus,
    pub results: Vec<Vec<QueryResultField>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statistics: Option<QueryStatistics>,
    pub terminal: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_action_hint: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

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
        assert_eq!(MCP_PRODUCT_PHASE, "phase_3_data_tools");
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
    fn guidance_catalog_ids_and_versions_are_unique() {
        let mut ids = BTreeSet::new();
        let mut pairs = BTreeSet::new();
        for entry in MCP_GUIDANCE_CATALOG {
            assert!(ids.insert(entry.id), "duplicate guidance id {}", entry.id);
            assert!(
                pairs.insert((entry.id, entry.version)),
                "duplicate guidance id/version {}@{}",
                entry.id,
                entry.version
            );
        }
    }

    #[test]
    fn guidance_catalog_round_trips_every_entry() {
        for entry in MCP_GUIDANCE_CATALOG {
            let by_pair = lookup_mcp_guidance(entry.id, entry.version)
                .expect("catalog entry must be found by id/version");
            assert_eq!(by_pair.id, entry.id);
            assert_eq!(by_pair.version, entry.version);

            let by_id =
                lookup_mcp_guidance_by_id(entry.id).expect("catalog entry must be found by id");
            assert_eq!(by_id.id, entry.id);
            assert_eq!(by_id.version, entry.version);
        }
    }

    #[test]
    fn guidance_markdown_content_is_publishable() {
        for entry in MCP_GUIDANCE_CATALOG {
            let content = entry.content.trim();
            assert!(
                !entry.title.trim().is_empty(),
                "{} title is empty",
                entry.id
            );
            assert!(!content.is_empty(), "{} content is empty", entry.id);
            assert!(
                content.starts_with("# "),
                "{} content must start with a markdown H1",
                entry.id
            );
            assert!(
                content.contains(entry.title),
                "{} content must include the catalog title {:?}",
                entry.id,
                entry.title
            );

            let lower = content.to_ascii_lowercase();
            assert!(
                !lower.contains("todo"),
                "{} content must not contain TODO",
                entry.id
            );
            assert!(
                !lower.contains("placeholder"),
                "{} content must not contain placeholder text",
                entry.id
            );
        }
    }

    #[test]
    fn required_guidance_keys_exist_in_catalog() {
        for key in [
            MCP_SECURITY_BOUNDARIES_KEY,
            MCP_CLOUDWATCH_SEARCH_GUIDANCE_KEY,
            MCP_CLOUDWATCH_INSIGHTS_GUIDANCE_KEY,
            MCP_DATABASE_GUIDANCE_KEY,
            MCP_PRIVACY_AND_AUDIT_NOTICE_KEY,
        ] {
            let (id, version) = key.split_once('@').expect("guidance key has version");
            assert!(
                lookup_mcp_guidance(id, version).is_some(),
                "required guidance key {key} must exist in catalog"
            );
        }
    }
}
