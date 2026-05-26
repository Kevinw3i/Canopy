use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseScopeSummary {
    pub name: String,
    pub connection: String,
    pub environment: String,
    pub allowed_schemas: Vec<String>,
    pub allowed_tables: Vec<String>,
    pub allowed_actions: Vec<String>,
    pub max_rows: u64,
    pub statement_timeout_ms: u64,
    pub require_explain: bool,
    pub max_examined_rows: u64,
    pub allow_full_table_scan: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDatabaseScopesRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canopy_mcp_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_secret_generation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDatabaseScopesResponse {
    pub scopes: Vec<DatabaseScopeSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryDatabaseRequest {
    pub scope: String,
    pub sql: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canopy_mcp_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_secret_generation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExplainSummary {
    pub access_type: Option<String>,
    pub key_used: Option<String>,
    pub estimated_rows: Option<u64>,
    pub full_table_scan: bool,
    pub tables: Vec<ExplainTableSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainTableSummary {
    pub table: String,
    pub access_type: Option<String>,
    pub key_used: Option<String>,
    pub estimated_rows: Option<u64>,
    pub full_table_scan: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryDatabaseResponse {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    pub row_count: usize,
    pub truncated: bool,
    pub scope: String,
    pub environment: String,
    pub explain: ExplainSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseErrorDetails {
    pub kind: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub possible_keys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_rows: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}
