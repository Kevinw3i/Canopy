use anyhow::{anyhow, Context, Result};
use axum::{
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shared::dto::database::{ListDatabaseScopesRequest, QueryDatabaseRequest};
use shared::dto::entitlements::UserEntitlements;
use shared::dto::mcp::{
    lookup_mcp_guidance_by_id, McpCloudwatchPreflightRequest, McpDescribeCapabilitiesResponse,
    McpGetEc2DiagnosticResultRequest, McpGuardrails, McpGuidanceResponse, McpGuidanceSyncRequest,
    McpListAllowedLogGroupsRequest, McpRegisterSessionRequest, McpRunEc2DiagnosticCommandRequest,
    McpRunInsightsQueryRequest, McpSearchLogsRequest, McpToolAvailability,
    MCP_CLOUDWATCH_INSIGHTS_GUIDANCE_KEY, MCP_CLOUDWATCH_SEARCH_GUIDANCE_KEY,
    MCP_DATABASE_GUIDANCE_KEY, MCP_EC2_DIAGNOSTICS_GUIDANCE_KEY, MCP_GUIDANCE_CATALOG,
    MCP_PRIVACY_AND_AUDIT_NOTICE_KEY, MCP_PRODUCT_PHASE, MCP_PROTOCOL_VERSION,
    MCP_SECURITY_BOUNDARIES_KEY,
};
use std::path::PathBuf;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::api_client::{ApiClient, ApiClientError};
use crate::build_info;

const DEFAULT_STABLE_PORT: u16 = 9877;
const SESSION_FILE_VERSION: u8 = 1;
const SERVER_NAME: &str = "canopy-local-mcp";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpSessionFile {
    pub session_file_version: u8,
    pub endpoint: String,
    pub stable_proxy_endpoint: String,
    pub bearer_token: String,
    pub authorization_header: String,
    pub local_secret_generation: String,
    pub canopy_mcp_session_id: String,
    pub secret_created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub pid: u32,
}

#[derive(Debug, Clone)]
pub struct McpRuntimeStatus {
    pub endpoint: String,
    pub stable_endpoint: String,
    pub session_file: PathBuf,
    pub expires_at: DateTime<Utc>,
}

pub struct McpRuntime {
    direct_handle: LocalServerHandle,
    stable_handle: Option<LocalServerHandle>,
    status: McpRuntimeStatus,
    session_file: PathBuf,
    lock_file: PathBuf,
    local_secret_generation: String,
}

impl McpRuntime {
    pub async fn start(api: ApiClient, entitlements: UserEntitlements) -> Result<Self> {
        if !entitlements.features.can_use_mcp {
            return Err(anyhow!("MCP is not enabled for this user"));
        }

        let Some(_) = api.get_token() else {
            return Err(anyhow!("Sign in before starting MCP server"));
        };

        let canopy_dir = canopy_dir()?;
        std::fs::create_dir_all(&canopy_dir)?;
        set_private_dir_permissions(&canopy_dir)?;

        let session_file = canopy_dir.join("mcp-session.json");
        let lock_file = canopy_dir.join("mcp-session.lock");
        cleanup_stale_session_file(&session_file)?;
        create_lock_file(&lock_file)?;

        let start_result = Self::start_inner(api, entitlements, session_file.clone()).await;
        match start_result {
            Ok(mut runtime) => {
                runtime.lock_file = lock_file;
                Ok(runtime)
            }
            Err(err) => {
                let _ = std::fs::remove_file(&lock_file);
                Err(err)
            }
        }
    }

    async fn start_inner(
        api: ApiClient,
        entitlements: UserEntitlements,
        session_file: PathBuf,
    ) -> Result<Self> {
        let local_secret = random_secret();
        let bearer_header = format!("Bearer {local_secret}");
        let local_secret_generation = format!("lsg_{}", Uuid::new_v4().as_simple());

        let registration = api
            .register_mcp_session(&McpRegisterSessionRequest {
                local_secret_generation: local_secret_generation.clone(),
                protocol_version: MCP_PROTOCOL_VERSION.into(),
                client_name: SERVER_NAME.into(),
                client_version: build_info::version().into(),
                product_phase: MCP_PRODUCT_PHASE.into(),
            })
            .await
            .map_err(api_error)?;

        let direct_listener = bind_loopback(0)?;
        let direct_addr = direct_listener.local_addr()?;
        let endpoint = format!("http://{direct_addr}/mcp");

        let server_state = Arc::new(McpServerState {
            api,
            entitlements,
            bearer_header: bearer_header.clone(),
            local_secret_generation: local_secret_generation.clone(),
            canopy_mcp_session_id: registration.canopy_mcp_session_id.clone(),
            protocol_session_id: RwLock::new(None),
        });

        let direct_handle = spawn_server(direct_listener, server_state.clone())?;

        let (stable_endpoint, stable_handle) = match bind_loopback(DEFAULT_STABLE_PORT) {
            Ok(listener) => {
                let addr = listener.local_addr()?;
                (
                    format!("http://{addr}/mcp"),
                    Some(spawn_server(listener, server_state.clone())?),
                )
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    port = DEFAULT_STABLE_PORT,
                    "stable MCP port unavailable; falling back to dynamic endpoint"
                );
                (endpoint.clone(), None)
            }
        };

        let session = McpSessionFile {
            session_file_version: SESSION_FILE_VERSION,
            endpoint: endpoint.clone(),
            stable_proxy_endpoint: stable_endpoint.clone(),
            bearer_token: local_secret.clone(),
            authorization_header: bearer_header,
            local_secret_generation: local_secret_generation.clone(),
            canopy_mcp_session_id: registration.canopy_mcp_session_id,
            secret_created_at: Utc::now(),
            expires_at: registration.expires_at,
            pid: std::process::id(),
        };
        write_session_file(&session_file, &session)?;

        Ok(Self {
            direct_handle,
            stable_handle,
            status: McpRuntimeStatus {
                endpoint,
                stable_endpoint,
                session_file: session_file.clone(),
                expires_at: session.expires_at,
            },
            session_file,
            lock_file: PathBuf::new(),
            local_secret_generation,
        })
    }

    pub fn status(&self) -> &McpRuntimeStatus {
        &self.status
    }

    pub fn local_secret_generation(&self) -> &str {
        &self.local_secret_generation
    }

    pub fn stop(self) -> Result<()> {
        self.direct_handle.stop();
        if let Some(handle) = self.stable_handle {
            handle.stop();
        }
        let _ = std::fs::remove_file(&self.session_file);
        let _ = std::fs::remove_file(&self.lock_file);
        Ok(())
    }
}

struct LocalServerHandle {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl LocalServerHandle {
    fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn bind_loopback(port: u16) -> std::io::Result<std::net::TcpListener> {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn spawn_server(
    listener: std::net::TcpListener,
    state: Arc<McpServerState>,
) -> Result<LocalServerHandle> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let addr = listener.local_addr()?;
    let thread = std::thread::Builder::new()
        .name(format!("canopy-mcp-{addr}"))
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    tracing::warn!(error = %err, "failed to start local MCP runtime");
                    return;
                }
            };

            runtime.block_on(async move {
                let listener = match tokio::net::TcpListener::from_std(listener) {
                    Ok(listener) => listener,
                    Err(err) => {
                        tracing::warn!(error = %err, "failed to register local MCP listener");
                        return;
                    }
                };

                let server =
                    axum::serve(listener, router(state)).with_graceful_shutdown(async move {
                        let _ = shutdown_rx.await;
                    });
                if let Err(err) = server.await {
                    tracing::warn!(error = %err, "local MCP server stopped");
                }
            });
        })
        .context("failed to spawn local MCP server thread")?;

    Ok(LocalServerHandle {
        shutdown: Some(shutdown_tx),
        thread: Some(thread),
    })
}

fn router(state: Arc<McpServerState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route(
            "/mcp",
            post(mcp_post).delete(mcp_delete).get(method_not_allowed),
        )
        .with_state(state)
}

struct McpServerState {
    api: ApiClient,
    entitlements: UserEntitlements,
    bearer_header: String,
    local_secret_generation: String,
    canopy_mcp_session_id: String,
    protocol_session_id: RwLock<Option<String>>,
}

async fn healthz(State(state): State<Arc<McpServerState>>, headers: HeaderMap) -> Response {
    if let Some(resp) = authorize(&state, &headers) {
        return resp;
    }

    Json(json!({
        "ok": true,
        "server": SERVER_NAME,
        "protocol_version": MCP_PROTOCOL_VERSION,
        "canopy_mcp_session_id": state.canopy_mcp_session_id,
        "local_secret_generation": state.local_secret_generation
    }))
    .into_response()
}

async fn method_not_allowed() -> Response {
    StatusCode::METHOD_NOT_ALLOWED.into_response()
}

async fn mcp_delete(State(state): State<Arc<McpServerState>>, headers: HeaderMap) -> Response {
    if let Some(resp) = authorize(&state, &headers) {
        return resp;
    }

    let Some(session_header) = headers
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
    else {
        return error_response(StatusCode::BAD_REQUEST, "missing Mcp-Session-Id");
    };

    let mut current = state.protocol_session_id.write().await;
    match current.as_deref() {
        Some(active) if active == session_header => {
            *current = None;
            StatusCode::NO_CONTENT.into_response()
        }
        _ => error_response(StatusCode::NOT_FOUND, "unknown Mcp-Session-Id"),
    }
}

async fn mcp_post(
    State(state): State<Arc<McpServerState>>,
    headers: HeaderMap,
    Json(req): Json<JsonRpcRequest>,
) -> Response {
    if let Some(resp) = authorize(&state, &headers) {
        return resp;
    }

    match req.method.as_str() {
        "initialize" => initialize(state, req).await,
        "notifications/initialized" => {
            if let Some(resp) = require_protocol_session(&state, &headers).await {
                return resp;
            }
            StatusCode::ACCEPTED.into_response()
        }
        "tools/list" => {
            if let Some(resp) = require_protocol_session(&state, &headers).await {
                return resp;
            }
            json_rpc_result(req.id, tools_list(&state.entitlements))
        }
        "tools/call" => {
            if let Some(resp) = require_protocol_session(&state, &headers).await {
                return resp;
            }
            tools_call(state, req).await
        }
        _ => json_rpc_error(req.id, -32601, "method not found"),
    }
}

async fn require_protocol_session(state: &McpServerState, headers: &HeaderMap) -> Option<Response> {
    let active = state.protocol_session_id.read().await.clone();
    let Some(active) = active else {
        return Some(error_response(
            StatusCode::BAD_REQUEST,
            "MCP session is not initialized",
        ));
    };

    let Some(header) = headers
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
    else {
        return Some(error_response(
            StatusCode::BAD_REQUEST,
            "missing Mcp-Session-Id",
        ));
    };

    if header != active {
        return Some(error_response(
            StatusCode::NOT_FOUND,
            "unknown Mcp-Session-Id",
        ));
    }

    None
}

async fn initialize(state: Arc<McpServerState>, req: JsonRpcRequest) -> Response {
    let requested = req
        .params
        .as_ref()
        .and_then(|params| params.get("protocolVersion"))
        .and_then(Value::as_str);
    if requested.is_some_and(|version| version < MCP_PROTOCOL_VERSION) {
        return json_rpc_error(req.id, -32000, "unsupported MCP protocol version");
    }

    let protocol_session_id = format!("mcp-proto-{}", Uuid::new_v4().as_simple());
    *state.protocol_session_id.write().await = Some(protocol_session_id.clone());

    json_rpc_result_with_headers(
        req.id,
        json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": build_info::version()
            }
        }),
        [("mcp-session-id", protocol_session_id)],
    )
}

fn tools_list(entitlements: &UserEntitlements) -> Value {
    let guidance_ids = MCP_GUIDANCE_CATALOG
        .iter()
        .map(|entry| entry.id)
        .collect::<Vec<_>>();
    let mut tools = vec![
        json!({
            "name": "canopy_describe_capabilities",
            "description": "REQUIRED FIRST CALL. Describe currently available Canopy tools, their phase status, and guardrail limits before any data-access tool.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "canopy_get_guidance",
            "description": "Return Canopy guidance before using any data-access tool.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "guidance_id": {
                        "type": "string",
                        "enum": guidance_ids
                    }
                },
                "required": ["guidance_id"],
                "additionalProperties": false
            }
        }),
    ];
    if entitlements.features.can_use_mcp_database {
        tools.push(json!({
            "name": "canopy_list_database_scopes",
            "description": "List database scopes available through Canopy MCP without exposing connection secrets.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }));
        tools.push(json!({
            "name": "canopy_query_database",
            "description": "Run a read-only MySQL SELECT through Canopy after SQL safety validation and EXPLAIN preflight.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "scope": { "type": "string" },
                    "connection": { "type": "string" },
                    "environment": { "type": "string" },
                    "sql": { "type": "string" }
                },
                "required": ["scope", "sql"],
                "additionalProperties": false
            }
        }));
    }
    if entitlements.features.can_use_mcp_cloudwatch {
        tools.push(json!({
            "name": "canopy_list_allowed_log_groups",
            "description": "List CloudWatch log groups available through Canopy MCP discovery. Initial calls require account_id and region; continuation calls use discovery_cursor.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id": { "type": "string" },
                    "region": { "type": "string" },
                    "prefix": { "type": "string" },
                    "discovery_cursor": { "type": "string" }
                },
                "additionalProperties": false
            }
        }));
        tools.push(json!({
            "name": "canopy_preflight_request",
            "description": "Validate a CloudWatch MCP data request and issue a scoped preflight_token for canopy_search_logs or canopy_run_insights_query.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tool_name": { "type": "string", "enum": ["canopy_search_logs", "canopy_run_insights_query"] },
                    "account_id": { "type": "string" },
                    "region": { "type": "string" },
                    "log_group_name": { "type": "string" },
                    "log_group_names": { "type": "array", "items": { "type": "string" } },
                    "filter_pattern": { "type": "string" },
                    "query_string": { "type": "string" },
                    "start_time": { "type": "integer" },
                    "end_time": { "type": "integer" },
                    "limit": { "type": "integer" }
                },
                "required": ["tool_name", "account_id", "region", "start_time", "end_time"],
                "additionalProperties": false
            }
        }));
        tools.push(json!({
            "name": "canopy_search_logs",
            "description": "Search CloudWatch log events through MCP. Initial calls require preflight_token only; continuation calls require search_cursor only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "preflight_token": { "type": "string" },
                    "search_cursor": { "type": "string" }
                },
                "additionalProperties": false
            }
        }));
        tools.push(json!({
            "name": "canopy_run_insights_query",
            "description": "Start or poll a CloudWatch Logs Insights query through MCP. Initial calls require preflight_token only; polling calls require query_token only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "preflight_token": { "type": "string" },
                    "query_token": { "type": "string" }
                },
                "additionalProperties": false
            }
        }));
    }
    if ec2_diagnostics_enabled(entitlements) {
        tools.push(json!({
            "name": "canopy_run_ec2_diagnostic_command",
            "description": "Submit an allowlisted, non-interactive EC2 diagnostic command through Canopy MCP. Requires EC2 diagnostics guidance first.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "instance_id": { "type": "string" },
                    "account_id": { "type": "string" },
                    "region": { "type": "string" },
                    "command": {
                        "oneOf": [
                            {
                                "type": "object",
                                "properties": {
                                    "type": { "const": "tail_log" },
                                    "path": { "type": "string" },
                                    "lines": { "type": "integer", "minimum": 1, "maximum": 500 }
                                },
                                "required": ["type", "path", "lines"],
                                "additionalProperties": false
                            },
                            {
                                "type": "object",
                                "properties": {
                                    "type": { "const": "grep_log" },
                                    "path": { "type": "string" },
                                    "literal_pattern": { "type": "string" },
                                    "case_insensitive": { "type": "boolean" },
                                    "max_matches": { "type": "integer", "minimum": 1, "maximum": 500 }
                                },
                                "required": ["type", "path", "literal_pattern", "max_matches"],
                                "additionalProperties": false
                            },
                            {
                                "type": "object",
                                "properties": {
                                    "type": { "const": "journalctl_unit" },
                                    "unit": { "type": "string" },
                                    "since": { "type": "string" },
                                    "lines": { "type": "integer", "minimum": 1, "maximum": 500 }
                                },
                                "required": ["type", "unit", "since", "lines"],
                                "additionalProperties": false
                            },
                            {
                                "type": "object",
                                "properties": {
                                    "type": { "const": "http_head" },
                                    "url": { "type": "string" },
                                    "max_time_seconds": { "type": "integer", "minimum": 1, "maximum": 30 }
                                },
                                "required": ["type", "url", "max_time_seconds"],
                                "additionalProperties": false
                            },
                            {
                                "type": "object",
                                "properties": {
                                    "type": { "const": "tcp_probe" },
                                    "host": { "type": "string" },
                                    "port": { "type": "integer", "minimum": 1, "maximum": 65535 },
                                    "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": 30 }
                                },
                                "required": ["type", "host", "port", "timeout_seconds"],
                                "additionalProperties": false
                            },
                            {
                                "type": "object",
                                "properties": {
                                    "type": { "const": "dns_lookup" },
                                    "host": { "type": "string" },
                                    "record_type": { "type": "string", "enum": ["A", "AAAA", "CNAME"] }
                                },
                                "required": ["type", "host", "record_type"],
                                "additionalProperties": false
                            }
                        ]
                    }
                },
                "required": ["instance_id", "account_id", "region", "command"],
                "additionalProperties": false
            }
        }));
        tools.push(json!({
            "name": "canopy_get_ec2_diagnostic_result",
            "description": "Fetch bounded, redacted, untrusted output for a previously submitted EC2 diagnostic command.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "mcp_ec2_command_id": { "type": "string" },
                    "max_bytes": { "type": "integer", "minimum": 1, "maximum": 65536 }
                },
                "required": ["mcp_ec2_command_id", "max_bytes"],
                "additionalProperties": false
            }
        }));
    }

    json!({ "tools": tools })
}

async fn tools_call(state: Arc<McpServerState>, req: JsonRpcRequest) -> Response {
    let Some(params) = req.params.as_ref() else {
        return json_rpc_error(req.id, -32602, "missing params");
    };
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return json_rpc_error(req.id, -32602, "missing tool name");
    };
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    match name {
        "canopy_describe_capabilities" => {
            let capabilities = describe_capabilities(&state.entitlements);
            match serde_json::to_string_pretty(&capabilities) {
                Ok(text) => json_rpc_result(req.id, text_content(text)),
                Err(_) => json_rpc_error(req.id, -32603, "failed to serialize capabilities"),
            }
        }
        "canopy_get_guidance" => {
            // Guidance content is now authoritative on the control-plane:
            // we ship the requested `guidance_id` plus the locally-known
            // version and let the server return both content and "delivered"
            // record atomically. This makes it impossible for a custom MCP
            // client to mark a gate satisfied without the server emitting
            // the actual document.
            let Some(guidance_id) = arguments.get("guidance_id").and_then(Value::as_str) else {
                return json_rpc_error(req.id, -32602, "missing guidance_id");
            };
            let Some(entry) = lookup_mcp_guidance_by_id(guidance_id) else {
                return json_rpc_error(req.id, -32602, "unknown guidance_id");
            };
            let sync = McpGuidanceSyncRequest {
                canopy_mcp_session_id: state.canopy_mcp_session_id.clone(),
                local_secret_generation: state.local_secret_generation.clone(),
                guidance_id: guidance_id.into(),
                guidance_version: entry.version.into(),
            };
            match state.api.sync_mcp_guidance(&sync).await {
                Ok(resp) => {
                    let payload = McpGuidanceResponse {
                        id: resp.guidance_id,
                        version: resp.guidance_version,
                        title: resp.title,
                        guidance_type: "guidance".into(),
                        required: true,
                        content_type: resp.content_type,
                        content: resp.content,
                    };
                    match serde_json::to_string_pretty(&payload) {
                        Ok(text) => json_rpc_result(req.id, text_content(text)),
                        Err(_) => json_rpc_error(req.id, -32603, "failed to serialize guidance"),
                    }
                }
                Err(err) => {
                    json_rpc_error(req.id, -32001, &format!("guidance sync failed: {}", err))
                }
            }
        }
        "canopy_list_database_scopes" => {
            if !state.entitlements.features.can_use_mcp_database {
                return json_rpc_error(req.id, -32003, "MCP database is not enabled");
            }
            let request = ListDatabaseScopesRequest {
                canopy_mcp_session_id: Some(state.canopy_mcp_session_id.clone()),
                local_secret_generation: Some(state.local_secret_generation.clone()),
            };
            match state.api.list_mcp_database_scopes(&request).await {
                Ok(scopes) => match serde_json::to_string_pretty(&scopes) {
                    Ok(text) => json_rpc_result(req.id, text_content(text)),
                    Err(_) => json_rpc_error(req.id, -32603, "failed to serialize database scopes"),
                },
                Err(err) => {
                    json_rpc_error(req.id, -32002, &format!("database scopes failed: {err}"))
                }
            }
        }
        "canopy_list_allowed_log_groups" => {
            let mut request: McpListAllowedLogGroupsRequest =
                match serde_json::from_value(arguments) {
                    Ok(request) => request,
                    Err(err) => {
                        return json_rpc_error(
                            req.id,
                            -32602,
                            &format!("invalid CloudWatch discovery arguments: {err}"),
                        )
                    }
                };
            request.canopy_mcp_session_id = Some(state.canopy_mcp_session_id.clone());
            request.local_secret_generation = Some(state.local_secret_generation.clone());
            match state.api.list_mcp_allowed_log_groups(&request).await {
                Ok(response) => match serde_json::to_string_pretty(&response) {
                    Ok(text) => json_rpc_result(req.id, text_content(text)),
                    Err(_) => json_rpc_error(
                        req.id,
                        -32603,
                        "failed to serialize CloudWatch discovery result",
                    ),
                },
                Err(err) => json_rpc_error(
                    req.id,
                    -32002,
                    &format!("CloudWatch discovery failed: {err}"),
                ),
            }
        }
        "canopy_preflight_request" => {
            let mut request: McpCloudwatchPreflightRequest = match serde_json::from_value(arguments)
            {
                Ok(request) => request,
                Err(err) => {
                    return json_rpc_error(
                        req.id,
                        -32602,
                        &format!("invalid CloudWatch preflight arguments: {err}"),
                    )
                }
            };
            request.canopy_mcp_session_id = Some(state.canopy_mcp_session_id.clone());
            request.local_secret_generation = Some(state.local_secret_generation.clone());
            match state.api.preflight_mcp_cloudwatch(&request).await {
                Ok(response) => match serde_json::to_string_pretty(&response) {
                    Ok(text) => json_rpc_result(req.id, text_content(text)),
                    Err(_) => json_rpc_error(
                        req.id,
                        -32603,
                        "failed to serialize CloudWatch preflight result",
                    ),
                },
                Err(err) => json_rpc_error(
                    req.id,
                    -32002,
                    &format!("CloudWatch preflight failed: {err}"),
                ),
            }
        }
        "canopy_search_logs" => {
            let mut request: McpSearchLogsRequest = match serde_json::from_value(arguments) {
                Ok(request) => request,
                Err(err) => {
                    return json_rpc_error(
                        req.id,
                        -32602,
                        &format!("invalid CloudWatch search arguments: {err}"),
                    )
                }
            };
            request.canopy_mcp_session_id = Some(state.canopy_mcp_session_id.clone());
            request.local_secret_generation = Some(state.local_secret_generation.clone());
            match state.api.search_mcp_logs(&request).await {
                Ok(response) => match serde_json::to_string_pretty(&response) {
                    Ok(text) => json_rpc_result(req.id, text_content(text)),
                    Err(_) => json_rpc_error(
                        req.id,
                        -32603,
                        "failed to serialize CloudWatch search result",
                    ),
                },
                Err(err) => {
                    json_rpc_error(req.id, -32002, &format!("CloudWatch search failed: {err}"))
                }
            }
        }
        "canopy_run_insights_query" => {
            let mut request: McpRunInsightsQueryRequest = match serde_json::from_value(arguments) {
                Ok(request) => request,
                Err(err) => {
                    return json_rpc_error(
                        req.id,
                        -32602,
                        &format!("invalid CloudWatch Insights arguments: {err}"),
                    )
                }
            };
            request.canopy_mcp_session_id = Some(state.canopy_mcp_session_id.clone());
            request.local_secret_generation = Some(state.local_secret_generation.clone());
            match state.api.run_mcp_insights_query(&request).await {
                Ok(response) => match serde_json::to_string_pretty(&response) {
                    Ok(text) => json_rpc_result(req.id, text_content(text)),
                    Err(_) => json_rpc_error(
                        req.id,
                        -32603,
                        "failed to serialize CloudWatch Insights result",
                    ),
                },
                Err(err) => json_rpc_error(
                    req.id,
                    -32002,
                    &format!("CloudWatch Insights failed: {err}"),
                ),
            }
        }
        "canopy_query_database" => {
            if !state.entitlements.features.can_use_mcp_database {
                return json_rpc_error(req.id, -32003, "MCP database is not enabled");
            }
            let mut request: QueryDatabaseRequest = match serde_json::from_value(arguments) {
                Ok(request) => request,
                Err(err) => {
                    return json_rpc_error(
                        req.id,
                        -32602,
                        &format!("invalid database query arguments: {err}"),
                    )
                }
            };
            if request.connection.is_none() {
                request.connection = database_scope_connection(&state.entitlements, &request.scope);
            }
            request.canopy_mcp_session_id = Some(state.canopy_mcp_session_id.clone());
            request.local_secret_generation = Some(state.local_secret_generation.clone());
            match state.api.query_mcp_database(&request).await {
                Ok(response) => match serde_json::to_string_pretty(&response) {
                    Ok(text) => json_rpc_result(req.id, text_content(text)),
                    Err(_) => json_rpc_error(req.id, -32603, "failed to serialize database result"),
                },
                Err(err) => {
                    json_rpc_error(req.id, -32002, &format!("database query failed: {err}"))
                }
            }
        }
        "canopy_run_ec2_diagnostic_command" => {
            if !ec2_diagnostics_enabled(&state.entitlements) {
                return json_rpc_error(req.id, -32003, "MCP EC2 diagnostics is not enabled");
            }
            let mut request: McpRunEc2DiagnosticCommandRequest =
                match serde_json::from_value(arguments) {
                    Ok(request) => request,
                    Err(err) => {
                        return json_rpc_error(
                            req.id,
                            -32602,
                            &format!("invalid EC2 diagnostic run arguments: {err}"),
                        )
                    }
                };
            request.canopy_mcp_session_id = Some(state.canopy_mcp_session_id.clone());
            request.local_secret_generation = Some(state.local_secret_generation.clone());
            match state.api.run_mcp_ec2_diagnostic_command(&request).await {
                Ok(response) => match serde_json::to_string_pretty(&response) {
                    Ok(text) => json_rpc_result(req.id, text_content(text)),
                    Err(_) => {
                        json_rpc_error(req.id, -32603, "failed to serialize EC2 diagnostic run")
                    }
                },
                Err(err) => {
                    json_rpc_error(req.id, -32002, &format!("EC2 diagnostic run failed: {err}"))
                }
            }
        }
        "canopy_get_ec2_diagnostic_result" => {
            if !ec2_diagnostics_enabled(&state.entitlements) {
                return json_rpc_error(req.id, -32003, "MCP EC2 diagnostics is not enabled");
            }
            let mut request: McpGetEc2DiagnosticResultRequest =
                match serde_json::from_value(arguments) {
                    Ok(request) => request,
                    Err(err) => {
                        return json_rpc_error(
                            req.id,
                            -32602,
                            &format!("invalid EC2 diagnostic result arguments: {err}"),
                        )
                    }
                };
            request.canopy_mcp_session_id = Some(state.canopy_mcp_session_id.clone());
            request.local_secret_generation = Some(state.local_secret_generation.clone());
            match state.api.get_mcp_ec2_diagnostic_result(&request).await {
                Ok(response) => match serde_json::to_string_pretty(&response) {
                    Ok(text) => json_rpc_result(req.id, text_content(text)),
                    Err(_) => {
                        json_rpc_error(req.id, -32603, "failed to serialize EC2 diagnostic result")
                    }
                },
                Err(err) => json_rpc_error(
                    req.id,
                    -32002,
                    &format!("EC2 diagnostic result failed: {err}"),
                ),
            }
        }
        _ => json_rpc_error(req.id, -32601, "unknown tool"),
    }
}

fn describe_capabilities(entitlements: &UserEntitlements) -> McpDescribeCapabilitiesResponse {
    let cloudwatch_enabled =
        entitlements.features.can_use_mcp && entitlements.features.can_use_mcp_cloudwatch;
    let database_enabled =
        entitlements.features.can_use_mcp && entitlements.features.can_use_mcp_database;
    let ec2_diagnostics_enabled = ec2_diagnostics_enabled(entitlements);
    McpDescribeCapabilitiesResponse {
        mcp_product_phase: MCP_PRODUCT_PHASE.into(),
        scope_disclosure: if cloudwatch_enabled {
            "cloudwatch_discovery_and_data_tools_enabled".into()
        } else {
            "cloudwatch_scope_hidden".into()
        },
        available_tools: vec![
            tool(
                "canopy_describe_capabilities",
                true,
                None,
                "phase_1_foundation",
                vec![],
                false,
            ),
            tool(
                "canopy_get_guidance",
                true,
                None,
                "phase_1_foundation",
                vec![],
                false,
            ),
            tool(
                "canopy_list_allowed_log_groups",
                cloudwatch_enabled,
                (!cloudwatch_enabled).then_some("entitlement_disabled"),
                "phase_2_discovery",
                vec!["security_boundaries@2026-05-13"],
                false,
            ),
            tool(
                "canopy_preflight_request",
                cloudwatch_enabled,
                (!cloudwatch_enabled).then_some("entitlement_disabled"),
                "phase_3_data_tools",
                vec![
                    MCP_SECURITY_BOUNDARIES_KEY,
                    MCP_CLOUDWATCH_SEARCH_GUIDANCE_KEY,
                    MCP_CLOUDWATCH_INSIGHTS_GUIDANCE_KEY,
                    MCP_PRIVACY_AND_AUDIT_NOTICE_KEY,
                ],
                false,
            ),
            tool(
                "canopy_search_logs",
                cloudwatch_enabled,
                (!cloudwatch_enabled).then_some("entitlement_disabled"),
                "phase_3_data_tools",
                vec![
                    "security_boundaries@2026-05-13",
                    "cloudwatch_search_workflow@2026-05-13",
                ],
                true,
            ),
            tool(
                "canopy_run_insights_query",
                cloudwatch_enabled,
                (!cloudwatch_enabled).then_some("entitlement_disabled"),
                "phase_3_data_tools",
                vec![
                    "security_boundaries@2026-05-13",
                    "cloudwatch_insights_workflow@2026-05-13",
                ],
                true,
            ),
            tool(
                "canopy_list_database_scopes",
                database_enabled,
                (!database_enabled).then_some("entitlement_disabled"),
                "phase_1_database_v1",
                vec![MCP_SECURITY_BOUNDARIES_KEY, MCP_DATABASE_GUIDANCE_KEY],
                false,
            ),
            tool(
                "canopy_query_database",
                database_enabled,
                (!database_enabled).then_some("entitlement_disabled"),
                "phase_1_database_v1",
                vec![
                    MCP_SECURITY_BOUNDARIES_KEY,
                    MCP_DATABASE_GUIDANCE_KEY,
                    MCP_PRIVACY_AND_AUDIT_NOTICE_KEY,
                ],
                false,
            ),
            tool(
                "canopy_run_ec2_diagnostic_command",
                ec2_diagnostics_enabled,
                (!ec2_diagnostics_enabled).then_some("entitlement_disabled"),
                "phase_1_ec2_diagnostics_v1",
                vec![
                    MCP_SECURITY_BOUNDARIES_KEY,
                    MCP_EC2_DIAGNOSTICS_GUIDANCE_KEY,
                    MCP_PRIVACY_AND_AUDIT_NOTICE_KEY,
                ],
                false,
            ),
            tool(
                "canopy_get_ec2_diagnostic_result",
                ec2_diagnostics_enabled,
                (!ec2_diagnostics_enabled).then_some("entitlement_disabled"),
                "phase_1_ec2_diagnostics_v1",
                vec![
                    MCP_SECURITY_BOUNDARIES_KEY,
                    MCP_EC2_DIAGNOSTICS_GUIDANCE_KEY,
                    MCP_PRIVACY_AND_AUDIT_NOTICE_KEY,
                ],
                false,
            ),
        ],
        business_scopes: if cloudwatch_enabled {
            entitlements.business_scopes.clone()
        } else {
            vec![]
        },
        guardrails: McpGuardrails::default(),
        message: capabilities_message(
            cloudwatch_enabled,
            database_enabled,
            ec2_diagnostics_enabled,
        ),
    }
}

fn ec2_diagnostics_enabled(entitlements: &UserEntitlements) -> bool {
    entitlements.features.can_use_mcp && entitlements.features.can_use_mcp_ec2
}

fn capabilities_message(
    cloudwatch_enabled: bool,
    database_enabled: bool,
    ec2_diagnostics_enabled: bool,
) -> String {
    let mut messages = Vec::new();
    if cloudwatch_enabled {
        messages.push(
            "CloudWatch MCP discovery and data tools are enabled. Use canopy_preflight_request before canopy_search_logs or canopy_run_insights_query.",
        );
    }
    if database_enabled {
        messages.push(
            "Database MCP tools are enabled. Use canopy_get_guidance before canopy_query_database.",
        );
    }
    if ec2_diagnostics_enabled {
        messages.push(
            "EC2 diagnostics MCP tools are enabled for allowlisted non-interactive diagnostics only.",
        );
    }
    if messages.is_empty() {
        "No MCP data tools are enabled for this user.".into()
    } else {
        messages.join(" ")
    }
}

fn database_scope_connection(entitlements: &UserEntitlements, scope_name: &str) -> Option<String> {
    let mut matches = entitlements
        .database_scopes
        .iter()
        .filter(|scope| scope.name == scope_name)
        .map(|scope| scope.connection.as_str())
        .collect::<Vec<_>>();
    matches.sort_unstable();
    matches.dedup();
    if matches.len() == 1 {
        Some(matches[0].to_string())
    } else {
        None
    }
}

fn tool(
    name: &str,
    enabled: bool,
    disabled_reason: Option<&str>,
    phase: &str,
    guidance: Vec<&str>,
    requires_preflight: bool,
) -> McpToolAvailability {
    McpToolAvailability {
        name: name.into(),
        enabled,
        disabled_reason: disabled_reason.map(str::to_string),
        phase: phase.into(),
        required_guidance: guidance.into_iter().map(str::to_string).collect(),
        requires_preflight,
    }
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

fn text_content(text: String) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": text
            }
        ]
    })
}

fn json_rpc_result(id: Option<Value>, result: Value) -> Response {
    json_rpc_result_with_headers(id, result, std::iter::empty::<(&str, String)>())
}

fn json_rpc_result_with_headers<I>(id: Option<Value>, result: Value, headers: I) -> Response
where
    I: IntoIterator<Item = (&'static str, String)>,
{
    let mut header_map = HeaderMap::new();
    for (name, value) in headers {
        if let Ok(value) = HeaderValue::from_str(&value) {
            header_map.insert(HeaderName::from_static(name), value);
        }
    }
    (
        StatusCode::OK,
        header_map,
        Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result
        })),
    )
        .into_response()
}

fn json_rpc_error(id: Option<Value>, code: i64, message: &str) -> Response {
    (
        StatusCode::OK,
        Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": code,
                "message": message
            }
        })),
    )
        .into_response()
}

fn authorize(state: &McpServerState, headers: &HeaderMap) -> Option<Response> {
    if let Some(origin) = headers.get("origin").and_then(|value| value.to_str().ok()) {
        if origin != "null" {
            return Some(error_response(
                StatusCode::FORBIDDEN,
                "browser origins are not allowed",
            ));
        }
    }
    let Some(header) = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
    else {
        return Some(error_response(
            StatusCode::UNAUTHORIZED,
            "missing bearer token",
        ));
    };
    if !bool::from(header.as_bytes().ct_eq(state.bearer_header.as_bytes())) {
        return Some(error_response(
            StatusCode::UNAUTHORIZED,
            "invalid bearer token",
        ));
    }
    None
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn api_error(err: ApiClientError) -> anyhow::Error {
    anyhow!(err.to_string())
}

fn random_secret() -> String {
    format!(
        "{}{}{}",
        Uuid::new_v4().as_simple(),
        Uuid::new_v4().as_simple(),
        Uuid::new_v4().as_simple()
    )
}

fn canopy_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("cannot find home directory")?;
    Ok(home.join(".canopy"))
}

fn cleanup_stale_session_file(session_file: &PathBuf) -> Result<()> {
    if !session_file.exists() {
        return Ok(());
    }

    let raw = match std::fs::read_to_string(session_file) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };

    let should_remove = match serde_json::from_str::<McpSessionFile>(&raw) {
        Ok(session) => session.expires_at <= Utc::now() || !process_is_running(session.pid),
        Err(_) => true,
    };

    if should_remove {
        std::fs::remove_file(session_file)?;
        tracing::warn!(path = %session_file.display(), "removed stale MCP session file");
    }

    Ok(())
}

fn create_lock_file(lock_file: &PathBuf) -> Result<()> {
    let mut options = private_create_new_options();
    match write_lock_file_with_options(lock_file, &mut options) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            if reclaim_stale_lock(lock_file)? {
                let mut options = private_create_new_options();
                write_lock_file_with_options(lock_file, &mut options)?;
                return Ok(());
            }
            let details = lock_owner_details(lock_file).unwrap_or_else(|| "unknown pid".into());
            anyhow::bail!("another Canopy TUI is using MCP ({details})")
        }
        Err(err) => Err(err.into()),
    }
}

fn private_create_new_options() -> std::fs::OpenOptions {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

fn write_lock_file_with_options(
    lock_file: &PathBuf,
    options: &mut std::fs::OpenOptions,
) -> std::io::Result<()> {
    let payload = json!({
        "pid": std::process::id(),
        "created_at": Utc::now(),
    });
    let mut file = options.open(lock_file)?;
    std::io::Write::write_all(&mut file, payload.to_string().as_bytes())?;
    Ok(())
}

fn reclaim_stale_lock(lock_file: &PathBuf) -> Result<bool> {
    let Some(pid) = lock_file_pid(lock_file) else {
        return Ok(false);
    };
    if process_is_running(pid) {
        return Ok(false);
    }
    std::fs::remove_file(lock_file)?;
    tracing::warn!(pid, "reclaimed stale MCP lock file");
    Ok(true)
}

fn lock_file_pid(lock_file: &PathBuf) -> Option<u32> {
    let raw = std::fs::read_to_string(lock_file).ok()?;
    let json: Value = serde_json::from_str(&raw).ok()?;
    json.get("pid")?
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
}

fn lock_owner_details(lock_file: &PathBuf) -> Option<String> {
    let raw = std::fs::read_to_string(lock_file).ok()?;
    let json: Value = serde_json::from_str(&raw).ok()?;
    let pid = json.get("pid").and_then(Value::as_u64)?;
    let created_at = json
        .get("created_at")
        .and_then(Value::as_str)
        .unwrap_or("unknown start time");
    Some(format!("pid {pid}, started {created_at}"))
}

fn process_is_running(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        // Phase 1 local MCP runtime targets macOS/Linux. Without a safe
        // cross-platform pid probe, do not reclaim locks on non-Unix systems.
        false
    }
}

fn write_session_file(path: &PathBuf, session: &McpSessionFile) -> Result<()> {
    let data = serde_json::to_vec_pretty(session)?;
    let tmp = path.with_file_name(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("mcp-session.json"),
        Uuid::new_v4().as_simple()
    ));
    let options = private_create_new_options();
    {
        let mut file = options.open(&tmp)?;
        std::io::Write::write_all(&mut file, &data)?;
        file.sync_all()?;
    }
    set_private_file_permissions(&tmp)?;
    std::fs::rename(&tmp, path)?;
    set_private_file_permissions(path)?;
    Ok(())
}

fn set_private_dir_permissions(path: &PathBuf) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_private_file_permissions(path: &PathBuf) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use shared::dto::entitlements::{FeatureFlags, McpBusinessScope};

    fn minimal_entitlements() -> UserEntitlements {
        UserEntitlements {
            user_id: "test-user".into(),
            email: "user@example.com".into(),
            display_name: "Test User".into(),
            groups: vec![],
            features: FeatureFlags {
                can_use_mcp: true,
                ..Default::default()
            },
            allowed_accounts: vec![],
            allowed_regions: vec![],
            allowed_log_group_arns: vec![],
            instance_tag_selectors: vec![],
            excluded_tag_selectors: vec![],
            allowed_clusters: vec![],
            task_tag_selectors: vec![],
            excluded_task_tag_selectors: vec![],
            excluded_container_names: vec![],
            allow_broad_cluster_discovery: false,
            allowed_os_users: vec![],
            max_session_seconds: None,
            database_scopes: vec![],
            business_scopes: vec![],
        }
    }

    fn ec2_diagnostics_entitlements() -> UserEntitlements {
        let mut entitlements = minimal_entitlements();
        entitlements.features.can_use_mcp_ec2 = true;
        entitlements
    }

    fn test_state(secret: &str) -> McpServerState {
        McpServerState {
            api: ApiClient::new("http://127.0.0.1").unwrap(),
            entitlements: minimal_entitlements(),
            bearer_header: format!("Bearer {secret}"),
            local_secret_generation: "lsg_test".into(),
            canopy_mcp_session_id: "mcp_test".into(),
            protocol_session_id: RwLock::new(None),
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "canopy-mcp-test-{name}-{}",
            Uuid::new_v4().as_simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_session() -> McpSessionFile {
        McpSessionFile {
            session_file_version: SESSION_FILE_VERSION,
            endpoint: "http://127.0.0.1:1/mcp".into(),
            stable_proxy_endpoint: "http://127.0.0.1:9877/mcp".into(),
            bearer_token: "secret".into(),
            authorization_header: "Bearer secret".into(),
            local_secret_generation: "lsg_test".into(),
            canopy_mcp_session_id: "mcp_test".into(),
            secret_created_at: Utc::now(),
            expires_at: Utc::now(),
            pid: std::process::id(),
        }
    }

    #[test]
    fn authorize_rejects_missing_invalid_and_non_null_origin() {
        let state = test_state("secret");
        assert!(authorize(&state, &HeaderMap::new()).is_some());

        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer wrong"));
        assert!(authorize(&state, &headers).is_some());

        headers.insert("authorization", HeaderValue::from_static("Bearer secret"));
        headers.insert("origin", HeaderValue::from_static("https://example.com"));
        assert!(authorize(&state, &headers).is_some());
    }

    #[test]
    fn authorize_allows_valid_bearer_and_null_origin() {
        let state = test_state("secret");
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer secret"));
        headers.insert("origin", HeaderValue::from_static("null"));
        assert!(authorize(&state, &headers).is_none());
    }

    #[tokio::test]
    async fn protocol_session_header_is_required_after_initialize() {
        let state = test_state("secret");
        assert!(require_protocol_session(&state, &HeaderMap::new())
            .await
            .is_some());

        *state.protocol_session_id.write().await = Some("proto-1".into());
        assert!(require_protocol_session(&state, &HeaderMap::new())
            .await
            .is_some());

        let mut headers = HeaderMap::new();
        headers.insert("mcp-session-id", HeaderValue::from_static("proto-2"));
        assert!(require_protocol_session(&state, &headers).await.is_some());

        headers.insert("mcp-session-id", HeaderValue::from_static("proto-1"));
        assert!(require_protocol_session(&state, &headers).await.is_none());
    }

    #[test]
    fn tools_list_returns_foundation_tools_without_cloudwatch_entitlement() {
        let tools = tools_list(&minimal_entitlements());
        let tool_list = tools["tools"].as_array().unwrap();
        let names = tool_list
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(names.contains(&"canopy_describe_capabilities"));
        assert!(names.contains(&"canopy_get_guidance"));
        assert!(!names.contains(&"canopy_run_ec2_diagnostic_command"));
        assert!(!names.contains(&"canopy_get_ec2_diagnostic_result"));

        let guidance_tool = tool_list
            .iter()
            .find(|tool| tool["name"] == "canopy_get_guidance")
            .expect("canopy_get_guidance tool is listed");
        let guidance_enum = guidance_tool["inputSchema"]["properties"]["guidance_id"]["enum"]
            .as_array()
            .expect("guidance enum is present");
        assert!(!guidance_enum.is_empty());
    }

    #[test]
    fn tools_list_includes_ec2_diagnostics_only_with_master_and_ec2_entitlement() {
        let tools = tools_list(&ec2_diagnostics_entitlements());
        let tool_list = tools["tools"].as_array().unwrap();
        let names = tool_list
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(names.contains(&"canopy_run_ec2_diagnostic_command"));
        assert!(names.contains(&"canopy_get_ec2_diagnostic_result"));

        let run_tool = tool_list
            .iter()
            .find(|tool| tool["name"] == "canopy_run_ec2_diagnostic_command")
            .expect("run EC2 diagnostic tool is listed");
        assert_eq!(
            run_tool["inputSchema"]["properties"]["command"]["oneOf"]
                .as_array()
                .expect("EC2 command variants are listed")
                .len(),
            6
        );

        let result_tool = tool_list
            .iter()
            .find(|tool| tool["name"] == "canopy_get_ec2_diagnostic_result")
            .expect("get EC2 diagnostic result tool is listed");
        assert_eq!(
            result_tool["inputSchema"]["properties"]["max_bytes"]["maximum"],
            65_536
        );

        let mut missing_master = ec2_diagnostics_entitlements();
        missing_master.features.can_use_mcp = false;
        let tools = tools_list(&missing_master);
        let names = tools["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(!names.contains(&"canopy_run_ec2_diagnostic_command"));
        assert!(!names.contains(&"canopy_get_ec2_diagnostic_result"));
    }

    #[test]
    fn guidance_tool_schema_enum_matches_catalog() {
        let tools = tools_list(&minimal_entitlements());
        let tool_list = tools["tools"].as_array().unwrap();
        let guidance_tool = tool_list
            .iter()
            .find(|tool| tool["name"] == "canopy_get_guidance")
            .expect("canopy_get_guidance tool is listed");

        let actual = guidance_tool["inputSchema"]["properties"]["guidance_id"]["enum"]
            .as_array()
            .expect("guidance enum is present")
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>();
        let expected = MCP_GUIDANCE_CATALOG
            .iter()
            .map(|entry| entry.id)
            .collect::<Vec<_>>();

        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn unknown_guidance_id_returns_invalid_params_before_forward() {
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(1)),
            method: "tools/call".into(),
            params: Some(json!({
                "name": "canopy_get_guidance",
                "arguments": {
                    "guidance_id": "i_made_this_up"
                }
            })),
        };

        let response = tools_call(Arc::new(test_state("secret")), req).await;
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["error"]["code"], -32602);
        assert_eq!(payload["error"]["message"], "unknown guidance_id");
    }

    #[test]
    fn describe_capabilities_discloses_business_scopes_only_with_cloudwatch_mcp() {
        let mut entitlements = minimal_entitlements();
        entitlements.business_scopes.push(McpBusinessScope {
            platform: "PLATFORM_A".into(),
            environment: "production".into(),
            aliases: vec!["正式環境".into(), "prod".into()],
            account_id: "111111111111".into(),
            account_name: "platform-a-prod".into(),
            regions: vec!["ap-northeast-1".into()],
            log_group_arn_patterns: vec![
                "arn:aws:logs:*:111111111111:log-group:/platform-a/prod/*".into(),
            ],
        });

        let hidden = describe_capabilities(&entitlements);
        assert!(hidden.business_scopes.is_empty());
        let hidden_json = serde_json::to_string(&hidden).unwrap();
        assert!(!hidden_json.contains("PLATFORM_A"));
        assert!(!hidden_json.contains("111111111111"));
        assert!(!hidden_json.contains("/platform-a/prod"));

        entitlements.features.can_use_mcp = false;
        entitlements.features.can_use_mcp_cloudwatch = true;
        let hidden_without_master_gate = describe_capabilities(&entitlements);
        assert!(hidden_without_master_gate.business_scopes.is_empty());

        entitlements.features.can_use_mcp = true;
        entitlements.features.can_use_mcp_cloudwatch = true;
        let visible = describe_capabilities(&entitlements);
        assert_eq!(visible.business_scopes.len(), 1);
        assert_eq!(visible.business_scopes[0].platform, "PLATFORM_A");

        let json = serde_json::to_string(&visible.business_scopes).unwrap();
        assert!(json.contains("PLATFORM_A"));
        assert!(!json.contains("role_arn"));
        assert!(!json.contains("external_id"));
        assert!(!json.contains("jwt"));
        assert!(!json.contains("local_secret_generation"));
        assert!(!json.contains("secret_key"));
        assert!(!json.contains("token"));
    }

    #[test]
    fn describe_capabilities_reports_ec2_diagnostics_entitlement_gate() {
        let hidden = describe_capabilities(&minimal_entitlements());
        let hidden_run = hidden
            .available_tools
            .iter()
            .find(|tool| tool.name == "canopy_run_ec2_diagnostic_command")
            .expect("EC2 diagnostic run capability is described");
        assert!(!hidden_run.enabled);
        assert_eq!(
            hidden_run.disabled_reason.as_deref(),
            Some("entitlement_disabled")
        );

        let visible = describe_capabilities(&ec2_diagnostics_entitlements());
        let visible_run = visible
            .available_tools
            .iter()
            .find(|tool| tool.name == "canopy_run_ec2_diagnostic_command")
            .expect("EC2 diagnostic run capability is described");
        assert!(visible_run.enabled);
        assert_eq!(
            visible_run.required_guidance,
            vec![
                MCP_SECURITY_BOUNDARIES_KEY.to_string(),
                MCP_EC2_DIAGNOSTICS_GUIDANCE_KEY.to_string(),
                MCP_PRIVACY_AND_AUDIT_NOTICE_KEY.to_string(),
            ]
        );
        let visible_result = visible
            .available_tools
            .iter()
            .find(|tool| tool.name == "canopy_get_ec2_diagnostic_result")
            .expect("EC2 diagnostic result capability is described");
        assert!(visible_result.enabled);
        assert!(visible.message.contains("EC2 diagnostics MCP tools"));
        assert!(visible.message.contains("non-interactive diagnostics only"));
    }

    #[tokio::test]
    async fn ec2_diagnostic_tool_call_without_entitlement_is_denied_locally() {
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(1)),
            method: "tools/call".into(),
            params: Some(json!({
                "name": "canopy_run_ec2_diagnostic_command",
                "arguments": {}
            })),
        };

        let response = tools_call(Arc::new(test_state("secret")), req).await;
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["error"]["code"], -32003);
        assert_eq!(
            payload["error"]["message"],
            "MCP EC2 diagnostics is not enabled"
        );
    }

    #[tokio::test]
    async fn unknown_tool_returns_jsonrpc_error() {
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(1)),
            method: "tools/call".into(),
            params: Some(json!({
                "name": "canopy_unknown_tool",
                "arguments": {}
            })),
        };

        let response = tools_call(Arc::new(test_state("secret")), req).await;
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["error"]["code"], -32601);
        assert_eq!(payload["error"]["message"], "unknown tool");
    }

    #[test]
    fn session_file_is_written_private() {
        let dir = temp_dir("session-file");
        let path = dir.join("mcp-session.json");
        write_session_file(&path, &sample_session()).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn cleanup_stale_session_file_removes_dead_pid() {
        let dir = temp_dir("stale-session-file");
        let path = dir.join("mcp-session.json");
        let mut session = sample_session();
        session.pid = 0;
        session.expires_at = Utc::now() + chrono::Duration::hours(1);
        write_session_file(&path, &session).unwrap();

        cleanup_stale_session_file(&path).unwrap();

        assert!(!path.exists());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn cleanup_stale_session_file_keeps_current_process() {
        let dir = temp_dir("active-session-file");
        let path = dir.join("mcp-session.json");
        let mut session = sample_session();
        session.expires_at = Utc::now() + chrono::Duration::hours(1);
        write_session_file(&path, &session).unwrap();

        cleanup_stale_session_file(&path).unwrap();

        assert!(path.exists());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn lock_file_reports_active_owner_and_reclaims_stale_owner() {
        let dir = temp_dir("lock-file");
        let lock = dir.join("mcp-session.lock");
        create_lock_file(&lock).unwrap();
        let err = create_lock_file(&lock).unwrap_err().to_string();
        assert!(err.contains("another Canopy TUI is using MCP"));

        std::fs::write(
            &lock,
            serde_json::json!({
                "pid": 0,
                "created_at": Utc::now()
            })
            .to_string(),
        )
        .unwrap();
        create_lock_file(&lock).unwrap();

        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn spawned_server_responds_to_healthz() {
        let listener = bind_loopback(0).unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = spawn_server(listener, Arc::new(test_state("secret"))).unwrap();
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/healthz");

        let mut last_error = String::new();
        for _ in 0..40 {
            match client
                .get(&url)
                .header("authorization", "Bearer secret")
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    let payload: Value = response.json().await.unwrap();
                    assert_eq!(payload["ok"], true);
                    handle.stop();
                    return;
                }
                Ok(response) => {
                    last_error = format!("status {}", response.status());
                }
                Err(err) => {
                    last_error = err.to_string();
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }

        handle.stop();
        panic!("local MCP healthz did not respond: {last_error}");
    }
}
