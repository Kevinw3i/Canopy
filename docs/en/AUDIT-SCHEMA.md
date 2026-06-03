# Audit Log Schema

Canopy audit events are JSON-lines records emitted through tracing and, when
configured, the durable `audit_log` file plus optional CloudWatch Logs / S3
export sinks.

All values in this document are illustrative placeholders.

## Evolution Policy

Audit schema changes are additive:

- New top-level fields must be optional.
- Fields without values must be omitted with `skip_serializing_if`.
- Existing field meanings should not be changed.
- Strict downstream consumers, such as Athena tables or SIEM mappings, must be
  migrated before relying on newly added fields.

## Top-Level Fields

| Field | Required | Notes |
|---|---:|---|
| `event_id` | yes | Unique audit event UUID. |
| `timestamp` | yes | RFC3339 UTC timestamp. |
| `actor` | yes | Authenticated actor, usually Cognito `sub`. |
| `action` | yes | Snake-case audit action. |
| `account_id` | no | AWS account scope when applicable. |
| `region` | no | AWS region scope when applicable. |
| `target_resource` | no | Resource identifier, such as EC2 instance id or log group ARN/name. |
| `target_resource_name` | no | Human-readable target label when known. For EC2 connect this is the instance `Name` tag. |
| `outcome` | yes | `success`, `failure`, or `denied`. |
| `error_message` | no | Sanitized error or denial reason. |
| `metadata` | no | Request context and action-specific JSON object. Treat as sensitive. |

`metadata` can contain user-entered CloudWatch queries or filter patterns by
design. Audit logs should therefore be handled as sensitive operational data.

## Actions

Current actions:

- `login`
- `logout`
- `ec2_list`
- `ec2_connect`
- `ec2_power`
- `ecs_task_list`
- `ecs_exec`
- `cloudwatch_search`
- `cloudwatch_insights_query`
- `cloudwatch_live_tail_start`
- `cloudwatch_live_tail_stop`
- `log_group_list`
- `entitlements_view`
- `mcp_session_register`
- `mcp_guidance_sync`
- `mcp_cloudwatch_discovery`
- `mcp_cloudwatch_preflight`
- `mcp_cloudwatch_search`
- `mcp_cloudwatch_insights`
- `mcp_database_scope_list`
- `mcp_database_query`
- `mcp_ec2_diagnostics`
- `mfa_totp_enroll`
- `mfa_totp_verify`
- `mfa_recovery_codes_generate`
- `mfa_recovery_code_verify`
- `mfa_webauthn_enroll`

`ec2_power` is emitted by the control-plane when an authorized operator requests
an EC2 start, stop, or reboot action.

`mfa_totp_enroll` is emitted when a local TOTP enrollment starts or confirms.
Metadata includes `stage`, `factor_id`, and `kind`; it must not include the
TOTP secret or verification code.

`mfa_totp_verify` is emitted when a local TOTP factor is verified for step-up.
Metadata includes `factor_id` and `kind`; it must not include the verification
code.

`mfa_recovery_codes_generate` is emitted when local MFA recovery codes are
generated or rotated. Metadata includes `count`; it must not include plaintext
recovery codes.

`mfa_recovery_code_verify` is emitted when a local MFA recovery code is consumed
for step-up. Metadata includes `remaining_codes`; it must not include the
plaintext recovery code.

`mfa_webauthn_enroll` is emitted when local WebAuthn registration starts or
finishes. Metadata includes `stage`, `factor_id`, `kind`, and the localhost
`origin` for start events; it must not include challenge bytes, browser
credential payloads, credential IDs, or public-key material.

`mfa_webauthn_verify` is emitted when local WebAuthn/passkey verification starts
or finishes for step-up. Metadata includes `stage`, `challenge_id` on start or
failure, `factor_id` on finish, `kind`, and the localhost `origin` for start
events; it must not include challenge bytes, browser assertion payloads,
credential IDs, or public-key material.

## Common Metadata Fields

Common request context:

- `actor_email`
- `actor_email_verified`
- `client_ip`
- `user_agent`
- `tui_version`

Auth metadata can include:

- `actor_email`
- `token_expires_at`
- `refresh_token`
- `flow`

CloudWatch metadata can include:

- `prefix`
- `filter_pattern`
- `query_string`
- `start_time`
- `end_time`
- `limit`
- `has_next_token`
- `log_group_names`
- `log_group_arns`
- `query_id`

EC2 metadata can include:

- `name_filter`
- `state_filter`
- `tag_filters`
- `page_size`
- `returned_count`
- `total_count`
- `failed_scopes`
- `method`
- `os_user`

ECS metadata can include:

- `clusters_filter`
- `clusters_returned`
- `tasks_returned`
- `truncated`
- `failed_scopes`
- `cluster_name`
- `cluster_arn`
- `task_arn`
- `container_name`
- `launch_type`
- `broad_discovery`
- `error_kind`

EC2 power metadata (`action: "ec2_power"`) can include:

- `power_action` — `start` / `stop` / `reboot`
- `previous_state` — instance state observed via DescribeInstances immediately
  before the AWS power call (e.g. `running`, `stopped`)
- `requested_state` — state AWS reported in the StartInstances /
  StopInstances / RebootInstances response (often a transient state like
  `pending` or `stopping`)
- `confirmation_present` — boolean. The TUI requires the user to type the
  instance id before submitting; this field records that the safeguard
  fired but never stores the typed value.

Entitlements metadata usually contains the common request context fields only.

MCP metadata is additive and is recorded inside `metadata`. Product Phase 3
uses dedicated top-level MCP actions:

- `mcp_session_register` for MCP session registration.
- `mcp_guidance_sync` for guidance delivery sync.
- `mcp_cloudwatch_discovery` for MCP CloudWatch log-group discovery.
- `mcp_cloudwatch_preflight` for CloudWatch data preflight token issuance and denial.
- `mcp_cloudwatch_search` for MCP CloudWatch FilterLogEvents attempt/success/failure/denial.
- `mcp_cloudwatch_insights` for MCP CloudWatch Logs Insights start/poll lifecycle events.
- `mcp_database_scope_list` for MCP Database v1 scope discovery.
- `mcp_database_query` for MCP Database v1 query events.
- `mcp_ec2_diagnostics` for MCP EC2 Diagnostics v1 command/result lifecycle metadata. Raw command specs and remote output are not audit fields.

Common MCP metadata can include:

- `client_type`: `mcp`
- `surface`: `mcp`
- `mcp_event_kind`
- `mcp_outcome_kind`
- `aws_execution_attempted`
- `canopy_mcp_session_id`
- `local_secret_generation`
- `protocol_version`
- `client_name`
- `client_version`
- `product_phase`

MCP session/guidance gate outcomes are shared by every guidance-gated tool
(`cloudwatch_discovery` / `cloudwatch_preflight` / `cloudwatch_search` /
`cloudwatch_insights`, `database_scope_list` / `database_query`). When a
request fails the session or guidance check, `mcp_outcome_kind` is one of the
following (these mirror `McpGuidanceDenial` in
`apps/control-plane/src/routes/mcp.rs` — keep this list in sync):

- `mcp_session_required` — no `canopy_mcp_session_id` / `local_secret_generation`
  was supplied. HTTP 403.
- `mcp_session_not_found` — the session id is unknown to the store (never
  registered, or already evicted/expired out). HTTP 404.
- `mcp_session_actor_mismatch` — the session belongs to a different actor than
  the authenticated caller. HTTP 403.
- `mcp_session_generation_mismatch` — the supplied `local_secret_generation`
  does not match the session. HTTP 403.
- `mcp_session_expired` — the session is past its `expires_at`. HTTP 403.
- `guidance_required` — the session is valid but the required guidance has not
  been delivered for gating. HTTP 403. (Not emitted by `mcp_guidance_sync`.)

`mcp_guidance_sync` emits the same session-validity reasons
(`mcp_session_actor_mismatch` / `mcp_session_generation_mismatch` /
`mcp_session_expired`) when the target session is invalid for the caller.

`mcp_session_store_unavailable` is intentionally **not** an audit outcome: a
session-store backend failure returns HTTP 503 and is deliberately **not**
written as a `Denied` event, so an infrastructure outage does not pollute the
denial trail or trip denial-based alerting. Detect store outages via service
logs/metrics (look for `DynamoDB MCP session store operation failed` warnings),
not the audit trail.

MCP CloudWatch discovery metadata can include:

- `mcp_event_kind`: `cloudwatch_discovery`
- `mcp_outcome_kind`: `success`, `entitlement_disabled`,
  `scope_not_authorized`, `guidance_required`, `mcp_session_required`,
  `discovery_cursor_expired`, `discovery_cursor_scope_mismatch`,
  `discovery_cursor_entitlement_changed`,
  `discovery_cursor_exhausted_or_policy_changed`, or other cursor validation
  reasons.
- `tool_name`: `canopy_list_allowed_log_groups`
- `prefix`
- `aws_execution_attempted`
- `returned_count`
- `scanned_count`
- `truncated`
- `cursor_issued`

MCP CloudWatch data metadata can include:

- `mcp_event_kind`: `cloudwatch_preflight`, `cloudwatch_search`, or
  `cloudwatch_insights`.
- `mcp_outcome_kind`: `attempt`, `success`, `started`, `complete`,
  `invalid_token_mode`, token validation reasons, entitlement/scope denial
  reasons, or AWS failure reasons.
- `tool_name`: `canopy_preflight_request`, `canopy_search_logs`, or
  `canopy_run_insights_query`.
- `log_group_name` / `log_group_names`
- `filter_pattern_raw` / `query_string_raw`: denial paths redact raw input as
  `[redacted: denial path]`. After the relevant guidance, preflight, and
  scope-entitlement gates pass, raw values are encrypted by default and these
  plaintext fields contain `[encrypted: see *_raw_encrypted]`.
- `filter_pattern_raw_encrypted` / `query_string_raw_encrypted`: sealed raw
  filter/query values for successful MCP CloudWatch data lifecycle events.
- `raw_audit_storage`: `encrypted_default` unless the same entitlement rule that
  authorizes the CloudWatch account/region/log groups also sets
  `can_view_mcp_raw_audit_plaintext = true`; then it is
  `plaintext_restricted`.
- `raw_plaintext_allowed`: boolean reviewer signal for whether the raw
  plaintext value was intentionally written under the same scoped entitlement
  rule.
- `has_preflight_token`, `has_search_cursor`, `has_query_token`
- `aws_execution_planned` / `aws_execution_attempted`
- `returned_count`, `row_count`, `status`, `truncated`, `cursor_issued`

MCP Database v1 metadata can include:

- `mcp_event_kind`: `database_scope_list` or `database_query`
- `mcp_outcome_kind`: one of the values listed below (matches the
  `reason` literal the executor emits — keep this list in sync with
  `apps/control-plane/src/services/database.rs` if new ones are added):

  - `attempt` / `success` — lifecycle markers.
  - View-guard rejections: `view_not_allowed_by_scope`,
    `non_base_table_not_allowed_by_scope`, `table_type_unknown`,
    `view_swap_detected_between_checks`, `view_check_failed`.
  - EXPLAIN-plan rejections: `full_table_scan`, `max_examined_rows`,
    `empty_explain`, `explain_failed`, `explain_table_case_mismatch`,
    `explain_schema_out_of_scope`, `explain_schema_outside_default_db`.
  - Overload: `connection_queue_full`,
    `database_connection_unavailable`.
  - Generic IO/exec failure: `database_execution_failed`,
    `credential_load_failed` (Secrets Manager fetch failed before any
    MySQL round-trip).
  - Validation failures: `bad_request`, `denied` (catch-all when no
    structured reason fits).
- `tool_name`: `canopy_list_database_scopes` or `canopy_query_database`
- `database_scope`
- `connection`
- `environment`
- `sql_raw`
- `tables`
- `db_execution_planned` / `explain_planned` **:
  intent recorded on the `attempt` event committed BEFORE Secrets
  Manager or MySQL is touched. SIEM rules that previously pivoted on
  `db_execution_attempted == true` on the attempt event must migrate to
  these fields.
- `db_execution_attempted` / `explain_attempted`: reserved for terminal
  events that actually entered each stage. **On the pre-DB `attempt`
  event these are `false`.** A `true` value implies the executor
  acquired a real MySQL connection (for `db_execution_attempted`) or
  issued the EXPLAIN statement (for `explain_attempted`).
- `explain_passed`
- `access_type`
- `key_used`
- `estimated_rows`
- `row_count`
- `views_allowed` / `view_check_required` / `view_check_passed`
- `rejection_reason`

MCP Database v1 records raw SQL by design. Treat audit access as sensitive.

### Overload events

When the executor refuses a request because of saturation rather than
policy or input, the terminal event is `outcome=failure` with
`mcp_outcome_kind` set to one of:

- `connection_queue_full` — the local per-connection semaphore queue
  hit its wait budget. HTTP 503.
- `database_connection_unavailable` — MySQL connection acquisition
  failed in a way consistent with upstream saturation (timeout, `1040
  ER_CON_COUNT_ERROR`, `1203 ER_TOO_MANY_USER_CONNECTIONS`). HTTP 503.

Both records carry `db_execution_attempted=false` and
`explain_attempted=false`; alerting on these reasons should drive
client-side backoff, not on-call paging.

## Examples

Successful EC2 connect:

```json
{"event_id":"018b7a5d-6e0b-7d1b-9e2c-9c4b4f8e1111","timestamp":"2026-05-08T02:15:30Z","actor":"example-cognito-sub","action":"ec2_connect","account_id":"123456789012","region":"ap-northeast-1","target_resource":"i-0123456789abcdef0","target_resource_name":"web-prod-01","outcome":"success","metadata":{"actor_email":"user@example.com","actor_email_verified":true,"client_ip":"10.0.0.10","user_agent":"canopy-tui/0.1.0","tui_version":"0.1.0","method":"ssm","os_user":"ec2-user"}}
```

Denied CloudWatch search:

```json
{"event_id":"018b7a5d-6e0b-7d1b-9e2c-9c4b4f8e2222","timestamp":"2026-05-08T02:16:30Z","actor":"example-cognito-sub","action":"cloudwatch_search","account_id":"123456789012","region":"ap-northeast-1","target_resource":"/app/web-service","outcome":"denied","error_message":"CloudWatch search not authorized","metadata":{"actor_email":"user@example.com","actor_email_verified":true,"client_ip":"10.0.0.10","user_agent":"canopy-tui/0.1.0","tui_version":"0.1.0","filter_pattern":"ERROR","start_time":1778199390000,"end_time":1778202990000,"limit":100}}
```

Failure during log group listing:

```json
{"event_id":"018b7a5d-6e0b-7d1b-9e2c-9c4b4f8e3333","timestamp":"2026-05-08T02:17:30Z","actor":"example-cognito-sub","action":"log_group_list","account_id":"123456789012","region":"ap-northeast-1","outcome":"failure","error_message":"AWS DescribeLogGroups failed","metadata":{"actor_email":"user@example.com","actor_email_verified":true,"client_ip":"10.0.0.10","user_agent":"canopy-tui/0.1.0","tui_version":"0.1.0","prefix":"/app/"}}
```

Pre-DB MCP Database `attempt` event (committed before Secrets Manager or
MySQL is touched; the `*_planned` fields signal user intent, while
`*_attempted` waits for the terminal event):

```json
{"event_id":"018b7a5d-6e0b-7d1b-9e2c-9c4b4f8e3330","timestamp":"2026-05-08T02:17:44Z","actor":"example-cognito-sub","action":"mcp_database_query","outcome":"success","metadata":{"actor_email":"user@example.com","actor_email_verified":true,"client_type":"mcp","surface":"mcp","mcp_event_kind":"database_query","mcp_outcome_kind":"attempt","tool_name":"canopy_query_database","database_scope":"orders_prod_readonly","connection":"orders_prod","environment":"production","sql_raw":"select id, status from orders where id = 123 limit 20","tables":["orders"],"db_execution_attempted":false,"explain_attempted":false,"db_execution_planned":true,"explain_planned":true,"views_allowed":false,"view_check_required":true}}
```

Successful MCP Database query:

```json
{"event_id":"018b7a5d-6e0b-7d1b-9e2c-9c4b4f8e3334","timestamp":"2026-05-08T02:17:45Z","actor":"example-cognito-sub","action":"mcp_database_query","outcome":"success","metadata":{"actor_email":"user@example.com","actor_email_verified":true,"client_type":"mcp","surface":"mcp","mcp_event_kind":"database_query","mcp_outcome_kind":"success","tool_name":"canopy_query_database","database_scope":"orders_prod_readonly","connection":"orders_prod","environment":"production","sql_raw":"select id, status from orders where id = 123 limit 20","tables":["orders"],"db_execution_attempted":true,"explain_attempted":true,"explain_passed":true,"views_allowed":false,"view_check_required":true,"view_check_passed":true,"access_type":"const","key_used":"PRIMARY","estimated_rows":1,"row_count":1}}
```

MCP Database overload (503; the executor refused the request because the
local connection-limiter queue was full):

```json
{"event_id":"018b7a5d-6e0b-7d1b-9e2c-9c4b4f8e3336","timestamp":"2026-05-08T02:17:55Z","actor":"example-cognito-sub","action":"mcp_database_query","outcome":"failure","error_message":"Database connection queue is full; retry after the in-flight requests complete.","metadata":{"actor_email":"user@example.com","actor_email_verified":true,"client_type":"mcp","surface":"mcp","mcp_event_kind":"database_query","mcp_outcome_kind":"connection_queue_full","tool_name":"canopy_query_database","database_scope":"orders_prod_readonly","connection":"orders_prod","environment":"production","db_execution_attempted":false,"explain_attempted":false,"views_allowed":false,"view_check_required":true,"view_check_passed":false,"rejection_reason":"connection_queue_full"}}
```

MCP Database query rejected by EXPLAIN gate:

```json
{"event_id":"018b7a5d-6e0b-7d1b-9e2c-9c4b4f8e3335","timestamp":"2026-05-08T02:17:50Z","actor":"example-cognito-sub","action":"mcp_database_query","outcome":"denied","error_message":"Query rejected before execution: full table scan is not allowed","metadata":{"actor_email":"user@example.com","actor_email_verified":true,"client_type":"mcp","surface":"mcp","mcp_event_kind":"database_query","mcp_outcome_kind":"full_table_scan","tool_name":"canopy_query_database","database_scope":"orders_prod_readonly","connection":"orders_prod","environment":"production","sql_raw":"[redacted: denial path; raw SQL is captured only by the post-guidance `attempt` event]","tables":["orders"],"db_execution_attempted":false,"explain_attempted":true,"explain_passed":false,"rejection_reason":"full_table_scan","access_type":"ALL","estimated_rows":2400000}}
```

Successful EC2 power action (stop):

```json
{"event_id":"018b7a5d-6e0b-7d1b-9e2c-9c4b4f8e4444","timestamp":"2026-05-08T02:18:30Z","actor":"example-cognito-sub","action":"ec2_power","account_id":"123456789012","region":"ap-northeast-1","target_resource":"i-0123456789abcdef0","target_resource_name":"web-prod-01","outcome":"success","metadata":{"actor_email":"user@example.com","actor_email_verified":true,"client_ip":"10.0.0.10","user_agent":"canopy-tui/0.1.0","tui_version":"0.1.0","power_action":"stop","previous_state":"running","requested_state":"stopping","confirmation_present":true}}
```

Denied EC2 power action (entitlement / scope rejection):

```json
{"event_id":"018b7a5d-6e0b-7d1b-9e2c-9c4b4f8e5555","timestamp":"2026-05-08T02:19:30Z","actor":"example-cognito-sub","action":"ec2_power","account_id":"123456789012","region":"ap-northeast-1","target_resource":"i-0123456789abcdef0","outcome":"denied","error_message":"instance excluded by tag policy","metadata":{"actor_email":"user@example.com","actor_email_verified":true,"client_ip":"10.0.0.10","user_agent":"canopy-tui/0.1.0","tui_version":"0.1.0","power_action":"stop","confirmation_present":true}}
```

Successful ECS task listing:

```json
{"event_id":"018b7a5d-6e0b-7d1b-9e2c-9c4b4f8e8888","timestamp":"2026-05-08T02:22:30Z","actor":"example-cognito-sub","action":"ecs_task_list","account_id":"123456789012","region":"ap-northeast-1","outcome":"success","metadata":{"actor_email":"user@example.com","actor_email_verified":true,"client_ip":"10.0.0.10","user_agent":"canopy-tui/0.1.0","tui_version":"0.1.0","page_size":50,"clusters_returned":1,"tasks_returned":4,"truncated":false,"failed_scopes":[],"broad_discovery":false}}
```

Successful ECS Exec:

```json
{"event_id":"018b7a5d-6e0b-7d1b-9e2c-9c4b4f8e9999","timestamp":"2026-05-08T02:23:30Z","actor":"example-cognito-sub","action":"ecs_exec","account_id":"123456789012","region":"ap-northeast-1","target_resource":"arn:aws:ecs:ap-northeast-1:123456789012:task/prod-app/abc123","outcome":"success","metadata":{"actor_email":"user@example.com","actor_email_verified":true,"client_ip":"10.0.0.10","user_agent":"canopy-tui/0.1.0","tui_version":"0.1.0","cluster_name":"prod-app","cluster_arn":"arn:aws:ecs:ap-northeast-1:123456789012:cluster/prod-app","task_arn":"arn:aws:ecs:ap-northeast-1:123456789012:task/prod-app/abc123","container_name":"app","launch_type":"FARGATE","broad_discovery":false}}
```

State-machine conflict (e.g. `start` while pending):

```json
{"event_id":"018b7a5d-6e0b-7d1b-9e2c-9c4b4f8e6666","timestamp":"2026-05-08T02:20:30Z","actor":"example-cognito-sub","action":"ec2_power","account_id":"123456789012","region":"ap-northeast-1","target_resource":"i-0123456789abcdef0","outcome":"denied","error_message":"already_in_target_or_transition","metadata":{"actor_email":"user@example.com","actor_email_verified":true,"client_ip":"10.0.0.10","user_agent":"canopy-tui/0.1.0","tui_version":"0.1.0","power_action":"start","previous_state":"pending","confirmation_present":true}}
```

AWS SDK failure during power call:

```json
{"event_id":"018b7a5d-6e0b-7d1b-9e2c-9c4b4f8e7777","timestamp":"2026-05-08T02:21:30Z","actor":"example-cognito-sub","action":"ec2_power","account_id":"123456789012","region":"ap-northeast-1","target_resource":"i-0123456789abcdef0","target_resource_name":"web-prod-01","outcome":"failure","error_message":"AWS StopInstances failed: rate exceeded","metadata":{"actor_email":"user@example.com","actor_email_verified":true,"client_ip":"10.0.0.10","user_agent":"canopy-tui/0.1.0","tui_version":"0.1.0","power_action":"stop","previous_state":"running","confirmation_present":true}}
```
