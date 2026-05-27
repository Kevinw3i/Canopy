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
- `mfa_totp_enroll`
- `mfa_totp_verify`
- `mfa_recovery_codes_generate`

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
