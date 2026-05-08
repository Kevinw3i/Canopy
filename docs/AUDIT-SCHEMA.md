# Audit Log Schema

Canopy audit events are JSON-lines records emitted through tracing and, when
configured, the durable `audit_log` file.

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
- `cloudwatch_search`
- `cloudwatch_insights_query`
- `cloudwatch_live_tail_start`
- `cloudwatch_live_tail_stop`
- `log_group_list`
- `entitlements_view`

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
