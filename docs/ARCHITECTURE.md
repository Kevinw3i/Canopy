# Canopy — Complete Architecture

> Version 0.1.0 | Rust workspace | TUI client + control-plane + shared DTOs

---

## System Overview

```
 Operator Terminal                    Control Plane                        External
 ================                    =============                        ========

 +-----------------+    HTTP/JSON    +--------------------+ STS/EC2/ECS/CWL +-------+
 |   TUI Client    |--------------->|   Control Plane    |--------------->|  AWS  |
 |   (ratatui)     |<---------------|   (axum)           |<---------------|       |
 |                 |    JWT bearer   |                    |                +-------+
 |  - Login        |                 |  - Auth (OIDC)     |
 |  - EC2/ECS Inv. |                 |  - Entitlements    |   OIDC         +-------+
 |  - CW Search    |                 |  - Audit logging   |--------------->| IdP   |
 |  - Live Tail    |                 |  - AWS integration |<---------------|       |
 |  - Access       |                 |  - Server-side     |   JWKS/token   +-------+
 |  - Settings     |                 |    filtering       |
 +-----------------+                 +--------------------+
        |
       | ssh / aws ssm / aws ec2-instance-connect / aws ecs execute-command
       v
 +-----------------------+
 | Target Instance/Task  |
 | (SSM / EIC / ECS Exec)|
 +-----------------------+
```

## Workspace Layout

```
Canopy/
  Cargo.toml                    Workspace root
  config.sample.toml            Production-safe config template
  entitlements.sample.toml      Entitlements sample
  .env.example                  Environment variables reference

  crates/
    shared/                     Shared DTOs + error types
      src/dto/
        auth.rs                 PKCE, DeviceCode, Token, Refresh DTOs
        ec2.rs                  Ec2Instance, ConnectRequest/Response, AssumedRoleCredentials
        ecs.rs                  EcsTask, EcsContainer, ECS Exec request/response DTOs
        cloudwatch.rs           LogGroup, LogEvent, Insights, LiveTail DTOs
        entitlements.rs         UserEntitlements, FeatureFlags, TagSelector, AllowedAccount
        audit.rs                AuditEvent, AuditAction, AuditOutcome
      src/errors.rs             ApiError

  apps/
    control-plane/              Axum REST API
      Dockerfile                Multi-stage build for ECS Fargate
      src/
        main.rs                 Startup, CORS, dev_mode loopback guard
        config.rs               AppConfig, OidcConfig, JwtConfig, AwsConfig
        middleware/auth.rs      JWT validation (require_auth)
        routes/
          auth.rs               /auth/* (PKCE, device-code, refresh, dev-login)
          ec2.rs                /api/ec2/list, /api/ec2/connect, /api/ec2/power
          ecs.rs                /api/ecs/tasks, /api/ecs/exec
          cloudwatch.rs         /api/cloudwatch/* (log-groups, filter, insights)
          live_tail.rs          /api/cloudwatch/live-tail (WebSocket, beta)
          entitlements.rs       /api/entitlements
        services/
          mod.rs                AppState, sign/verify_query_token (HMAC)
          auth.rs               JWT issue/validate, OIDC exchange
          oidc.rs               Discovery, JWKS cache, token exchange, device code
          ec2.rs                build_connect_command, EC2 entitlement filtering
          ecs.rs                ECS task filtering, rule-local scopes, exec command builder
          cloudwatch.rs         QueryPoller, mock data
          entitlements.rs       EntitlementService, arn_matches_pattern
          audit.rs              JSONL file + tracing (fail-closed)
        aws/
          credentials.rs        AssumeRole, scoped EC2/ECS policies, sanitize session name
          clients.rs            AwsClients factory (fresh per-request)
          ec2_convert.rs        SDK Instance -> DTO conversion
        models/
          entitlements.rs       EntitlementStore (evaluate, load TOML)

    tui-client/                 Ratatui terminal UI
      src/
        app.rs                  Event loop, action handling
        config.rs               ClientConfig (fail-closed without config)
        event.rs                Event/Action/Screen, EventReader (pausable)
        tui.rs                  Terminal init/suspend/resume
        api_client.rs           HTTP client for control-plane
        live_tail_ws.rs         Live tail stub (dev mode)
        updater.rs              Auto-update via GitHub Releases (SHA256 verified)
        auth/
          pkce.rs               Dual-stack listener, URL decode, browser
          device_code.rs        Poll + exponential backoff
        components/
          login.rs              Dev-mode aware focus order
          dashboard.rs          Live-tail beta gating
          ec2.rs                EC2/ECS inventory table, details, connect, container picker
          cloudwatch_search.rs  Quick search + Insights (dual mode)
          live_tail.rs          Pause/resume state machine
          access.rs             User identity, groups, feature flags
          settings.rs           Current config display
          error_modal.rs        Overlay error dialog
          loading.rs            Async loading spinner
        widgets/
          input.rs              UTF-8 safe cursor (byte boundaries)
          table.rs              Keyboard-navigable table

  infra/                        Terraform IaC for control-plane (see infra/README.md)
  scripts/
    package.sh                  TUI client packaging for distribution
    docker-entrypoint.sh        Container startup + Secrets Manager injection
```

## Authentication Flow

### PKCE (Desktop)

```
 TUI                     Control Plane              OIDC Provider
  |                           |                          |
  | bind localhost:9876       |                          |
  | (IPv4 + IPv6)            |                          |
  |                           |                          |
  |--POST /auth/pkce/start-->|                          |
  |  {code_verifier,          |                          |
  |   redirect_uri}           |                          |
  |<--{authorize_url, state}--|                          |
  |                           |                          |
  |--open browser----------->|------------------------->|
  |<--callback code+state----|--------------------------|
  |  (URL-decoded)            |                          |
  |                           |                          |
  |--POST /auth/pkce/exchange>|--token exchange--------->|
  |  {code, code_verifier,    |  {code, code_verifier,   |
  |   state, redirect_uri}    |   client_id}             |
  |                           |<--{id_token, refresh}----|
  |                           |                          |
  |                           |--JWKS fetch (cached)---->|
  |                           |<--{keys: [JWK...]}-------|
  |                           |                          |
  |                           |  verify signature (RS256/ES256)
  |                           |  validate iss, aud, exp (fail-closed)
  |                           |  lookup entitlement groups
  |                           |  issue internal JWT
  |                           |                          |
  |<--{access_token, refresh}-|                          |
```

### Device Code (Headless)

```
 TUI                     Control Plane              OIDC Provider
  |                           |                          |
  |--POST /device-code/start->|--device_authorization--->|
  |<--{user_code, uri}--------|<--{device_code, ...}-----|
  |                           |                          |
  | display: "Go to {uri},    |                          |
  |  enter: {user_code}"      |                          |
  |                           |                          |
  | (background poll)         |                          |
  |--POST /device-code/poll-->|--token endpoint--------->|
  |<--pending / complete------|<--pending / tokens-------|
```

## EC2 Connect Flow

```
 TUI                     Control Plane              AWS
  |                           |                      |
  |--POST /api/ec2/connect-->|                      |
  |  {instance_id, account,   |                      |
  |   region, method, os_user}|                      |
  |                           |                      |
  |                    1. Audit health check          |
  |                    2. Region entitlement           |
  |                    3. IAM SimulatePrincipalPolicy  |
  |                       for each candidate role:    |
  |                           |--Simulate----------->|
  |                           |<--Allowed/Denied-----|
  |                       pick first Allowed role     |
  |                    4. AssumeRole (full)            |
  |                           |--AssumeRole--------->|
  |                           |<--credentials--------|
  |                    5. DescribeInstances (tags)     |
  |                           |--DescribeInstances-->|
  |                           |<--instance + tags----|
  |                    6. Entitlement checks           |
  |                       (tags, features, os_user)   |
  |                    7. Scoped AssumeRole            |
  |                       (inline policy: SSM or EIC) |
  |                           |--AssumeRole+policy-->|
  |                           |<--scoped creds-------|
  |                    8. (EIC) resolve endpoint       |
  |                           |--DescribeEICEndpts-->|
  |                           |<--endpoint_id--------|
  |                    9. Audit (fail-closed on write) |
  |                           |                      |
  |<--{command, args, env}----|                      |
  |                           |                      |
  | (if 2+ OS users) show     |                      |
  | user selection popup       |                      |
  |                            |                      |
  | pause EventReader          |                      |
  | suspend TUI                |                      |
  | spawn:                     |                      |
  |  SSM+user: ssh -l {user} -o ProxyCommand="..."    |
  |  SSM:      aws ssm start-session --target ...      |
  |  EIC:      aws ec2-instance-connect ssh            |
  |            --instance-connect-endpoint-id {ep}     |
  |  SSH:      ssh {user}@{ip}  (operator's own key)   |
  |                             |                      |
  | if max_session_seconds set: |                      |
  |   background timer (1s poll)|                      |
  |   on timeout → kill process |                      |
  |   print "Session timeout"   |                      |
  |                             |                      |
  | resume TUI + EventReader    |                      |
```

### role_arn resolution modes

```
 role_arn value               Behavior
 ───────────────────────────  ─────────────────────────────────────
 "direct"                     Use ambient AWS credentials (default profile)
 "profile:NAME"               Use ~/.aws/credentials profile NAME
 "arn:aws:iam::...:role/..."  STS AssumeRole into that IAM role (production)
```

For inventory/search paths, `direct` and `profile:` modes can use local
credentials after `GetCallerIdentity` confirms the configured account. SSM/EIC
connect and ECS Exec require an AssumeRole ARN because the control-plane must
return short-lived scoped credentials to the spawned CLI process. Direct SSH is
the only connect path that does not need AWS-scoped credentials.

## ECS Task Inventory and Exec Flow

```
 TUI                     Control Plane              AWS
  |                           |                      |
  |--POST /api/ecs/tasks---->|                      |
  |  {account?, region?,      |                      |
  |   cluster?, page_size?}   |                      |
  |                           |                      |
  |                    1. Audit health check          |
  |                    2. Build rule-local ECS scopes |
  |                       (account, role, region,     |
  |                        cluster, task tags,        |
  |                        container denylist)        |
  |                    3. Reject unauthorized scope   |
  |                    4. List/Describe clusters      |
  |                       and tasks per scoped rule   |
  |                           |--List/Describe ECS-->|
  |                           |<--tasks + metadata---|
  |                    5. Server-side task filtering  |
  |                    6. Audit result + partials     |
  |<--{tasks, failed_scopes, truncated}--------------|
  |
  | (Enter on running exec-ready task)
  | show container picker for running containers
  |
  |--POST /api/ecs/exec----->|
  |  {cluster_arn, task_arn, |
  |   container_name, ...}   |
  |                    1. Re-fetch task by ARN        |
  |                    2. Re-check same rule-local    |
  |                       scope and container denylist |
  |                    3. IAM SimulatePrincipalPolicy |
  |                       for assumable candidates    |
  |                    4. Scoped AssumeRole policy:   |
  |                       ExecuteCommand on task,     |
  |                       region-limited DescribeTasks|
  |                       and ssmmessages channels    |
  |<--{aws ecs execute-command, env creds, timeout}--|
  | suspend TUI -> spawn AWS CLI -> resume TUI        |
```

## Entitlement Model

```
 EntitlementStore (TOML file or dev_defaults)
  |
  |-- rules[]
  |    |-- id, group
  |    |-- features: {can_view_ec2, can_view_ecs, can_use_ecs_exec, can_use_ssm, ...}
  |    |-- allowed_accounts: [{account_id, account_name, role_arn}]
  |    |-- allowed_regions: ["us-east-1", ...]
  |    |-- allowed_log_group_arns: ["arn:...:log-group:/app/*"]
  |    |-- instance_tag_selectors: [{key: [values]}]
  |    |-- excluded_tag_selectors: [{key: [values]}]  (deny-list)
  |    |-- allowed_clusters: ["arn:aws:ecs:...:cluster/prod-*"]
  |    |-- task_tag_selectors: [{key: [values]}]
  |    |-- excluded_task_tag_selectors: [{key: [values]}]  (deny-list)
  |    |-- excluded_container_names: ["xray-daemon", ...]
  |    |-- allow_broad_cluster_discovery: false
  |    |-- allowed_os_users: ["ec2-user", "ubuntu"]
  |    +-- max_session_seconds: 3600  (optional, 0 = no limit)
  |
  +-- memberships[]
       +-- [{user_id, group}]

 Merge (across groups):
  features:              OR  (any group grants → user has it)
  accounts:              dedup by (account_id, role_arn)
  regions:               dedup
  log_group_arns:        dedup
  tag_selectors:         concatenate (match ANY)
  excluded_tag_selectors: concatenate (match ANY → hidden)
  ECS scopes:            displayed as merged entitlements, enforced rule-locally
  os_users:              dedup
  max_session_seconds:   MIN non-zero (strictest wins)
```

## Security Boundaries

| # | Boundary | Implementation |
|---|----------|----------------|
| 1 | OIDC id_token | JWKS signature verification + iss/aud/exp (fail-closed) |
| 2 | Internal JWT | HMAC-SHA256, configurable expiry, carries email_verified |
| 3 | Entitlements | Server-side filtering with per-rule scope isolation (no cross-group splicing) |
| 4 | Connect creds | Inline IAM session policy (per-method, per-instance or per-task, OS-user / ECS-cluster bound) |
| 5 | SSM os_user | SSH ProxyCommand + IAM condition `ssm:SessionDocumentAccessCheck` |
| 6 | EIC creds | Allows AWS CLI `ec2:DescribeInstances` preflight only in the target region; OS-user bound via `ec2:osuser` condition |
| 7 | ECS scope | Task list and exec must match one rule-local account/role/region/cluster/task-tag/container scope |
| 8 | Audit | Fail-closed on all endpoints (auth, EC2, ECS, CW, entitlements). Transient recovery without restart |
| 9 | Config | dev_mode refuses non-loopback bind; CORS restricted with real AWS; SSM requires explicit allowed_os_users |
| 10 | Insights token | HMAC-signed query auth (survives restart), rejects empty log_group_names |
| 11 | IAM Simulation | SimulatePrincipalPolicy selects EC2 describe/power/connect and ECS Exec AssumeRole candidates with full action+resource sets; local direct/profile candidates are not simulated, and inconclusive AssumeRole simulations fall back only when every simulated candidate errors |
| 12 | Session timeout | max_session_seconds per group, min 900s for STS, kill after timeout (strictest wins) |
| 13 | Account identity | GetCallerIdentity verifies direct/profile/AssumeRole credentials match configured account_id |
| 14 | Email verification | Entitlement email matching gated on IdP `email_verified` claim |
| 15 | STS ExternalId | Configurable ExternalId on all AssumeRole calls (default "canopy") |
| 16 | Token storage | Unix 0600 enforced on every write; insecure permissions rejected on load |

## Scoped Credential Policies

**SSM with os_user** (SSH document only):
```json
{"Action": ["ssm:StartSession"],
 "Resource": ["...instance/{id}", "...document/AWS-StartSSHSession"]}
```

**SSM without os_user** (SSH + shell):
```json
{"Action": ["ssm:StartSession"],
 "Resource": ["...instance/{id}", "...document/AWS-StartSSHSession",
              "...document/SSM-SessionManagerRunShell"]}
```

**EC2 Instance Connect** (no Describe*):
```json
{"Action": ["ec2-instance-connect:SendSSHPublicKey",
            "ec2-instance-connect:OpenTunnel"],
 "Resource": ["...instance/{id}", "...instance-connect-endpoint/*"]}
```

**ECS Exec**:
```json
[
  {
    "Action": ["ecs:ExecuteCommand"],
    "Resource": ["...task/{cluster}/{task-id}"],
    "Condition": {"ArnEquals": {"ecs:cluster": "...cluster/{cluster}"}}
  },
  {
    "Action": ["ecs:DescribeTasks"],
    "Resource": "*",
    "Condition": {"StringEquals": {"aws:RequestedRegion": "{region}"}}
  },
  {
    "Action": [
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel"
    ],
    "Resource": "*",
    "Condition": {"StringEquals": {"aws:RequestedRegion": "{region}"}}
  }
]
```

## Insights Query Authorization

```
 start: token = "{query_id}.{base64({user,log_groups})}.{hmac_sha256}"
 poll:  verify HMAC -> check user + re-verify log_groups -> call AWS
```

No shared state -- survives restarts and multi-replica routing.

## Audit Trail

```
 log_event() -> Result<(), &str>
   |-- tracing::info (always)
   +-- JSONL file (when configured)
       on failure: sink_failed=true, return Err
       effect: all endpoints -> 503 via require_audit_healthy()
```

## Configuration

| Field | Default | Description |
|-------|---------|-------------|
| `bind_address` | `127.0.0.1:8443` | Server listen address |
| `dev_mode` | `false` | Dev login + mock data |
| `entitlements_file` | -- | Entitlements TOML (required in prod) |
| `audit_log` | -- | Durable JSONL audit file |
| `cors_allowed_origins` | `[]` | CORS origins (permissive in dev) |
| `oidc.issuer_url` | -- | OIDC provider URL |
| `oidc.client_id` | -- | OIDC client ID |
| `oidc.acr_values` | `[]` | Optional auth context values sent to the OIDC provider |
| `oidc.prompt` | -- | Optional OIDC prompt parameter, e.g. `login` |
| `oidc.max_age_seconds` | -- | Optional OIDC `max_age`; also validates `auth_time` |
| `oidc.required_acr_values` | `[]` | Optional accepted `acr` claim values for fail-closed MFA enforcement |
| `oidc.required_amr_values` | `[]` | Optional required `amr` claim values for fail-closed MFA enforcement |
| `oidc.jwks_uri` | auto | JWKS endpoint |
| `jwt.secret` | -- | HMAC secret (JWTs + query tokens) |
| `aws.session_duration_seconds` | `3600` | STS AssumeRole duration |
| `control_plane_url` | -- | (TUI) Control plane URL |
| `pkce_callback_port` | `9876` | (TUI) PKCE callback port |
| `enable_live_tail` | `false` | (TUI) Live tail beta |

## Tests

| Crate | Coverage Areas |
|-------|----------------|
| control-plane | Auth/OIDC, entitlement loading and merge invariants, EC2 filtering/connect/power routes, ECS task list/exec scope enforcement, CloudWatch search, audit fail-closed, credential policies, config validation, HMAC helpers |
| shared | Auth, EC2, ECS, CloudWatch, entitlements, audit, error, and PTY DTO serialization/defaults |
| tui-client | Login/auth flows, dashboard feature gating, EC2/ECS inventory rendering and scope cycling, ECS container picker, connect session lifecycle, CloudWatch search, widgets, updater, config, API client integration |
| workspace | `cargo test --workspace` is the source of truth for current counts |
