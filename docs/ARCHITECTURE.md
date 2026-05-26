# Canopy — Complete Architecture

> Version 0.1.0 | 57 Rust source files | ~12,700 lines | 380 tests

---

## System Overview

```
 Operator Terminal                    Control Plane                        External
 ================                    =============                        ========

 +-----------------+    HTTP/JSON    +--------------------+   STS/EC2/CWL  +-------+
 |   TUI Client    |--------------->|   Control Plane    |--------------->|  AWS  |
 |   (ratatui)     |<---------------|   (axum)           |<---------------|       |
 |                 |    JWT bearer   |                    |                +-------+
 |  - Login        |                 |  - Auth (OIDC)     |
 |  - EC2 Inventory|                 |  - Entitlements    |   OIDC         +-------+
 |  - CW Search    |                 |  - Audit logging   |--------------->| IdP   |
 |  - Live Tail    |                 |  - AWS integration |<---------------|       |
 |  - Access       |                 |  - Server-side     |   JWKS/token   +-------+
 |  - Settings     |                 |    filtering       |
 +-----------------+                 +--------------------+
        |
        | ssh / aws ssm / aws ec2-instance-connect
        v
 +-----------------+
 | Target Instance |
 | (SSM / EIC)     |
 +-----------------+
```

## Workspace Layout

```
Canopy/
  Cargo.toml                    Workspace root
  config.sample.toml            Production-safe config template
  entitlements.sample.toml      Entitlements sample
  .env.example                  Environment variables reference

  crates/
    shared/                     Shared DTOs + error types (~680 lines)
      src/dto/
        auth.rs                 PKCE, DeviceCode, Token, Refresh DTOs
        ec2.rs                  Ec2Instance, ConnectRequest/Response, AssumedRoleCredentials
        cloudwatch.rs           LogGroup, LogEvent, Insights, LiveTail DTOs
        entitlements.rs         UserEntitlements, FeatureFlags, TagSelector, AllowedAccount
        audit.rs                AuditEvent, AuditAction, AuditOutcome
      src/errors.rs             ApiError

  apps/
    control-plane/              Axum REST API (~6,100 lines)
      Dockerfile                Multi-stage build for ECS Fargate
      src/
        main.rs                 Startup, CORS, dev_mode loopback guard
        config.rs               AppConfig, OidcConfig, JwtConfig, AwsConfig
        middleware/auth.rs      JWT validation (require_auth)
        routes/
          auth.rs               /auth/* (PKCE, device-code, refresh, dev-login)
          ec2.rs                /api/ec2/list, /api/ec2/connect
          cloudwatch.rs         /api/cloudwatch/* (log-groups, filter, insights)
          live_tail.rs          /api/cloudwatch/live-tail (WebSocket, beta)
          entitlements.rs       /api/entitlements
        services/
          mod.rs                AppState, sign/verify_query_token (HMAC)
          auth.rs               JWT issue/validate, OIDC exchange
          oidc.rs               Discovery, JWKS cache, token exchange, device code
          ec2.rs                build_connect_command, entitlement filtering
          cloudwatch.rs         QueryPoller, mock data
          entitlements.rs       EntitlementService, arn_matches_pattern
          audit.rs              JSONL file + tracing (fail-closed)
        aws/
          credentials.rs        AssumeRole, scoped policy, sanitize session name
          clients.rs            AwsClients factory (fresh per-request)
          ec2_convert.rs        SDK Instance -> DTO conversion
        models/
          entitlements.rs       EntitlementStore (evaluate, load TOML)

    tui-client/                 Ratatui terminal UI (~5,900 lines)
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
          ec2.rs                Instance table, detail, connect
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

For `direct` and `profile:` modes, scoped credentials are skipped —
the spawned CLI process uses the ambient or profile credentials directly.

## Entitlement Model

```
 EntitlementStore (TOML file or dev_defaults)
  |
  |-- rules[]
  |    |-- id, group
  |    |-- features: {can_view_ec2, can_use_ssm, ...}
  |    |-- allowed_accounts: [{account_id, account_name, role_arn}]
  |    |-- allowed_regions: ["us-east-1", ...]
  |    |-- allowed_log_group_arns: ["arn:...:log-group:/app/*"]
  |    |-- instance_tag_selectors: [{key: [values]}]
  |    |-- excluded_tag_selectors: [{key: [values]}]  (deny-list)
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
  os_users:              dedup
  max_session_seconds:   MIN non-zero (strictest wins)
```

## Security Boundaries

| # | Boundary | Implementation |
|---|----------|----------------|
| 1 | OIDC id_token | JWKS signature verification + iss/aud/exp (fail-closed) |
| 2 | Internal JWT | HMAC-SHA256, configurable expiry, carries email_verified |
| 3 | Entitlements | Server-side filtering with per-rule scope isolation (no cross-group splicing) |
| 4 | Connect creds | Inline IAM session policy (per-method, per-instance, OS-user bound) |
| 5 | SSM os_user | SSH ProxyCommand + IAM condition `ssm:SessionDocumentAccessCheck` |
| 6 | EIC creds | Allows AWS CLI `ec2:DescribeInstances` preflight only in the target region; OS-user bound via `ec2:osuser` condition |
| 7 | Audit | Fail-closed on all endpoints (auth, EC2, CW, entitlements). Transient recovery without restart |
| 8 | Config | dev_mode refuses non-loopback bind; CORS restricted with real AWS; SSM requires explicit allowed_os_users |
| 9 | Insights token | HMAC-signed query auth (survives restart), rejects empty log_group_names |
| 10 | IAM Simulation | SimulatePrincipalPolicy with full action+resource set; inconclusive = skip candidate |
| 11 | Session timeout | max_session_seconds per group, min 900s for STS, kill after timeout (strictest wins) |
| 12 | Account identity | GetCallerIdentity verifies direct/profile/AssumeRole credentials match configured account_id |
| 13 | Email verification | Entitlement email matching gated on IdP `email_verified` claim |
| 14 | STS ExternalId | Configurable ExternalId on all AssumeRole calls (default "canopy") |
| 15 | Token storage | Unix 0600 enforced on every write; insecure permissions rejected on load |

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
| `oidc.jwks_uri` | auto | JWKS endpoint |
| `jwt.secret` | -- | HMAC secret (JWTs + query tokens) |
| `aws.session_duration_seconds` | `3600` | STS AssumeRole duration |
| `control_plane_url` | -- | (TUI) Control plane URL |
| `pkce_callback_port` | `9876` | (TUI) PKCE callback port |
| `enable_live_tail` | `false` | (TUI) Live tail beta |

## Tests

| Crate | Unit | Integration | Areas |
|-------|------|-------------|-------|
| control-plane | 123 | 57 | Auth middleware (9), OIDC (22), EC2 filter/connect (14), EC2 convert (12), Entitlement merge (13+4), CloudWatch (2), Audit (3), Credentials (10), Config (5), HMAC helpers (4), Route handlers (57) |
| shared | 43 | — | Auth DTOs (8), EC2 DTOs (7), CloudWatch DTOs (8), Entitlements DTOs (10), Errors (5), TagSelector (5) |
| tui-client | 150 | 7 | Components (80+), Widgets (20), PKCE (11), Updater (10), Config (3), ApiClient (4+7 integration) |
| **Total** | **316** | **64** | **380 tests** |
