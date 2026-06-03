<p align="center">
  <img src="assets/banner.svg" alt="Canopy" width="800"/>
</p>

Internal terminal operations console for AWS infrastructure management.

```
┌──────────────┐         ┌──────────────────┐         ┌──────────────┐
│  TUI Client  │──HTTP──▶│  Control Plane   │──STS───▶│   AWS APIs   │
│  (ratatui)   │         │  (axum)          │         │ EC2/ECS/CWL  │
│              │◀─JSON───│                  │◀────────│ SSM/STS/Exec │
└──────────────┘         │  - Auth (OIDC)   │         └──────────────┘
                         │  - Entitlements  │
                         │  - Audit logging │
                         │  - Server-side   │
                         │    filtering     │
                         └──────────────────┘
```

| Crate | Path | Purpose |
|-------|------|---------|
| `shared` | `crates/shared` | Shared DTOs, error types |
| `control-plane` | `apps/control-plane` | Axum REST API — auth, entitlements, AWS access |
| `tui-client` | `apps/tui-client` | Ratatui terminal UI — 7 screens, event loop |

---

## Quick start (local development)

### Prerequisites

- Rust 1.75+
- Two terminal windows

> AWS CLI and Session Manager plugin are only needed for connection features (SSM/EIC/ECS Exec). Inventory and search flows work without them.

### Step 1: Build

```bash
cd ~/Desktop/Canopy
cargo build
cargo test        # workspace tests should all pass
```

### Step 2: Start the control-plane (Terminal 1)

```bash
DEV_MODE=1 cargo run -p control-plane
```

You should see:
```
Control-plane listening on 127.0.0.1:8443
```

### Step 3: Start the TUI (Terminal 2)

```bash
DEV_MODE=1 cargo run -p tui-client
```

The TUI opens on the login screen. Type `dev-admin` and press Enter.

### Step 4: Explore

| Screen | How to get there | What it shows |
|--------|-----------------|---------------|
| Dashboard | Automatic after login | Welcome message, navigation menu |
| EC2 / ECS Inventory | Press `1` | EC2 mock instances; press `Ctrl+E` when entitled to switch to ECS tasks. `Enter` opens container selection for exec-ready tasks when ECS Exec is granted |
| CloudWatch Search | Press `2` | Query input, mock log events |
| Access / Identity | Press `4` | Your user, groups, feature flags, allowed accounts |
| Settings | Press `5` | Current config values; press `p` to open Change Password |

Press `Esc` to go back, `Ctrl+x` on Dashboard to log out, `q` to quit.

### Dev users

Two users are pre-configured in the built-in dev defaults:

| Username | Group | What they can do |
|----------|-------|-----------------|
| `dev-admin` | platform-engineering | Everything: EC2, ECS, CloudWatch, SSM, EIC across 2 accounts |
| `dev-readonly` | readonly-ops | Read-only: EC2 view + CloudWatch search on staging only, no connect |

Try logging in as `dev-readonly` to see how the UI hides features the user doesn't have.

---

## Project files

```
Canopy/
├── config.sample.toml         ← Control-plane config (production template)
├── entitlements.sample.toml   ← Permission rules template
├── entitlements.catalog.sample.toml ← Catalog authoring template
├── .env.example               ← Environment variables reference
├── Cargo.toml                 ← Workspace root
│
├── apps/
│   ├── control-plane/         ← Backend server (includes Dockerfile)
│   └── tui-client/            ← Terminal UI (auto-update support)
│
├── crates/
│   └── shared/                ← Shared types
│
├── infra/                     ← Terraform IaC for ECS Fargate deployment
│
├── scripts/
│   ├── package.sh             ← TUI packaging for distribution
│   └── docker-entrypoint.sh   ← Container startup + Secrets Manager injection
│
└── docs/
    ├── en/
    │   ├── ARCHITECTURE.md    ← Full architecture reference
    │   └── AUDIT-SCHEMA.md    ← Audit event schema
    └── zh-TW/
        ├── PRD.md             ← Product requirements
        ├── ECS_FARGATE_DEPLOYMENT.md ← ECS deployment (manual / Terraform)
        ├── COGNITO-SETUP.md   ← AWS Cognito OIDC setup
        ├── OPERATOR-SETUP.md  ← TUI distribution to operators
        └── RELEASING.md       ← Release workflow & CI
```

---

## Configuration reference

### Control-plane config (`DEV_MODE=1` / `config.toml`)

```toml
# ── Server ──────────────────────────────────────────
bind_address = "127.0.0.1:8443"   # IP:port to listen on
dev_mode = true                    # true = enables dev-login
                                   # false = requires OIDC

# ── AWS data source ────────────────────────────────
# mock_aws_data controls whether EC2/CloudWatch use mock or real AWS.
# Defaults to dev_mode value if omitted.
# Set to false while keeping dev_mode = true to use dev-login with real AWS.
# mock_aws_data = false

# ── Entitlements ────────────────────────────────────
# Path to the permission rules file (TOML).
# Required when dev_mode = false.
# Optional when dev_mode = true (falls back to built-in dev defaults).
entitlements_file = "entitlements.toml"

# ── Audit ───────────────────────────────────────────
# Optional. When set, every action is appended to this file as JSON-lines.
# If not set, audit events are only emitted via structured tracing (stdout).
# audit_log = "/var/log/canopy/audit.jsonl"

# Optional remote audit exports. These enqueue JSON audit events after the
# local tracing/file audit write has accepted the event.
# [audit_export]
# queue_size = 1024
#
# [audit_export.cloudwatch_logs]
# log_group_name = "/aws/canopy/audit"
# log_stream_name = "control-plane"
# create_log_stream = true
#
# [audit_export.s3]
# bucket = "canopy-audit"
# prefix = "prod/"

# ── CORS ────────────────────────────────────────────
# List of allowed origins. Empty + dev_mode = allow all.
# cors_allowed_origins = ["http://localhost:9876"]

# ── OIDC ────────────────────────────────────────────
# Not used in dev mode (dev-login bypasses OIDC).
# Required for production — see "Production deployment" below.
[oidc]
issuer_url = "https://placeholder.example.com"
client_id = "not-used-in-dev-mode"
# client_secret = "optional-for-public-pkce-clients"
# scopes = ["openid", "profile", "email"]        # default
#
# Optional endpoint overrides (auto-discovered from issuer_url if omitted):
# authorization_endpoint = "https://..."
# token_endpoint = "https://..."
# device_authorization_endpoint = "https://..."
# jwks_uri = "https://..."

# ── JWT ─────────────────────────────────────────────
[jwt]
secret = "<local-dev-jwt-secret>"
                      # Signing key for internal JWTs.
                      # Production: use `openssl rand -base64 32`
expiry_seconds = 7200 # Token lifetime in seconds

# ── AWS ─────────────────────────────────────────────
[aws]
default_region = "us-east-1"      # Fallback region for STS calls
session_duration_seconds = 3600   # AssumeRole session duration
# sts_external_id = "canopy" # ExternalId for AssumeRole (must match trust policy)
```

**How it's loaded:**
1. If `CONFIG_PATH` env var is set → load that file
2. Else if `config.toml` exists in cwd → load it
3. Else if `DEV_MODE=1` → use built-in defaults (no file needed)
4. Else → error

### Entitlements file (`entitlements.sample.toml` / `entitlements.toml`)

Defines who can access what. Structure:

```toml
# ── One [[rules]] block per group ───────────────────

[[rules]]
id = "rule-platform-eng"                # Unique rule ID
group = "platform-engineering"           # Group name (matches memberships below)
allowed_regions = ["us-east-1", "us-west-2"]
allowed_log_group_arns = [
    "arn:aws:logs:*:123456789012:log-group:/app/*",   # Wildcards supported
]
allowed_clusters = [
    "arn:aws:ecs:us-east-1:123456789012:cluster/prod-*",
]
allowed_os_users = ["ec2-user", "ubuntu"]              # For SSM/EIC connect

[rules.features]
can_view_ec2 = true               # Can see EC2 instances
can_view_ecs = true               # Can see ECS tasks in allowed clusters
can_use_ecs_exec = true           # Can open ECS Exec sessions
can_use_cloudwatch_search = true  # Can search CloudWatch logs
can_use_cloudwatch_tail = true    # Can use Live Tail
can_use_ssm = true                # Can connect via SSM Session Manager
can_use_ec2_instance_connect = true  # Can connect via EC2 Instance Connect
can_use_mcp = true                # Can start the local MCP / AI Tools server
can_use_mcp_cloudwatch = false    # Reserved for MCP CloudWatch data tools
can_view_mcp_raw_audit_plaintext = false  # Default: encrypt raw MCP CloudWatch filters/queries in audit
can_use_mcp_ec2 = false           # Enables only scoped MCP EC2 diagnostics when mcp_ec2_diagnostic_scopes are present
can_use_mcp_database = true       # Can use MCP Database tools when scoped below

# Optional MCP EC2 diagnostics scopes. These are rule-local command scopes;
# they are not merged across rules. Keep can_use_mcp_ec2=false unless the same
# rule also provides concrete safe-for-MCP log/connectivity scopes.
#
# [[rules.mcp_ec2_diagnostic_scopes]]
# id = "rails-nginx-health"
# max_lines = 100
# max_since_seconds = 1800
# max_timeout_seconds = 30
# max_matches = 50
# connectivity_probe_budget_per_window = 20
# budget_window_seconds = 600
# denylist_version = "2026-06-04"
# allowlist_rule_id = "rails-nginx-health-v1"
#
# [[rules.mcp_ec2_diagnostic_scopes.allowed_log_paths]]
# path_pattern = "/var/log/nginx/error.log"
# canonical_safe_prefix = "/var/log/nginx/"
# safe_for_mcp_output = true
#
# [[rules.mcp_ec2_diagnostic_scopes.allowed_http_urls]]
# normalized_url = "https://orders.internal/health"
# query_policy = "no_query"
# safe_for_mcp_output = true

# Optional MCP Business Scopes. These are AI/MCP discovery hints only;
# authorization still comes from this same rule's accounts, regions, and
# log group ARN patterns.
[rules.metadata]
description = "MCP CloudWatch business scopes"

[[rules.metadata.scopes]]
platform = "PLATFORM_A"
environment = "production"
aliases = ["正式環境", "prod", "PRO"]

[[rules.metadata.scopes]]
platform = "PLATFORM_A"
environment = "demo"
aliases = ["Demo", "測試環境"]

# Optional MCP Database v1 scope. v1 is MySQL only and SELECT-only.
# The referenced connection must exist in config.toml / Terraform
# database_connections_toml, and passwords must live in Secrets Manager.
[[rules.database_scopes]]
name = "orders_prod_readonly"
connection = "orders_prod"
environment = "production"
allowed_schemas = ["orders"]
allowed_tables = ["orders", "order_items"]
allowed_actions = ["select"]
max_rows = 100
statement_timeout_ms = 5000
require_explain = true
max_examined_rows = 10000
allow_full_table_scan = false
# default-deny VIEW reads. Flip to `true` only after the operator has
# reviewed the view's DEFINER and base-table reach — see entitlements.sample.toml
# and docs/zh-TW/OPERATOR-SETUP.md for the full opt-in checklist.
allow_views = false

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "production"
# role_arn supports three modes:
#   "direct"              → use ambient AWS credentials (no AssumeRole)
#                           SSM/EIC/ECS Exec not supported (SSH only)
#   "profile:NAME"        → use a specific AWS profile from ~/.aws/credentials
#                           SSM/EIC/ECS Exec not supported (SSH only)
#   "arn:aws:iam::...:role/..." → AssumeRole into that IAM role (production)
#                           Supports SSM, EIC, SSH, and ECS Exec with scoped credentials
role_arn = "arn:aws:iam::123456789012:role/CanopyRole"

[[rules.allowed_accounts]]
account_id = "234567890123"
account_name = "staging"
role_arn = "arn:aws:iam::234567890123:role/CanopyRole"

[[rules.instance_tag_selectors]]        # Instance must match at least one selector
[rules.instance_tag_selectors.tags]
Environment = ["production", "staging"]  # Tag key = allowed values

[[rules.task_tag_selectors]]             # ECS task must match at least one selector
[rules.task_tag_selectors.tags]
Environment = ["production"]

# max_session_seconds = 3600             # Optional: auto-disconnect after 60 min
                                         # Minimum 900 seconds for non-SSH connects (AWS STS limit)
                                         # Omit or 0 = no limit
                                         # Multi-group merge: uses the strictest (smallest) value

# ── User → group mappings ───────────────────────────

[[memberships]]
user_id = "alice@example.com"            # Matches OIDC sub claim (or dev username)
group = "platform-engineering"

[[memberships]]
user_id = "bob@example.com"
group = "readonly-ops"
```

**Merge rule**: If a user belongs to multiple groups, feature flags are merged additively — if *any* group grants a feature, the user has it. ECS account, region, cluster, task tag, and sidecar denylist checks are evaluated rule-locally by the control-plane to avoid cross-group scope splicing.

### Catalog-managed entitlements

For larger deployments, keep the hand-edited source in `entitlements.catalog.toml` and generate the low-level runtime file that the control-plane loads:

```bash
cp entitlements.catalog.sample.toml entitlements.catalog.toml
cargo run -p canopy-entitlements -- generate \
  --catalog entitlements.catalog.toml \
  --output entitlements.generated.toml
```

Validate the catalog, generated runtime, and deploy-time Terraform consistency before rollout:

```bash
CANOPY_VALIDATE_ENTITLEMENTS_SCRIPT=./scripts/validate-entitlements.sh \
  cargo run -p canopy-entitlements -- validate \
    --catalog entitlements.catalog.toml \
    --runtime-file entitlements.generated.toml \
    --tfvars infra/terraform.tfvars
```

Useful review commands:

```bash
cargo run -p canopy-entitlements -- preview \
  --catalog entitlements.catalog.toml \
  --group platform-engineering

cargo run -p canopy-entitlements -- diff \
  --old entitlements.catalog.before.toml \
  --new entitlements.catalog.toml

cargo run -p canopy-entitlements -- explain \
  --catalog entitlements.catalog.toml \
  --sub user-sub-uuid \
  --email alice@company.internal \
  --email-verified \
  --external-group canopy-platform-engineering

cargo run -p canopy-entitlements -- dry-run \
  --catalog entitlements.catalog.toml \
  --operation cloudwatch-search \
  --sub user-sub-uuid \
  --external-group canopy-platform-engineering \
  --account 123456789012 \
  --region ap-northeast-1 \
  --log-group-arn arn:aws:logs:ap-northeast-1:123456789012:log-group:/aws/ecs/prod-api
```

When using the catalog path, do not hand-edit `entitlements.generated.toml`; regenerate it from the catalog and deploy that generated file. Set `entitlements_file = "entitlements.generated.toml"` in `config.toml`, and pass the same path through `--entitlements` or `ENTITLEMENTS_FILE` when running deployment scripts. Cognito mappings belong in the catalog's `[[group_mappings]]`; the generated runtime carries them forward for login and refresh authorization.

### TUI client config

Prefer the setup script so the config is written to the OS-specific path the
TUI actually reads. The script accepts the URL as an argument, `--url`, or via
the `CANOPY_CONTROL_PLANE_URL` env var. Optionally pass
`--change-password-url` (or `CANOPY_CHANGE_PASSWORD_URL`) for the Cognito
hosted-UI password page. For day-to-day use copy
`scripts/setup-tui-config.local.sh.example` to `setup-tui-config.local.sh`
(gitignored) and fill in your real values.

```bash
scripts/setup-tui-config.sh https://canopy.your-domain.com
```

The TUI uses the standard config directory for each OS:

| OS | Config path |
|----|-------------|
| macOS | `~/Library/Application Support/canopy/config.toml` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/canopy/config.toml` |

```toml
control_plane_url = "http://localhost:8443"  # Control-plane URL
dev_mode = true                # true = show dev-login option
                               # false = SSO-only login
refresh_interval_secs = 30     # Auto-refresh interval
live_tail_scrollback = 10000   # Max events in live-tail buffer
pkce_callback_port = 9876      # Local port for OIDC PKCE callback
enable_live_tail = true        # Show live-tail in menu (beta feature)
# change_password_url = "https://<cognito-domain>/forgotPassword?client_id=<app-client-id>&response_type=code&scope=openid+profile+email&redirect_uri=http://localhost:9876/callback"

# Auto-update (checks GitHub Releases at most every 10 minutes)
auto_update = false            # true = check & apply updates on startup
# update_repo_owner = "Kevinw3i"  # GitHub owner (default)
# update_repo_name = "Canopy"     # GitHub repo  (default)

[theme]
preset = "default"              # default | mono | high_contrast
# accent = "cyan"               # color name, indexed:N, ansi:N, or #RRGGBB
# selected_bg = "indexed:24"
# selected_fg = "white"

[keybindings]
quit = ["ctrl+c"]
logout = ["ctrl+x"]
dashboard_up = ["up", "k"]
dashboard_down = ["down", "j"]
dashboard_select = ["enter"]
dashboard_quit = ["q"]
dashboard_inventory = ["1"]
dashboard_cloudwatch = ["2"]
dashboard_live_tail = ["3"]
dashboard_access = ["4"]
dashboard_settings = ["5"]
settings_back = ["esc", "q"]
settings_change_password = ["p"]
```

When `auto_update = true`, the TUI checks for new `tui-v*` releases on GitHub at startup (throttled to once per 10 minutes). If a newer version is found:
- **Writable install**: downloads the tarball, verifies SHA256, replaces the binary in-place. A green banner prompts the user to restart.
- **Read-only install**: shows a banner suggesting a manual download.

Press `Ctrl+D` to dismiss the update banner.

Theme presets and overrides apply across the TUI workflow chrome: login, dashboard, settings, access, EC2/ECS inventory, CloudWatch search, live tail, modals, and connect-session status/help/copy surfaces. Remote terminal output in connect sessions keeps the VT100 colors sent by the remote process.

**How it's loaded:**
1. If `DEV_MODE=1` → use built-in defaults and ignore the OS config file
2. Else if `canopy/config.toml` exists under the OS config directory → load it
3. Else → error with path hint

### Environment variables

| Variable | Used by | Purpose |
|----------|---------|---------|
| `CONFIG_PATH` | control-plane | Override config file path (default: `config.toml`) |
| `DEV_MODE=1` | both | TUI: force built-in dev defaults and ignore the OS config file. Control-plane: fall back to built-in dev defaults if no config file is found |
| `RUST_LOG` | both | Log level filter (e.g. `control_plane=debug,tower_http=debug`) |
| `ALLOW_DEV_MODE_REMOTE=1` | control-plane | Override safety check that blocks dev_mode on non-loopback addresses |
| `AWS_REGION` | control-plane | Base AWS region (also settable in config) |
| `AWS_PROFILE` | control-plane | AWS credentials profile for base STS caller |

---

## Production deployment

### Step 1: Generate a JWT secret

```bash
openssl rand -base64 32
# Example output: <generated-jwt-secret>
```

### Step 2: Create `config.toml`

```bash
cp config.sample.toml config.toml
```

Edit `config.toml`:

```toml
bind_address = "127.0.0.1:8443"
dev_mode = false
entitlements_file = "entitlements.toml"
audit_log = "/var/log/canopy/audit.jsonl"

[oidc]
issuer_url = "https://accounts.google.com"          # Or your OIDC provider
client_id = "your-client-id-from-oidc-provider"
# client_secret = "<oidc-client-secret>"            # Only if provider requires it
scopes = ["openid", "profile", "email"]

[jwt]
secret = "REPLACE_ME_WITH_OPENSSL_RAND_BASE64_32_OUTPUT"   # From step 1 — never
                                                            # leave this literal in
                                                            # production.
expiry_seconds = 3600

[aws]
default_region = "us-east-1"
session_duration_seconds = 3600
```

### Step 3: Create `entitlements.toml`

Small deployments can copy and edit the runtime file directly:

```bash
cp entitlements.sample.toml entitlements.toml
```

Change:
- `account_id` → your real AWS account IDs
- `role_arn` → your real IAM role ARNs (see Step 5)
- `user_id` in `[[memberships]]` → real OIDC user identifiers (usually email)
- `allowed_regions` → your real regions
- `allowed_log_group_arns` → your real log group patterns
- `can_use_mcp` → enable the TUI `MCP / AI Tools` page for local Codex/Claude MCP access

Larger deployments should use the catalog authoring path instead:

```bash
cp entitlements.catalog.sample.toml entitlements.catalog.toml
cargo run -p canopy-entitlements -- generate \
  --catalog entitlements.catalog.toml \
  --output entitlements.generated.toml
CANOPY_VALIDATE_ENTITLEMENTS_SCRIPT=./scripts/validate-entitlements.sh \
  cargo run -p canopy-entitlements -- validate \
    --catalog entitlements.catalog.toml \
    --runtime-file entitlements.generated.toml \
    --tfvars infra/terraform.tfvars
```

If you use the generated file, set `entitlements_file = "entitlements.generated.toml"` in `config.toml` and deploy that same file with `scripts/deploy-control-plane-local.sh --entitlements entitlements.generated.toml` or `ENTITLEMENTS_FILE=entitlements.generated.toml`.

MCP permissions are intentionally separate from the normal TUI permissions:

- `can_use_mcp` is the master switch for the local MCP server.
- `can_use_mcp_cloudwatch` does **not** follow `can_use_cloudwatch_search`; it is a separate MCP feature gate.
- `rules.metadata.scopes` can describe business names such as `PLATFORM_A production` or aliases such as `正式環境`, but it is only a discovery hint. It never authorizes AWS resources, never contains regions, and is returned only from matching rules that also grant MCP CloudWatch access, allowed accounts, allowed regions, and log group ARN patterns.
- The AI workflow is: call `canopy_describe_capabilities`, choose a returned `business_scopes` entry, then call `canopy_list_allowed_log_groups` with that entry's `account_id` and one of its `regions`. The server still performs the normal entitlement check for `account_id + region + log group`.
- MCP CloudWatch raw filter/query audit values are encrypted by default; set `can_view_mcp_raw_audit_plaintext = true` only on the same rule that authorizes the exact account/region/log-group scope.
- `can_use_mcp_database` enables MCP database tools only when a matching `[[rules.database_scopes]]` grants a specific connection/schema/table scope.
- Product Phase 3 exposes MCP foundation tools (`canopy_describe_capabilities`, `canopy_get_guidance`), CloudWatch discovery (`canopy_list_allowed_log_groups`), and preflight-gated CloudWatch data tools (`canopy_preflight_request`, `canopy_search_logs`, `canopy_run_insights_query`) when MCP CloudWatch is enabled, plus MCP Database v1 when explicitly enabled. Initial CloudWatch search/Insights calls require a server-issued preflight token; continuation/poll calls require the returned cursor/token.
- MCP guidance content is a server-owned source asset under `crates/shared/src/dto/mcp_guidance/` and is compiled into the binary through `MCP_GUIDANCE_CATALOG`; it is not loaded from local Codex skills or runtime operator files.
- MCP Database v1 exposes `canopy_list_database_scopes` and `canopy_query_database` for MySQL read-only `SELECT` queries. The control-plane enforces SQL validation, table scope, `LIMIT`, Secrets Manager credentials, and `EXPLAIN FORMAT=JSON` before executing the query. MCP responses never include DB host, secret ARN, username, or password. The view-guard is **default-deny**: every referenced object is verified as `BASE TABLE` under MDL inside the same transaction that runs EXPLAIN and the SELECT; scopes can opt into reading views by setting `allow_views = true` after reviewing the view's DEFINER and base-table reach. Connection-pool saturation surfaces as HTTP 503 (`connection_queue_full` / `database_connection_unavailable`), not 500 — see `docs/zh-TW/OPERATOR-SETUP.md` for the operator hardening checklist.

### Step 4: Set up your OIDC provider

The control-plane supports any OpenID Connect provider. Common choices:

| Provider | issuer_url | Notes |
|----------|------------|-------|
| Google | `https://accounts.google.com` | Create OAuth client in Google Cloud Console |
| AWS IAM Identity Center | `https://your-sso-portal.awsapps.com/start` | Enable OIDC application |
| **AWS Cognito** | `https://cognito-idp.{region}.amazonaws.com/{user-pool-id}` | **Recommended for AWS users.** See [docs/zh-TW/COGNITO-SETUP.md](docs/zh-TW/COGNITO-SETUP.md) |
| Okta | `https://{your-domain}.okta.com` | Create OIDC application |
| Azure AD | `https://login.microsoftonline.com/{tenant-id}/v2.0` | Register application |

**What to configure at the provider:**
1. Create an OIDC application / OAuth 2.0 client
2. Set redirect URI: `http://localhost:9876/callback` (for PKCE)
3. Enable device code flow if needed (for headless terminals)
4. Copy the `client_id` (and `client_secret` if not a public client)
5. Put these values in `config.toml` under `[oidc]`

### Step 5: Create IAM roles in your AWS accounts

Each AWS account in `entitlements.toml` needs an IAM role that the control-plane can assume.

**Trust policy** (allow the control-plane's AWS identity to assume the role):
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::CONTROL_PLANE_ACCOUNT:role/CanopyBase"
    },
    "Action": [
      "sts:AssumeRole",
      "sts:TagSession"
    ],
    "Condition": {
      "StringEquals": {
        "sts:ExternalId": "canopy"
      }
    }
  }]
}
```

The control-plane's own AWS identity also needs `sts:AssumeRole`, `sts:TagSession`,
and `iam:SimulatePrincipalPolicy` on these target role ARNs so it can choose a
role and then mint scoped STS credentials for connect flows.

**Permission policy** (what the target role can do before Canopy applies its
per-request inline session policy):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceConnectEndpoints",
        "logs:DescribeLogGroups",
        "logs:FilterLogEvents",
        "logs:StartQuery",
        "logs:GetQueryResults",
        "logs:StartLiveTail",
        "ssm:StartSession",
        "ssm:DescribeInstanceInformation",
        "ec2-instance-connect:SendSSHPublicKey",
        "ec2-instance-connect:OpenTunnel",
        "ecs:DescribeClusters",
        "ecs:DescribeTasks",
        "ecs:ListClusters",
        "ecs:ListTasks",
        "ecs:ExecuteCommand",
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel"
      ],
      "Resource": "*"
    }
  ]
}
```

### Step 6: Deploy behind TLS

The control-plane listens on plain HTTP. Terminate TLS at a reverse proxy:

```nginx
server {
    listen 443 ssl;
    server_name canopy.internal;

    ssl_certificate     /etc/ssl/certs/canopy.pem;
    ssl_certificate_key /etc/ssl/private/canopy.key;

    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Step 7: Start

```bash
CONFIG_PATH=config.toml cargo run --release -p control-plane
```

### Step 8: Package and distribute the TUI

Use the packaging script to build a self-contained distribution folder:

```bash
cargo build --release -p tui-client
scripts/package.sh https://canopy.internal
```

This creates `dist/` containing:

```
dist/
├── tui-client     ← Release binary
├── config.toml    ← Client config (control_plane_url pre-filled)
└── install.sh     ← One-command install script
```

Deliver the `dist/` folder to operators (S3, Artifactory, shared drive, etc.).

### Step 9: Operators run the install script

Each operator runs one command:

```bash
./install.sh
```

The script automatically:
1. Installs the `canopy` binary to `~/.local/bin/` by default (`CANOPY_BIN_DIR` can override it)
2. Creates the TUI config file (URL already filled in, OS-specific path)
3. Installs AWS CLI v2 if missing when installer verification is available; otherwise prompts for manual install (needed for SSM/EIC/ECS Exec connection flows)
4. Installs Session Manager Plugin if missing on macOS; Linux operators get a manual install prompt until verified installer signature support is configured (needed for SSM/ECS Exec)
5. Removes macOS Gatekeeper quarantine flag if needed
6. Runs a full verification check

See [docs/zh-TW/OPERATOR-SETUP.md](docs/zh-TW/OPERATOR-SETUP.md) for the complete operator guide and troubleshooting.

---

## Authentication flow

```
TUI                    Control-Plane              OIDC Provider
 │                          │                          │
 ├──PKCE auth start────────▶│                          │
 │◀──authorize URL──────────│                          │
 │                          │                          │
 ├──(browser redirect)─────────────────────────────────▶│
 │◀──(callback with code)──────────────────────────────│
 │                          │                          │
 ├──exchange code──────────▶│──verify code────────────▶│
 │                          │◀──id_token──────────────│
 │◀──JWT access token───────│                          │
 │                          │                          │
 ├──API calls + JWT────────▶│──AssumeRole─────────────▶│ AWS
 │◀──filtered results───────│◀──data──────────────────│
```

**Dev mode** skips the OIDC flow entirely — `dev-login` issues a JWT directly.

## Audit logging

Every action is logged with structured tracing **and** to a durable JSON-lines file when `audit_log` is configured:

- Login / logout
- EC2 list requests
- ECS task list / exec requests
- CloudWatch searches
- Live tail start/stop
- Connect actions
- Each log includes: event_id, actor, timestamp, account, region, target, outcome

Audit schema changes are additive. New top-level fields are optional and omitted
when absent; strict downstream schemas should be migrated before relying on new
fields such as `target_resource_name`. See [Audit Log Schema](docs/en/AUDIT-SCHEMA.md).

When the durable audit file is configured and a write fails, the API returns 503 (fail-closed).

## Keyboard shortcuts

| Key | Context | Action |
|-----|---------|--------|
| `j/k` | Tables | Navigate rows |
| `Enter` | Tables | Toggle detail / execute |
| `/` | EC2, ECS, CW | Focus search/filter |
| `Ctrl+E` | Inventory | Toggle EC2/ECS view when entitled |
| `s` | EC2 | SSM Session Manager connect |
| `e` | EC2 | EC2 Instance Connect SSH |
| `c` | EC2 | Direct SSH (your own key) |
| `r` | EC2, ECS | Refresh |
| `[`/`]` | Inventory, CW Search | Cycle accounts (prev/next) |
| `{`/`}` | Inventory, CW Search | Cycle regions (prev/next) |
| `x` | CW Search | Export results |
| `Tab` | CW Search | Toggle quick/insights mode |
| `Esc` | Any | Go back / unfocus |
| `q` | Dashboard | Quit |
| `Ctrl+x` | Dashboard | Logout |
| `p` | Settings | Open Change Password |
| `Ctrl+C` | Any | Quit |

## Security model

- **Server-side filtering**: EC2 instances, ECS tasks, and CloudWatch data are filtered by entitlements on the backend before returning to the TUI. The client never sees unauthorized resources.
- **Scope isolation**: Feature grants and resource scopes are evaluated per-rule to prevent cross-group privilege escalation. A feature from one group cannot be applied to resources from another group.
- **Short-lived credentials**: STS AssumeRole with session tags. Connect operations use inline session policies that scope the primary action to the specific instance or ECS task, including OS-user binding via IAM conditions (`ssm:SessionDocumentAccessCheck`, `ec2:osuser`) and ECS cluster binding for `ecs:ExecuteCommand`; ECS Exec credentials also include only the required `ecs:DescribeTasks` and `ssmmessages` helper actions, limited to the requested AWS region.
- **Account identity verification**: `direct`/`profile:` and AssumeRole credentials are verified via `GetCallerIdentity` to ensure they match the configured `account_id`.
- **No long-lived AWS keys in the TUI**: All AWS access goes through the control-plane.
- **Audit fail-closed**: If the durable audit log cannot be written, all protected APIs (including login, refresh, entitlements) return 503. Transient I/O failures self-recover without restart.
- **Dev-mode safety guard**: `dev_mode = true` is blocked on non-loopback bind addresses unless explicitly overridden. CORS is restricted to localhost when using real AWS data.
- **Email-verified matching**: Entitlement membership matching by email is only active when the IdP confirms `email_verified = true`, preventing privilege escalation via unverified email claims.
- **Token storage**: Persisted with Unix 0600 permissions at `~/.local/share/canopy/token`. Files with insecure permissions are rejected on load.
