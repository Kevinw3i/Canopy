<p align="center">
  <img src="assets/banner.svg" alt="Canopy" width="800"/>
</p>

內部營運終端機操作介面，用於管理 AWS 基礎設施。

```
┌──────────────┐         ┌──────────────────┐         ┌──────────────┐
│  TUI 客戶端  │──HTTP──▶│   Control Plane  │──STS───▶│   AWS APIs   │
│  (ratatui)   │         │   (axum)         │         │ EC2/ECS/CWL  │
│              │◀─JSON───│                  │◀────────│ SSM/STS/Exec │
└──────────────┘         │  - 認證 (OIDC)   │         └──────────────┘
                         │  - 授權 (權限)    │
                         │  - 稽核日誌       │
                         │  - 伺服器端過濾   │
                         └──────────────────┘
```

| Crate | 路徑 | 用途 |
|-------|------|------|
| `shared` | `crates/shared` | 共用 DTO 和錯誤型別 |
| `control-plane` | `apps/control-plane` | Axum REST API — 認證、授權、AWS 存取 |
| `tui-client` | `apps/tui-client` | Ratatui 終端機介面 — 7 個畫面、事件迴圈 |

---

## 快速啟動（本機開發）

### 先決條件

- Rust 1.75+
- 兩個終端機視窗

> AWS CLI 和 Session Manager plugin 只有連線功能（SSM/EIC/ECS Exec）需要；清查與搜尋流程不需要。

### 第一步：建置

```bash
cd ~/Desktop/Canopy
cargo build
cargo test        # workspace 測試應全部通過
```

### 第二步：啟動 Control Plane（終端機 1）

```bash
DEV_MODE=1 cargo run -p control-plane
```

看到以下訊息就是成功：
```
Control-plane listening on 127.0.0.1:8443
```

### 第三步：啟動 TUI（終端機 2）

```bash
DEV_MODE=1 cargo run -p tui-client
```

進入登入畫面後輸入 `dev-admin`，按 Enter。

### 第四步：操作

| 畫面 | 怎麼進去 | 顯示什麼 |
|------|----------|----------|
| 儀表板 | 登入後自動進入 | 歡迎訊息、導航選單 |
| EC2 / ECS 清查 | 按 `1` | EC2 mock 執行個體；有權限時按 `Ctrl+E` 切到 ECS tasks。若 task 可 exec 且有 ECS Exec 權限，`Enter` 開啟 container 選擇 |
| CloudWatch 搜尋 | 按 `2` | 查詢輸入框，mock 日誌事件 |
| 存取/身分 | 按 `4` | 使用者、群組、功能旗標、允許的帳號 |
| 設定 | 按 `5` | 目前的設定值；按 `p` 開啟 Change Password |

按 `Esc` 返回上一頁，Dashboard 按 `Ctrl+x` 登出，按 `q` 離開。

### 開發用帳號

內建 dev defaults 預設了兩個使用者：

| 使用者名稱 | 群組 | 可以做什麼 |
|-----------|------|-----------|
| `dev-admin` | platform-engineering | 全部功能：EC2、ECS、CloudWatch、SSM、EIC，跨 2 個帳號 |
| `dev-readonly` | readonly-ops | 唯讀：只能看 staging 帳號的 EC2 和 CloudWatch，不能連線 |

試試用 `dev-readonly` 登入，觀察介面如何隱藏該使用者沒有權限的功能。

---

## 專案檔案

```
Canopy/
├── config.sample.toml         ← Control Plane 設定（生產環境範本）
├── entitlements.sample.toml   ← 權限規則範本
├── entitlements.catalog.sample.toml ← Catalog 編輯範本
├── .env.example               ← 環境變數參考
├── Cargo.toml                 ← Workspace 根設定
│
├── apps/
│   ├── control-plane/         ← 後端伺服器（含 Dockerfile）
│   └── tui-client/            ← 終端機介面（支援自動更新）
│
├── crates/
│   └── shared/                ← 共用型別
│
├── infra/                     ← Terraform IaC（ECS Fargate 部署）
│
├── scripts/
│   ├── package.sh             ← TUI 打包分發腳本
│   └── docker-entrypoint.sh   ← 容器啟動 + Secrets Manager 注入
│
└── docs/
    ├── en/
    │   ├── ARCHITECTURE.md    ← 完整架構參考
    │   └── AUDIT-SCHEMA.md    ← 稽核事件 schema
    └── zh-TW/
        ├── PRD.md             ← 產品需求文件
        ├── ECS_FARGATE_DEPLOYMENT.md ← ECS 部署（手動 / Terraform）
        ├── COGNITO-SETUP.md   ← AWS Cognito OIDC 設定
        ├── OPERATOR-SETUP.md  ← TUI 分發給維運人員
        └── RELEASING.md       ← 發版流程與 CI
```

---

## 設定參考

### Control Plane 設定（`DEV_MODE=1` / `config.toml`）

```toml
# ── 伺服器 ──────────────────────────────────────────
bind_address = "127.0.0.1:8443"   # 監聽的 IP:port
dev_mode = true                    # true = 啟用 dev-login
                                   # false = 需要 OIDC

# ── AWS 資料來源 ────────────────────────────────────
# mock_aws_data 控制 EC2/CloudWatch 用 mock 還是真實 AWS。
# 省略時跟隨 dev_mode 的值。
# 設為 false 且保持 dev_mode = true → 用 dev-login 但打真實 AWS API。
# mock_aws_data = false

# ── 權限規則 ────────────────────────────────────────
# 權限規則檔案路徑（TOML 格式）
# dev_mode = false 時必填
# dev_mode = true 時可選（沒填就用內建預設值）
entitlements_file = "entitlements.toml"

# ── 稽核日誌 ────────────────────────────────────────
# 可選。設定後每個操作會以 JSON-lines 格式寫入此檔案。
# 沒設定的話只會透過 structured tracing 輸出到 stdout。
# audit_log = "/var/log/canopy/audit.jsonl"

# 可選的遠端稽核匯出。local tracing / file audit 接受 event 後，
# 會把同一筆 JSON audit event enqueue 到遠端 sink。
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
# 允許的來源清單。空值 + dev_mode = 允許全部。
# cors_allowed_origins = ["http://localhost:9876"]

# ── OIDC ────────────────────────────────────────────
# dev mode 時不會使用（dev-login 直接跳過 OIDC）
# 生產環境必填——見下方「生產環境部署」段落
[oidc]
issuer_url = "https://placeholder.example.com"
client_id = "not-used-in-dev-mode"
# client_secret = "公開 PKCE 客戶端可省略"
# scopes = ["openid", "profile", "email"]        # 預設值
#
# 可選的端點覆寫（省略時自動從 issuer_url 探索）：
# authorization_endpoint = "https://..."
# token_endpoint = "https://..."
# device_authorization_endpoint = "https://..."
# jwks_uri = "https://..."

# ── JWT ─────────────────────────────────────────────
[jwt]
secret = "<local-dev-jwt-secret>"
                      # 內部 JWT 的簽署金鑰
                      # 生產環境請用：openssl rand -base64 32
expiry_seconds = 7200 # Token 有效期（秒）

# ── AWS ─────────────────────────────────────────────
[aws]
default_region = "us-east-1"      # STS 呼叫的預設區域
session_duration_seconds = 3600   # AssumeRole 會話時長
# sts_external_id = "canopy" # AssumeRole ExternalId（須與 trust policy 一致）
```

**載入順序：**
1. 設了 `CONFIG_PATH` 環境變數 → 載入該檔案
2. 否則如果當前目錄有 `config.toml` → 載入它
3. 否則如果 `DEV_MODE=1` → 用內建預設值（不需要檔案）
4. 以上都沒有 → 報錯

### 權限規則檔（`entitlements.sample.toml` / `entitlements.toml`）

定義「誰可以存取什麼」。結構：

```toml
# ── 每個群組一個 [[rules]] 區塊 ─────────────────────

[[rules]]
id = "rule-platform-eng"                # 規則唯一 ID
group = "platform-engineering"           # 群組名稱（對應下方 memberships）
allowed_regions = ["us-east-1", "us-west-2"]
allowed_log_group_arns = [
    "arn:aws:logs:*:123456789012:log-group:/app/*",   # 支援萬用字元
]
allowed_clusters = [
    "arn:aws:ecs:us-east-1:123456789012:cluster/prod-*",
]
allowed_os_users = ["ec2-user", "ubuntu"]              # 用於 SSM/EIC 連線

[rules.features]
can_view_ec2 = true               # 可以看 EC2 執行個體
can_view_ecs = true               # 可以看授權 cluster 裡的 ECS tasks
can_use_ecs_exec = true           # 可以開啟 ECS Exec session
can_use_cloudwatch_search = true  # 可以搜尋 CloudWatch 日誌
can_use_cloudwatch_tail = true    # 可以使用 Live Tail
can_use_ssm = true                # 可以透過 SSM Session Manager 連線
can_use_ec2_instance_connect = true  # 可以透過 EC2 Instance Connect 連線
can_use_mcp = true                # 可以啟動本機 MCP / AI Tools server
can_use_mcp_cloudwatch = false    # 預留給 MCP CloudWatch data tools
can_view_mcp_raw_audit_plaintext = false  # 預設：MCP CloudWatch raw filter/query audit 加密保存
can_use_mcp_ec2 = false           # 僅在同 rule 有 mcp_ec2_diagnostic_scopes 時啟用 scoped MCP EC2 diagnostics
can_use_mcp_database = true       # 搭配下方 scope 使用 MCP Database tools

# 可選：MCP EC2 diagnostics scopes。這些是 rule-local command scopes；
# 不會跨 rule merge。除非同一條 rule 也提供具體 safe-for-MCP
# log/connectivity scopes，否則保持 can_use_mcp_ec2=false。
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
# normalized_url = "https://orders.example.com/health"
# query_policy = "no_query"
# safe_for_mcp_output = true

# 可選：MCP Business Scopes。這只提供 AI/MCP discovery 提示；
# 真正授權仍看同一條 rule 的 accounts、regions、log group ARN patterns。
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

# 可選：MCP Database v1 scope。v1 只支援 MySQL，且只允許 SELECT。
# connection 必須存在於 config.toml / Terraform database_connections_toml，
# 密碼只能放 Secrets Manager。
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
# 預設拒絕 VIEW。要設 true 之前，operator 必須完成 review checklist —
# 詳見 entitlements.sample.toml 與 docs/zh-TW/OPERATOR-SETUP.md。
allow_views = false

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "production"
# role_arn 支援三種模式：
#   "direct"              → 直接用本機預設 AWS 憑證（不走 AssumeRole）
#                           不支援 SSM/EIC/ECS Exec 連線（僅 SSH）
#   "profile:NAME"        → 用 ~/.aws/credentials 裡指定的 profile
#                           不支援 SSM/EIC/ECS Exec 連線（僅 SSH）
#   "arn:aws:iam::...:role/..." → AssumeRole 到該 IAM Role（生產環境）
#                           支援 SSM、EIC、SSH、ECS Exec，使用範圍限定憑證
role_arn = "arn:aws:iam::123456789012:role/CanopyRole"

[[rules.allowed_accounts]]
account_id = "234567890123"
account_name = "staging"
role_arn = "arn:aws:iam::234567890123:role/CanopyRole"

[[rules.instance_tag_selectors]]        # 執行個體必須匹配至少一個 selector
[rules.instance_tag_selectors.tags]
Environment = ["production", "staging"]  # 標籤鍵 = 允許的值

[[rules.task_tag_selectors]]             # ECS task 必須匹配至少一個 selector
[rules.task_tag_selectors.tags]
Environment = ["production"]

# max_session_seconds = 3600             # 可選：連線 60 分鐘後自動斷開
                                         # 非 SSH 連線最低 900 秒（AWS STS 限制）
                                         # 省略或 0 = 不限時
                                         # 多群組合併：取最嚴格（最小非零值）

# ── 使用者 → 群組對應 ───────────────────────────────

[[memberships]]
user_id = "alice@example.com"            # 對應 OIDC 的 sub claim（或 dev 使用者名稱）
group = "platform-engineering"
```

**合併規則**：
- 功能旗標、帳號、區域、OS users — 加法式合併（任一群組授予即擁有）
- `max_session_seconds` — 取最嚴格（最小非零值）
- `excluded_tag_selectors` — 聯集（任一群組排除即排除）
- ECS 的 account、region、cluster、task tag、sidecar denylist 由 control-plane 以 rule-local scope 評估，避免跨群組 scope 被拼接成未授權組合

### Catalog 管理的權限規則

較大的部署建議把人工維護的來源放在 `entitlements.catalog.toml`，再產生 control-plane 實際載入的低階 runtime 檔：

```bash
cp entitlements.catalog.sample.toml entitlements.catalog.toml
cargo run -p canopy-entitlements -- generate \
  --catalog entitlements.catalog.toml \
  --output entitlements.generated.toml
```

部署前驗證 catalog、產生出的 runtime，以及 Terraform 部署設定是否一致：

```bash
CANOPY_VALIDATE_ENTITLEMENTS_SCRIPT=./scripts/validate-entitlements.sh \
  cargo run -p canopy-entitlements -- validate \
    --catalog entitlements.catalog.toml \
    --runtime-file entitlements.generated.toml \
    --tfvars infra/terraform.tfvars
```

常用 review 指令：

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

使用 catalog 流程時，不要手改 `entitlements.generated.toml`；要從 catalog 重新產生並部署 generated runtime。`config.toml` 的 `entitlements_file` 要設成 `entitlements.generated.toml`，部署腳本也要用同一個檔案，例如 `--entitlements` 或 `ENTITLEMENTS_FILE`。Cognito mapping 應寫在 catalog 的 `[[group_mappings]]`，generated runtime 會保留它們供登入與 refresh 授權使用。

#### 本機 Entitlement Catalog Web UI

`canopy-entitlements ui` 會啟動只綁 loopback 的 operator UI，用來 review 與編輯 catalog draft。靜態 HTML、CSS、JavaScript 都會編進 binary，所以 release build 不需要額外的 Node 或 asset build step 就能提供 UI。

```bash
cargo run -p canopy-entitlements -- ui \
  --catalog entitlements.catalog.toml \
  --runtime entitlements.generated.toml \
  --import-runtime entitlements.toml \
  --db-config database_connections.local.toml \
  --deployment-mode terraform \
  --tfvars infra/terraform.tfvars \
  --auth-config /etc/canopy/entitlements-ui-auth.toml \
  --identity-source os-allowlist
```

啟動後 server 會印出包含一次性 bootstrap code 的 localhost URL，code 只放在 URL fragment。Browser 會把 code 換成 HttpOnly、SameSite=Strict session cookie；API 不接受 query-string token。Write API 會檢查本機 Host / Origin，`GET /api/state` 只回 sanitized state，不回 raw secret。

`--allow-dev-identity` 只適合本機 preview、explain、validate、dry-run。Development identity claims 不能 apply 真實 catalog 或 runtime 檔。Production apply 目前可用路徑是 `--identity-source os-allowlist` 搭配 repo 外受保護的 auth config；`admin_group` 預設為 `admin`，`[os_allowlist].users` 必須包含目前 OS user。`--identity-source verified-jwt` 在這個工具完成 canonical JWT verification 前會 fail closed。

`database_connections.local.toml` 是 UI draft 與 validation 使用的本機 DB connection snippet，schema 與 `config.toml` 的 `[database_connections.<name>]` 相同，但不會被 control-plane 自動載入。Production validate / apply 時，同一份 connection metadata 也必須存在於 `--deployment-mode config|terraform` 選到的 canonical deployment source。UI 只保存 metadata 與 `secret_arn`；會拒絕 inline username、password、可寫連線，以及 production 不安全 TLS 設定。

Apply 會用本機 transaction protocol 寫入 catalog、generated runtime 與選用的 DB snippet，包含 lock file、baseline digest compare-and-swap、backup 與 recovery manifest。Generated runtime 仍是部署用 entitlement artifact；UI 是 catalog workflow 上的 authoring 與 review surface。

### TUI 客戶端設定

建議用腳本建立設定檔，避免不同作業系統路徑不一致。腳本接受位置參數、
`--url`，或環境變數 `CANOPY_CONTROL_PLANE_URL`。可額外傳
`--change-password-url`（或 `CANOPY_CHANGE_PASSWORD_URL`）指定 Cognito
hosted UI 的密碼頁網址。日常使用建議複製
`scripts/setup-tui-config.local.sh.example` 為 `setup-tui-config.local.sh`
（已 gitignore）並填入真實值。

```bash
scripts/setup-tui-config.sh https://canopy.your-domain.com
```

TUI 會使用作業系統標準 config 目錄：

| 作業系統 | 設定檔位置 |
|----------|------------|
| macOS | `~/Library/Application Support/canopy/config.toml` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/canopy/config.toml` |

```toml
control_plane_url = "http://localhost:8443"  # Control Plane 網址
dev_mode = true                # true = 顯示 dev-login 選項
                               # false = 只顯示 SSO 登入
refresh_interval_secs = 30     # 自動重新整理間隔
live_tail_scrollback = 10000   # Live Tail 緩衝區最大事件數
pkce_callback_port = 9876      # OIDC PKCE 回呼的本地 port
enable_live_tail = true        # 選單中顯示 Live Tail（beta 功能）
# change_password_url = "https://<cognito-domain>/forgotPassword?client_id=<app-client-id>&response_type=code&scope=openid+profile+email&redirect_uri=http://localhost:9876/callback"

# 自動更新（最多每 10 分鐘檢查一次 GitHub Releases）
auto_update = false            # true = 啟動時檢查並套用更新
# update_repo_owner = "Kevinw3i"  # GitHub owner（預設值）
# update_repo_name = "Canopy"     # GitHub repo（預設值）

[theme]
preset = "default"              # default | mono | high_contrast
# accent = "cyan"               # 色名、indexed:N、ansi:N 或 #RRGGBB
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

當 `auto_update = true` 時，TUI 啟動時會檢查 GitHub 上是否有更新的 `tui-v*` release（每 10 分鐘最多檢查一次）。如果找到新版本：
- **可寫入的安裝**：自動下載 tarball、驗證 SHA256、原地替換 binary。畫面頂部會顯示綠色 banner 提示重啟。
- **唯讀安裝**：顯示 banner 提示手動下載更新。

按 `Ctrl+D` 關閉更新 banner。

主題 preset 與覆寫會套用在整個 TUI workflow chrome：登入、Dashboard、Settings、Access、EC2/ECS inventory、CloudWatch search、Live Tail、modal，以及連線 session 的狀態列、help、copy 畫面。連線 session 內的遠端 terminal 輸出仍保留遠端程序送出的 VT100 顏色。

**載入順序：**
1. `DEV_MODE=1` → 用內建預設值，並忽略作業系統 config 路徑的設定檔
2. 否則作業系統標準 config 路徑的 `canopy/config.toml` 存在 → 載入
3. 以上都沒有 → 報錯並提示路徑

### 環境變數

| 變數 | 使用者 | 用途 |
|------|--------|------|
| `CONFIG_PATH` | control-plane | 覆寫設定檔路徑（預設：`config.toml`） |
| `DEV_MODE=1` | 兩者 | TUI：強制使用內建 dev 預設值並忽略作業系統 config 設定檔。Control Plane：找不到設定檔時改用內建預設值 |
| `RUST_LOG` | 兩者 | 日誌等級過濾（例：`control_plane=debug,tower_http=debug`） |
| `ALLOW_DEV_MODE_REMOTE=1` | control-plane | 覆寫安全檢查，允許 dev_mode 在非 loopback 位址 |
| `AWS_REGION` | control-plane | 基礎 AWS 區域（也可在設定檔設定） |
| `AWS_PROFILE` | control-plane | 基礎 STS 呼叫使用的 AWS 憑證 profile |

---

## 生產環境部署

### 第一步：產生 JWT Secret

```bash
openssl rand -base64 32
# 範例輸出：<generated-jwt-secret>
```

### 第二步：建立 `config.toml`

```bash
cp config.sample.toml config.toml
```

編輯 `config.toml`：

```toml
bind_address = "127.0.0.1:8443"
dev_mode = false
entitlements_file = "entitlements.toml"
audit_log = "/var/log/canopy/audit.jsonl"

[oidc]
issuer_url = "https://accounts.google.com"          # 或你的 OIDC 提供者
client_id = "your-client-id-from-oidc-provider"     # 從 OIDC 提供者取得
# client_secret = "<oidc-client-secret>"            # 僅在提供者要求時填寫
scopes = ["openid", "profile", "email"]

[jwt]
secret = "REPLACE_ME_WITH_OPENSSL_RAND_BASE64_32_OUTPUT"   # 第一步產生的值；
                                                            # 生產環境絕對不可保留此
                                                            # 字面值。
expiry_seconds = 3600

[aws]
default_region = "us-east-1"
session_duration_seconds = 3600
```

### 第三步：建立 `entitlements.toml`

小型部署可以直接複製並編輯 runtime 檔：

```bash
cp entitlements.sample.toml entitlements.toml
```

修改以下欄位：
- `account_id` → 真實的 AWS 帳號 ID
- `role_arn` → 真實的 IAM Role ARN（見第五步）
- `[[memberships]]` 中的 `user_id` → 真實的 OIDC 使用者識別（通常是 email）
- `allowed_regions` → 真實的 AWS 區域
- `allowed_log_group_arns` → 真實的 Log Group ARN 樣式
- `can_use_mcp` → 開啟 TUI 的 `MCP / AI Tools` 頁面，讓使用者用本機 Codex/Claude 連到 Canopy MCP

較大的部署建議改用 catalog 流程：

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

若使用 generated 檔，`config.toml` 的 `entitlements_file` 要設成 `entitlements.generated.toml`，部署時也要用同一個檔案，例如 `scripts/deploy-control-plane-local.sh --entitlements entitlements.generated.toml` 或 `ENTITLEMENTS_FILE=entitlements.generated.toml`。

MCP 權限刻意和一般 TUI 權限分開：

- `can_use_mcp` 是本機 MCP server 的總開關。
- `can_use_mcp_cloudwatch` 不會跟隨 `can_use_cloudwatch_search`；這是獨立的 MCP feature gate。
- `rules.metadata.scopes` 可以描述 `PLATFORM_A production`、`正式環境` 這類業務語意，但它只是一個 discovery hint。metadata 不授權 AWS 資源、不放 region，且只有同一條 matching rule 同時具備 MCP CloudWatch 權限、allowed accounts、allowed regions、log group ARN patterns 時才會回傳。
- AI 使用流程是：先呼叫 `canopy_describe_capabilities` 取得 `business_scopes`，選出對應的 `account_id` 與其中一個 `regions`，再呼叫 `canopy_list_allowed_log_groups`。server 仍會對 `account_id + region + log group` 做原本的 entitlement 檢查。
- MCP CloudWatch raw filter/query audit 預設加密保存；只有同一條 rule 同時授權該 account / region / log group scope 時，才應設定 `can_view_mcp_raw_audit_plaintext = true`。
- `can_use_mcp_database` 只是在 MCP 開 DB tools；真正能查哪些 DB / schema / table，要看同一條 matching rule 裡的 `[[rules.database_scopes]]`。
- Product Phase 3 提供 MCP 基礎工具（`canopy_describe_capabilities`、`canopy_get_guidance`），並在 MCP CloudWatch 啟用時提供 CloudWatch discovery（`canopy_list_allowed_log_groups`）與 preflight-gated CloudWatch data tools（`canopy_preflight_request`、`canopy_search_logs`、`canopy_run_insights_query`），也可在明確啟用時提供 MCP Database v1。CloudWatch search / Insights 初始呼叫必須使用 control-plane 發出的 preflight token；續頁 / polling 則必須使用 response 回傳的 cursor/token。
- MCP guidance 內容是 server-owned source asset，放在 `crates/shared/src/dto/mcp_guidance/`，並透過 `MCP_GUIDANCE_CATALOG` 編譯進 binary；它不是從本機 Codex skills 或 runtime operator 檔案讀取。
- MCP Database v1 提供 `canopy_list_database_scopes` 與 `canopy_query_database`，只允許 MySQL read-only `SELECT`。control-plane 會在執行前強制檢查 SQL、table scope、`LIMIT`、Secrets Manager 憑證與 `EXPLAIN FORMAT=JSON`。MCP response 不會回傳 DB host、secret ARN、username 或 password。view-guard **預設拒絕 VIEW**：所有 query 都會在 MDL-protected transaction 內把 EXPLAIN、type re-check、SELECT 跑在同一條 connection；要允許 VIEW 需在 scope 設 `allow_views = true` 並完成 DEFINER / base-table review。Connection 池飽和會回 HTTP 503（`connection_queue_full` / `database_connection_unavailable`），不是 500 — operator 加固 checklist 請見 `docs/zh-TW/OPERATOR-SETUP.md`。

### 第四步：設定 OIDC 提供者

Control Plane 支援任何 OpenID Connect 提供者：

| 提供者 | issuer_url | 說明 |
|--------|------------|------|
| Google | `https://accounts.google.com` | 在 Google Cloud Console 建立 OAuth 客戶端 |
| AWS IAM Identity Center | `https://your-sso-portal.awsapps.com/start` | 啟用 OIDC 應用程式 |
| **AWS Cognito** | `https://cognito-idp.{region}.amazonaws.com/{pool-id}` | **推薦 AWS 使用者。** 見 [docs/zh-TW/COGNITO-SETUP.md](docs/zh-TW/COGNITO-SETUP.md) |
| Okta | `https://{your-domain}.okta.com` | 建立 OIDC 應用程式 |
| Azure AD | `https://login.microsoftonline.com/{tenant-id}/v2.0` | 註冊應用程式 |

**在提供者端需要做的事：**
1. 建立一個 OIDC 應用程式 / OAuth 2.0 客戶端
2. 設定 redirect URI：`http://localhost:9876/callback`（給 PKCE 用）
3. 如需要 headless 終端機，啟用 device code 流程
4. 複製 `client_id`（如果不是公開客戶端，還有 `client_secret`）
5. 將這些值填入 `config.toml` 的 `[oidc]` 區塊

### 第五步：在 AWS 帳號建立 IAM Role

`entitlements.toml` 中的每個 AWS 帳號都需要一個 IAM Role，讓 Control Plane 能 AssumeRole。

**Trust Policy**（允許 Control Plane 的 AWS 身分 Assume 這個 Role）：
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

Control Plane 本身的 AWS 身分也需要在這些目標 role ARN 上具備
`sts:AssumeRole`、`sts:TagSession` 和 `iam:SimulatePrincipalPolicy`，
才能挑選可用 role，並替連線流程簽發範圍限縮的 STS 憑證。

**Permission Policy**（這個 Role 可以做什麼）：
```json
{
  "Version": "2012-10-17",
  "Statement": [{
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
  }]
}
```

### 第六步：部署在 TLS 反向代理後面

Control Plane 只監聽 plain HTTP，需要透過反向代理提供 TLS：

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

### 第七步：啟動

```bash
CONFIG_PATH=config.toml cargo run --release -p control-plane
```

### 第八步：打包並分發 TUI

使用打包腳本建立自包含的分發資料夾：

```bash
cargo build --release -p tui-client
scripts/package.sh https://canopy.internal
```

會產生 `dist/` 資料夾：

```
dist/
├── tui-client     ← Release 二進位檔
├── config.toml    ← 客戶端設定（control_plane_url 已寫入）
└── install.sh     ← 一鍵安裝腳本
```

將 `dist/` 資料夾透過內部管道交付（S3、Artifactory、共享磁碟等）。

### 第九步：維運人員執行安裝腳本

每位維運人員只需要跑一個指令：

```bash
./install.sh
```

腳本會自動：
1. 預設安裝 `canopy` 二進位檔到 `~/.local/bin/`（可用 `CANOPY_BIN_DIR` 覆寫）
2. 建立 TUI 設定檔（URL 已預填，路徑依作業系統決定）
3. 偵測 AWS CLI v2；可完成 installer 驗證時自動安裝，否則提示手動安裝（SSM/EIC/ECS Exec 連線需要）
4. macOS 會偵測並安裝 Session Manager Plugin；Linux 在可信簽章驗證支援完成前會提示手動安裝（SSM/ECS Exec 需要）
5. 移除 macOS Gatekeeper 隔離標記（如適用）
6. 跑完整驗證檢查

詳細說明與疑難排解見 [docs/zh-TW/OPERATOR-SETUP.md](docs/zh-TW/OPERATOR-SETUP.md)。

---

## 認證流程

```
TUI                     Control Plane              OIDC 提供者
 │                           │                          │
 ├── PKCE auth start ───────▶│                          │
 │◀── authorize URL ─────────│                          │
 │                           │                          │
 ├── (瀏覽器重導) ───────────────────────────────────▶│
 │◀── (callback with code) ─────────────────────────────│
 │                           │                          │
 ├── exchange code ─────────▶│── 驗證 code ───────────▶│
 │                           │◀── id_token ────────────│
 │◀── 內部 JWT ─────────────│                          │
 │                           │                          │
 ├── API 請求 + JWT ────────▶│── AssumeRole ──────────▶ AWS
 │◀── 過濾後的資料 ─────────│◀── 原始資料 ────────────│
```

**Dev mode** 完全跳過 OIDC 流程 — `dev-login` 直接簽發 JWT。

## 稽核日誌

當設定了 `audit_log` 時，每個操作會同時寫入：
1. 結構化 tracing 輸出（stdout，JSON 格式）
2. 持久化 JSON-lines 檔案

記錄的操作包括：
- 登入/登出
- EC2 列表請求
- ECS task list / exec 請求
- CloudWatch 搜尋
- Live Tail 啟動/停止
- 連線動作

每筆記錄包含：event_id、actor、timestamp、account、region、target、outcome。

稽核 schema 採用 additive 方式演進。新增 top-level 欄位會是 optional，沒有值時會省略；如果下游有嚴格 schema（例如 Athena table 或 SIEM mapping），在使用 `target_resource_name` 這類新欄位前需要先做 schema migration。詳細欄位見 [Audit Log Schema](docs/en/AUDIT-SCHEMA.md)。

當持久化稽核檔案寫入失敗時，API 會回傳 503（fail-closed 策略）。

## 鍵盤快捷鍵

| 按鍵 | 情境 | 動作 |
|------|------|------|
| `j/k` | 表格 | 上下移動 |
| `Enter` | 表格 | 展開詳細/執行 |
| `/` | EC2、ECS、CW | 啟動搜尋/過濾 |
| `Ctrl+E` | 清查 | 有權限時切換 EC2/ECS 視圖 |
| `s` | EC2 | SSM Session Manager 連線 |
| `e` | EC2 | EC2 Instance Connect SSH |
| `c` | EC2 | 直接 SSH（使用你自己的金鑰） |
| `r` | EC2、ECS | 重新整理 |
| `[`/`]` | 清查、CW 搜尋 | 切換帳號（上一個/下一個） |
| `{`/`}` | 清查、CW 搜尋 | 切換區域（上一個/下一個） |
| `x` | CW 搜尋 | 匯出結果 |
| `Tab` | CW 搜尋 | 切換 Quick/Insights 模式 |
| `Esc` | 任何 | 返回/取消焦點 |
| `q` | 儀表板 | 離開 |
| `Ctrl+x` | 儀表板 | 登出 |
| `p` | 設定 | 開啟 Change Password |
| `Ctrl+C` | 任何 | 離開 |

## 安全模型

- **伺服器端過濾**：EC2、ECS tasks 和 CloudWatch 資料在後端依權限過濾後才回傳，客戶端永遠看不到未授權的資源
- **範圍隔離**：功能授權與資源範圍依規則逐一驗證，防止跨群組權限拼接。一個群組的功能不能套用到另一個群組的資源上
- **短期憑證**：STS AssumeRole 附帶 session tags；連線操作使用 inline session policy 將主要動作限縮到特定執行個體或 ECS task，並透過 IAM 條件綁定 OS 使用者（`ssm:SessionDocumentAccessCheck`、`ec2:osuser`）或 ECS cluster（`ecs:ExecuteCommand`）；ECS Exec 憑證另只包含必要的 `ecs:DescribeTasks` 與 `ssmmessages` 輔助動作，並限縮到請求的 AWS region
- **帳號身份驗證**：`direct`/`profile:` 和 AssumeRole 憑證透過 `GetCallerIdentity` 驗證，確保與設定的 `account_id` 一致
- **TUI 無 AWS 長期金鑰**：所有 AWS 存取都經由 Control Plane
- **稽核失敗則拒絕**：持久化稽核日誌寫入失敗時，所有受保護的 API（包含登入、刷新、權限查詢）回傳 503。暫時性 I/O 錯誤可自行恢復，無需重啟
- **Dev mode 安全防護**：非 loopback 位址禁止啟用 dev_mode（除非明確覆寫）。使用真實 AWS 資料時，CORS 限制為僅 localhost
- **Email 驗證匹配**：權限成員匹配僅在 IdP 確認 `email_verified = true` 時才使用 email，防止透過未驗證的 email 聲明進行權限提升
- **Token 儲存**：以 Unix 0600 權限存放在 `~/.local/share/canopy/token`。權限不安全的檔案在讀取時會被拒絕
