<p align="center">
  <img src="assets/banner.svg" alt="Canopy" width="800"/>
</p>

內部營運終端機操作介面，用於管理 AWS 基礎設施。

```
┌──────────────┐         ┌──────────────────┐         ┌─────────┐
│  TUI 客戶端  │──HTTP──▶│   Control Plane  │──STS───▶│   AWS   │
│  (ratatui)   │         │   (axum)         │         │ EC2/CWL │
│              │◀─JSON───│                  │◀────────│ SSM/STS │
└──────────────┘         │  - 認證 (OIDC)   │         └─────────┘
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

> AWS CLI 和 Session Manager plugin 只有「連線」功能（SSM/EIC）需要，其他功能不需要。

### 第一步：建置

```bash
cd ~/Desktop/Canopy
cargo build
cargo test        # 39 個測試，應全部通過
```

### 第二步：啟動 Control Plane（終端機 1）

```bash
CONFIG_PATH=config.dev.toml cargo run -p control-plane
```

看到以下訊息就是成功：
```
Loaded entitlements from "entitlements.dev.toml": 2 rules, 2 memberships
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
| EC2 清查 | 按 `1` | 5 台 mock 執行個體，`/` 搜尋，`Enter` 看詳細 |
| CloudWatch 搜尋 | 按 `2` | 查詢輸入框，mock 日誌事件 |
| 存取/身分 | 按 `4` | 使用者、群組、功能旗標、允許的帳號 |
| 設定 | 按 `5` | 目前的設定值；按 `p` 開啟 Change Password |

按 `Esc` 返回上一頁，Dashboard 按 `Ctrl+x` 登出，按 `q` 離開。

### 開發用帳號

`entitlements.dev.toml` 預設了兩個使用者：

| 使用者名稱 | 群組 | 可以做什麼 |
|-----------|------|-----------|
| `dev-admin` | platform-engineering | 全部功能：EC2、CloudWatch、SSM、EIC，跨 2 個帳號 |
| `dev-readonly` | readonly-ops | 唯讀：只能看 staging 帳號的 EC2 和 CloudWatch，不能連線 |

試試用 `dev-readonly` 登入，觀察介面如何隱藏該使用者沒有權限的功能。

---

## 專案檔案

```
Canopy/
├── config.dev.toml            ← Control Plane 設定（本機開發用）
├── config.sample.toml         ← Control Plane 設定（生產環境範本）
├── entitlements.dev.toml      ← 權限規則（本機開發用）
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
    ├── PRD.md                 ← 產品需求文件
    ├── ARCHITECTURE.md        ← 完整架構參考
    ├── ECS_FARGATE_DEPLOYMENT.md ← ECS 部署（手動 / Terraform）
    ├── COGNITO-SETUP.md       ← AWS Cognito OIDC 設定
    ├── OPERATOR-SETUP.md      ← TUI 分發給維運人員
    └── RELEASING.md           ← 發版流程與 CI
```

---

## 設定參考

### Control Plane 設定（`config.dev.toml` / `config.toml`）

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
entitlements_file = "entitlements.dev.toml"

# ── 稽核日誌 ────────────────────────────────────────
# 可選。設定後每個操作會以 JSON-lines 格式寫入此檔案。
# 沒設定的話只會透過 structured tracing 輸出到 stdout。
# audit_log = "/var/log/canopy/audit.jsonl"

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
secret = "local-dev-secret-do-not-use-in-production"
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

### 權限規則檔（`entitlements.dev.toml`）

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
allowed_os_users = ["ec2-user", "ubuntu"]              # 用於 SSM/EIC 連線

[rules.features]
can_view_ec2 = true               # 可以看 EC2 執行個體
can_use_cloudwatch_search = true  # 可以搜尋 CloudWatch 日誌
can_use_cloudwatch_tail = true    # 可以使用 Live Tail
can_use_ssm = true                # 可以透過 SSM Session Manager 連線
can_use_ec2_instance_connect = true  # 可以透過 EC2 Instance Connect 連線

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "production"
# role_arn 支援三種模式：
#   "direct"              → 直接用本機預設 AWS 憑證（不走 AssumeRole）
#                           不支援 SSM/EIC 連線（僅 SSH）
#   "profile:NAME"        → 用 ~/.aws/credentials 裡指定的 profile
#                           不支援 SSM/EIC 連線（僅 SSH）
#   "arn:aws:iam::...:role/..." → AssumeRole 到該 IAM Role（生產環境）
#                           支援 SSM、EIC、SSH，使用範圍限定憑證
role_arn = "arn:aws:iam::123456789012:role/CanopyRole"

[[rules.allowed_accounts]]
account_id = "234567890123"
account_name = "staging"
role_arn = "arn:aws:iam::234567890123:role/CanopyRole"

[[rules.instance_tag_selectors]]        # 執行個體必須匹配至少一個 selector
[rules.instance_tag_selectors.tags]
Environment = ["production", "staging"]  # 標籤鍵 = 允許的值

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

### TUI 客戶端設定

建議用腳本建立設定檔，避免不同作業系統路徑不一致：

```bash
scripts/setup-tui-config.sh https://<your-canopy-domain>
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
```

當 `auto_update = true` 時，TUI 啟動時會檢查 GitHub 上是否有更新的 `tui-v*` release（每 10 分鐘最多檢查一次）。如果找到新版本：
- **可寫入的安裝**：自動下載 tarball、驗證 SHA256、原地替換 binary。畫面頂部會顯示綠色 banner 提示重啟。
- **唯讀安裝**：顯示 banner 提示手動下載更新。

按 `Ctrl+D` 關閉更新 banner。

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
# client_secret = "your-secret"                     # 僅在提供者要求時填寫
scopes = ["openid", "profile", "email"]

[jwt]
secret = "<generated-jwt-secret>"       # 第一步產生的值
expiry_seconds = 3600

[aws]
default_region = "us-east-1"
session_duration_seconds = 3600
```

### 第三步：建立 `entitlements.toml`

以開發檔為起點：

```bash
cp entitlements.dev.toml entitlements.toml
```

修改以下欄位：
- `account_id` → 真實的 AWS 帳號 ID
- `role_arn` → 真實的 IAM Role ARN（見第五步）
- `[[memberships]]` 中的 `user_id` → 真實的 OIDC 使用者識別（通常是 email）
- `allowed_regions` → 真實的 AWS 區域
- `allowed_log_group_arns` → 真實的 Log Group ARN 樣式

### 第四步：設定 OIDC 提供者

Control Plane 支援任何 OpenID Connect 提供者：

| 提供者 | issuer_url | 說明 |
|--------|------------|------|
| Google | `https://accounts.google.com` | 在 Google Cloud Console 建立 OAuth 客戶端 |
| AWS IAM Identity Center | `https://your-sso-portal.awsapps.com/start` | 啟用 OIDC 應用程式 |
| **AWS Cognito** | `https://cognito-idp.{region}.amazonaws.com/{pool-id}` | **推薦 AWS 使用者。** 見 [docs/COGNITO-SETUP.md](docs/COGNITO-SETUP.md) |
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
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {
        "sts:ExternalId": "canopy"
      }
    }
  }]
}
```

**Permission Policy**（這個 Role 可以做什麼）：
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ec2:DescribeInstances",
      "logs:DescribeLogGroups",
      "logs:FilterLogEvents",
      "logs:StartQuery",
      "logs:GetQueryResults",
      "logs:StartLiveTail",
      "ssm:StartSession",
      "ssm:DescribeInstanceInformation",
      "ec2-instance-connect:SendSSHPublicKey",
      "ec2-instance-connect:OpenTunnel"
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
1. 安裝 `canopy` 二進位檔到 `/usr/local/bin/`
2. 建立 TUI 設定檔（URL 已預填，路徑依作業系統決定）
3. 偵測並安裝 AWS CLI v2（如果沒有）
4. 偵測並安裝 Session Manager Plugin（如果沒有）
5. 移除 macOS Gatekeeper 隔離標記（如適用）
6. 跑完整驗證檢查

詳細說明與疑難排解見 [docs/OPERATOR-SETUP.md](docs/OPERATOR-SETUP.md)。

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
- CloudWatch 搜尋
- Live Tail 啟動/停止
- 連線動作

每筆記錄包含：event_id、actor、timestamp、account、region、target、outcome。

當持久化稽核檔案寫入失敗時，API 會回傳 503（fail-closed 策略）。

## 鍵盤快捷鍵

| 按鍵 | 情境 | 動作 |
|------|------|------|
| `j/k` | 表格 | 上下移動 |
| `Enter` | 表格 | 展開詳細/執行 |
| `/` | EC2、CW | 啟動搜尋/過濾 |
| `s` | EC2 | SSM Session Manager 連線 |
| `e` | EC2 | EC2 Instance Connect SSH |
| `c` | EC2 | 直接 SSH（使用你自己的金鑰） |
| `r` | EC2 | 重新整理 |
| `[`/`]` | CW 搜尋 | 切換帳號（上一個/下一個） |
| `{`/`}` | CW 搜尋 | 切換區域（上一個/下一個） |
| `x` | CW 搜尋 | 匯出結果 |
| `Tab` | CW 搜尋 | 切換 Quick/Insights 模式 |
| `Esc` | 任何 | 返回/取消焦點 |
| `q` | 儀表板 | 離開 |
| `Ctrl+x` | 儀表板 | 登出 |
| `p` | 設定 | 開啟 Change Password |
| `Ctrl+C` | 任何 | 離開 |

## 安全模型

- **伺服器端過濾**：EC2 和 CloudWatch 資料在後端依權限過濾後才回傳，客戶端永遠看不到未授權的資源
- **範圍隔離**：功能授權與資源範圍依規則逐一驗證，防止跨群組權限拼接。一個群組的功能不能套用到另一個群組的資源上
- **短期憑證**：STS AssumeRole 附帶 session tags；連線操作使用 inline session policy 限縮到特定執行個體，並透過 IAM 條件綁定 OS 使用者（`ssm:SessionDocumentAccessCheck`、`ec2-instance-connect:osUser`）
- **帳號身份驗證**：`direct`/`profile:` 和 AssumeRole 憑證透過 `GetCallerIdentity` 驗證，確保與設定的 `account_id` 一致
- **TUI 無 AWS 長期金鑰**：所有 AWS 存取都經由 Control Plane
- **稽核失敗則拒絕**：持久化稽核日誌寫入失敗時，所有受保護的 API（包含登入、刷新、權限查詢）回傳 503。暫時性 I/O 錯誤可自行恢復，無需重啟
- **Dev mode 安全防護**：非 loopback 位址禁止啟用 dev_mode（除非明確覆寫）。使用真實 AWS 資料時，CORS 限制為僅 localhost
- **Email 驗證匹配**：權限成員匹配僅在 IdP 確認 `email_verified = true` 時才使用 email，防止透過未驗證的 email 聲明進行權限提升
- **Token 儲存**：以 Unix 0600 權限存放在 `~/.local/share/canopy/token`。權限不安全的檔案在讀取時會被拒絕
