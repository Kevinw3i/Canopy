# Canopy — 產品需求文件 (PRD)

> 版本：0.1.0 | 最後更新：2026-04-05

---

## 1. 產品概述

Canopy 是一套**內部營運終端機介面 (TUI)**，讓受授權的維運人員透過終端機安全地：

1. 瀏覽與搜尋跨帳號的 EC2 執行個體
2. 執行 CloudWatch Logs 快速搜尋與 Logs Insights 查詢
3. 即時串流 CloudWatch Logs（Live Tail）
4. 檢視授權 ECS cluster/task，並在符合條件時開啟 ECS Exec
5. 透過 SSM Session Manager 或 EC2 Instance Connect 連線至執行個體
6. 檢視自身的身分、群組與存取權限

本系統**不是**單機直連 AWS 的工具——它採用 Client/Server 架構，由後端控制面 (Control Plane) 統一處理認證、授權、權限評估與 AWS 存取，確保：

- 使用者只能看到被授權的資源（伺服器端過濾）
- 所有操作皆被完整稽核記錄
- 不需要在終端機上放置長期 AWS 憑證

---

## 2. 目標使用者

| 角色 | 說明 |
|------|------|
| Platform Engineer | 擁有完整存取權限：EC2/ECS 瀏覽、CloudWatch 搜尋/Live Tail、SSM/EIC/ECS Exec 連線 |
| On-Call Engineer | 有限的 CloudWatch 搜尋與 EC2/ECS 唯讀瀏覽，無連線權限 |
| Read-Only Observer | 僅 staging 環境的 EC2 瀏覽與 CloudWatch 搜尋；ECS 視覺化需另授權 |

權限透過**群組 → 權限規則**映射，支援多群組加法式合併。

---

## 3. 系統架構

```
┌──────────────────┐      HTTPS/JSON       ┌──────────────────────┐      STS AssumeRole
│   TUI Client     │◀────────────────────▶│   Control Plane       │◀──────────────────▶ AWS
│   (ratatui)      │                       │   (axum)              │
│                  │      WebSocket        │                       │    EC2 / ECS / CloudWatch
│  - 7 個畫面      │◀────────────────────▶│  - 認證 (OIDC)        │    Logs / STS / SSM
│  - 鍵盤操作      │                       │  - 授權 (Entitlements)│
│  - async 事件迴圈│                       │  - 稽核日誌           │
│  - 外部指令連線  │                       │  - 伺服器端過濾       │
└──────────────────┘                       └──────────────────────┘
```

### 3.1 Crate 架構

| Crate | 路徑 | 用途 |
|-------|------|------|
| `shared` | `crates/shared` | 共用 DTO、錯誤型別（純資料，無商業邏輯） |
| `control-plane` | `apps/control-plane` | Axum REST API 後端 |
| `tui-client` | `apps/tui-client` | Ratatui 終端機介面 |

### 3.2 技術選型

| 面向 | 技術 |
|------|------|
| TUI 框架 | ratatui 0.28 + crossterm 0.28 |
| 非同步執行 | tokio（full features） |
| HTTP 後端 | axum 0.7 + tower |
| HTTP 客戶端 | reqwest 0.12 |
| 序列化 | serde + serde_json |
| 認證 | jsonwebtoken (JWT)、OIDC Discovery、PKCE |
| AWS SDK | aws-sdk-ec2、aws-sdk-ecs、aws-sdk-cloudwatchlogs、aws-sdk-sts、aws-sdk-iam |
| 日誌 | tracing + tracing-subscriber (JSON 格式) |
| 設定 | toml |

---

## 4. 認證與授權

### 4.1 認證方式（依優先序）

| 方式 | 情境 | 說明 |
|------|------|------|
| SSO / OIDC (PKCE) | 桌面終端機 | 打開瀏覽器完成 OIDC 認證，回呼本地 HTTP server |
| Device Code | 無頭終端機 (headless) | 顯示使用者碼和驗證 URL，輪詢直到完成 |
| Dev Login | 僅開發模式 | 以本地使用者名稱取得 JWT，生產環境禁用 |

### 4.2 認證流程

```
TUI                     Control Plane              OIDC Provider
 │                           │                          │
 ├── PKCE auth start ───────▶│                          │
 │◀── authorize URL ─────────│                          │
 │                           │                          │
 ├── (瀏覽器重導) ────────────────────────────────────▶│
 │◀── (callback with code) ──────────────────────────────│
 │                           │                          │
 ├── exchange code ─────────▶│── 驗證 code ───────────▶│
 │                           │◀── id_token ────────────│
 │◀── 內部 JWT ──────────────│                          │
 │                           │                          │
 ├── API 請求 + JWT ────────▶│── AssumeRole ──────────▶ AWS
 │◀── 過濾後的資料 ──────────│◀── 原始資料 ────────────│
```

### 4.3 授權模型 (Entitlements)

每位使用者屬於一或多個群組，每個群組對應一組權限規則：

| 權限維度 | 說明 |
|----------|------|
| `can_view_ec2` | 是否可瀏覽 EC2 執行個體 |
| `can_use_cloudwatch_search` | 是否可使用 CloudWatch 搜尋 |
| `can_use_cloudwatch_tail` | 是否可使用 Live Tail |
| `can_use_ssm` | 是否可透過 SSM 連線 |
| `can_use_ec2_instance_connect` | 是否可透過 EC2 Instance Connect 連線 |
| `can_view_ecs` | 是否可檢視授權 ECS tasks |
| `can_use_ecs_exec` | 是否可對授權 task/container 開啟 ECS Exec |
| `allowed_accounts` | 允許存取的 AWS 帳號 + 對應的 IAM Role ARN |
| `allowed_regions` | 允許的 AWS 區域 |
| `allowed_log_group_arns` | 允許的 CloudWatch Log Group ARN 樣式（支援萬用字元） |
| `instance_tag_selectors` | EC2 標籤過濾條件（執行個體必須匹配至少一個 selector） |
| `allowed_os_users` | 允許的作業系統使用者（用於 SSM/EIC/SSH 連線）。設定 2+ 個時連線時會彈出選擇介面 |
| `excluded_tag_selectors` | 排除規則：匹配的機器即使通過 allow 也會被隱藏 |
| `allowed_clusters` | ECS cluster ARN / pattern allow-list |
| `task_tag_selectors` | ECS task 標籤 allow-list |
| `excluded_task_tag_selectors` | ECS task 標籤 deny-list |
| `excluded_container_names` | ECS Exec container deny-list（例如 sidecar） |
| `allow_broad_cluster_discovery` | 明確允許 `cluster/*` 這類廣泛 cluster discovery |
| `max_session_seconds` | 連線時間上限（秒）。省略或 0 = 不限時 |

**合併策略**：

| 維度 | 合併方式 |
|------|----------|
| 功能旗標 | 加法（OR）— 任一群組授予即擁有 |
| 帳號/區域/OS users | 加法（聯集去重） |
| `instance_tag_selectors` | 聯集（匹配任一即可見） |
| `excluded_tag_selectors` | 聯集（匹配任一即排除） |
| ECS cluster / task / container scope | 後端以 rule-local scope 評估，不允許把不同群組的 account、region、cluster、task selector 或 container denylist 拼接使用 |
| `max_session_seconds` | **取最嚴格（最小非零值）** |

### 4.4 安全規則

- **伺服器端過濾**：EC2、ECS tasks、CloudWatch data 在後端依權限過濾後才回傳，客戶端永遠看不到未授權的資源
- **短期憑證**：透過 STS AssumeRole 取得暫時性憑證，附帶 Session Tags 供稽核
- **連線範圍限縮**：連線操作使用 inline session policy 將主要動作限縮到目標執行個體或 ECS task；ECS Exec 只額外授予同區域必要的 task 描述與 `ssmmessages` channel 動作
- **ECS scope 不跨規則拼接**：ECS task list / exec 的 account、role、region、cluster、task tag、container denylist 必須來自同一授權規則
- **稽核失敗則拒絕 (fail-closed)**：當稽核日誌寫入失敗時，後端拒絕處理請求
- **開發模式防護**：禁止在非 loopback 位址啟用 dev_mode（除非明確覆寫）

---

## 5. 畫面規格

### 5.1 登入畫面 (Login)

- 顯示 SSO/OIDC (PKCE) 按鈕
- 顯示 Device Code 按鈕
- 開發模式下額外顯示使用者名稱輸入框與 Dev Login 按鈕
- 生產模式下隱藏 Dev Login 控制項，焦點預設在 SSO 按鈕
- 顯示認證狀態訊息

### 5.2 儀表板 (Dashboard)

- 顯示歡迎訊息：使用者名稱、群組、帳號數、區域數
- 選單導航至各功能畫面
- 依使用者權限啟用/停用選單項目
- Live Tail 受 feature flag 控制（beta 功能）
- 快捷鍵：`1`-`5` 直接跳轉、`j`/`k` 上下選擇、`Enter` 進入、`q` 離開

### 5.3 EC2 / ECS 清查畫面 (Inventory)

**列表區**：

| 欄位 | 說明 |
|------|------|
| Instance ID | 執行個體 ID |
| Name | Name 標籤 |
| Private IP | 私有 IP |
| Public IP | 公有 IP |
| State | 狀態（綠色=Running、紅色=Stopped、黃色=其他） |
| Type | 執行個體類型 |
| SSM | SSM 受管理（Yes/No） |
| EIC | 支援 Instance Connect（Yes/No） |
| Env | Environment 標籤 |

**功能**：

- 搜尋框：依名稱、ID、IP 篩選（`/` 啟動）
- 右側詳細資料面板（`Enter` 切換）
- SSM 連線（`s`）、EC2 Instance Connect（`e`）、直接 SSH（`c`）
- OS user 選擇彈窗（當 `allowed_os_users` 有 2 個以上時自動顯示）
- 重新整理（`r`）
- 分頁支援
- 載入中/錯誤狀態顯示
- 若使用者有 `can_view_ecs`，`Ctrl+E` 可在 EC2 與 ECS 清查視圖切換

**三種連線方式**：

| 按鍵 | 方式 | 實際指令 | 需要什麼 |
|------|------|---------|---------|
| `s` | SSM Session Manager | `aws ssm start-session --target i-xxx` | SSM Agent + AWS CLI |
| `e` | EC2 Instance Connect | `aws ec2-instance-connect ssh --instance-id i-xxx` | EIC 套件 + AWS CLI v2 |
| `c` | 直接 SSH | `ssh user@IP` | 使用者的 SSH 公鑰已在 EC2 上 |

**OS user 選擇邏輯**：

| `allowed_os_users` 設定 | 按 `s`/`e`/`c` 後的行為 |
|-------------------------|------------------------|
| `[]`（空） | 直接連（SSM shell，不指定 user） |
| `["ec2-user"]`（1 個） | 直接用該 user 連，跳過選單 |
| `["ec2-user", "ubuntu"]`（2+ 個） | 彈出選擇介面，`j`/`k` 選、`Enter` 確認 |

**連線流程**：

1. 使用者按 `s`/`e`/`c`
2. 若有多個 OS user，顯示選擇彈窗
3. TUI 向 Control Plane 請求連線授權
4. Control Plane 驗證權限（帳號、區域、tag selector、OS user）
5. SSM/EIC：產生範圍限縮的 STS 憑證 + 回傳指令
6. SSH：回傳 `ssh user@IP` 指令（不需要 AWS 憑證）
7. TUI 暫停 alternate screen → 執行指令 → 結束後恢復 TUI

**ECS Task 視圖**：

| 欄位 | 說明 |
|------|------|
| Cluster | Cluster 名稱 |
| Family | Task definition family |
| Task ID | Task ARN 尾段 |
| Launch | Launch type |
| Status | Task 狀態 |
| Containers | 可見 container 與 exec-ready 狀態 |
| Account | AWS 帳號 |
| Region | AWS 區域 |

**ECS 功能**：

- 帳號/區域 scope selector 只列出目前 ECS grant 可證明的選項，避免 EC2-only grant 出現在 ECS 視圖
- `r` 重新整理 task list；`/` 搜尋 cluster、family、task id、container name
- `Enter` 只在 task running、`enable_execute_command = true`，且至少一個 container running 並啟動 execute-command agent 時開啟 container picker
- ECS Exec 固定執行 `/bin/sh`，不接受使用者自訂 command
- 後端會重新驗證 task/container scope、task tag selectors、container denylist，並為 AWS CLI 回傳短期範圍限縮憑證
- `role_arn = "direct"` / `profile:NAME` 可用於 ECS task inventory，但 ECS Exec 需要可 AssumeRole 的 IAM role ARN

**錯誤處理**：

- AWS CLI 未安裝
- Session Manager plugin 未安裝
- AWS CLI v2 未安裝
- Session 過期
- AccessDenied

### 5.4 CloudWatch 搜尋畫面 (CloudWatch Search)

**兩種搜尋模式**：

| 模式 | API | 說明 |
|------|-----|------|
| Quick Search | `FilterLogEvents` | 即時過濾，適合簡單搜尋 |
| Insights Query | `StartQuery` + `GetQueryResults` | 結構化查詢語言，支援聚合 |

**功能**：

- 帳號/區域/Log Group 選擇（依權限預設首個可用值）
- 查詢輸入框（`/` 啟動）
- `Tab` 切換搜尋模式
- 結果表格
- 事件詳細檢視（下方面板，依日誌等級上色）
- Insights 查詢狀態輪詢（自動重試直到完成）
- 匯出結果為 JSON 或純文字（`x`）
- 查詢歷史紀錄

**查詢授權安全**：

- 啟動 Insights 查詢時，Control Plane 產生簽章 token（HMAC-SHA256）
- 取得查詢結果時需提供此 token，防止未授權的查詢 ID 重播攻擊

### 5.5 Live Tail 畫面

- 選擇 Log Group
- 啟動/停止（`s`）、暫停/恢復（`p`）
- 本地文字過濾（`/`）
- Scrollback ring buffer（預設 10,000 筆）
- 自動捲動（`a` 切換）、手動捲動（`j`/`k`）
- 依嚴重等級上色：ERROR=紅、WARN=黃、INFO=綠、DEBUG=藍
- 顯示連線狀態、每秒事件數、緩衝事件數
- 透過 WebSocket 連線至 Control Plane
- 斷線時停止串流並顯示錯誤（自動重連仍待補）
- 清除緩衝區（`c`）

**目前狀態**：Beta 功能，受 `enable_live_tail` feature flag 控制。TUI 已可在開發模式連到 Control Plane WebSocket 並串流 mock 事件；生產模式下 WebSocket 端點仍回傳 404。

### 5.6 存取/身分畫面 (Access)

- 顯示目前登入的使用者 ID、Email、顯示名稱
- 顯示所屬群組
- 顯示功能旗標狀態（綠色=Yes、紅色=No）
- 顯示允許的帳號（含 Role ARN）
- 顯示允許的區域
- 顯示允許的 Log Group ARN 樣式
- 顯示 ECS scope：allowed clusters、task tag selectors、excluded task selectors、excluded container names、broad discovery opt-in

### 5.7 設定畫面 (Settings)

- 顯示目前設定：Control Plane URL、開發模式、刷新間隔、Live Tail scrollback
- 提示設定檔路徑

---

## 6. API 規格

### 6.1 認證端點（公開）

| 方法 | 路徑 | 說明 |
|------|------|------|
| POST | `/auth/dev-login` | 開發模式登入 |
| POST | `/auth/pkce/start` | 啟動 PKCE 流程 |
| POST | `/auth/pkce/exchange` | 交換授權碼 |
| POST | `/auth/device-code/start` | 啟動 Device Code 流程 |
| POST | `/auth/device-code/poll` | 輪詢 Device Code 狀態 |
| POST | `/auth/refresh` | 刷新 Token |

### 6.2 受保護端點（需 Bearer JWT）

| 方法 | 路徑 | 說明 |
|------|------|------|
| GET | `/api/entitlements` | 取得目前使用者的完整權限 |
| POST | `/api/ec2/list` | 列出 EC2 執行個體（伺服器端過濾） |
| POST | `/api/ec2/connect` | 取得連線指令與憑證 |
| POST | `/api/ec2/power` | 對單一 EC2 執行 start / stop / reboot（需 typed confirmation） |
| POST | `/api/ecs/tasks` | 列出授權 ECS tasks（伺服器端過濾、支援 account/region/cluster scope） |
| POST | `/api/ecs/exec` | 取得 ECS Exec 指令與範圍限縮憑證 |
| POST | `/api/cloudwatch/log-groups` | 列出允許的 Log Groups |
| POST | `/api/cloudwatch/filter-events` | 執行 FilterLogEvents 搜尋 |
| POST | `/api/cloudwatch/insights/start` | 啟動 Logs Insights 查詢 |
| POST | `/api/cloudwatch/insights/results` | 取得查詢結果 |

### 6.3 WebSocket 端點

| 路徑 | 說明 |
|------|------|
| GET `/api/cloudwatch/live-tail` | CloudWatch Live Tail 串流（in-message 認證） |

---

## 7. 稽核與合規

每項操作皆記錄以下欄位：

| 欄位 | 說明 |
|------|------|
| `event_id` | UUID |
| `timestamp` | RFC 3339 時間戳記 |
| `actor` | 使用者 ID |
| `action` | 操作類型（login、ec2_list、ecs_task_list、ecs_exec、cloudwatch_search 等） |
| `account_id` | 目標 AWS 帳號 |
| `region` | 目標 AWS 區域 |
| `target_resource` | 目標資源（instance_id、log_group 等） |
| `outcome` | 結果（success、failure、denied） |
| `error_message` | 錯誤訊息（如有） |

**雙重輸出**：

1. 結構化 tracing 日誌（stdout/stderr，JSON 格式）
2. 可選的持久化 JSON-lines 檔案（`audit_log` 設定）

**稽核失敗策略**：fail-closed — 當持久化稽核日誌寫入失敗時，受保護的 API 端點回傳 503 Service Unavailable。

---

## 8. AWS 整合

### 8.1 使用的 AWS API

| 服務 | API | 用途 |
|------|-----|------|
| EC2 | `DescribeInstances` | 列出執行個體 |
| EC2 | `StartInstances` / `StopInstances` / `RebootInstances` | 高風險 power actions |
| ECS | `ListClusters` / `DescribeClusters` / `ListTasks` / `DescribeTasks` | 列出與驗證授權 tasks |
| ECS | `ExecuteCommand` | 由 TUI 透過 control-plane 回傳的短期憑證啟動 ECS Exec |
| IAM | `SimulatePrincipalPolicy` | EC2 查詢/power/connect 與 ECS Exec 前檢查候選 role 是否具備必要動作 |
| CloudWatch Logs | `DescribeLogGroups` | 列出 Log Groups |
| CloudWatch Logs | `FilterLogEvents` | 快速搜尋 |
| CloudWatch Logs | `StartQuery` | 啟動 Insights 查詢 |
| CloudWatch Logs | `GetQueryResults` | 取得查詢結果 |
| CloudWatch Logs | `StartLiveTail` | 即時串流日誌 |
| STS | `AssumeRole` | 跨帳號存取 + Session Tags |

### 8.2 多帳號存取

- 每個允許的帳號對應一個 IAM Role ARN
- Control Plane 使用 base AWS 憑證（環境變數、instance profile 等）呼叫 STS AssumeRole
- 附帶 Session Tags：`canopy-user`、`canopy-team`、`canopy-environment`
- EC2 查詢使用扇出 (fan-out) 模式：對每個 (帳號, role, 區域) 組合並行查詢
- 結果以 instance_id 去重

### 8.3 連線憑證範圍限縮

連線操作產生的 STS 憑證附帶 inline session policy：

- SSM：僅允許 `ssm:StartSession` 對目標執行個體
- EIC：允許同區域 `ec2:DescribeInstances` 作為 AWS CLI preflight，並僅允許 `ec2-instance-connect:SendSSHPublicKey` 和 `ec2-instance-connect:OpenTunnel` 對目標 instance / EIC endpoint
- ECS Exec：僅允許 `ecs:ExecuteCommand` 對目標 task，並以 `ecs:cluster` 條件限制目標 cluster；另允許同區域 `ecs:DescribeTasks` 與必要的同區域 `ssmmessages:*Channel`
- 範圍限縮 STS 憑證預設 900 秒；若 entitlement 設定 `max_session_seconds`，使用最嚴格的非零上限，低於 STS 最小值 900 秒的非 SSH 連線會被拒絕
- 除 EIC 必要的同區域 `ec2:DescribeInstances` 與 ECS Exec 必要的同區域 `ecs:DescribeTasks` 外，不授予額外 Describe 權限，以避免客戶端繞過伺服器端過濾

---

## 9. 設定

### 9.1 Control Plane (`config.toml`)

```toml
bind_address = "127.0.0.1:8443"
dev_mode = false
entitlements_file = "entitlements.toml"
audit_log = "/var/log/canopy/audit.jsonl"
cors_allowed_origins = ["http://localhost:9876"]

[oidc]
issuer_url = "https://accounts.google.com"
client_id = "your-client-id"
scopes = ["openid", "profile", "email"]
# 若要使用長效登入，需依 OIDC provider 設定 refresh token 發放
# （例如 offline access scope / provider policy），且 refresh grant 需回傳 id_token。

[jwt]
secret = "<generated-jwt-secret>"
expiry_seconds = 3600

[aws]
default_region = "us-east-1"
session_duration_seconds = 3600
```

### 9.2 TUI Client config

TUI config is stored under the OS standard config directory:

- macOS: `~/Library/Application Support/canopy/config.toml`
- Linux: `${XDG_CONFIG_HOME:-~/.config}/canopy/config.toml`

```toml
control_plane_url = "https://canopy.internal"
dev_mode = false
refresh_interval_secs = 30
live_tail_scrollback = 10000
pkce_callback_port = 9876
enable_live_tail = false
auto_update = false              # 啟動時自動檢查 GitHub Releases 更新
# update_repo_owner = "Kevinw3i" # GitHub owner（預設值）
# update_repo_name = "Canopy"    # GitHub repo（預設值）
```

### 9.3 權限規則 (`entitlements.toml`)

```toml
[[rules]]
id = "platform-eng"
group = "platform-engineering"
allowed_accounts = [
  { account_id = "123456789012", account_name = "production", role_arn = "..." }
]
allowed_regions = ["us-east-1", "us-west-2"]
allowed_log_group_arns = ["arn:aws:logs:*:123456789012:log-group:/app/*"]
allowed_clusters = ["arn:aws:ecs:us-east-1:123456789012:cluster/prod-*"]
allowed_os_users = ["ec2-user", "ubuntu"]

[rules.features]
can_view_ec2 = true
can_view_ecs = true
can_use_ecs_exec = true
can_use_cloudwatch_search = true
can_use_cloudwatch_tail = true
can_use_ssm = true
can_use_ec2_instance_connect = true

[[rules.task_tag_selectors]]
[rules.task_tag_selectors.tags]
Environment = ["production"]

[[memberships]]
user_id = "alice@example.com"
group = "platform-engineering"
```

---

## 10. 測試策略

### 10.1 單元測試與整合測試

| 模組 | 覆蓋範圍 |
|------|----------|
| `shared::dto::*` | EC2 / ECS / CloudWatch / entitlement DTO 序列化與預設值 |
| `control-plane::models::entitlements` | 權限評估、多群組合併、ECS cluster allow-list 驗證、broad wildcard opt-in |
| `control-plane::services::{ec2,ecs,entitlements,cloudwatch}` | 伺服器端過濾、rule-local ECS scope、exec command 建構、ARN 萬用字元匹配、mock 資料 |
| `control-plane::routes::*` | 受保護 API route、audit fail-closed、pagination、scope denied / partial failure 行為 |
| `tui-client` components | EC2/ECS inventory rendering、scope cycling、container picker、connect session、CloudWatch search、device-code backoff |

### 10.2 待補強的測試

- 更多 OIDC 流程測試（目前已涵蓋 device-code、refresh 與 PKCE authorization-code mock HTTP server）
- 更多 WebSocket Live Tail 連線測試（目前已涵蓋 dev/mock session start、mock event、invalid token error 與 TUI WebSocket event action E2E）
- 更多 TUI 元件渲染快照測試（目前已涵蓋 ECS inventory table 與 ECS Exec container picker）
- 更多端到端測試（目前已涵蓋 TUI ApiClient → control-plane → mock AWS 的 auth、entitlements、EC2、ECS、CloudWatch log groups/filter events）

---

## 11. 部署

### 11.1 先決條件

- Rust 1.75+
- AWS CLI v2（用於 SSM/EIC/ECS Exec 連線）
- Session Manager plugin（用於 SSM/ECS Exec）
- OIDC Provider（Google、Okta、Azure AD 等）

### 11.2 生產部署步驟

1. 建立 OIDC client 與 Secrets Manager secret（JWT secret，必要時也包含 OIDC client secret）
2. 填寫 `infra/terraform.tfvars`（VPC/subnet/ACM、OIDC、secret ARN/version、AWS region、CPU architecture、Phase 2 image tag）
3. 建立 `entitlements.toml`（權限規則）
4. 執行 `scripts/validate-terraform-tfvars.sh infra` 驗證 ALB/DNS/subnet/service preconditions（Phase 1 帶 `-var="create_service=false"`；Phase 2 帶 `-var="create_service=true"` 與 `-var="image_tag=<tag>"`）
5. 執行 `scripts/validate-entitlements.sh entitlements.toml infra/terraform.tfvars` 驗證權限規則與 Terraform 變數一致，並在部署前攔截本機 profile、ECS access / SSM shell scope 缺漏、未 opt-in 的寬鬆 cluster wildcard
6. 部署 Control Plane 至 ECS Fargate（推薦使用 `infra/` 的 Terraform，詳見 `infra/README.md`）
7. 打包 TUI 客戶端：`scripts/package.sh https://canopy.internal`
8. 分發 `dist/` 資料夾給維運人員
9. 維運人員執行 `./install.sh` 完成安裝（自動處理設定檔；可驗證時自動安裝 AWS CLI；macOS 自動安裝 SSM Plugin，Linux 提示手動安裝）

ECS 部署不需要 commit 或掛載生產 `config.toml`。Terraform task definition
會設定 `GENERATE_CONFIG=1`，container entrypoint 會從環境變數與
ECS-native secrets 在啟動時產生 control-plane 設定。

> 詳細操作見 `docs/OPERATOR-SETUP.md`

### 11.3 自動更新

TUI 客戶端支援自動更新功能（預設關閉）。啟用 `auto_update = true` 後：

- 啟動時檢查 GitHub Releases 是否有新的 `tui-v*` 正式版（每 10 分鐘最多一次）
- 可寫入的安裝：自動下載 tarball、驗證 SHA256、原地替換 binary，提示重啟
- 唯讀安裝：顯示 banner 提示手動下載
- 按 `Ctrl+D` 關閉更新通知

### 11.4 安全注意事項

- Control Plane 監聽 plain HTTP，需透過反向代理提供 TLS
- JWT secret 必須為高熵隨機字串
- 禁止在非 loopback 位址啟用 dev_mode
- 稽核日誌檔案應設定適當的檔案權限
- Token 持久化檔案設為 `0600` 權限

---

## 12. 已知限制與未來規劃

### 目前限制

- Live Tail 為 beta 功能，TUI WebSocket 客戶端目前支援 dev/mock 串流與 log group picker；production real-AWS streaming 與自動重連尚未完整
- ECS 目前支援 task inventory 與 ECS Exec，不支援 ECS service/deployment 管理
- ECS broad cluster discovery 需要明確 opt-in，且 response 仍受服務端上限保護
- OIDC refresh token 流程已支援 PKCE/device-code 取得、TUI 401 refresh/retry 與 rotated token 持久化；仍要求 provider 發放 refresh token 並在 refresh grant 回傳 id_token
- SSM 受管理狀態為啟發式判斷（有 IAM Role 且 Running）
- EC2 Instance Connect 支援判斷為近似值
- 未支援 AWS Organizations 自動帳號發現
- 權限規則僅支援 TOML 檔案，無資料庫後端

### 未來規劃

- [ ] Production CloudWatch Live Tail streaming 與自動重連
- [ ] 資料庫後端的權限管理
- [ ] AWS Organizations 帳號自動發現
- [ ] SSM DescribeInstanceInformation 精確判斷受管理狀態
- [ ] Multi-factor Authentication 支援
- [ ] 自訂快捷鍵設定
- [ ] 主題與配色自訂
- [ ] 匯出稽核日誌至 CloudWatch Logs / S3
