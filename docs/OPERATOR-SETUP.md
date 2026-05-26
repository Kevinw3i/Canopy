# 分發 TUI 給維運人員 — 逐步操作

本文件說明如何將 Canopy TUI 客戶端交付給維運人員，讓他們能在自己的電腦上使用。

**設計原則**：維運人員只需要跑一個指令。設定、相依工具、驗證全部由安裝腳本處理。

---

## 管理員操作（你做一次）

### 1. 編譯 release 二進位檔

```bash
cd ~/Desktop/Canopy
cargo build --release -p tui-client
```

完成後二進位檔在 `target/release/tui-client`。

> **跨平台**：上面編出的是你目前電腦的架構（macOS arm64）。
> 如果維運人員使用不同平台，需要分別編譯：
>
> | 目標平台 | 編譯指令 |
> |----------|----------|
> | macOS arm64（M1/M2/M3） | `cargo build --release -p tui-client` |
> | macOS x86_64（Intel） | `cargo build --release -p tui-client --target x86_64-apple-darwin` |
> | Linux x86_64 | `cargo build --release -p tui-client --target x86_64-unknown-linux-gnu` |
> | Linux arm64 | `cargo build --release -p tui-client --target aarch64-unknown-linux-gnu` |
>
> 跨平台編譯需要先安裝對應的 target：`rustup target add <target>`

### 2. 本機快速建立 TUI 設定檔

如果只是在目前電腦測試剛編好的 TUI，可以直接執行：

```bash
cd ~/Desktop/Canopy
scripts/setup-tui-config.sh https://canopy.your-domain.com
./target/release/tui-client
```

或者把您的真實 URL 與 Cognito 設定寫進 `scripts/setup-tui-config.local.sh`
（從 `setup-tui-config.local.sh.example` 複製，已 gitignore）然後改執行：

```bash
scripts/setup-tui-config.local.sh
```

這個腳本會依照作業系統寫到 TUI 實際讀取的位置：

| 作業系統 | 設定檔位置 |
|----------|------------|
| macOS | `~/Library/Application Support/canopy/config.toml` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/canopy/config.toml` |
| Windows Git Bash | `%APPDATA%/canopy/config.toml` |

如果設定檔已存在，腳本預設不覆寫。需要重寫時：

```bash
scripts/setup-tui-config.sh https://canopy.your-domain.com --force
```

### 3. 執行打包腳本

```bash
cd ~/Desktop/Canopy
scripts/package.sh
```

腳本會：
1. 複製二進位檔到 `dist/`
2. 將你設定的 `CONTROL_PLANE_URL` 寫入設定範本
3. 產生 `install.sh` 安裝腳本
4. 顯示分發資料夾路徑

> 第一次執行會提示你輸入 Control Plane 的網址（例如 `https://canopy.internal`）。
> 這個網址會被寫死在安裝腳本中，維運人員不需要知道或手動填寫。

### 4. 交付給維運人員

將 `dist/` 資料夾透過你們的內部管道交付：

- 內部 S3 bucket
- Artifactory / Nexus
- GitHub Release
- 共享磁碟
- 或直接 `scp`

---

## 維運人員操作（每位人員各做一次）

### 唯一步驟

```bash
cd canopy-dist
./install.sh
```

完成。安裝腳本會自動：

1. 安裝 `canopy` 二進位檔到 `/usr/local/bin/`
2. 建立 TUI 設定檔（URL 已預填，路徑依作業系統決定）
3. 偵測 AWS CLI v2，沒有就自動安裝
4. 偵測 Session Manager Plugin，沒有就自動安裝
5. 移除 macOS Gatekeeper 隔離標記（如適用）
6. 跑完整驗證，逐項報告結果

### 啟動

```bash
canopy
```

### 使用 MCP / AI Tools

若管理員在 `entitlements.toml` 中授權：

```toml
[rules.features]
can_use_mcp = true
```

使用者登入 TUI 後會看到 `MCP / AI Tools` 頁面。

操作流程：

1. 進入 `MCP / AI Tools`
2. 按 `e` 啟動本機 MCP server
3. TUI 會先檢查 `/healthz`
4. health check 成功後選擇 `Codex CLI` 或 `Claude Code`
5. TUI 會開一個新的 macOS Terminal 視窗啟動對應 AI client

目前 Product Phase 2 提供 MCP 基礎工具與 CloudWatch discovery：

- `canopy_describe_capabilities`
- `canopy_get_guidance`
- `canopy_list_allowed_log_groups`

並可在明確啟用時提供 MCP Database v1。CloudWatch search / Insights / EC2 data tools 尚未開放。即使使用者有
`can_use_cloudwatch_search = true`，也不會自動取得 MCP CloudWatch
查詢權限；後續會由獨立的 `can_use_mcp_cloudwatch` 與 control-plane MCP
專用 route 控制。

MCP Database v1 若啟用，會多兩個工具：

- `canopy_list_database_scopes`
- `canopy_query_database`

啟用條件：

```toml
[rules.features]
can_use_mcp = true
can_use_mcp_database = true

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
allow_views = false  # 預設拒絕 VIEW；opt-in 之前請看下方 checklist
```

connection 本身設定在 control-plane `config.toml` 或 Terraform
`database_connections_toml`。密碼只放 Secrets Manager，secret JSON 固定：

```json
{"username":"canopy_readonly","password":"..."}
```

執行查詢前 control-plane 會先做 SELECT-only SQL validation，接著跑
`EXPLAIN FORMAT=JSON`。若沒有合理索引路徑、掃描量超過 scope 限制、
或 EXPLAIN 失敗，真正的 SELECT 不會執行。raw SQL 會進 audit，audit
讀取權限要視為敏感權限。

---

## MCP Database operator hardening

啟用 `can_use_mcp_database = true` 之前，建議完成以下設定。

### 1. 在唯讀 DB role 上加 `wait_timeout`（**必設**，不是 nice-to-have）

Control-plane 內部已對每個請求做 wall-clock bounding（caller 端最壞
~23 秒：semaphore queue + connect + work + cleanup），但兩個 cleanup
失敗模式仍需要 server 端配合才能鎖死 over-admission：

1. **`disconnect()` 完成 path**：每個建好的 connection，Canopy 透過
   `OptsBuilder::init` 已自動 `SET SESSION wait_timeout = 25`、
   `net_read_timeout = 10`、`net_write_timeout = 10`。Server 端會在 25 秒內
   reap 任何卡住的 session，限制 `POOL_CLEANUP_HARD_CAP` (30 s) 後 limiter
   permit 才釋放。**這條 path 不需要 operator 配置**，code 內 init SQL
   就能保證。
2. **acquire failure path**：`Conn::new` / `pool.get_conn` 超時時被取消，
   init SQL 可能還沒跑就被砍。這時 orphan session 的 lifetime 就是
   **role-level** `wait_timeout`。Canopy 會在這條 path 持有 limiter permit
   `ACQUIRE_FAILURE_PERMIT_HOLD` (60 s)，**必須**比 role-level wait_timeout
   長才能保證 server 端 orphan 在 permit 釋放前已被 reap。

**Invariant（必須遵守，否則 max_connections 不是 hard bound）**：
**`@@session.wait_timeout` AND `@@global.wait_timeout` 兩個都 ≤ 30 秒。**
預設 28800（8 小時）絕對不行。

Control-plane **啟動時 preflight** 會用 read-only secret 連到每個
`database_connections` entry，**同時**跑 `SELECT @@session.wait_timeout` 與
`SELECT @@global.wait_timeout`，兩個都必須 ≤ 30 秒。

**違反者的行為（重要：與其他 routes 隔離）**：

- `GET /health` 仍會 **200**（global readiness 維持 ready=true，EC2 /
  CloudWatch / auth path 不會被 deregister）。
- **只有受影響的 database scope** 會回 `503 SERVICE_UNAVAILABLE` +
  `code: "SERVICE_UNAVAILABLE"` + message 指向 `GET /health` 的 message。
- 其他健康的 `database_connections` 仍可服務查詢。
- 背景 reprobe 每 60 秒重試該 connection（cool-down 5 分鐘若是 connect/handshake
  phase failure）；operator 修好 upstream 後自動恢復，不需重啟 control-plane。

換言之這個 invariant 由 code per-connection 強制，doc 只是說明為什麼。Operator
應該以 **MCP database query 回 503** 為訊號（不是 /health），並查 control-plane
日誌 `DB preflight FAILED for database connection` / `DB preflight regressed` /
`DB preflight recovered` 等 line 找哪個 connection name。

> **常見陷阱**：靠 `init_connect` 把 `@@session.wait_timeout` 壓到 25，但
> `@@global.wait_timeout` 還是 28800 → preflight 仍會 503，因為 partial
> session（init SQL 還沒跑完）會繼承 `@@global`。**必須**改 global。

```sql
-- MySQL 8.x / RDS / Aurora MySQL：以下任一條 path 都行，**必須是 immediate-effective**。

CREATE USER 'canopy_readonly'@'%' IDENTIFIED BY '...';
GRANT SELECT ON orders.* TO 'canopy_readonly'@'%';
GRANT SHOW VIEW ON orders.* TO 'canopy_readonly'@'%';   -- 若 allow_views=true 需要
ALTER USER 'canopy_readonly'@'%' WITH MAX_USER_CONNECTIONS 16;

-- Path A：MySQL/RDS parameter group（推薦，作用在所有 sessions）。
--   * 修 cluster/instance parameter group 把 `wait_timeout` 改成 25。
--   * 套用 → 對 MySQL 8 / Aurora MySQL 是 dynamic（不需 restart）。
--   * 套用後跑 path C 驗證。

-- Path B：手動 SET GLOBAL + SET PERSIST（適合非 RDS 自建 MySQL）。
SET GLOBAL  wait_timeout = 25;   -- 立刻對 NEW sessions 生效。
SET PERSIST wait_timeout = 25;   -- 跨重啟生效。
-- 對既有 sessions 不會立刻生效；如有長連線可手動 KILL 或等他們自然 close。

-- Path C（必跑）：以 canopy_readonly 身分驗證。
--   不能用 admin/root 驗 — 必須是 control-plane 實際會用的 secret。
--   **必須同時查 @@session 與 @@global**：control-plane preflight 兩個都檢，
--   只滿足 @@session（例如靠 init_connect）會讓 service 啟動後永遠 503。
mysql -h <host> -u canopy_readonly -p<password> <db> \
  -e "SELECT @@session.wait_timeout, @@global.wait_timeout;"
-- 兩個 column 結果都必須 ≤ 30，否則 control-plane 起來會 503。
```

**Don't use `SET PERSIST_ONLY init_connect = ...`**：這個 (a) 不是 immediate-
effective，要 restart 才生效；(b) 是 server-level session-startup hook，不是
role-level setting；(c) 對 SUPER / CONNECTION_ADMIN user 完全跳過；(d) 只動
session 不動 global，preflight 同時檢 @@global 會直接 503。四個性質都會讓
operator 以為 invariant 滿足、實際 session 仍跑 default 28 800 秒。

`MAX_USER_CONNECTIONS` 也建議設一個保守上限，這樣 MySQL 在飽和時會
回 1203 (`ER_TOO_MANY_USER_CONNECTIONS`)，Canopy 會把它翻成
**HTTP 503 + `database_connection_unavailable`**（不是 500）。
client/SDK 看到 503 應做指數退避，不要當應用 bug 派人。

### 2. `max_connections` 設保守

Connection 池上限在 control-plane `config.toml` 的
`database_connections_toml` 設定：

```toml
[orders_prod]
host = "..."
database = "orders"
secret_arn = "..."
readonly = true
max_connections = 8          # per control-plane process
connect_timeout_ms = 3000    # 同時是 503 queue/connect timeout 預算
statement_timeout_ms = 5000
explain_timeout_ms = 3000
```

超過 `max_connections` 的請求會排隊 `connect_timeout_ms`，超過後回
**HTTP 503 + `connection_queue_full`**。

### 3. TLS 絕對不要關

預設 `require_tls = true`。`accept_invalid_tls_certs` /
`skip_tls_hostname_verification` 兩個 flag **只用於本機開發**。production
配置碰任一就應該被 review reject。

### 4. `allow_views = true` opt-in checklist

只有在以下都成立才把 scope 的 `allow_views` 設 `true`：

- [ ] 已列出這個 scope 透過 `allowed_tables` 可觸及的所有 VIEW
- [ ] 每個 VIEW 的 `DEFINER` user **不**超過 `canopy_readonly` 權限
- [ ] 每個 VIEW 的 base tables **都**落在 scope 的 `allowed_schemas` 內，
      或這些 base tables 本來就允許查
- [ ] 文件化「為什麼用 VIEW 不直接 query base tables」
- [ ] 在 audit 監控加一條規則：`views_allowed=true` 的查詢加重審

注意：即使 `allow_views=true`，view-guard pipeline 仍然執行（MDL 保護、
EXPLAIN 評估、SELECT 在同一個 transaction），只是不會在 information_schema
看到 VIEW 時 reject。每個查詢的 (schema, table) 對數仍受
`MAX_VIEW_TARGETS_PER_QUERY = 32` 上限。

### 5. Audit 監控訊號

關鍵 `mcp_outcome_kind` 值（更多請看 `docs/AUDIT-SCHEMA.md`）：

| Outcome kind | HTTP | 應對 |
|---|---|---|
| `connection_queue_full` | 503 | Client 應指數退避；可能要調 `max_connections` |
| `database_connection_unavailable` | 503 | MySQL/RDS Proxy 飽和（1037/1040/1041/1203）；查 server-side 容量 |
| `view_not_allowed_by_scope` | 400 | 使用者試圖查 view 而 scope 沒開 |
| `view_swap_detected_between_checks` | 400 | 罕見；意味查詢期間有 DDL；查 migration 時間表 |
| `full_table_scan` / `max_examined_rows` | 400 | 缺索引或查詢太寬；不是 bug |
| `database_execution_failed` | 500 | 真實錯誤；要派人 |

---

## 安裝腳本做了什麼

以下是 `install.sh` 的完整行為說明（維運人員不需要讀這段，這是給你的參考）：

```
install.sh
├── 1. 偵測作業系統和 CPU 架構
├── 2. 安裝二進位檔 → /usr/local/bin/canopy
├── 3. macOS: 移除 Gatekeeper 隔離標記
├── 4. 建立設定檔
│      ├── macOS → ~/Library/Application Support/canopy/config.toml
│      └── Linux → ${XDG_CONFIG_HOME:-~/.config}/canopy/config.toml
│      （如果已存在則跳過，不覆寫）
├── 5. 檢查 AWS CLI v2
│      ├── 已安裝 → 跳過
│      └── 未安裝 → 下載並安裝（macOS .pkg / Linux .zip）
├── 6. 檢查 Session Manager Plugin
│      ├── 已安裝 → 跳過
│      └── 未安裝 → 下載並安裝（macOS .pkg / Linux .deb/.rpm）
└── 7. 驗證
       ├── canopy 可執行
       ├── 設定檔存在且格式正確
       ├── aws --version 回傳 2.x
       ├── session-manager-plugin --version 正常
       └── Control Plane 網路可達（curl 測試）
```

---

## 常見問題

### Q: macOS 顯示 "cannot be opened because the developer cannot be verified"

安裝腳本會自動處理已安裝的 binary 與同資料夾內的啟動檔。如果是先直接雙擊 `Canopy.command` 被 Gatekeeper 擋下，請先右鍵 → Open 一次，或對整個解壓縮後的資料夾清除 quarantine。

```bash
xattr -dr com.apple.quarantine /path/to/canopy-dist
```

### Q: 啟動後顯示 "Failed to fetch entitlements"

1. 確認 Control Plane 正在運行
2. 執行 `curl https://canopy.internal/api/entitlements` 確認網路可達
3. 如果回傳 401 Unauthorized → Control Plane 正常，重新登入即可

### Q: SSM 連線顯示 "AccessDenied"

這不是安裝問題，是權限問題：
1. 確認你的帳號在 `entitlements.toml` 中被授權 `can_use_ssm = true`
2. 確認目標 AWS 帳號的 IAM Role 有 `ssm:StartSession` 權限

### Q: 畫面顯示不正常 / 亂碼

確認終端機環境：

```bash
echo $TERM    # 期望：xterm-256color 或類似
echo $LANG    # 期望：包含 UTF-8
```

建議使用：iTerm2（macOS）、Alacritty、WezTerm、Windows Terminal。

### Q: 想完全移除

```bash
sudo rm /usr/local/bin/canopy
rm -rf "$HOME/Library/Application Support/canopy"  # macOS
rm -rf ~/.config/canopy ~/.local/share/canopy      # Linux
```

---

## 檔案位置一覽

| 檔案 | 路徑 | 用途 |
|------|------|------|
| 二進位檔 | `/usr/local/bin/canopy` | TUI 主程式 |
| 設定檔（macOS） | `~/Library/Application Support/canopy/config.toml` | 客戶端設定（URL 已預填） |
| 設定檔（Linux） | `${XDG_CONFIG_HOME:-~/.config}/canopy/config.toml` | 客戶端設定（URL 已預填） |
| Token 快取（macOS） | `~/Library/Application Support/canopy/token` | 登入後自動建立，權限 0600 |
| Token 快取（Linux） | `~/.local/share/canopy/token` | 登入後自動建立，權限 0600 |
| 除錯日誌 | `./tui-client.log` 或 `/tmp/tui-client.log` | TUI 執行日誌 |
