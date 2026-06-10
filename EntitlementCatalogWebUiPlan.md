# Entitlement Catalog 本機 Web 管理 UI 計畫

## Summary

建立 `canopy-entitlements ui` 本機 Web 管理頁，讓 operator 透過 UI 快速確認與增加 group 權限。UI 以 `entitlements.catalog.toml` 為 source of truth，支援完整 catalog 編輯、從現有 `entitlements.toml` 匯入、DB connection 設定、preview/dry-run/validate/diff，最後用 Draft -> Validate -> Apply 流程產生 `entitlements.generated.toml`。

第一版是本機 operator 工具，不做 control-plane 遠端 admin API。服務只綁 `127.0.0.1`，啟動時產生一次性 bootstrap code，瀏覽器只在 URL fragment 使用 `/#code=...` 完成一次性交換；server 不接受 query token，也不記錄 code。交換成功後只用 HttpOnly、SameSite=Strict cookie 操作 API。Production 的 admin gate group 必須來自 canonical auth/deployment config，預設固定為 `admin`：Apply 前必須用啟動時鎖定的 operator identity，在 apply 前已持久化的 baseline catalog 中解析確認屬於該 canonical admin group。

## Implementation Phases

每個階段完成後都要執行階段性 Review，優先修復 P0/P1/P2 問題，補上可防回歸的測試，並整理 Review Notes / 防回歸清單。下一階段開始前必須回顧前一階段 Review Notes，確認同類問題沒有重複出現。若階段內有行為、設定、API、測試方式或操作流程變更，必須同步更新文件；若沒有文件影響，Review 時要明確記錄本階段不需文件更新。

### Phase 0 - Source split, ignored local artifacts, and safety baseline

- 建立 catalog source 與 generated runtime 的分離模式：`entitlements.catalog.toml` 是 source of truth，`entitlements.generated.toml` 是產物。
- 將真實 catalog、generated runtime、DB local snippet、transaction artifact、backup/temp file、operator token/JWT pattern 納入 `.gitignore`。
- 確認 sample/config 文件只包含 sanitized 範例，不含真實 account、business scope、secret、token 或本機設定。
- 完成條件：
  - 產物與本機 secret 類檔案不會被一般 `git add` 納入。
  - public push 前的 leak scan 沒有發現真實敏感資訊或 business scope 字串。
  - 文件說明 source/generated/local snippet 的差異。

### Phase 1 - UI command, embedded static assets, and read-only state

- 新增 `canopy-entitlements ui` subcommand 與本機 `axum` server。
- 靜態 HTML/CSS/JS 以 compile-time include 內嵌進 binary，不依賴執行時工作目錄外部 asset。
- `GET /api/state` 提供 sanitized state：catalog、runtime path、import source、db config summary、draft overview、validation summary。
- 完成條件：
  - release/dev binary 在沒有外部 asset 檔案時仍可 render UI。
  - read API 未授權時不洩漏 catalog content；授權後不回傳 raw secret value。
  - Overview、Groups、Packages、Scopes、Accounts/Roles、DB Connections、Review & Apply 都有 nonblank 初始畫面。

### Phase 2 - Import, preview, explain, dry-run, and validation plumbing

- 支援 `--import-runtime` 將現有 runtime 保真匯入 catalog draft。
- `POST /api/preview`、`POST /api/explain`、`POST /api/dry-run`、`POST /api/validate` 復用現有 catalog logic。
- validate 使用暫存 runtime，不修改正式 catalog/runtime/db config。
- 完成條件：
  - import -> generate 後語意等價，role ARN/account/template 不跨 rule 錯合併。
  - preview/explain/dry-run API 回傳 structured JSON，錯誤可定位到來源 id。
  - validation 覆蓋 catalog validation、runtime drift、DB scope connection reference 與 deployment source cross-check。

### Phase 3 - Catalog editing workflows

- 完成 Groups、Packages、Scopes、Accounts/Roles 的 draft 編輯 API 與 UI。
- Groups matrix 可快速新增/移除 group -> package binding。
- Packages 可管理既有 feature toggles，Scopes 可管理 account、region、selectors、database scopes、MCP EC2 scopes。
- 完成條件：
  - invalid payload、duplicate id、dangling reference 都回 structured error。
  - 所有 high-risk feature 與 guardrail weakening 都會被 validation/diff 標示。
  - 編輯流程不會讓 UI state 與 server draft state 分歧。

### Phase 4 - DB connection snippet editor

- 完成 `[database_connections.*]` metadata 的 draft 編輯與 deterministic TOML 輸出。
- 強制 `readonly=true`，production 預設 `require_tls=true`，拒絕 username/password/inline secret。
- 與 deployment config/tfvars 中的 canonical DB connection source 交叉檢查。
- 完成條件：
  - DB connection round-trip 不遺失欄位，輸出排序 deterministic。
  - unsafe TLS、inline secret、missing secret ARN、connection reference drift 都是 blocking validation。
  - UI 不提供 password/username 欄位，也不顯示 secret value。

### Phase 5 - Local session, write API protection, and production identity gates

- 完成 bootstrap fragment exchange、HttpOnly SameSite=Strict cookie、Origin/Host 檢查與安全 headers。
- Production `verified-jwt` 必須從受保護 auth config 讀取 trust root；`os-allowlist` 必須從受保護 auth config 讀取 OS user allowlist。
- `dev-claims` 只允許本機 preview/dry-run，不可讓真實 apply 通過。
- 完成條件：
  - bootstrap code 具備高 entropy、短 TTL、single-use，且不進入 query、storage、log 或 browser history。
  - auth config 與 operator JWT path 皆通過 owner/mode/repo/symlink 檢查。
  - apply 前重新確認 verified JWT freshness 或 OS allowlist freshness；失效或被移除時 fail closed。

### Phase 6 - Review & Apply transaction protocol

- `POST /api/apply` 只在 validation clean、operator 屬於 canonical admin group、baseline catalog authorization 通過時執行。
- 多檔寫入 catalog、runtime、db config 時使用 lock、baseline digest compare-and-swap、same-dir temp file、0600 permission、fsync、backup manifest、固定 rename order 與 recovery。
- 任何 late failure 必須 restore backup；restore 失敗時回報 recovery manifest path。
- 完成條件：
  - apply 成功後 catalog、generated runtime、db config 三者一致，且產生 `.bak`/manifest。
  - lock contention、baseline digest mismatch、temp write failure、backup/rename failure、incomplete transaction recovery 都有 regression test。
  - draft 內 self-grant admin membership 或 group mapping 不會影響當次 apply gate。

### Phase 7 - Browser smoke, e2e, and UX hardening

- 使用 browser smoke 覆蓋主要頁面、RD database 權限新增流程、Review diff、validation、apply 成功與失敗狀態。
- 驗證窄 viewport 下表格、表單、錯誤訊息與按鈕文字不重疊。
- 補齊 end-to-end tests：新增 RD database scope/package/binding、validate、apply、preview/explain/dry-run 驗證。
- 完成條件：
  - Desktop 與 mobile-sized viewport 都可完成核心流程。
  - UI 不顯示 secret value，錯誤與 high-risk change 可掃描且不遮住操作。
  - release binary smoke test 通過，確認 embedded asset 行為。

### Phase 8 - Final review, leak scan, and merge readiness

- 依需求文件逐項做總 Review：功能、資料流、UI/UX、DB config、auth gate、transaction、測試、文件與先前 Review Notes。
- 執行 regression/safety test plan 與 public repo leak scan。
- 確認提交範圍只包含本階段應提交的檔案，不包含真實 catalog/runtime/db snippet/token/backup。
- 完成條件：
  - 沒有 P0/P1/P2 問題或未補 regression test 的可測試缺陷。
  - 測試、文件、計畫書與實際行為一致。
  - branch 具備可追溯 commit history，且可安全 merge/push public repo。

## Key Changes

### `canopy-entitlements ui` subcommand

- 在 `canopy-entitlements` 新增 `ui` subcommand。
- 支援 flags：
  - `--catalog entitlements.catalog.toml`
  - `--runtime entitlements.generated.toml`
  - `--import-runtime entitlements.toml`
  - `--deployment-mode config|terraform`
  - `--tfvars infra/terraform.tfvars`
  - `--deployment-config config.toml`
  - `--auth-config /etc/canopy/entitlements-ui-auth.toml`
  - `--db-config database_connections.local.toml`
  - `--dev-admin-group admin`
  - `--identity-source verified-jwt|os-allowlist|dev-claims`
  - `--operator-jwt <path>`
  - `--allow-dev-identity`
  - `--dev-operator-sub <sub>`
  - `--dev-operator-email <email>`
  - `--dev-operator-email-verified`
  - repeatable `--dev-operator-external-group <group>`
  - `--bind 127.0.0.1:0`
- 使用 `axum` 提供本機 HTTP API。
- 靜態 HTML/CSS/JS 放在 `apps/entitlements-cli/assets/ui/{index.html,app.css,app.js}`，由 Rust module 用 `include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/ui/index.html"))` 這類 compile-time include 內嵌，避免新增 Node build pipeline，也避免 release binary 依賴工作目錄外部 asset。
- `database_connections.local.toml`、apply backup、transaction manifest、temp file 必須加入 `.gitignore`；真實 secret 仍只放 Secrets Manager，UI 只保存 `secret_arn`。
- UI server 啟動時固定 operator session identity；write API 不接受 client 自報 identity。正式 apply 只能使用 verified identity：`verified-jwt` 必須驗 issuer/audience/signature/email_verified/exp/nbf/iat、clock skew、最大 session age，且 apply 前必須重新確認 authorization freshness；`os-allowlist` 只能映射本機 OS user 到預先持久化 admin allowlist，且 apply 前必須重讀 canonical allowlist；`dev-claims` 只允許搭配 `--allow-dev-identity` 啟動，並且預設禁止 apply 真實 catalog/runtime。
- Production trust root 不可由啟動 CLI flag 任意指定，也不可由 UI draft 修改。OIDC issuer/audience/JWKS 與 OS admin allowlist 必須來自受保護 canonical auth config，例如 `/etc/canopy/entitlements-ui-auth.toml` 或 control-plane deployment config；檔案必須通過 owner/mode 檢查、不可位於 repo working tree、不可 group/world writable。`--operator-jwt` 只提供 operator token，不提供信任根。
- 第一版 `--auth-config` 至少支援 `admin_group = "admin"` 與 `[os_allowlist] users = ["<os-user>"]`；apply-time 必須重讀並重新檢查檔案安全與 allowlist 內容。
- Production admin gate group 不可由啟動 CLI flag 任意指定，也不可由 UI draft 修改；必須來自同一份受保護 canonical auth/deployment config，缺省值硬性固定為 `admin`。`--dev-admin-group` 只允許搭配 `--allow-dev-identity` 做本機 preview/dry-run，不得讓真實 catalog/runtime apply。
- `--operator-jwt` token 檔案本身也必須通過 owner/mode 檢查、不可位於 repo working tree、不可 group/world writable、不可 symlink 到 repo working tree；token 檔名 pattern 必須被 `.gitignore` 覆蓋。未來可改支援 stdin/keychain，第一版若使用檔案路徑必須 fail closed。
- Production deployment source 必須由 `--deployment-mode` 選定 canonical path：config mode 只接受 canonical `config.toml`，terraform mode 只接受實際部署使用的 `infra/terraform.tfvars`/plan input。Review & Apply 必須顯示 deployment mode、canonical path、sha256 digest；apply audit 與 transaction manifest 必須記錄 digest，不接受任意替代檔讓 validate/apply clean。
- HTTP 安全 headers 必須包含 CSP `default-src 'self'`、`Referrer-Policy: no-referrer`；所有 write API 必須驗 `Origin` / `Host` 為本機允許值。

### Web UI

- UI 設計為密集、可掃描的 ops console。
- 左側 nav：
  - Overview
  - Groups
  - Packages
  - Scopes
  - Accounts/Roles
  - DB Connections
  - Review & Apply
- Groups 頁顯示 group -> packages matrix，可快速新增 binding、移除 binding、檢查高風險 feature。
- Packages 頁用 feature toggles 管理 `ec2:view`、`mcp:database`、`mcp:ec2`、`ecs:exec` 等既有 catalog feature。
- Scopes 頁支援 account、region、log group、ECS、tag selectors、database scopes、MCP EC2 scopes。
- DB Connections 頁編輯 `[database_connections.*]` metadata，強制 `readonly=true`、production 預設 `require_tls=true`、不接受 username/password。
- Review & Apply 頁顯示 semantic diff、validation result、generated runtime path、DB connection reference warnings。
- Semantic diff 必須比現有 `semantic_grants()` 更細，不能只比較 feature 與 scope id。對 DB scope 要比較 connection、environment、schema、table、action、max_rows、max_examined_rows、allow_full_table_scan、allow_views；對 MCP EC2 scope 要比較 log path、journal unit、http/tcp/dns target、private target ref、quota/budget、unsafe output、path allow/deny policy、denylist、private-target enforcement、output redaction policy。任何同 id scope 的權限擴大或 guardrail weakening 都要顯示為 high-risk change。

### 本機 API

- `GET /api/state`
  - 讀取 catalog、db config、目前 draft、validation 狀態、generated runtime path、import runtime source path。
- `POST /api/session/exchange`
  - body 接收 fragment 取出的 bootstrap code，不接受 query string。
  - bootstrap code 必須 cryptographically random，至少 128-bit entropy，TTL 上限 30 秒，single-use；交換成功或失敗都立即失效。
  - `index.html` 的第一段必須是極小 inline bootstrap prelude，只負責 parse hash、同步 `history.replaceState(null, "", location.pathname)` 清除 fragment、把 code 暫存在記憶體變數，且必須先於任何外部 CSS/JS/app initialization 執行。CSP 只能用 hash/nonce 精準允許這段 prelude。
  - 前端讀取 fragment 後，必須在送出 exchange request 前完成同步清除；code 只短暫留在記憶體變數。
  - code/session 不得寫入 localStorage/sessionStorage；交換成功後只用 HttpOnly、SameSite=Strict cookie。
- `POST /api/import-runtime`
  - 把 `--import-runtime` 指定的現有 `entitlements.toml` 匯入成 catalog draft。
  - `--import-runtime`、`--catalog`、`--runtime` 三者不得是同一路徑；`--runtime` 永遠是 generated output，不可兼作 import source。
  - 以 runtime rule 為來源，但必須保真轉換；不可 best-effort。
  - importer 必須以 role ARN 等價類拆分 package/binding，避免同一 runtime rule 中多個 allowed account 使用不同 role 時被套錯 role。
  - account 以 `account_id + account_name` 去重；role 以 role ARN template 去重。若 role ARN 含同一 account id，轉成 `{account_id}` template；無法安全 template 化時保留 concrete ARN 並拆成獨立 role。
  - stable id 以 runtime rule id 優先；collision 使用 deterministic suffix；所有無法保真或會造成 duplicate output id 的情況都 fail closed，並回報來源 rule id/group。
  - 保留 rule-local features、accounts、regions、selectors、database scopes、MCP EC2 scopes、memberships、group mappings。
- `PUT /api/draft/*`
  - 更新 draft 中的 accounts、roles、scopes、packages、bindings、group mappings、memberships、db connections。
- `POST /api/preview`
  - 復用現有 catalog preview logic，回 JSON 給 UI。
- `POST /api/explain`
  - 復用現有 catalog explain logic，回 JSON 給 UI。
- `POST /api/dry-run`
  - 復用現有 catalog dry-run logic，回 JSON 給 UI。
  - 新增 `mcp-database` dry-run operation；參數包含 `scope`、`connection`、`environment`、`schema`、`table`、`action`。
  - `mcp-database` dry-run 只做 entitlement/static scope allow-deny，不連真 DB，不讀 Secrets Manager。
  - 驗證同一條 generated rule 同時具備 `mcp:use`、`mcp:database` 與 matching database scope。
- `POST /api/validate`
  - 產生暫存 runtime。
  - 檢查 catalog validation、runtime drift、deployment config/tfvars consistency、DB scope connection 是否存在。
  - `database_connections.local.toml` 是本機 DB connection snippet，不會被 control-plane 自動載入。
  - Production validate/apply 必須指定 `--deployment-mode config|terraform`，並使用對應 canonical deployment source：`--deployment-config config.toml` 或 `--tfvars infra/terraform.tfvars`。只靠 `--db-config` local snippet 只能做 draft preview，不能讓 production validate/apply clean。
  - Deployment source 必須通過 canonical path 與 sha256 digest 計算；Review & Apply 顯示 mode/path/digest，apply audit 與 transaction manifest 記錄同一 digest。非 canonical path、repo 內替代 auth config、或與實際部署 plan input 不一致時，一律 blocking error。
  - Validate 必須檢查：所有 catalog DB scope connection 都存在於 `--db-config`；deployment source 若是 `--deployment-config`，同名 connection 必須存在於 `[database_connections.*]`；deployment source 若是 `--tfvars`，同名 connection 必須存在於 `database_connections_toml`。任一 deployment source 不可讀、缺少 connection、或同名 connection metadata 不一致，都回 blocking warning/error，避免 UI 通過但部署後不可用。
  - 不修改正式 catalog/runtime/db config。
- `POST /api/apply`
  - 只有 validation clean 且 operator identity resolves to canonical admin group（預設 `admin`）時才可執行。
  - admin gate 只能使用 canonical auth/deployment config 內的 admin group，以及啟動時固定且 verified 的 operator identity；對 apply 前已持久化的 baseline catalog 解析。draft 內新增或修改的 admin membership/group mapping 不能影響當次 apply。CLI dev claims 與 `--dev-admin-group` 不可讓正式 apply 通過。
  - `verified-jwt` 在 apply 前必須重新驗證 authorization freshness：`exp` 未過期、`nbf` 已生效、`iat` 在允許 clock skew 與最大 session age 內，並且必須用 IdP introspection/userinfo/group refresh 或 apply-time fresh token 確認 admin group 仍有效；過期、not-yet-valid、idle 超過最大 session age、token revoked、或 group removed 都拒絕 apply。
  - `os-allowlist` 在 apply 前必須重讀 canonical allowlist、重算 digest/mtime、重新確認 OS user 仍在 allowlist；allowlist 移除或 digest 與啟動時紀錄不一致時，必須拒絕 apply 並要求 operator 重新驗證。
  - 多檔寫入使用 transaction protocol：建立 lock file、baseline digest compare-and-swap、同目錄 temp file、0600 權限、fsync file+dir、timestamped backup manifest、固定 rename order、啟動時 incomplete transaction recovery。artifact 命名固定為 `.canopy-entitlements-transaction-*`、`*.tmp`、`*.bak` 或 `*.bak.*`，並由 `.gitignore` 覆蓋。
  - 任何 late failure 必須用 backup restore；restore 失敗時回報明確 recovery manifest path。

### DB connection snippet 契約

- `database_connections.local.toml` 採用 control-plane `config.toml` 相同的 `[database_connections.<name>]` schema。
- 這份檔案只是本機 snippet 與 validation input，不是 control-plane runtime source。
- 部署時 operator 仍需把同一份 connection snippet 放入 `config.toml` 或 Terraform `database_connections_toml`。
- Production validate/apply 會用 `--deployment-mode` 對應的 canonical `--deployment-config` 或 `--tfvars` 當實際 deploy source 交叉檢查；沒有 canonical deployment source 時，UI 只能做本機 draft/edit/preview。
- UI 可提供 copy/export，但第一版不自動修改 Terraform tfvars。
- Snippet 禁止 username、password、inline secret；只允許 `secret_arn`。
- Production 安全預設：`readonly=true`、`require_tls=true`、`accept_invalid_tls_certs=false`、`skip_tls_hostname_verification=false`。

## Test Plan

### Catalog model / import unit tests

- 從 runtime `entitlements.toml` 匯入 catalog 後，再 generate runtime；驗證 features、accounts、regions、selectors、ECS scopes、database scopes、MCP EC2 scopes、memberships、group mappings 語意等價。
- 匯入多個同 group rule 時，產生穩定且不衝突的 scope/package/binding id。
- 匯入含同 account 多 role、同 role template、Organization placeholder、tag allow/deny selector 的 runtime，確認不跨 rule 合併。
- 匯入含一條 runtime rule、多個 allowed accounts、各自不同 role_arn 時，必須拆分 role ARN 等價類，generate 後 allowed account/role 語意完全保真。
- 匯入後 generate 的 runtime 必須做 exact semantic equality，比對 allowed_accounts.account_id/account_name/role_arn、features、scope fields、group wiring。
- 匯入 malformed runtime、duplicate output id、unknown feature、missing account/role/scope/package reference 時，錯誤訊息可定位到來源項目。

### Catalog editing / validation unit tests

- package feature mapping 覆蓋全部 feature：
  - EC2
  - CloudWatch
  - SSM
  - power actions
  - MCP CloudWatch
  - MCP raw audit
  - MCP database
  - MCP EC2
  - ECS view/exec
- DB scope 指向不存在的 DB connection 時 validation 失敗。
- DB scope identifier 必須 lowercase ASCII；mixed-case schema/table 被拒絕。
- `allow_views=false` 為預設；設為 true 時 preview/diff 必須標示高風險。
- 同一 DB scope id 下擴大 allowed_tables、allowed_actions、max_rows、max_examined_rows、allow_full_table_scan 或 allow_views 時，semantic diff 必須顯示新增/擴權與 high-risk。
- 同一 MCP EC2 scope id 下擴大 log path、HTTP/TCP/DNS target、private target 或 quota budget 時，semantic diff 必須顯示新增/擴權與 high-risk。
- 同一 MCP EC2 scope id 下弱化 unsafe output、path allow/deny policy、denylist、private-target enforcement 或 output redaction policy 時，semantic diff 必須顯示 guardrail weakening 與 high-risk。
- MCP EC2 diagnostic scope 測試涵蓋：
  - empty scope
  - unsafe output
  - blanket `/var/log/**`
  - denylist path
  - private IP 無 `private_target_ref`
  - undefined `private_target_ref`
- high-risk feature list 必須包含：
  - `mcp:database`
  - `mcp:ec2`
  - `ecs:exec`
  - power actions
  - raw audit plaintext

### DB connection config tests

- 接受合法 MySQL connection metadata：
  - engine
  - host
  - port
  - database
  - secret_arn
  - timeouts
  - max_connections
  - TLS flags
- 拒絕 username/password、inline secret、空 `secret_arn`、`readonly=false`。
- 拒絕 production `require_tls=false`、`accept_invalid_tls_certs=true`、`skip_tls_hostname_verification=true`。
- `database_connections.local.toml` round-trip 不遺失欄位，輸出保持 deterministic ordering。
- DB connection name 與 `scopes.database_scopes[].connection` cross-reference 必須一致。
- `database_connections.local.toml` 與 Terraform `database_connections_toml` 同名 connection 不一致時，validate 必須提示 deploy/runtime drift。
- 缺少 `--deployment-config` 與 `--tfvars` 時，production validate/apply 不可 clean；只允許 local draft preview。
- 指定非 canonical deployment source、digest 與實際 deploy input 不一致、或 Review & Apply 顯示的 digest 與 apply audit digest 不一致時，validate/apply 必須失敗。
- `database_connections.local.toml` 與 `config.toml` 的 `[database_connections.*]` 同名 connection 不一致時，validate 必須提示 deploy/runtime drift。

### Auth config tests

- production `verified-jwt` 必須從 canonical auth config 讀取 issuer/audience/JWKS；CLI 不接受 issuer/audience/JWKS trust root flags。
- production admin gate group 必須從 canonical auth/deployment config 讀取，缺省固定為 `admin`；CLI 不接受 production admin group override。
- identity 屬於 RD 但不屬於 canonical admin group 時，即使用 `--dev-admin-group RD` 啟動，也不得 apply 真實 catalog/runtime。
- canonical auth config 與 OS allowlist 必須拒絕 group/world writable、非預期 owner、位於 repo working tree、symlink 到 repo working tree。
- forged JWT 搭配自製 JWKS、自製 issuer、自製 OS allowlist path 都不得讓 production apply 通過。
- `--operator-jwt` 只能提供 token；token 的 trust root 必須來自 canonical auth config。token 檔案必須拒絕 group/world writable、非預期 owner、位於 repo working tree、symlink 到 repo working tree。
- `verified-jwt` 必須驗 `exp`、`nbf`、`iat`、clock skew、最大 session age，並在 apply 前用 IdP introspection/userinfo/group refresh 或 apply-time fresh token 確認 admin group 仍有效；expired token、not-yet-valid token、revoked token、group removed、長時間 idle 後 apply 都必須失敗。
- `os-allowlist` apply 前必須重讀 canonical allowlist；移除 OS user、allowlist digest/mtime 改變、或 owner/mode 變不安全時都必須失敗。
- `dev-claims` 搭配 `--allow-dev-identity` 可用於本機 preview/dry-run，但不得 apply 真實 catalog/runtime。

### Local API tests

- 所有 write API 無 token、錯 token、過期 token 都拒絕。
- bootstrap code 只能透過 URL fragment 使用一次；server 不接受 query token；code 至少 128-bit entropy、TTL 上限 30 秒、single-use，交換成功或失敗都失效，交換後只設 HttpOnly SameSite=Strict cookie。
- bootstrap TTL 測試必須覆蓋 30 秒邊界、過期後 exchange 失敗、失敗後 single-use code 立即失效。
- `index.html` 第一段 inline/hash-pinned bootstrap prelude 必須在任何外部 CSS/JS/app initialization 前同步清除 fragment；app.js 404、JS parse error、CSP 阻擋、exchange endpoint 延遲、失敗、前端 crash 模擬時，browser history/address bar 都不得保留 code。
- 前端讀取 bootstrap code 後、送出 exchange request 前必須同步清除 fragment，不得把 code/session 寫入 localStorage/sessionStorage，browser history/address bar 不得保留 code。
- write API 必須拒絕不合法 Origin/Host。
- read API 不得洩漏 catalog content 給未授權請求。
- `GET /api/state` 回傳 sanitized state，不包含 password、secret value、raw backup file content。
- `PUT /api/draft/*` 對 invalid payload、unknown id、duplicate id、dangling reference 都回 structured error。
- `POST /api/validate` 使用 temp runtime，不修改正式 catalog/runtime/db config。
- `POST /api/apply` 在 validation 未通過、non-admin identity、audit/write failure、runtime generate failure 時不改寫任何正式檔。
- `POST /api/apply` 的 admin gate 必須使用 baseline catalog；draft 內 self-grant admin membership/group mapping 不得讓本次 apply 通過。
- `POST /api/apply` 的 admin gate 必須拒絕 self-asserted dev claims；只有 verified JWT 或 OS allowlist identity 可套用真實 catalog/runtime。
- apply transaction 測試覆蓋 lock contention、baseline digest mismatch、temp write failure、backup failure、每個 rename/write failure injection，以及 incomplete transaction recovery。
- apply 成功時同時產生 `.bak`，且正式 catalog、db config、generated runtime 三者一致。

### UI component / browser smoke tests

- Overview、Groups、Packages、Scopes、Accounts/Roles、DB Connections、Review & Apply 都能 render nonblank。
- release binary smoke test：在不依賴工作目錄 asset file 的情況下啟動 UI，確認內嵌 HTML/CSS/JS route 都 render nonblank。
- Groups matrix 可新增 RD -> database package binding，切換 package 後 Review 顯示 semantic diff。
- DB Connections form 不允許輸入 password/username 欄位，unsafe TLS 會在 UI 顯示 blocking validation。
- Review & Apply 頁顯示高風險變更、admin gate、validate 結果、runtime path，不顯示 secret value。
- 窄 viewport 下表格可水平/垂直掃描，按鈕文字不重疊，錯誤訊息不遮住主要表單。

### End-to-end tests

- 啟動 `canopy-entitlements ui` 到 random localhost port，建立 draft，新增 RD database scope/package/binding，validate，apply。
- 以 `--import-runtime entitlements.toml` 匯入，確認 `--runtime` 只作為 generated output，且 import/runtime/catalog 路徑重複時會拒絕啟動。
- Apply 後用現有 `canopy-entitlements preview --group RD --format json` 驗證 RD 有 `mcp:database` 與對應 DB scope。
- Apply 後用 `generate` 重新產出 runtime，確認與 UI 產物 byte-for-byte 一致。
- 用 `explain` 驗證 Cognito external group mapping 到 RD 後可看到 database scope。
- 用 `dry-run` 驗證 RD 對允許的 DB scope 通過，對未授權 connection/schema/table 失敗。
- 用 `dry-run --operation mcp-database` 驗證 RD 對允許的 DB scope 通過，對未授權 connection/schema/table/action 失敗。

### Regression / safety tests

- `cargo test -p canopy-entitlements`
- `cargo test -p entitlements`
- `cargo test -p shared`
- `cargo test -p control-plane mcp_database`
- `bash scripts/test-validate-entitlements.sh`
- `cargo run -p canopy-entitlements -- generate --catalog entitlements.catalog.sample.toml --output <tmp>`
- `cargo run -p canopy-entitlements -- dry-run --operation mcp-database --catalog <tmp-catalog> --sub <sub> --connection <conn> --schema <schema> --table <table> --action select --format json`
- `CANOPY_VALIDATE_ENTITLEMENTS_SCRIPT=./scripts/validate-entitlements.sh cargo run -p canopy-entitlements -- validate --catalog entitlements.catalog.sample.toml --runtime-file <tmp> --tfvars infra/terraform.tfvars.example`
- Leak scan：
  - 確認 `entitlements.catalog.toml`、`entitlements.generated.toml`、`database_connections.local.toml` 都被 ignore。
  - 確認 `*.bak`、`*.bak.*`、`*.tmp`、`.canopy-entitlements-transaction-*` 都被 ignore。
  - 確認 `*.jwt`、`*.token`、`operator*.jwt`、`operator*.token` 都被 ignore。
  - 掃描 public repo 不含真實 account、business scope、secret pattern。

## Assumptions

- 第一版是本機管理工具，不提供遠端多人協作。
- 第一版不提供 control-plane hot reload。
- UI 管理 catalog 與 DB connection snippet。
- UI 不管理 Terraform ALB、IAM role 建立、Secrets Manager secret 寫入。
- `admin` group 是 apply gate 的 catalog identity check。
- 若未來要強授權，下一版應改成 control-plane 內建 Web Admin + JWT/MFA/audit。
- 真實 `entitlements.catalog.toml`、`entitlements.generated.toml`、`database_connections.local.toml` 都不得 commit。
- Repo 只 commit sanitized sample。
