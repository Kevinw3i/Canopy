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
