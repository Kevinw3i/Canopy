#!/bin/bash
# ============================================================
# 打包 Canopy TUI 分發資料夾
#
# 用法：
#   scripts/package.sh
#   scripts/package.sh https://canopy.internal
#
# 會產生 dist/ 資料夾，包含：
#   tui-client    — 二進位檔
#   config.toml   — 客戶端設定（URL 已寫入）
#   install.sh    — 維運人員的一鍵安裝腳本
#   Canopy.command — macOS 雙擊啟動腳本
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$PROJECT_DIR/dist"
BINARY="$PROJECT_DIR/target/release/tui-client"

# ── 1. 確認二進位檔存在 ──────────────────────────────

if [ ! -f "$BINARY" ]; then
    echo "ERROR: $BINARY 不存在"
    echo ""
    echo "請先編譯："
    echo "  cargo build --release -p tui-client"
    exit 1
fi

echo "Binary: $BINARY ($(du -h "$BINARY" | awk '{print $1}'))"

# ── 2. 取得 Control Plane URL ────────────────────────

CONTROL_PLANE_URL="${1:-}"

if [ -z "$CONTROL_PLANE_URL" ]; then
    echo ""
    read -p "Control Plane URL (例: https://canopy.internal): " CONTROL_PLANE_URL
fi

if [ -z "$CONTROL_PLANE_URL" ]; then
    echo "ERROR: Control Plane URL 不能為空"
    exit 1
fi

# 移除尾端斜線
CONTROL_PLANE_URL="${CONTROL_PLANE_URL%/}"

case "$CONTROL_PLANE_URL" in
    http://*|https://*) ;;
    *)
        echo "ERROR: Control Plane URL 必須以 http:// 或 https:// 開頭"
        exit 1
        ;;
esac

if [[ "$CONTROL_PLANE_URL" == *\"* || "$CONTROL_PLANE_URL" == *$'\n'* || "$CONTROL_PLANE_URL" == *$'\r'* ]]; then
    echo "ERROR: Control Plane URL 不可包含引號或換行"
    exit 1
fi

echo "URL:    $CONTROL_PLANE_URL"

# ── 3. 建立 dist 資料夾 ─────────────────────────────

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

cp "$BINARY" "$DIST_DIR/tui-client"

# ── 4. 產生設定範本（URL 已寫入）─────────────────────

cat > "$DIST_DIR/config.toml" << EOF
control_plane_url = "$CONTROL_PLANE_URL"
dev_mode = false
refresh_interval_secs = 30
live_tail_scrollback = 10000
pkce_callback_port = 9876
enable_live_tail = false
auto_update = true
# change_password_url = "https://<cognito-domain>/forgotPassword?client_id=<app-client-id>&response_type=code&scope=openid+profile+email&redirect_uri=http://localhost:9876/callback"

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
EOF

# ── 5. 產生 macOS 雙擊啟動腳本 ───────────────────────

cat > "$DIST_DIR/Canopy.command" << 'LAUNCHER'
#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALLED_CANOPY="${HOME}/.local/bin/canopy"
LOCAL_CANOPY="${SCRIPT_DIR}/tui-client"
LOCAL_CONFIG="${SCRIPT_DIR}/config.toml"
CONFIG_DIR="${HOME}/Library/Application Support/canopy"
CONFIG_DST="${CONFIG_DIR}/config.toml"

show_launcher_error() {
    local message="Canopy executable not found.\n\nRun install.sh first, or keep Canopy.command next to tui-client."
    if command -v osascript >/dev/null 2>&1; then
        osascript -e 'display dialog "Canopy executable not found.\n\nRun install.sh first, or keep Canopy.command next to tui-client." buttons {"OK"} with icon caution' >/dev/null || true
    else
        printf "%b\n" "$message"
        echo ""
        read -r -p "Press Enter to close..."
    fi
    exit 1
}

if [ -f "$LOCAL_CONFIG" ] && [ ! -f "$CONFIG_DST" ]; then
    mkdir -p "$CONFIG_DIR"
    cp "$LOCAL_CONFIG" "$CONFIG_DST"
fi

if [ -x "$INSTALLED_CANOPY" ]; then
    exec "$INSTALLED_CANOPY"
fi

if [ -f "$LOCAL_CANOPY" ]; then
    chmod +x "$LOCAL_CANOPY" 2>/dev/null || true
    xattr -dr com.apple.quarantine "$LOCAL_CANOPY" 2>/dev/null || true
    exec "$LOCAL_CANOPY"
fi

show_launcher_error
LAUNCHER

chmod +x "$DIST_DIR/Canopy.command"

# ── 6. 產生安裝腳本 ─────────────────────────────────

cat > "$DIST_DIR/install.sh" << 'INSTALLER'
#!/bin/bash
# ============================================================
# Canopy TUI — 安裝腳本
# 維運人員執行這一個腳本就夠了
# ============================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}[OK]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[!!]${NC} $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; }

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_SRC="$INSTALL_DIR/tui-client"
BIN_DIR="${CANOPY_BIN_DIR:-$HOME/.local/bin}"
BIN_DST="$BIN_DIR/canopy"
RUN_CMD="canopy"
CONFIG_SRC="$INSTALL_DIR/config.toml"

resolve_config_dir() {
    case "$(uname -s)" in
        Darwin)
            printf '%s\n' "$HOME/Library/Application Support/canopy"
            ;;
        Linux)
            printf '%s\n' "${XDG_CONFIG_HOME:-$HOME/.config}/canopy"
            ;;
        CYGWIN*|MINGW*|MSYS*)
            if [ -n "${APPDATA:-}" ]; then
                printf '%s\n' "$APPDATA/canopy"
            else
                printf '%s\n' "$HOME/AppData/Roaming/canopy"
            fi
            ;;
        *)
            printf '%s\n' "${XDG_CONFIG_HOME:-$HOME/.config}/canopy"
            ;;
    esac
}

# ── 安全工具函式 ────────────────────────────────────────
AWS_DEVELOPER_ID_INSTALLER_TEAM_ID="94KV3E626L"
AWS_CLI_PGP_FINGERPRINT="FB5DB77FD5C118B80511ADA8A6310ACC4672475C"

download_file() {
    local url="$1"
    local dest="$2"

    curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL "$url" -o "$dest" || {
        fail "下載失敗: $url"
        rm -f "$dest"
        return 1
    }
}

verify_macos_pkg_signature() {
    local pkg="$1"
    local label="$2"
    local signature_output

    signature_output="$(pkgutil --check-signature "$pkg" 2>&1)" || {
        fail "$label 簽章驗證失敗"
        printf '%s\n' "$signature_output"
        rm -f "$pkg"
        return 1
    }

    if ! printf '%s\n' "$signature_output" | grep -q "Developer ID Installer" \
        || ! printf '%s\n' "$signature_output" | grep -q "$AWS_DEVELOPER_ID_INSTALLER_TEAM_ID"; then
        fail "$label 不是預期的 AWS installer 簽章 Team ID: $AWS_DEVELOPER_ID_INSTALLER_TEAM_ID"
        printf '%s\n' "$signature_output"
        rm -f "$pkg"
        return 1
    fi
}

write_aws_cli_pgp_key() {
    local key_file="$1"
    cat > "$key_file" << 'AWS_CLI_PGP_KEY'
-----BEGIN PGP PUBLIC KEY BLOCK-----
mQINBF2Cr7UBEADJZHcgusOJl7ENSyumXh85z0TRV0xJorM2B/JL0kHOyigQluUG
ZMLhENaG0bYatdrKP+3H91lvK050pXwnO/R7fB/FSTouki4ciIx5OuLlnJZIxSzx
PqGl0mkxImLNbGWoi6Lto0LYxqHN2iQtzlwTVmq9733zd3XfcXrZ3+LblHAgEt5G
TfNxEKJ8soPLyWmwDH6HWCnjZ/aIQRBTIQ05uVeEoYxSh6wOai7ss/KveoSNBbYz
gbdzoqI2Y8cgH2nbfgp3DSasaLZEdCSsIsK1u05CinE7k2qZ7KgKAUIcT/cR/grk
C6VwsnDU0OUCideXcQ8WeHutqvgZH1JgKDbznoIzeQHJD238GEu+eKhRHcz8/jeG
94zkcgJOz3KbZGYMiTh277Fvj9zzvZsbMBCedV1BTg3TqgvdX4bdkhf5cH+7NtWO
lrFj6UwAsGukBTAOxC0l/dnSmZhJ7Z1KmEWilro/gOrjtOxqRQutlIqG22TaqoPG
fYVN+en3Zwbt97kcgZDwqbuykNt64oZWc4XKCa3mprEGC3IbJTBFqglXmZ7l9ywG
EEUJYOlb2XrSuPWml39beWdKM8kzr1OjnlOm6+lpTRCBfo0wa9F8YZRhHPAkwKkX
XDeOGpWRj4ohOx0d2GWkyV5xyN14p2tQOCdOODmz80yUTgRpPVQUtOEhXQARAQAB
tCFBV1MgQ0xJIFRlYW0gPGF3cy1jbGlAYW1hem9uLmNvbT6JAlQEEwEIAD4CGwMF
CwkIBwIGFQoJCAsCBBYCAwECHgECF4AWIQT7Xbd/1cEYuAURraimMQrMRnJHXAUC
aGveYQUJDMpiLAAKCRCmMQrMRnJHXKBYD/9Ab0qQdGiO5hObchG8xh8Rpb4Mjyf6
0JrVo6m8GNjNj6BHkSc8fuTQJ/FaEhaQxj3pjZ3GXPrXjIIVChmICLlFuRXYzrXc
Pw0lniybypsZEVai5kO0tCNBCCFuMN9RsmmRG8mf7lC4FSTbUDmxG/QlYK+0IV/l
uJkzxWa+rySkdpm0JdqumjegNRgObdXHAQDWlubWQHWyZyIQ2B4U7AxqSpcdJp6I
S4Zds4wVLd1WE5pquYQ8vS2cNlDm4QNg8wTj58e3lKN47hXHMIb6CHxRnb947oJa
pg189LLPR5koh+EorNkA1wu5mAJtJvy5YMsppy2y/kIjp3lyY6AmPT1posgGk70Z
CmToEZ5rbd7ARExtlh76A0cabMDFlEHDIK8RNUOSRr7L64+KxOUegKBfQHb9dADY
qqiKqpCbKgvtWlds909Ms74JBgr2KwZCSY1HaOxnIr4CY43QRqAq5YHOay/mU+6w
hhmdF18vpyK0vfkvvGresWtSXbag7Hkt3XjaEw76BzxQH21EBDqU8WJVjHgU6ru+
DJTs+SxgJbaT3hb/vyjlw0lK+hFfhWKRwgOXH8vqducF95NRSUxtS4fpqxWVaw3Q
V2OWSjbne99A5EPEySzryFTKbMGwaTlAwMCwYevt4YT6eb7NmFhTx0Fis4TalUs+
j+c7Kg92pDx2uQ==
=OBAt
-----END PGP PUBLIC KEY BLOCK-----
AWS_CLI_PGP_KEY
}

verify_aws_cli_zip_signature() {
    local zip="$1"
    local sig="$2"
    local gpg_home
    local key_file
    local verify_output
    local compact

    if ! command -v gpg >/dev/null 2>&1; then
        fail "找不到 gpg，無法驗證 AWS CLI v2 Linux installer 簽章"
        return 1
    fi

    gpg_home="$(mktemp -d /tmp/canopy-gpg.XXXXXX)"
    key_file="$gpg_home/aws-cli-public-key.asc"
    chmod 700 "$gpg_home"
    write_aws_cli_pgp_key "$key_file"
    gpg --homedir "$gpg_home" --batch --import "$key_file" >/dev/null 2>&1 || {
        fail "匯入 AWS CLI PGP key 失敗"
        rm -rf "$gpg_home"
        return 1
    }

    verify_output="$(gpg --homedir "$gpg_home" --batch --status-fd 1 --verify "$sig" "$zip" 2>&1)" || {
        fail "AWS CLI v2 Linux installer 簽章驗證失敗"
        printf '%s\n' "$verify_output"
        rm -rf "$gpg_home"
        return 1
    }
    compact="$(printf '%s' "$verify_output" | tr -cd '[:xdigit:]' | tr '[:lower:]' '[:upper:]')"
    rm -rf "$gpg_home"

    case "$compact" in
        *"$AWS_CLI_PGP_FINGERPRINT"*) ;;
        *)
            fail "AWS CLI v2 Linux installer PGP fingerprint 不符: $AWS_CLI_PGP_FINGERPRINT"
            printf '%s\n' "$verify_output"
            return 1
            ;;
    esac
}

echo ""
echo "======================================"
echo "  Canopy TUI — 安裝"
echo "======================================"
echo ""

# ── 偵測環境 ─────────────────────────────────────────

OS="$(uname -s)"
ARCH="$(uname -m)"
CONFIG_DIR="$(resolve_config_dir)"
CONFIG_DST="$CONFIG_DIR/config.toml"
echo "系統: $OS $ARCH"
echo ""

# ── 1. 安裝二進位檔 ─────────────────────────────────

echo "[1/5] 安裝 canopy ..."

if [ ! -f "$BIN_SRC" ]; then
    fail "找不到 tui-client 二進位檔"
    fail "請確認 install.sh 和 tui-client 在同一個資料夾"
    exit 1
fi

mkdir -p "$BIN_DIR"
cp "$BIN_SRC" "$BIN_DST"
chmod +x "$BIN_DST"

# macOS: 移除 Gatekeeper 隔離標記
if [ "$OS" = "Darwin" ]; then
    xattr -dr com.apple.quarantine "$BIN_DST" "$INSTALL_DIR"/* 2>/dev/null || true
fi

ok "已安裝到 $BIN_DST"

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        RUN_CMD="$BIN_DST"
        warn "$BIN_DIR 不在 PATH；請加入 PATH，或直接執行 $BIN_DST"
        ;;
esac

# ── 2. 建立設定檔 ───────────────────────────────────

echo "[2/5] 建立設定檔 ..."

mkdir -p "$CONFIG_DIR"

if [ -f "$CONFIG_DST" ]; then
    warn "設定檔已存在，不覆寫: $CONFIG_DST"
else
    cp "$CONFIG_SRC" "$CONFIG_DST"
    ok "已建立 $CONFIG_DST"
fi

# ── 3. 安裝 AWS CLI v2 ─────────────────────────────

echo "[3/5] 檢查 AWS CLI v2 ..."

install_aws_cli() {
    echo "       正在安裝 AWS CLI v2 ..."
    case "$OS" in
        Darwin)
            if ! download_file "https://awscli.amazonaws.com/AWSCLIV2.pkg" "/tmp/AWSCLIV2.pkg" \
                || ! verify_macos_pkg_signature "/tmp/AWSCLIV2.pkg" "AWS CLI v2 installer"; then
                warn "AWS CLI 自動安裝已中止（完整性驗證失敗）"
                warn "請從 https://aws.amazon.com/cli/ 手動安裝"
                return 1
            fi
            sudo installer -pkg /tmp/AWSCLIV2.pkg -target / > /dev/null 2>&1
            rm -f /tmp/AWSCLIV2.pkg
            ;;
        Linux)
            case "$ARCH" in
                aarch64|arm64) CLI_URL="https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" ;;
                *)             CLI_URL="https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" ;;
            esac
            if ! download_file "$CLI_URL" "/tmp/awscliv2.zip" \
                || ! download_file "${CLI_URL}.sig" "/tmp/awscliv2.zip.sig" \
                || ! verify_aws_cli_zip_signature "/tmp/awscliv2.zip" "/tmp/awscliv2.zip.sig"; then
                rm -f /tmp/awscliv2.zip /tmp/awscliv2.zip.sig
                warn "AWS CLI 自動安裝已中止（完整性驗證失敗）"
                warn "請從 https://aws.amazon.com/cli/ 手動安裝"
                return 1
            fi
            unzip -q -o /tmp/awscliv2.zip -d /tmp/aws-install
            sudo /tmp/aws-install/aws/install --update > /dev/null 2>&1
            rm -rf /tmp/awscliv2.zip /tmp/awscliv2.zip.sig /tmp/aws-install
            ;;
        *)
            warn "不支援的作業系統，請手動安裝 AWS CLI v2"
            return 1
            ;;
    esac
}

if command -v aws &> /dev/null; then
    AWS_VER="$(aws --version 2>&1 | head -1)"
    if echo "$AWS_VER" | grep -q "aws-cli/2"; then
        ok "$AWS_VER"
    else
        warn "偵測到 AWS CLI v1: $AWS_VER"
        warn "部分功能需要 v2，正在升級 ..."
        install_aws_cli
        ok "$(aws --version 2>&1 | head -1)"
    fi
else
    install_aws_cli
    if command -v aws &> /dev/null; then
        ok "$(aws --version 2>&1 | head -1)"
    else
        warn "AWS CLI 安裝失敗，SSM/EIC/ECS Exec 連線功能將無法使用"
        warn "EC2/ECS 清查和 CloudWatch 搜尋不受影響"
    fi
fi

# ── 4. 安裝 Session Manager Plugin ─────────────────

echo "[4/5] 檢查 Session Manager Plugin ..."

install_ssm_plugin() {
    echo "       正在安裝 Session Manager Plugin ..."
    case "$OS" in
        Darwin)
            case "$ARCH" in
                arm64) PKG_URL="https://s3.amazonaws.com/session-manager-downloads/plugin/latest/mac_arm64/session-manager-plugin.pkg" ;;
                *)     PKG_URL="https://s3.amazonaws.com/session-manager-downloads/plugin/latest/mac/session-manager-plugin.pkg" ;;
            esac
            if ! download_file "$PKG_URL" "/tmp/session-manager-plugin.pkg" \
                || ! verify_macos_pkg_signature "/tmp/session-manager-plugin.pkg" "Session Manager Plugin installer"; then
                warn "Session Manager Plugin 自動安裝已中止（完整性驗證失敗）"
                warn "請從 AWS 官方文件手動安裝"
                return 1
            fi
            sudo installer -pkg /tmp/session-manager-plugin.pkg -target / > /dev/null 2>&1
            rm -f /tmp/session-manager-plugin.pkg
            ;;
        Linux)
            warn "Linux Session Manager Plugin 自動安裝已停用（尚未設定可信簽章驗證）"
            warn "請從 AWS 官方文件手動安裝 Session Manager Plugin"
            return 1
            ;;
        *)
            warn "不支援的作業系統，請手動安裝 Session Manager Plugin"
            return 1
            ;;
    esac
}

if command -v session-manager-plugin &> /dev/null; then
    SSM_VER="$(session-manager-plugin --version 2>&1)"
    ok "session-manager-plugin $SSM_VER"
else
    install_ssm_plugin
    if command -v session-manager-plugin &> /dev/null; then
        ok "session-manager-plugin $(session-manager-plugin --version 2>&1)"
    else
        warn "Session Manager Plugin 安裝失敗，SSM/ECS Exec 連線功能將無法使用"
        warn "EC2/ECS 清查和 CloudWatch 搜尋不受影響"
    fi
fi

# ── 5. 驗證 ─────────────────────────────────────────

echo "[5/5] 驗證安裝 ..."
echo ""

PASS=0
TOTAL=0

check() {
    TOTAL=$((TOTAL + 1))
    if eval "$2" > /dev/null 2>&1; then
        ok "$1"
        PASS=$((PASS + 1))
    else
        fail "$1"
    fi
}

check "canopy 可執行"         "test -x \"\$BIN_DST\""
check "設定檔存在"                 "test -f \"\$CONFIG_DST\""
check "設定檔包含 control_plane_url" "grep -q control_plane_url \"\$CONFIG_DST\""
check "AWS CLI v2 已安裝"          "aws --version 2>&1 | grep -q 'aws-cli/2'"
check "Session Manager Plugin 已安裝" "command -v session-manager-plugin"

# Control Plane 連線測試
TOTAL=$((TOTAL + 1))
CP_URL="$(grep control_plane_url "$CONFIG_DST" 2>/dev/null | head -1 | sed 's/.*= *"//' | sed 's/".*//')"
if [ -n "$CP_URL" ]; then
    HTTP_CODE="$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 "$CP_URL/api/entitlements" 2>/dev/null || echo "000")"
    if [ "$HTTP_CODE" = "401" ]; then
        ok "Control Plane 可連線 ($CP_URL → 401 Unauthorized，正常)"
        PASS=$((PASS + 1))
    elif [ "$HTTP_CODE" = "000" ]; then
        warn "Control Plane 無法連線 ($CP_URL)"
        warn "可能是 VPN 未連線，或 Control Plane 尚未啟動"
    else
        warn "Control Plane 回應異常 ($CP_URL → HTTP $HTTP_CODE)"
        PASS=$((PASS + 1))  # 至少有回應
    fi
else
    fail "無法從設定檔讀取 control_plane_url"
fi

echo ""
echo "======================================"
echo "  結果: $PASS/$TOTAL 項通過"
echo "======================================"
echo ""

if [ "$PASS" -ge 5 ]; then
    echo -e "${GREEN}安裝完成！${NC}"
else
    echo -e "${YELLOW}安裝完成，但有部分項目未通過。${NC}"
    echo "EC2/ECS 清查和 CloudWatch 搜尋功能仍可正常使用。"
    echo "SSM/EIC/ECS Exec 連線功能需要 AWS CLI v2；SSM/ECS Exec 另需要 Session Manager Plugin。"
fi

echo ""
echo "啟動方式："
echo "  $RUN_CMD"
if [ "$(uname -s)" = "Darwin" ] && [ -f "$INSTALL_DIR/Canopy.command" ]; then
    echo "  或雙擊 $INSTALL_DIR/Canopy.command"
fi
echo ""
INSTALLER

chmod +x "$DIST_DIR/install.sh"

# ── 6. 完成 ─────────────────────────────────────────

echo ""
echo "========================================"
echo "  打包完成"
echo "========================================"
echo ""
echo "分發資料夾: $DIST_DIR/"
echo ""
ls -lh "$DIST_DIR/"
echo ""
echo "將此資料夾交給維運人員，他們只需要執行："
echo ""
echo "  cd dist && ./install.sh"
echo ""
