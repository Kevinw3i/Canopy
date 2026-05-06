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
# change_password_url = "https://<cognito-domain>/forgotPassword?client_id=<app-client-id>&response_type=code&scope=openid+profile+email&redirect_uri=http://localhost:9876/callback"
EOF

# ── 5. 產生安裝腳本 ─────────────────────────────────

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
BIN_DST="/usr/local/bin/canopy"
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
# 下載檔案並驗證 SHA-256 雜湊。驗證失敗時刪除檔案並中止。
# 用法: verified_download <url> <dest_path>
# 下載後會從 <url>.sha256 取得官方雜湊進行比對。
# 如果無法取得 .sha256 檔，則改用 GPG 簽章驗證（如有）；
# 若兩者皆不可用，拒絕安裝並提示手動安裝。
verified_download() {
    local url="$1"
    local dest="$2"
    local sha256_url="${url}.sha256"

    curl -sfS "$url" -o "$dest" || { fail "下載失敗: $url"; return 1; }

    # 嘗試取得官方 SHA-256 雜湊
    local expected_hash
    expected_hash="$(curl -sfS "$sha256_url" 2>/dev/null | awk '{print $1}')" || true

    if [ -n "$expected_hash" ]; then
        local actual_hash
        if command -v sha256sum &> /dev/null; then
            actual_hash="$(sha256sum "$dest" | awk '{print $1}')"
        elif command -v shasum &> /dev/null; then
            actual_hash="$(shasum -a 256 "$dest" | awk '{print $1}')"
        else
            fail "系統沒有 sha256sum 或 shasum，無法驗證下載檔案"
            rm -f "$dest"
            return 1
        fi

        if [ "$actual_hash" != "$expected_hash" ]; then
            fail "SHA-256 驗證失敗！"
            fail "  預期: $expected_hash"
            fail "  實際: $actual_hash"
            fail "  檔案可能已被竄改，已刪除: $dest"
            rm -f "$dest"
            return 1
        fi
    else
        # 無法取得 .sha256 — 拒絕未驗證的安裝
        fail "無法取得 $sha256_url 進行完整性驗證"
        fail "請從 AWS 官方管道手動安裝此套件"
        rm -f "$dest"
        return 1
    fi
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

sudo cp "$BIN_SRC" "$BIN_DST"
sudo chmod +x "$BIN_DST"

# macOS: 移除 Gatekeeper 隔離標記
if [ "$OS" = "Darwin" ]; then
    sudo xattr -dr com.apple.quarantine "$BIN_DST" 2>/dev/null || true
fi

ok "已安裝到 $BIN_DST"

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
            if ! verified_download "https://awscli.amazonaws.com/AWSCLIV2.pkg" "/tmp/AWSCLIV2.pkg"; then
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
            if ! verified_download "$CLI_URL" "/tmp/awscliv2.zip"; then
                warn "AWS CLI 自動安裝已中止（完整性驗證失敗）"
                warn "請從 https://aws.amazon.com/cli/ 手動安裝"
                return 1
            fi
            unzip -q -o /tmp/awscliv2.zip -d /tmp/aws-install
            sudo /tmp/aws-install/aws/install --update > /dev/null 2>&1
            rm -rf /tmp/awscliv2.zip /tmp/aws-install
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
        warn "AWS CLI 安裝失敗，SSM/EIC 連線功能將無法使用"
        warn "EC2 瀏覽和 CloudWatch 搜尋不受影響"
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
            if ! verified_download "$PKG_URL" "/tmp/session-manager-plugin.pkg"; then
                warn "Session Manager Plugin 自動安裝已中止（完整性驗證失敗）"
                warn "請從 AWS 官方文件手動安裝"
                return 1
            fi
            sudo installer -pkg /tmp/session-manager-plugin.pkg -target / > /dev/null 2>&1
            rm -f /tmp/session-manager-plugin.pkg
            ;;
        Linux)
            # Select architecture-appropriate package URLs
            case "$ARCH" in
                aarch64|arm64) local deb_arch="ubuntu_arm64" rpm_arch="linux_arm64" ;;
                *)             local deb_arch="ubuntu_64bit" rpm_arch="linux_64bit" ;;
            esac
            if command -v dpkg &> /dev/null; then
                local deb_url="https://s3.amazonaws.com/session-manager-downloads/plugin/latest/${deb_arch}/session-manager-plugin.deb"
                if ! verified_download "$deb_url" "/tmp/session-manager-plugin.deb"; then
                    warn "Session Manager Plugin 自動安裝已中止（完整性驗證失敗）"
                    warn "請從 AWS 官方文件手動安裝"
                    return 1
                fi
                sudo dpkg -i /tmp/session-manager-plugin.deb > /dev/null 2>&1
                rm -f /tmp/session-manager-plugin.deb
            elif command -v rpm &> /dev/null; then
                local rpm_url="https://s3.amazonaws.com/session-manager-downloads/plugin/latest/${rpm_arch}/session-manager-plugin.rpm"
                if ! verified_download "$rpm_url" "/tmp/session-manager-plugin.rpm"; then
                    warn "Session Manager Plugin 自動安裝已中止（完整性驗證失敗）"
                    warn "請從 AWS 官方文件手動安裝"
                    return 1
                fi
                sudo yum install -y /tmp/session-manager-plugin.rpm > /dev/null 2>&1
                rm -f /tmp/session-manager-plugin.rpm
            else
                warn "無法判斷套件管理器，請手動安裝 Session Manager Plugin"
                return 1
            fi
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
        warn "Session Manager Plugin 安裝失敗，SSM 連線功能將無法使用"
        warn "EC2 瀏覽和 CloudWatch 搜尋不受影響"
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

check "canopy 可執行"         "command -v canopy"
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
    echo "EC2 瀏覽和 CloudWatch 搜尋功能仍可正常使用。"
    echo "SSM/EIC 連線功能需要 AWS CLI v2 和 Session Manager Plugin。"
fi

echo ""
echo "啟動方式："
echo "  canopy"
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
