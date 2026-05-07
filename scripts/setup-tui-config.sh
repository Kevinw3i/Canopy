#!/usr/bin/env bash
set -euo pipefail

CONTROL_PLANE_URL="${CANOPY_CONTROL_PLANE_URL:-}"
CHANGE_PASSWORD_URL="${CANOPY_CHANGE_PASSWORD_URL:-}"
FORCE=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/setup-tui-config.sh [CONTROL_PLANE_URL] [options]
  scripts/setup-tui-config.sh --url CONTROL_PLANE_URL [options]

Options:
  --url URL                       Control-plane URL (https://...).
  --change-password-url URL       Optional self-service password URL
                                  (typically the Cognito hosted UI).
  --force                         Overwrite existing config.
  -h, --help                      Show this help.

Environment:
  CANOPY_CONTROL_PLANE_URL        Default control-plane URL.
  CANOPY_CHANGE_PASSWORD_URL      Default change-password URL.
  CANOPY_CONFIG_DIR               Override the config directory.
  CANOPY_CONFIG_OVERWRITE=1       Overwrite an existing config file.

Note:
  All real domains/IDs must come from env, flag, or a local wrapper
  (see scripts/setup-tui-config.local.sh.example). The script itself
  ships no defaults to avoid leaking production hostnames into git.

Examples:
  scripts/setup-tui-config.sh https://canopy.your-domain.com
  scripts/setup-tui-config.sh --url https://canopy.your-domain.com --force
  CANOPY_CONTROL_PLANE_URL=https://canopy.your-domain.com \
    CANOPY_CHANGE_PASSWORD_URL='https://<cognito-domain>/forgotPassword?...' \
    scripts/setup-tui-config.sh
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --url)
      if [ "$#" -lt 2 ]; then
        echo "ERROR: --url requires a value" >&2
        exit 1
      fi
      CONTROL_PLANE_URL="$2"
      shift 2
      ;;
    --change-password-url)
      if [ "$#" -lt 2 ]; then
        echo "ERROR: --change-password-url requires a value" >&2
        exit 1
      fi
      CHANGE_PASSWORD_URL="$2"
      shift 2
      ;;
    --*)
      echo "ERROR: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      CONTROL_PLANE_URL="$1"
      shift
      ;;
  esac
done

if [ -z "$CONTROL_PLANE_URL" ]; then
  echo "ERROR: control-plane URL is required." >&2
  echo "Pass it as an argument, --url, or via CANOPY_CONTROL_PLANE_URL." >&2
  echo "See scripts/setup-tui-config.local.sh.example for a wrapper template." >&2
  exit 1
fi

validate_http_url() {
  local label="$1" value="$2"
  case "$value" in
    http://*|https://*) ;;
    *)
      echo "ERROR: $label must start with http:// or https://" >&2
      exit 1
      ;;
  esac
  if [[ "$value" == *\"* || "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
    echo "ERROR: $label cannot contain quotes or newlines" >&2
    exit 1
  fi
}

CONTROL_PLANE_URL="${CONTROL_PLANE_URL%/}"
validate_http_url "control-plane URL" "$CONTROL_PLANE_URL"

if [ -n "$CHANGE_PASSWORD_URL" ]; then
  validate_http_url "change-password URL" "$CHANGE_PASSWORD_URL"
fi

resolve_config_dir() {
  if [ -n "${CANOPY_CONFIG_DIR:-}" ]; then
    printf '%s\n' "$CANOPY_CONFIG_DIR"
    return
  fi

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

CONFIG_DIR="$(resolve_config_dir)"
CONFIG_PATH="$CONFIG_DIR/config.toml"

if [ -f "$CONFIG_PATH" ] && [ "$FORCE" != "1" ] && [ "${CANOPY_CONFIG_OVERWRITE:-0}" != "1" ]; then
  echo "Config already exists, not overwritten:"
  echo "  $CONFIG_PATH"
  echo
  echo "Use --force or CANOPY_CONFIG_OVERWRITE=1 to overwrite it."
  exit 0
fi

umask 077
mkdir -p "$CONFIG_DIR"

cat > "$CONFIG_PATH" <<TOML
control_plane_url = "$CONTROL_PLANE_URL"
dev_mode = false
pkce_callback_port = 9876
enable_live_tail = false
show_public_ip = false
auto_update = true
TOML

if [ -n "$CHANGE_PASSWORD_URL" ]; then
  printf 'change_password_url = "%s"\n' "$CHANGE_PASSWORD_URL" >> "$CONFIG_PATH"
else
  printf '# change_password_url = "https://<cognito-domain>/forgotPassword?client_id=<app-client-id>&response_type=code&scope=openid+profile+email&redirect_uri=http://localhost:9876/callback"\n' >> "$CONFIG_PATH"
fi

chmod 600 "$CONFIG_PATH" 2>/dev/null || true

echo "TUI config written:"
echo "  $CONFIG_PATH"
echo
echo "Run:"
echo "  ./target/release/tui-client"
