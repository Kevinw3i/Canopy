#!/usr/bin/env bash
set -euo pipefail

DEFAULT_CONTROL_PLANE_URL="https://<your-canopy-domain>"
CONTROL_PLANE_URL="${CANOPY_CONTROL_PLANE_URL:-$DEFAULT_CONTROL_PLANE_URL}"
FORCE=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/setup-tui-config.sh [CONTROL_PLANE_URL]
  scripts/setup-tui-config.sh --url CONTROL_PLANE_URL [--force]

Environment:
  CANOPY_CONTROL_PLANE_URL   Default control-plane URL.
  CANOPY_CONFIG_DIR          Override the config directory.
  CANOPY_CONFIG_OVERWRITE=1  Overwrite an existing config file.

Examples:
  scripts/setup-tui-config.sh
  scripts/setup-tui-config.sh https://<your-canopy-domain>
  scripts/setup-tui-config.sh --url https://<your-canopy-domain> --force
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
  echo "ERROR: control-plane URL cannot be empty" >&2
  exit 1
fi

CONTROL_PLANE_URL="${CONTROL_PLANE_URL%/}"

case "$CONTROL_PLANE_URL" in
  http://*|https://*) ;;
  *)
    echo "ERROR: control-plane URL must start with http:// or https://" >&2
    exit 1
    ;;
esac

if [[ "$CONTROL_PLANE_URL" == *\"* || "$CONTROL_PLANE_URL" == *$'\n'* || "$CONTROL_PLANE_URL" == *$'\r'* ]]; then
  echo "ERROR: control-plane URL cannot contain quotes or newlines" >&2
  exit 1
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
auto_update = false
# change_password_url = "https://<cognito-domain>/forgotPassword?client_id=<app-client-id>&response_type=code&scope=openid+profile+email&redirect_uri=http://localhost:9876/callback"
TOML

chmod 600 "$CONFIG_PATH" 2>/dev/null || true

echo "TUI config written:"
echo "  $CONFIG_PATH"
echo
echo "Run:"
echo "  ./target/release/tui-client"
