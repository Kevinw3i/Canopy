#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT"

CONFIG_PATH="${CONFIG_PATH:-config.dev.toml}"

if [ ! -f "$CONFIG_PATH" ]; then
  echo "ERROR: $CONFIG_PATH not found." >&2
  echo "Create $CONFIG_PATH before starting the local control-plane server." >&2
  echo "For DEV_MODE=1 built-in defaults, run: DEV_MODE=1 cargo run -p control-plane" >&2
  exit 1
fi

exec env CONFIG_PATH="$CONFIG_PATH" cargo run -p control-plane
