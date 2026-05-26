#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_SCRIPT="$SCRIPT_DIR/deploy-control-plane-local.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

expect_failure() {
  local name="$1"
  local expected="$2"
  shift 2

  if "$DEPLOY_SCRIPT" "$@" > "$TMP_DIR/$name.out" 2>&1; then
    cat "$TMP_DIR/$name.out" >&2
    echo "ERROR: expected $name to fail." >&2
    exit 1
  fi

  grep -q "$expected" "$TMP_DIR/$name.out"
}

expect_failure "invalid-tag" "Invalid Docker image tag" "-bad-tag"
expect_failure "latest-tag" "Using 'latest' is not allowed" "latest"
expect_failure "latest-case-tag" "Using 'latest' is not allowed" "LaTeSt"

echo "deploy-control-plane-local validation tests passed."
