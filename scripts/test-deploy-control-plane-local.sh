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

  grep -q -- "$expected" "$TMP_DIR/$name.out"
}

expect_failure "missing-tag" "Usage:"
expect_failure "invalid-tag" "Invalid Docker image tag" "-bad-tag"
expect_failure "latest-tag" "Using 'latest' is not allowed" "latest"
expect_failure "latest-case-tag" "Using 'latest' is not allowed" "LaTeSt"
expect_failure "extra-tag" "Only one image tag is allowed" "cp-v0.1.0" "cp-v0.1.1"
expect_failure "empty-profile" "--profile requires a value" "cp-v0.1.0" "--profile" ""
expect_failure "invalid-cargo-jobs-zero" "--cargo-jobs must be a positive integer" "cp-v0.1.0" "--cargo-jobs" "0"
expect_failure "invalid-cargo-jobs-word" "--cargo-jobs must be a positive integer" "cp-v0.1.0" "--cargo-jobs" "fast"
expect_failure "parent-entitlements-path" "--entitlements must be a path inside the repo root" "cp-v0.1.0" "--entitlements" "../entitlements.toml"
expect_failure "absolute-entitlements-path" "--entitlements must be a path inside the repo root" "cp-v0.1.0" "--entitlements" "/tmp/entitlements.toml"

echo "deploy-control-plane-local validation tests passed."
