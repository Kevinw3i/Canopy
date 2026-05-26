#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

write_tfvars() {
  local path="$1"
  local role_arn="$2"

  cat > "$path" <<EOF
enable_direct_access = false
assumable_role_arns = [
  "$role_arn",
]
EOF
}

write_entitlements() {
  local path="$1"
  local role_arn="$2"

  cat > "$path" <<EOF
[[rules]]
id = "ecs"
can_view_ecs = true
allowed_accounts = [
  { account_id = "123456789012", account_name = "prod", role_arn = "$role_arn" },
]
EOF
}

expect_success() {
  local name="$1"
  local entitlements="$2"
  local tfvars="$3"

  if ! "$SCRIPT_DIR/validate-entitlements.sh" "$entitlements" "$tfvars" > "$TMP_DIR/$name.out" 2>&1; then
    cat "$TMP_DIR/$name.out" >&2
    echo "ERROR: expected $name to pass." >&2
    exit 1
  fi
}

expect_failure() {
  local name="$1"
  local entitlements="$2"
  local tfvars="$3"
  local expected="$4"

  if "$SCRIPT_DIR/validate-entitlements.sh" "$entitlements" "$tfvars" > "$TMP_DIR/$name.out" 2>&1; then
    cat "$TMP_DIR/$name.out" >&2
    echo "ERROR: expected $name to fail." >&2
    exit 1
  fi

  grep -qF -- "$expected" "$TMP_DIR/$name.out"
}

expect_command_failure() {
  local name="$1"
  local expected="$2"
  shift 2

  if "$SCRIPT_DIR/validate-entitlements.sh" "$@" > "$TMP_DIR/$name.out" 2>&1; then
    cat "$TMP_DIR/$name.out" >&2
    echo "ERROR: expected $name to fail." >&2
    exit 1
  fi

  grep -qF -- "$expected" "$TMP_DIR/$name.out"
}

expect_command_failure "missing-args" "Usage:"

GOV_ROLE="arn:aws-us-gov:iam::123456789012:role/path/CanopyRole"
write_entitlements "$TMP_DIR/gov-entitlements.toml" "$GOV_ROLE"
write_tfvars "$TMP_DIR/gov.tfvars" "$GOV_ROLE"
expect_success "gov-partition" "$TMP_DIR/gov-entitlements.toml" "$TMP_DIR/gov.tfvars"

expect_command_failure \
  "missing-entitlements-file" \
  "Entitlements file not found" \
  "$TMP_DIR/no-entitlements.toml" \
  "$TMP_DIR/gov.tfvars"

expect_command_failure \
  "missing-tfvars-file" \
  "Terraform tfvars not found" \
  "$TMP_DIR/gov-entitlements.toml" \
  "$TMP_DIR/no.tfvars"

cat > "$TMP_DIR/missing.tfvars" <<'EOF'
enable_direct_access = false
assumable_role_arns = []
EOF
expect_failure \
  "missing-role" \
  "$TMP_DIR/gov-entitlements.toml" \
  "$TMP_DIR/missing.tfvars" \
  "not listed"

write_entitlements "$TMP_DIR/invalid-entitlements.toml" "arn:aws:s3:::not-a-role"
write_tfvars "$TMP_DIR/invalid.tfvars" "arn:aws-us-gov:iam::123456789012:role/path/CanopyRole"
expect_failure \
  "invalid-role" \
  "$TMP_DIR/invalid-entitlements.toml" \
  "$TMP_DIR/invalid.tfvars" \
  "concrete IAM role ARN"

write_entitlements "$TMP_DIR/direct-entitlements.toml" "direct"
write_tfvars "$TMP_DIR/direct-disabled.tfvars" "$GOV_ROLE"
expect_failure \
  "direct-disabled" \
  "$TMP_DIR/direct-entitlements.toml" \
  "$TMP_DIR/direct-disabled.tfvars" \
  "enable_direct_access is not true"

cat > "$TMP_DIR/direct-enabled.tfvars" <<'EOF'
enable_direct_access = true
assumable_role_arns = []
EOF
expect_success "direct-enabled" "$TMP_DIR/direct-entitlements.toml" "$TMP_DIR/direct-enabled.tfvars"

write_entitlements "$TMP_DIR/profile-entitlements.toml" "profile:dev"
expect_failure \
  "profile-role" \
  "$TMP_DIR/profile-entitlements.toml" \
  "$TMP_DIR/direct-enabled.tfvars" \
  "profile:*"

cat > "$TMP_DIR/exec-direct-entitlements.toml" <<'EOF'
[[rules]]
id = "ecs-exec-direct"
can_view_ecs = true
can_use_ecs_exec = true
allowed_accounts = [
  { account_id = "123456789012", account_name = "prod", role_arn = "direct" },
]
EOF
expect_failure \
  "exec-direct-role" \
  "$TMP_DIR/exec-direct-entitlements.toml" \
  "$TMP_DIR/direct-enabled.tfvars" \
  "enables can_use_ecs_exec but uses direct/profile credentials"

echo "validate-entitlements tests passed."
