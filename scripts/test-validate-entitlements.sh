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

  grep -q "$expected" "$TMP_DIR/$name.out"
}

GOV_ROLE="arn:aws-us-gov:iam::123456789012:role/path/CanopyRole"
write_entitlements "$TMP_DIR/gov-entitlements.toml" "$GOV_ROLE"
write_tfvars "$TMP_DIR/gov.tfvars" "$GOV_ROLE"
expect_success "gov-partition" "$TMP_DIR/gov-entitlements.toml" "$TMP_DIR/gov.tfvars"

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

echo "validate-entitlements tests passed."
