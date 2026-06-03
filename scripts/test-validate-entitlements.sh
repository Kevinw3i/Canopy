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
allowed_clusters = ["prod"]

[rules.features]
can_view_ecs = true

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "$role_arn"
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

expect_command_success() {
  local name="$1"
  shift

  if ! "$@" > "$TMP_DIR/$name.out" 2>&1; then
    cat "$TMP_DIR/$name.out" >&2
    echo "ERROR: expected $name to pass." >&2
    exit 1
  fi
}

expect_command_success_with_output() {
  local name="$1"
  local expected="$2"
  shift 2

  expect_command_success "$name" "$@"
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

expect_raw_command_failure() {
  local name="$1"
  local expected="$2"
  shift 2

  if "$@" > "$TMP_DIR/$name.out" 2>&1; then
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

cat > "$TMP_DIR/duplicate-key-entitlements.toml" <<EOF
[[rules]]
id = "duplicate-key"
allowed_regions = ["ap-northeast-1"]
allowed_regions = ["us-east-1"]

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "$GOV_ROLE"
EOF
expect_failure \
  "invalid-toml-duplicate-key" \
  "$TMP_DIR/duplicate-key-entitlements.toml" \
  "$TMP_DIR/gov.tfvars" \
  "entitlements TOML parse failed"

cat > "$TMP_DIR/misplaced-session-duration-entitlements.toml" <<EOF
[[rules]]
id = "misplaced-session-duration"
group = "platform-engineering"
allowed_regions = ["ap-northeast-1"]
session_duration_seconds = 14400

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "$GOV_ROLE"
EOF
expect_failure \
  "misplaced-session-duration" \
  "$TMP_DIR/misplaced-session-duration-entitlements.toml" \
  "$TMP_DIR/gov.tfvars" \
  "use max_session_seconds"

ORG_ROLE_TEMPLATE="arn:aws:iam::{account_id}:role/CanopyRole"
ORG_ROLE_PATTERN="arn:aws:iam::*:role/CanopyRole"
cat > "$TMP_DIR/org-discovery-entitlements.toml" <<EOF
[[rules]]
id = "org-discovery"
allowed_clusters = ["prod"]

[rules.features]
can_view_ecs = true

[[rules.allowed_accounts]]
account_id = "*"
account_name = "organization"
role_arn = "$ORG_ROLE_TEMPLATE"
EOF
cat > "$TMP_DIR/org-discovery.tfvars" <<EOF
enable_direct_access = false
assumable_role_arns = []
assumable_role_arn_patterns = [
  "$ORG_ROLE_PATTERN",
]
EOF
cat > "$TMP_DIR/org-discovery-missing-pattern.tfvars" <<'EOF'
enable_direct_access = false
assumable_role_arns = []
assumable_role_arn_patterns = []
EOF
expect_success \
  "org-discovery-role-template" \
  "$TMP_DIR/org-discovery-entitlements.toml" \
  "$TMP_DIR/org-discovery.tfvars"

expect_failure \
  "org-discovery-missing-role-pattern" \
  "$TMP_DIR/org-discovery-entitlements.toml" \
  "$TMP_DIR/org-discovery-missing-pattern.tfvars" \
  "assumable_role_arn_patterns"

cat > "$TMP_DIR/org-discovery-invalid-template-entitlements.toml" <<'EOF'
[[rules]]
id = "org-discovery-invalid-template"
allowed_clusters = ["prod"]

[rules.features]
can_view_ecs = true

[[rules.allowed_accounts]]
account_id = "*"
account_name = "organization"
role_arn = "arn:aws:iam::{account_id}:role/{account_id}/CanopyRole"
EOF
expect_failure \
  "org-discovery-invalid-role-template" \
  "$TMP_DIR/org-discovery-invalid-template-entitlements.toml" \
  "$TMP_DIR/org-discovery.tfvars" \
  "exactly one {account_id} token"

cat > "$TMP_DIR/org-discovery-single-quoted-entitlements.toml" <<'EOF'
[[rules]]
id = "org-discovery-single-quoted"
allowed_clusters = ["prod"]

[rules.features]
can_view_ecs = true

[[rules.allowed_accounts]]
account_id = '*'
account_name = 'organization'
role_arn = 'arn:aws:iam::{account_id}:role/CanopyRole'
EOF
expect_success \
  "org-discovery-single-quoted-role-template" \
  "$TMP_DIR/org-discovery-single-quoted-entitlements.toml" \
  "$TMP_DIR/org-discovery.tfvars"

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

cat > "$TMP_DIR/active-placeholder-entitlements.toml" <<'EOF'
[[rules]]
id = "placeholder-rule"
group = "platform-engineering"
allowed_regions = ["ap-northeast-1"]

[rules.features]
can_view_ec2 = true

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "production"
role_arn = "direct"

[[memberships]]
user_id = "admin@example.com"
group = "platform-engineering"
EOF
cat > "$TMP_DIR/direct-enabled.tfvars" <<'EOF'
enable_direct_access = true
assumable_role_arns = []
EOF
expect_failure \
  "active-sample-placeholder" \
  "$TMP_DIR/active-placeholder-entitlements.toml" \
  "$TMP_DIR/direct-enabled.tfvars" \
  "sample placeholder values"

cat > "$TMP_DIR/commented-placeholder-entitlements.toml" <<EOF
# account_id = "<ACCOUNT_ID>"
[[rules]]
id = "gov"
can_view_ec2 = true
allowed_accounts = [
  { account_id = "123456789012", account_name = "prod", role_arn = "$GOV_ROLE" },
]
EOF
expect_success "commented-placeholder-ignored" "$TMP_DIR/commented-placeholder-entitlements.toml" "$TMP_DIR/gov.tfvars"

cat > "$TMP_DIR/missing.tfvars" <<'EOF'
enable_direct_access = false
assumable_role_arns = []
EOF
expect_failure \
  "missing-role" \
  "$TMP_DIR/gov-entitlements.toml" \
  "$TMP_DIR/missing.tfvars" \
  "not listed"

cat > "$TMP_DIR/misleading.tfvars" <<EOF
enable_direct_access = false
assumable_role_arns = []
other_role_arn = "$GOV_ROLE"
EOF
expect_failure \
  "role-only-outside-assumable-list" \
  "$TMP_DIR/gov-entitlements.toml" \
  "$TMP_DIR/misleading.tfvars" \
  "not listed"

SECOND_ROLE="arn:aws:iam::123456789012:role/CanopySecondRole"
cat > "$TMP_DIR/two-inline-roles-entitlements.toml" <<EOF
[[rules]]
id = "two-inline-roles"
allowed_clusters = ["prod"]
allowed_accounts = [
  { account_id = "123456789012", account_name = "prod", role_arn = "$GOV_ROLE" }, { account_id = "123456789012", account_name = "prod-second", role_arn = "$SECOND_ROLE" },
]

[rules.features]
can_view_ecs = true
EOF
expect_failure \
  "second-inline-role-missing" \
  "$TMP_DIR/two-inline-roles-entitlements.toml" \
  "$TMP_DIR/gov.tfvars" \
  "not listed"

cat > "$TMP_DIR/single-quoted-role-entitlements.toml" <<EOF
[[rules]]
id = "single-quoted-role"
allowed_clusters = ["prod"]

[rules.features]
can_view_ecs = true

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = '$GOV_ROLE'
EOF
expect_success \
  "single-quoted-role" \
  "$TMP_DIR/single-quoted-role-entitlements.toml" \
  "$TMP_DIR/gov.tfvars"

write_entitlements "$TMP_DIR/invalid-entitlements.toml" "arn:aws:s3:::not-a-role"
write_tfvars "$TMP_DIR/invalid.tfvars" "arn:aws-us-gov:iam::123456789012:role/path/CanopyRole"
expect_failure \
  "invalid-role" \
  "$TMP_DIR/invalid-entitlements.toml" \
  "$TMP_DIR/invalid.tfvars" \
  "concrete IAM role ARN"

write_entitlements "$TMP_DIR/unsupported-role-entitlements.toml" "canopy-role"
expect_failure \
  "unsupported-role" \
  "$TMP_DIR/unsupported-role-entitlements.toml" \
  "$TMP_DIR/direct-enabled.tfvars" \
  "role_arn in entitlements must be \"direct\", \"profile:*\", or a concrete IAM role ARN"

write_entitlements "$TMP_DIR/direct-entitlements.toml" "direct"
write_tfvars "$TMP_DIR/direct-disabled.tfvars" "$GOV_ROLE"
expect_failure \
  "direct-disabled" \
  "$TMP_DIR/direct-entitlements.toml" \
  "$TMP_DIR/direct-disabled.tfvars" \
  "enable_direct_access is not true"

cat > "$TMP_DIR/single-quoted-direct-entitlements.toml" <<'EOF'
[[rules]]
id = "single-quoted-direct"

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = 'direct'
EOF
expect_failure \
  "single-quoted-direct-disabled" \
  "$TMP_DIR/single-quoted-direct-entitlements.toml" \
  "$TMP_DIR/direct-disabled.tfvars" \
  "enable_direct_access is not true"

expect_success "direct-enabled" "$TMP_DIR/direct-entitlements.toml" "$TMP_DIR/direct-enabled.tfvars"

cat > "$TMP_DIR/group-mapping-entitlements.toml" <<'EOF'
memberships = []

[[group_mappings]]
external_group = "CognitoPlatform"
canopy_group = "platform-engineering"

[[rules]]
id = "platform"
group = "platform-engineering"

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "direct"
EOF
expect_success \
  "group-mapping-without-local-membership" \
  "$TMP_DIR/group-mapping-entitlements.toml" \
  "$TMP_DIR/direct-enabled.tfvars"

FAKE_AWS_DIR="$TMP_DIR/fake-aws-bin"
mkdir -p "$FAKE_AWS_DIR"
cat > "$FAKE_AWS_DIR/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ "${1:-}" = "cognito-idp" ] && [ "${2:-}" = "list-groups" ]; then
  printf 'CognitoPlatform\tcanopy-unmapped\n'
  exit 0
fi

echo "unexpected aws command: $*" >&2
exit 2
EOF
chmod +x "$FAKE_AWS_DIR/aws"

cat > "$TMP_DIR/cognito.tfvars" <<'EOF'
enable_direct_access = true
assumable_role_arns = []
aws_region = "us-east-1"
oidc_issuer_url = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEfGhI"
EOF

expect_command_success_with_output \
  "cognito-online-warns-for-unmapped-canopy-group" \
  "WARNING: Cognito group 'canopy-unmapped' has canopy-* prefix but no group_mappings entry" \
  env PATH="$FAKE_AWS_DIR:$PATH" \
  "$SCRIPT_DIR/validate-entitlements.sh" \
  --cognito-online \
  "$TMP_DIR/group-mapping-entitlements.toml" \
  "$TMP_DIR/cognito.tfvars"

sed 's/CognitoPlatform/MissingGroup/' "$TMP_DIR/group-mapping-entitlements.toml" \
  > "$TMP_DIR/missing-cognito-group-entitlements.toml"
expect_raw_command_failure \
  "cognito-online-missing-external-group" \
  "external_group 'MissingGroup' does not exist in Cognito User Pool" \
  env PATH="$FAKE_AWS_DIR:$PATH" \
  "$SCRIPT_DIR/validate-entitlements.sh" \
  --cognito-user-pool-id us-east-1_AbCdEfGhI \
  --cognito-region us-east-1 \
  "$TMP_DIR/missing-cognito-group-entitlements.toml" \
  "$TMP_DIR/direct-enabled.tfvars"

expect_raw_command_failure \
  "cognito-online-strict-unmapped-canopy-group" \
  "Cognito group 'canopy-unmapped' has canopy-* prefix but no group_mappings entry" \
  env PATH="$FAKE_AWS_DIR:$PATH" \
  "$SCRIPT_DIR/validate-entitlements.sh" \
  --cognito-online \
  --strict-cognito-groups \
  "$TMP_DIR/group-mapping-entitlements.toml" \
  "$TMP_DIR/cognito.tfvars"

expect_raw_command_failure \
  "cognito-online-strict-env-implies-online-check" \
  "Cognito group 'canopy-unmapped' has canopy-* prefix but no group_mappings entry" \
  env PATH="$FAKE_AWS_DIR:$PATH" CANOPY_COGNITO_STRICT_GROUPS=1 \
  "$SCRIPT_DIR/validate-entitlements.sh" \
  "$TMP_DIR/group-mapping-entitlements.toml" \
  "$TMP_DIR/cognito.tfvars"

cat > "$TMP_DIR/rule-group-without-source-entitlements.toml" <<'EOF'
[[rules]]
id = "platform"
group = "platform-engineering"

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "direct"
EOF
expect_failure \
  "rule-group-without-source" \
  "$TMP_DIR/rule-group-without-source-entitlements.toml" \
  "$TMP_DIR/direct-enabled.tfvars" \
  "rule group 'platform-engineering' has no source"

cat > "$TMP_DIR/empty-group-mapping-entitlements.toml" <<'EOF'
memberships = []

[[group_mappings]]
external_group = ""
canopy_group = "platform-engineering"

[[rules]]
id = "platform"
group = "platform-engineering"

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "direct"
EOF
expect_failure \
  "empty-group-mapping" \
  "$TMP_DIR/empty-group-mapping-entitlements.toml" \
  "$TMP_DIR/direct-enabled.tfvars" \
  "external_group must not be empty"

cat > "$TMP_DIR/duplicate-group-mapping-entitlements.toml" <<'EOF'
memberships = []

[[group_mappings]]
external_group = "CognitoPlatform"
canopy_group = "platform-engineering"

[[group_mappings]]
external_group = "CognitoPlatform"
canopy_group = "platform-engineering"

[[rules]]
id = "platform"
group = "platform-engineering"

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "direct"
EOF
expect_failure \
  "duplicate-group-mapping" \
  "$TMP_DIR/duplicate-group-mapping-entitlements.toml" \
  "$TMP_DIR/direct-enabled.tfvars" \
  "external_group 'CognitoPlatform' is duplicated"

cat > "$TMP_DIR/group-mapping-missing-rule-entitlements.toml" <<'EOF'
memberships = []

[[group_mappings]]
external_group = "CognitoPlatform"
canopy_group = "platform-engineering"

[[rules]]
id = "readonly"
group = "readonly-ops"

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "direct"
EOF
expect_failure \
  "group-mapping-missing-rule" \
  "$TMP_DIR/group-mapping-missing-rule-entitlements.toml" \
  "$TMP_DIR/direct-enabled.tfvars" \
  "with no matching rule group"

cat > "$TMP_DIR/membership-missing-rule-entitlements.toml" <<'EOF'
[[memberships]]
user_id = "alice"
group = "platform-engineering"

[[rules]]
id = "readonly"
group = "readonly-ops"

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "direct"
EOF
expect_failure \
  "membership-missing-rule" \
  "$TMP_DIR/membership-missing-rule-entitlements.toml" \
  "$TMP_DIR/direct-enabled.tfvars" \
  "membership user_id 'alice' points to group 'platform-engineering' with no matching rule group"

cat > "$TMP_DIR/orphan-rule-group-entitlements.toml" <<'EOF'
[[memberships]]
user_id = "alice"
group = "platform-engineering"

[[rules]]
id = "platform"
group = "platform-engineering"

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "direct"

[[rules]]
id = "readonly"
group = "readonly-ops"

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "direct"
EOF
expect_failure \
  "orphan-rule-group" \
  "$TMP_DIR/orphan-rule-group-entitlements.toml" \
  "$TMP_DIR/direct-enabled.tfvars" \
  "rule group 'readonly-ops' has no source"

cat > "$TMP_DIR/metadata-scopes-entitlements.toml" <<EOF
[[rules]]
id = "metadata-scopes"
allowed_regions = ["ap-northeast-1"]
allowed_log_group_arns = ["arn:aws:logs:*:123456789012:log-group:/platform-a/*"]

[rules.features]
can_use_mcp = true
can_use_mcp_cloudwatch = true

[rules.metadata]
description = "MCP CloudWatch business scopes"

[[rules.metadata.scopes]]
platform = "PLATFORM_A"
environment = "production"
aliases = ["正式環境", "prod", "PRO"]

[[rules.metadata.scopes]]
platform = "PLATFORM_A"
environment = "demo"
aliases = ["Demo", "測試環境"]

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "$GOV_ROLE"
EOF
expect_success "metadata-scopes" "$TMP_DIR/metadata-scopes-entitlements.toml" "$TMP_DIR/gov.tfvars"

write_entitlements "$TMP_DIR/profile-entitlements.toml" "profile:dev"
expect_failure \
  "profile-role" \
  "$TMP_DIR/profile-entitlements.toml" \
  "$TMP_DIR/direct-enabled.tfvars" \
  "profile:*"

cat > "$TMP_DIR/single-quoted-profile-entitlements.toml" <<'EOF'
[[rules]]
id = "single-quoted-profile"

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = 'profile:dev'
EOF
expect_failure \
  "single-quoted-profile-role" \
  "$TMP_DIR/single-quoted-profile-entitlements.toml" \
  "$TMP_DIR/direct-enabled.tfvars" \
  "profile:*"

cat > "$TMP_DIR/exec-direct-entitlements.toml" <<'EOF'
[[rules]]
id = "ecs-exec-direct"
allowed_clusters = ["prod"]

[rules.features]
can_view_ecs = true
can_use_ecs_exec = true

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "direct"
EOF
expect_failure \
  "exec-direct-role" \
  "$TMP_DIR/exec-direct-entitlements.toml" \
  "$TMP_DIR/direct-enabled.tfvars" \
  "enables can_use_ecs_exec but uses direct/profile credentials"

cat > "$TMP_DIR/exec-profile-single-quoted-entitlements.toml" <<'EOF'
[[rules]]
id = "ecs-exec-single-quoted-profile"
allowed_clusters = ["prod"]

[rules.features]
can_view_ecs = true
can_use_ecs_exec = true

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = 'profile:dev'
EOF
expect_failure \
  "exec-single-quoted-profile-role" \
  "$TMP_DIR/exec-profile-single-quoted-entitlements.toml" \
  "$TMP_DIR/direct-enabled.tfvars" \
  "enables can_use_ecs_exec but uses direct/profile credentials"

cat > "$TMP_DIR/exec-direct-inline-features-entitlements.toml" <<'EOF'
[[rules]]
id = "ecs-exec-direct-inline-features"
allowed_clusters = ["prod"]
features = { can_view_ecs = true, can_use_ecs_exec = true }

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "direct"
EOF
expect_failure \
  "exec-direct-inline-features" \
  "$TMP_DIR/exec-direct-inline-features-entitlements.toml" \
  "$TMP_DIR/direct-enabled.tfvars" \
  "enables can_use_ecs_exec but uses direct/profile credentials"

cat > "$TMP_DIR/exec-without-view-entitlements.toml" <<EOF
[[rules]]
id = "ecs-exec-without-view"
allowed_clusters = ["prod"]

[rules.features]
can_view_ecs = false
can_use_ecs_exec = true

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "$GOV_ROLE"
EOF
expect_failure \
  "exec-without-view" \
  "$TMP_DIR/exec-without-view-entitlements.toml" \
  "$TMP_DIR/gov.tfvars" \
  "ECS Exec must imply ECS view"

cat > "$TMP_DIR/exec-without-view-inline-features-entitlements.toml" <<EOF
[[rules]]
id = "ecs-exec-without-view-inline-features"
allowed_clusters = ["prod"]
features = { can_use_ecs_exec = true }

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "$GOV_ROLE"
EOF
expect_failure \
  "exec-without-view-inline-features" \
  "$TMP_DIR/exec-without-view-inline-features-entitlements.toml" \
  "$TMP_DIR/gov.tfvars" \
  "ECS Exec must imply ECS view"

cat > "$TMP_DIR/ecs-without-clusters-entitlements.toml" <<EOF
[[rules]]
id = "ecs-without-clusters"

[rules.features]
can_view_ecs = true

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "$GOV_ROLE"
EOF
expect_failure \
  "ecs-without-clusters" \
  "$TMP_DIR/ecs-without-clusters-entitlements.toml" \
  "$TMP_DIR/gov.tfvars" \
  "allowed_clusters is empty"

cat > "$TMP_DIR/ecs-without-clusters-inline-features-entitlements.toml" <<EOF
[[rules]]
id = "ecs-without-clusters-inline-features"
features = { can_view_ecs = true }

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "$GOV_ROLE"
EOF
expect_failure \
  "ecs-without-clusters-inline-features" \
  "$TMP_DIR/ecs-without-clusters-inline-features-entitlements.toml" \
  "$TMP_DIR/gov.tfvars" \
  "allowed_clusters is empty"

cat > "$TMP_DIR/single-quoted-cluster-entitlements.toml" <<EOF
[[rules]]
id = "single-quoted-cluster"
allowed_clusters = ['prod']

[rules.features]
can_view_ecs = true

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "$GOV_ROLE"
EOF
expect_success \
  "single-quoted-cluster" \
  "$TMP_DIR/single-quoted-cluster-entitlements.toml" \
  "$TMP_DIR/gov.tfvars"

cat > "$TMP_DIR/broad-cluster-without-opt-in-entitlements.toml" <<EOF
[[rules]]
id = "ecs-broad-cluster"
allowed_clusters = ["cluster/*"]

[rules.features]
can_view_ecs = true

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "$GOV_ROLE"
EOF
expect_failure \
  "broad-cluster-without-opt-in" \
  "$TMP_DIR/broad-cluster-without-opt-in-entitlements.toml" \
  "$TMP_DIR/gov.tfvars" \
  "allow_broad_cluster_discovery=true"

cat > "$TMP_DIR/single-quoted-broad-cluster-entitlements.toml" <<EOF
[[rules]]
id = "single-quoted-broad-cluster"
allowed_clusters = ['cluster/*']

[rules.features]
can_view_ecs = true

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "$GOV_ROLE"
EOF
expect_failure \
  "single-quoted-broad-cluster" \
  "$TMP_DIR/single-quoted-broad-cluster-entitlements.toml" \
  "$TMP_DIR/gov.tfvars" \
  "allow_broad_cluster_discovery=true"

cat > "$TMP_DIR/broad-cluster-misplaced-opt-in-entitlements.toml" <<EOF
[[rules]]
id = "ecs-broad-cluster-misplaced-opt-in"
allowed_clusters = ["cluster/*"]

[rules.features]
can_view_ecs = true
allow_broad_cluster_discovery = true

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "$GOV_ROLE"
EOF
expect_failure \
  "broad-cluster-misplaced-opt-in" \
  "$TMP_DIR/broad-cluster-misplaced-opt-in-entitlements.toml" \
  "$TMP_DIR/gov.tfvars" \
  "allow_broad_cluster_discovery=true"

cat > "$TMP_DIR/broad-cluster-with-opt-in-entitlements.toml" <<EOF
[[rules]]
id = "ecs-broad-cluster-opt-in"
allowed_clusters = ["arn:aws:ecs:us-east-1:123456789012:cluster/*"]
allow_broad_cluster_discovery = true

[rules.features]
can_view_ecs = true

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "$GOV_ROLE"
EOF
expect_success \
  "broad-cluster-with-opt-in" \
  "$TMP_DIR/broad-cluster-with-opt-in-entitlements.toml" \
  "$TMP_DIR/gov.tfvars"

cat > "$TMP_DIR/invalid-cluster-pattern-entitlements.toml" <<EOF
[[rules]]
id = "ecs-invalid-cluster-pattern"
allowed_clusters = ["cluster/p?od-*"]
allow_broad_cluster_discovery = true

[rules.features]
can_view_ecs = true

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "$GOV_ROLE"
EOF
expect_failure \
  "invalid-cluster-pattern" \
  "$TMP_DIR/invalid-cluster-pattern-entitlements.toml" \
  "$TMP_DIR/gov.tfvars" \
  "only literal characters and '*' are allowed"

cat > "$TMP_DIR/ssm-without-os-users-entitlements.toml" <<EOF
[[rules]]
id = "ssm-without-os-users"

[rules.features]
can_use_ssm = true

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "$GOV_ROLE"
EOF
expect_failure \
  "ssm-without-os-users" \
  "$TMP_DIR/ssm-without-os-users-entitlements.toml" \
  "$TMP_DIR/gov.tfvars" \
  "can_use_ssm=true but no allowed_os_users"

cat > "$TMP_DIR/ssm-without-os-users-inline-features-entitlements.toml" <<EOF
[[rules]]
id = "ssm-without-os-users-inline-features"
features = { can_use_ssm = true }

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "$GOV_ROLE"
EOF
expect_failure \
  "ssm-without-os-users-inline-features" \
  "$TMP_DIR/ssm-without-os-users-inline-features-entitlements.toml" \
  "$TMP_DIR/gov.tfvars" \
  "can_use_ssm=true but no allowed_os_users"

cat > "$TMP_DIR/ssm-misplaced-os-users-entitlements.toml" <<EOF
[[rules]]
id = "ssm-misplaced-os-users"

[rules.features]
can_use_ssm = true
allowed_os_users = ["ec2-user"]

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "$GOV_ROLE"
EOF
expect_failure \
  "ssm-misplaced-os-users" \
  "$TMP_DIR/ssm-misplaced-os-users-entitlements.toml" \
  "$TMP_DIR/gov.tfvars" \
  "can_use_ssm=true but no allowed_os_users"

cat > "$TMP_DIR/single-quoted-os-users-entitlements.toml" <<EOF
[[rules]]
id = "single-quoted-os-users"
allowed_os_users = ['ec2-user']

[rules.features]
can_use_ssm = true

[[rules.allowed_accounts]]
account_id = "123456789012"
account_name = "prod"
role_arn = "$GOV_ROLE"
EOF
expect_success \
  "single-quoted-os-users" \
  "$TMP_DIR/single-quoted-os-users-entitlements.toml" \
  "$TMP_DIR/gov.tfvars"

echo "validate-entitlements tests passed."
