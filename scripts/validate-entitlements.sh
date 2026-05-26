#!/usr/bin/env bash
# Validates that an entitlements file is consistent with Terraform variables.
# Usage: ./scripts/validate-entitlements.sh <entitlements.toml> <terraform.tfvars>
#
# Checks:
#   0. Active sample placeholders are rejected before production image builds
#   1. If any account uses role_arn = "direct", enable_direct_access must be true in tfvars
#   2. profile:* role_arn entries are rejected for ECS deployments
#   3. All role ARNs in entitlements must appear in assumable_role_arns in tfvars
#   4. ECS Exec rules must use AssumeRole ARNs, not direct/profile credentials
#   5. ECS Exec must imply ECS view, and ECS access rules need allowed_clusters
#   6. SSM access rules need explicit allowed_os_users
set -euo pipefail

usage() {
  echo "Usage: $0 <entitlements.toml> <terraform.tfvars>" >&2
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

if [ "$#" -ne 2 ]; then
  usage
  exit 1
fi

ENTITLEMENTS="$1"
TFVARS="$2"

[ -f "$ENTITLEMENTS" ] || fail "Entitlements file not found: $ENTITLEMENTS"
[ -f "$TFVARS" ] || fail "Terraform tfvars not found: $TFVARS"

ERRORS=0

# Strip comments from both files before matching
strip_comments() {
  sed 's/#.*$//' "$1"
}

extract_assumable_role_arns() {
  strip_comments "$TFVARS" | awk '
    /^[[:space:]]*assumable_role_arns[[:space:]]*=/ {
      in_list = 1
      line = $0
      sub(/^[^=]*=/, "", line)
      print line
      if (line ~ /\]/) {
        in_list = 0
      }
      next
    }
    in_list {
      print
      if ($0 ~ /\]/) {
        in_list = 0
      }
    }
  ' | grep -oE '"arn:[^"]+"' | tr -d '"' | sort -u || true
}

ACTIVE_ENTITLEMENTS="$(strip_comments "$ENTITLEMENTS")"

# Check 0: sample placeholders should never reach an ECS image.
if grep -Eq '<[^>]+>|REPLACE(_ME)?|example\.com' <<< "$ACTIVE_ENTITLEMENTS"; then
  echo "ERROR: entitlements contains sample placeholder values in active configuration"
  ERRORS=$((ERRORS + 1))
fi

# Check 1: direct access (only in uncommented lines)
if grep -qE 'role_arn\s*=\s*"direct"' <<< "$ACTIVE_ENTITLEMENTS"; then
  if ! strip_comments "$TFVARS" | grep -qE 'enable_direct_access\s*=\s*true'; then
    echo "ERROR: entitlements uses role_arn = \"direct\" but enable_direct_access is not true in $TFVARS"
    ERRORS=$((ERRORS + 1))
  fi
fi

# Check 2: local AWS profiles cannot work inside the ECS task.
if grep -qE 'role_arn\s*=\s*"profile:[^"]*"' <<< "$ACTIVE_ENTITLEMENTS"; then
  echo "ERROR: entitlements uses role_arn = \"profile:*\", which is local-development only and cannot be deployed to ECS"
  ERRORS=$((ERRORS + 1))
fi

# Check 3: all role ARNs present in assumable_role_arns (uncommented lines only)
ROLE_ARNS=$(printf '%s\n' "$ACTIVE_ENTITLEMENTS" | \
  grep -oE 'role_arn\s*=\s*"arn:[^"]+"' | \
  sed 's/role_arn[[:space:]]*=[[:space:]]*//' | tr -d '"' | sort -u || true)
ASSUMABLE_ROLE_ARNS="$(extract_assumable_role_arns)"

for arn in $ROLE_ARNS; do
  if ! grep -qE '^arn:aws[a-zA-Z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$' <<< "$arn"; then
    echo "ERROR: role_arn in entitlements must be a concrete IAM role ARN without wildcards (value redacted)"
    ERRORS=$((ERRORS + 1))
    continue
  fi

  if ! grep -qxF "$arn" <<< "$ASSUMABLE_ROLE_ARNS"; then
    echo "ERROR: a role_arn in entitlements is not listed in $TFVARS assumable_role_arns (value redacted)"
    ERRORS=$((ERRORS + 1))
  fi
done

# Check 4: ECS Exec needs scoped AssumeRole credentials. Direct access may be
# valid for inventory/logs, but the ECS exec route intentionally rejects
# direct/profile credentials in non-mock deployments.
ECS_EXEC_LOCAL_RULES=$(printf '%s\n' "$ACTIVE_ENTITLEMENTS" | awk '
function flush_rule() {
  if (in_rule && can_exec && has_local_role) {
    print rule_id
  }
}
/^[[:space:]]*\[\[rules\]\][[:space:]]*$/ {
  flush_rule()
  in_rule = 1
  can_exec = 0
  has_local_role = 0
  rule_id = "<unknown>"
  next
}
in_rule && /^[[:space:]]*id[[:space:]]*=/ {
  rule_id = $0
  sub(/^[^"]*"/, "", rule_id)
  sub(/".*$/, "", rule_id)
}
in_rule && /^[[:space:]]*can_use_ecs_exec[[:space:]]*=[[:space:]]*true/ {
  can_exec = 1
}
in_rule && /role_arn[[:space:]]*=[[:space:]]*"(direct|profile:[^"]*)"/ {
  has_local_role = 1
}
END {
  flush_rule()
}
')

if [ -n "$ECS_EXEC_LOCAL_RULES" ]; then
  while IFS= read -r rule_id; do
    echo "ERROR: rule '$rule_id' enables can_use_ecs_exec but uses direct/profile credentials; ECS Exec deployments require an AssumeRole ARN"
  done <<< "$ECS_EXEC_LOCAL_RULES"
  ERRORS=$((ERRORS + 1))
fi

# Check 5: mirror control-plane ECS rule shape invariants before image build.
ECS_RULE_SHAPE_ERRORS=$(printf '%s\n' "$ACTIVE_ENTITLEMENTS" | awk '
function flush_rule() {
  if (in_rule && can_exec && !can_view) {
    print rule_id "|exec_without_view"
  }
  if (in_rule && (can_view || can_exec) && !has_clusters) {
    print rule_id "|missing_clusters"
  }
}
/^[[:space:]]*\[\[rules\]\][[:space:]]*$/ {
  flush_rule()
  in_rule = 1
  in_clusters = 0
  can_view = 0
  can_exec = 0
  has_clusters = 0
  rule_id = "<unknown>"
  next
}
in_rule && /^[[:space:]]*id[[:space:]]*=/ {
  rule_id = $0
  sub(/^[^"]*"/, "", rule_id)
  sub(/".*$/, "", rule_id)
}
in_rule && /^[[:space:]]*can_view_ecs[[:space:]]*=[[:space:]]*true/ {
  can_view = 1
}
in_rule && /^[[:space:]]*can_use_ecs_exec[[:space:]]*=[[:space:]]*true/ {
  can_exec = 1
}
in_rule && /^[[:space:]]*allowed_clusters[[:space:]]*=/ {
  in_clusters = 1
}
in_rule && in_clusters && /"[^"]+"/ {
  has_clusters = 1
}
in_rule && in_clusters && /\]/ {
  in_clusters = 0
}
END {
  flush_rule()
}
')

if [ -n "$ECS_RULE_SHAPE_ERRORS" ]; then
  while IFS='|' read -r rule_id error_kind; do
    case "$error_kind" in
      exec_without_view)
        echo "ERROR: rule '$rule_id' has can_use_ecs_exec=true but can_view_ecs=false; ECS Exec must imply ECS view in the same rule"
        ;;
      missing_clusters)
        echo "ERROR: rule '$rule_id' grants ECS access but allowed_clusters is empty"
        ;;
    esac
  done <<< "$ECS_RULE_SHAPE_ERRORS"
  ERRORS=$((ERRORS + 1))
fi

# Check 6: mirror SSM shell-scope invariant before image build.
SSM_RULE_SHAPE_ERRORS=$(printf '%s\n' "$ACTIVE_ENTITLEMENTS" | awk '
function flush_rule() {
  if (in_rule && can_ssm && !has_os_users) {
    print rule_id
  }
}
/^[[:space:]]*\[\[rules\]\][[:space:]]*$/ {
  flush_rule()
  in_rule = 1
  in_os_users = 0
  can_ssm = 0
  has_os_users = 0
  rule_id = "<unknown>"
  next
}
in_rule && /^[[:space:]]*id[[:space:]]*=/ {
  rule_id = $0
  sub(/^[^"]*"/, "", rule_id)
  sub(/".*$/, "", rule_id)
}
in_rule && /^[[:space:]]*can_use_ssm[[:space:]]*=[[:space:]]*true/ {
  can_ssm = 1
}
in_rule && /^[[:space:]]*allowed_os_users[[:space:]]*=/ {
  in_os_users = 1
}
in_rule && in_os_users && /"[^"]+"/ {
  has_os_users = 1
}
in_rule && in_os_users && /\]/ {
  in_os_users = 0
}
END {
  flush_rule()
}
')

if [ -n "$SSM_RULE_SHAPE_ERRORS" ]; then
  while IFS= read -r rule_id; do
    echo "ERROR: rule '$rule_id' has can_use_ssm=true but no allowed_os_users; set explicit users or [\"*\"] for unrestricted shell access"
  done <<< "$SSM_RULE_SHAPE_ERRORS"
  ERRORS=$((ERRORS + 1))
fi

if [ "$ERRORS" -gt 0 ]; then
  echo "Validation failed with $ERRORS error(s)."
  exit 1
fi

echo "Entitlements/Terraform validation passed."
