#!/usr/bin/env bash
# Validates that an entitlements file is consistent with Terraform variables.
# Usage: ./scripts/validate-entitlements.sh <entitlements.toml> <terraform.tfvars>
#
# Checks:
#   0. Active sample placeholders are rejected before production image builds
#   1. If any account uses role_arn = "direct", enable_direct_access must be true in tfvars
#   2. profile:* role_arn entries are rejected for ECS deployments
#   3. role_arn entries must be direct, profile:*, or concrete ARN values
#   4. All role ARNs in entitlements must appear in assumable_role_arns in tfvars,
#      or AWS Organizations templates must appear in assumable_role_arn_patterns
#   5. ECS Exec rules must use AssumeRole ARNs, not direct/profile credentials
#   6. ECS Exec must imply ECS view, ECS access rules need allowed_clusters,
#      and broad ECS cluster wildcards require explicit opt-in
#   7. SSM access rules need explicit allowed_os_users
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

extract_assumable_role_arn_patterns() {
  strip_comments "$TFVARS" | awk '
    /^[[:space:]]*assumable_role_arn_patterns[[:space:]]*=/ {
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

extract_role_arn_values() {
  printf '%s\n' "$ACTIVE_ENTITLEMENTS" | awk '
    {
      line = $0
      while (match(line, /role_arn[[:space:]]*=[[:space:]]*["\047][^"\047]+["\047]/)) {
        value = substr(line, RSTART, RLENGTH)
        sub(/^[^"\047]*["\047]/, "", value)
        sub(/["\047]$/, "", value)
        print value
        line = substr(line, RSTART + RLENGTH)
      }
    }
  ' | sort -u || true
}

role_template_to_pattern() {
  printf '%s\n' "$1" | sed 's/{account_id}/*/g'
}

ACTIVE_ENTITLEMENTS="$(strip_comments "$ENTITLEMENTS")"

# Check 0: sample placeholders should never reach an ECS image.
if grep -Eq '<[^>]+>|REPLACE(_ME)?|example\.com' <<< "$ACTIVE_ENTITLEMENTS"; then
  echo "ERROR: entitlements contains sample placeholder values in active configuration"
  ERRORS=$((ERRORS + 1))
fi

# Check 1: direct access (only in uncommented lines)
if grep -qE "role_arn[[:space:]]*=[[:space:]]*['\"]direct['\"]" <<< "$ACTIVE_ENTITLEMENTS"; then
  if ! strip_comments "$TFVARS" | grep -qE 'enable_direct_access\s*=\s*true'; then
    echo "ERROR: entitlements uses role_arn = \"direct\" but enable_direct_access is not true in $TFVARS"
    ERRORS=$((ERRORS + 1))
  fi
fi

# Check 2: local AWS profiles cannot work inside the ECS task.
if grep -qE "role_arn[[:space:]]*=[[:space:]]*['\"]profile:[^'\"]*['\"]" <<< "$ACTIVE_ENTITLEMENTS"; then
  echo "ERROR: entitlements uses role_arn = \"profile:*\", which is local-development only and cannot be deployed to ECS"
  ERRORS=$((ERRORS + 1))
fi

ROLE_VALUES="$(extract_role_arn_values)"

# Check 3a: Organizations account placeholders must be paired with a role template,
# and role templates must only be used with account_id="*".
ORG_ACCOUNT_TEMPLATE_ERRORS=$(printf '%s\n' "$ACTIVE_ENTITLEMENTS" | awk '
function extract_value(line, key, value) {
  if (match(line, key "[[:space:]]*=[[:space:]]*[\"\\047][^\"\\047]+[\"\\047]")) {
    value = substr(line, RSTART, RLENGTH)
    sub(/^[^"\047]*["\047]/, "", value)
    sub(/["\047]$/, "", value)
    return value
  }
  return ""
}
function flush_account() {
  if (!in_account) {
    return
  }
  if (account_id == "*" && role_arn !~ /\{account_id\}/) {
    print "placeholder_without_template"
  }
  if (account_id != "" && account_id != "*" && role_arn ~ /\{account_id\}/) {
    print "template_without_placeholder"
  }
}
{
  inline_account_id = extract_value($0, "account_id")
  inline_role_arn = extract_value($0, "role_arn")
  if (inline_account_id != "" || inline_role_arn != "") {
    if (inline_account_id == "*" && inline_role_arn != "" && inline_role_arn !~ /\{account_id\}/) {
      print "placeholder_without_template"
    }
    if (inline_account_id != "" && inline_account_id != "*" && inline_role_arn ~ /\{account_id\}/) {
      print "template_without_placeholder"
    }
  }
}
/^[[:space:]]*\[\[rules\.allowed_accounts\]\][[:space:]]*$/ {
  flush_account()
  in_account = 1
  account_id = ""
  role_arn = ""
  next
}
in_account && /^[[:space:]]*\[/ {
  flush_account()
  in_account = 0
}
in_account && /^[[:space:]]*account_id[[:space:]]*=/ {
  account_id = extract_value($0, "account_id")
}
in_account && /^[[:space:]]*role_arn[[:space:]]*=/ {
  role_arn = extract_value($0, "role_arn")
}
END {
  flush_account()
}
')

if [ -n "$ORG_ACCOUNT_TEMPLATE_ERRORS" ]; then
  while IFS= read -r error_kind; do
    case "$error_kind" in
      placeholder_without_template)
        echo "ERROR: account_id=\"*\" requires an AWS Organizations role_arn template containing {account_id}"
        ;;
      template_without_placeholder)
        echo "ERROR: role_arn templates containing {account_id} require account_id=\"*\""
        ;;
    esac
  done <<< "$ORG_ACCOUNT_TEMPLATE_ERRORS"
  ERRORS=$((ERRORS + 1))
fi

# Check 3: role_arn entries must use a supported credential mode.
while IFS= read -r role_value; do
  [ -n "$role_value" ] || continue
  case "$role_value" in
    direct|profile:*|arn:*) ;;
    *)
      echo "ERROR: role_arn in entitlements must be \"direct\", \"profile:*\", or a concrete IAM role ARN (value redacted)"
      ERRORS=$((ERRORS + 1))
      ;;
  esac
done <<< "$ROLE_VALUES"

# Check 4: all role ARNs present in assumable_role_arns (uncommented lines only)
ROLE_ARNS=$(printf '%s\n' "$ROLE_VALUES" | grep -E '^arn:' || true)
ASSUMABLE_ROLE_ARNS="$(extract_assumable_role_arns)"
ASSUMABLE_ROLE_ARN_PATTERNS="$(extract_assumable_role_arn_patterns)"

for arn in $ROLE_ARNS; do
  if grep -qF '{account_id}' <<< "$arn"; then
    TOKEN_COUNT=$(grep -oF '{account_id}' <<< "$arn" | wc -l | tr -d '[:space:]')
    if [ "$TOKEN_COUNT" != "1" ] || ! grep -qE '^arn:aws[a-zA-Z-]*:iam::\{account_id\}:role/[A-Za-z0-9+=,.@_/-]+$' <<< "$arn"; then
      echo "ERROR: AWS Organizations role_arn template must be an IAM role ARN with exactly one {account_id} token in the account-id segment (value redacted)"
      ERRORS=$((ERRORS + 1))
      continue
    fi

    arn_pattern="$(role_template_to_pattern "$arn")"
    if ! grep -qxF "$arn_pattern" <<< "$ASSUMABLE_ROLE_ARN_PATTERNS"; then
      echo "ERROR: an AWS Organizations role_arn template in entitlements is not listed in $TFVARS assumable_role_arn_patterns (value redacted)"
      ERRORS=$((ERRORS + 1))
    fi
    continue
  fi

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

# Check 5: ECS Exec needs scoped AssumeRole credentials. Direct access may be
# valid for inventory/logs, but the ECS exec route intentionally rejects
# direct/profile credentials in non-mock deployments.
ECS_EXEC_LOCAL_RULES=$(printf '%s\n' "$ACTIVE_ENTITLEMENTS" | awk '
function feature_true(line, key) {
  return line ~ "^[[:space:]]*" key "[[:space:]]*=[[:space:]]*true([[:space:]]*$|[[:space:],}])" ||
    line ~ "^[[:space:]]*features[[:space:]]*=[[:space:]]*[{].*" key "[[:space:]]*=[[:space:]]*true([[:space:]]*$|[[:space:],}])"
}
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
in_rule && feature_true($0, "can_use_ecs_exec") {
  can_exec = 1
}
in_rule && /role_arn[[:space:]]*=[[:space:]]*["\047](direct|profile:[^"\047]*)["\047]/ {
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

# Check 6: mirror control-plane ECS rule shape invariants before image build.
ECS_RULE_SHAPE_ERRORS=$(printf '%s\n' "$ACTIVE_ENTITLEMENTS" | awk '
function feature_true(line, key) {
  return line ~ "^[[:space:]]*" key "[[:space:]]*=[[:space:]]*true([[:space:]]*$|[[:space:],}])" ||
    line ~ "^[[:space:]]*features[[:space:]]*=[[:space:]]*[{].*" key "[[:space:]]*=[[:space:]]*true([[:space:]]*$|[[:space:],}])"
}
function cluster_name(pattern, rest, pos) {
  rest = pattern
  while ((pos = index(rest, "cluster/")) > 0) {
    rest = substr(rest, pos + 8)
  }
  return rest
}
function validate_cluster(pattern, name, first_star, literal_prefix_len) {
  if (pattern == "*") {
    has_bare_star = 1
    return
  }

  name = cluster_name(pattern)
  if (name ~ /[?\[\]{}\\]/) {
    has_invalid_glob_chars = 1
  }

  first_star = index(name, "*")
  if (first_star > 0) {
    literal_prefix_len = length(substr(name, 1, first_star - 1))
    if (literal_prefix_len < 3) {
      has_broad_cluster_wildcard = 1
    }
  }
}
function scan_cluster_entries(line, entry) {
  while (match(line, /["\047][^"\047]+["\047]/)) {
    entry = substr(line, RSTART, RLENGTH)
    sub(/^["\047]/, "", entry)
    sub(/["\047]$/, "", entry)
    has_clusters = 1
    validate_cluster(entry)
    line = substr(line, RSTART + RLENGTH)
  }
}
function flush_rule() {
  if (in_rule && can_exec && !can_view) {
    print rule_id "|exec_without_view"
  }
  if (in_rule && (can_view || can_exec) && !has_clusters) {
    print rule_id "|missing_clusters"
  }
  if (in_rule && has_bare_star) {
    print rule_id "|bare_star_cluster"
  }
  if (in_rule && has_invalid_glob_chars) {
    print rule_id "|invalid_cluster_glob"
  }
  if (in_rule && has_broad_cluster_wildcard && !allow_broad_cluster_discovery) {
    print rule_id "|broad_cluster_without_opt_in"
  }
}
/^[[:space:]]*\[\[rules\]\][[:space:]]*$/ {
  flush_rule()
  in_rule = 1
  in_rule_table = 1
  in_clusters = 0
  can_view = 0
  can_exec = 0
  has_clusters = 0
  has_bare_star = 0
  has_invalid_glob_chars = 0
  has_broad_cluster_wildcard = 0
  allow_broad_cluster_discovery = 0
  rule_id = "<unknown>"
  next
}
in_rule && /^[[:space:]]*\[/ {
  in_rule_table = 0
  in_clusters = 0
}
in_rule && /^[[:space:]]*id[[:space:]]*=/ {
  rule_id = $0
  sub(/^[^"]*"/, "", rule_id)
  sub(/".*$/, "", rule_id)
}
in_rule && feature_true($0, "can_view_ecs") {
  can_view = 1
}
in_rule && feature_true($0, "can_use_ecs_exec") {
  can_exec = 1
}
in_rule && in_rule_table && /^[[:space:]]*allow_broad_cluster_discovery[[:space:]]*=[[:space:]]*true/ {
  allow_broad_cluster_discovery = 1
}
in_rule && in_rule_table && /^[[:space:]]*allowed_clusters[[:space:]]*=/ {
  in_clusters = 1
  scan_cluster_entries($0)
  if ($0 ~ /\]/) {
    in_clusters = 0
  }
  next
}
in_rule && in_clusters {
  scan_cluster_entries($0)
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
      bare_star_cluster)
        echo "ERROR: rule '$rule_id' has invalid allowed_clusters entry; bare '*' is not allowed"
        ;;
      invalid_cluster_glob)
        echo "ERROR: rule '$rule_id' has invalid allowed_clusters entry; only literal characters and '*' are allowed in cluster name patterns"
        ;;
      broad_cluster_without_opt_in)
        echo "ERROR: rule '$rule_id' has broad allowed_clusters wildcard; wildcard cluster patterns require at least 3 literal characters before '*' unless allow_broad_cluster_discovery=true"
        ;;
    esac
  done <<< "$ECS_RULE_SHAPE_ERRORS"
  ERRORS=$((ERRORS + 1))
fi

# Check 7: mirror SSM shell-scope invariant before image build.
SSM_RULE_SHAPE_ERRORS=$(printf '%s\n' "$ACTIVE_ENTITLEMENTS" | awk '
function feature_true(line, key) {
  return line ~ "^[[:space:]]*" key "[[:space:]]*=[[:space:]]*true([[:space:]]*$|[[:space:],}])" ||
    line ~ "^[[:space:]]*features[[:space:]]*=[[:space:]]*[{].*" key "[[:space:]]*=[[:space:]]*true([[:space:]]*$|[[:space:],}])"
}
function flush_rule() {
  if (in_rule && can_ssm && !has_os_users) {
    print rule_id
  }
}
/^[[:space:]]*\[\[rules\]\][[:space:]]*$/ {
  flush_rule()
  in_rule = 1
  in_rule_table = 1
  in_os_users = 0
  can_ssm = 0
  has_os_users = 0
  rule_id = "<unknown>"
  next
}
in_rule && /^[[:space:]]*\[/ {
  in_rule_table = 0
  in_os_users = 0
}
in_rule && /^[[:space:]]*id[[:space:]]*=/ {
  rule_id = $0
  sub(/^[^"]*"/, "", rule_id)
  sub(/".*$/, "", rule_id)
}
in_rule && feature_true($0, "can_use_ssm") {
  can_ssm = 1
}
in_rule && in_rule_table && /^[[:space:]]*allowed_os_users[[:space:]]*=/ {
  in_os_users = 1
}
in_rule && in_os_users && /["\047][^"\047]+["\047]/ {
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
