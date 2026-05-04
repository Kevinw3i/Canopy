#!/usr/bin/env bash
# Validates that an entitlements file is consistent with Terraform variables.
# Usage: ./scripts/validate-entitlements.sh <entitlements.toml> <terraform.tfvars>
#
# Checks:
#   1. If any account uses role_arn = "direct", enable_direct_access must be true in tfvars
#   2. All role ARNs in entitlements must appear in assumable_role_arns in tfvars
set -euo pipefail

ENTITLEMENTS="${1:?Usage: $0 <entitlements.toml> <terraform.tfvars>}"
TFVARS="${2:?Usage: $0 <entitlements.toml> <terraform.tfvars>}"

ERRORS=0

# Strip comments from both files before matching
strip_comments() {
  sed 's/#.*$//' "$1"
}

# Check 1: direct access (only in uncommented lines)
if strip_comments "$ENTITLEMENTS" | grep -qE 'role_arn\s*=\s*"direct"'; then
  if ! strip_comments "$TFVARS" | grep -qE 'enable_direct_access\s*=\s*true'; then
    echo "ERROR: entitlements uses role_arn = \"direct\" but enable_direct_access is not true in $TFVARS"
    ERRORS=$((ERRORS + 1))
  fi
fi

# Check 2: all role ARNs present in assumable_role_arns (uncommented lines only)
ROLE_ARNS=$(strip_comments "$ENTITLEMENTS" | \
  grep -oE 'role_arn\s*=\s*"arn:aws:iam::[^"]+"' | \
  sed 's/role_arn[[:space:]]*=[[:space:]]*//' | tr -d '"' | sort -u || true)

for arn in $ROLE_ARNS; do
  if ! strip_comments "$TFVARS" | grep -qF "$arn"; then
    echo "ERROR: a role_arn in entitlements is not listed in $TFVARS assumable_role_arns (value redacted)"
    ERRORS=$((ERRORS + 1))
  fi
done

if [ "$ERRORS" -gt 0 ]; then
  echo "Validation failed with $ERRORS error(s)."
  exit 1
fi

echo "Entitlements/Terraform validation passed."
