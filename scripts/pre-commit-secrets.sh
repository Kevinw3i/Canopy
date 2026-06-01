#!/usr/bin/env bash
# pre-commit hook: block commits that contain sensitive data
# Install: ln -sf ../../scripts/pre-commit-secrets.sh .git/hooks/pre-commit

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

BLOCKED=0

# ── Local-only sensitive identifiers (loaded from .git/info) ────
# Keep repo-safe defaults here. Add your real values in:
#   .git/info/pre-commit-secrets.local
#
# Example:
#   REAL_ACCOUNT_IDS=("123456789012" "210987654321")
#   PRIVATE_PROFILES=("my-private-profile")
REAL_ACCOUNT_IDS=()
PRIVATE_PROFILES=()

LOCAL_CONFIG=".git/info/pre-commit-secrets.local"
if [ -f "$LOCAL_CONFIG" ]; then
  # shellcheck source=/dev/null
  . "$LOCAL_CONFIG"
fi

# Safe/mock account IDs that are OK to commit
SAFE_PATTERNS="111111111111|222222222222|333333333333|999999999999|123456789012|234567890123|000000000000"

staged_diff=$(git diff --cached --diff-filter=ACMR -U0)

for acct in ${REAL_ACCOUNT_IDS[@]+"${REAL_ACCOUNT_IDS[@]}"}; do
  matches=$(echo "$staged_diff" | grep -n "^\+.*${acct}" || true)
  if [ -n "$matches" ]; then
    echo -e "${RED}BLOCKED:${NC} Real AWS account ID ${YELLOW}${acct}${NC} found in staged changes:"
    echo "$matches" | head -5
    BLOCKED=1
  fi
done

# ── 2. AWS access keys (AKIA* = long-term, ASIA* = STS temp) ───
# Only flag keys that look real (20 chars alphanumeric after prefix)
real_keys=$(echo "$staged_diff" | grep -oE '^\+.*(AKIA|ASIA)[A-Z0-9]{16}' | grep -vE 'ASIATEST|ASIADEVMOCK|AKIAEXAMPLE' || true)
if [ -n "$real_keys" ]; then
  echo -e "${RED}BLOCKED:${NC} Possible real AWS access key found:"
  echo "$real_keys" | head -5
  BLOCKED=1
fi

# ── 3. AWS profile names that look private ──────────────────────
for prof in ${PRIVATE_PROFILES[@]+"${PRIVATE_PROFILES[@]}"}; do
  matches=$(echo "$staged_diff" | grep -inE "^\+.*(profile|AWS_PROFILE).*${prof}" || true)
  if [ -n "$matches" ]; then
    echo -e "${RED}BLOCKED:${NC} Private AWS profile ${YELLOW}${prof}${NC} found in staged changes:"
    echo "$matches" | head -5
    BLOCKED=1
  fi
done

# ── 4. Hardcoded secrets / tokens ───────────────────────────────
secret_patterns='(password|secret_key|api_key|private_key|auth_token)\s*=\s*"[^"]{8,}"'
# Exclude lines that are clearly examples/placeholders
secrets=$(echo "$staged_diff" | grep -iEo "^\+.*${secret_patterns}" \
  | grep -ivE '(example|placeholder|mock|test|sample|not-used|local-dev|changeme|TODO|xxx)' || true)
if [ -n "$secrets" ]; then
  echo -e "${RED}BLOCKED:${NC} Possible hardcoded secret found:"
  echo "$secrets" | head -5
  BLOCKED=1
fi

# ── 5. Sensitive file patterns that should never be committed ───
sensitive_files=$(git diff --cached --name-only --diff-filter=ACMR | grep -iE '\.(pem|key|pfx|p12)$|\.env$|credentials$|\.tfvars$|\.tfstate' || true)
if [ -n "$sensitive_files" ]; then
  echo -e "${RED}BLOCKED:${NC} Sensitive file(s) staged for commit:"
  echo "$sensitive_files"
  BLOCKED=1
fi

# ── Result ──────────────────────────────────────────────────────
if [ "$BLOCKED" -ne 0 ]; then
  echo ""
  echo -e "${YELLOW}Commit aborted.${NC} Remove sensitive data or use ${YELLOW}git commit --no-verify${NC} to bypass (not recommended)."
  exit 1
fi

exit 0
