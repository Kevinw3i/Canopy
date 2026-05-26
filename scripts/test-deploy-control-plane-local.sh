#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEPLOY_SCRIPT="$SCRIPT_DIR/deploy-control-plane-local.sh"
TMP_DIR="$(mktemp -d)"
REPO_TMP_DIR="$REPO_ROOT/.canopy-test-deploy-$$"
trap 'rm -rf "$TMP_DIR" "$REPO_TMP_DIR"' EXIT

expect_failure() {
  local name="$1"
  local expected="$2"
  shift 2

  if "$DEPLOY_SCRIPT" "$@" > "$TMP_DIR/$name.out" 2>&1; then
    cat "$TMP_DIR/$name.out" >&2
    echo "ERROR: expected $name to fail." >&2
    exit 1
  fi

  grep -qF -- "$expected" "$TMP_DIR/$name.out"
}

expect_failure "missing-tag" "Usage:"
expect_failure "invalid-tag" "Invalid Docker image tag" "-bad-tag"
expect_failure "latest-tag" "Using 'latest' is not allowed" "latest"
expect_failure "latest-case-tag" "Using 'latest' is not allowed" "LaTeSt"
expect_failure "extra-tag" "Only one image tag is allowed" "cp-v0.1.0" "cp-v0.1.1"
expect_failure "empty-profile" "--profile requires a value" "cp-v0.1.0" "--profile" ""
expect_failure "empty-region" "--region requires a value" "cp-v0.1.0" "--region" ""
expect_failure "empty-entitlements" "--entitlements requires a value" "cp-v0.1.0" "--entitlements" ""
expect_failure "empty-platform" "--platform requires a value" "cp-v0.1.0" "--platform" ""
expect_failure "invalid-cargo-jobs-zero" "--cargo-jobs must be a positive integer" "cp-v0.1.0" "--cargo-jobs" "0"
expect_failure "invalid-cargo-jobs-word" "--cargo-jobs must be a positive integer" "cp-v0.1.0" "--cargo-jobs" "fast"
expect_failure "empty-cluster" "--cluster requires a value" "cp-v0.1.0" "--cluster" ""
expect_failure "empty-service" "--service requires a value" "cp-v0.1.0" "--service" ""
expect_failure "empty-target-group" "--target-group requires a value" "cp-v0.1.0" "--target-group" ""
expect_failure "empty-target-group-arn" "--target-group-arn requires a value" "cp-v0.1.0" "--target-group-arn" ""
expect_failure "empty-log-group" "--log-group requires a value" "cp-v0.1.0" "--log-group" ""
expect_failure "unknown-option" "Unknown option: --bogus" "cp-v0.1.0" "--bogus"
expect_failure "parent-entitlements-path" "--entitlements must be a path inside the repo root" "cp-v0.1.0" "--entitlements" "../entitlements.toml"
expect_failure "absolute-entitlements-path" "--entitlements must be a path inside the repo root" "cp-v0.1.0" "--entitlements" "/tmp/entitlements.toml"

mkdir -p "$REPO_TMP_DIR/bin" "$REPO_TMP_DIR/infra"

cat > "$REPO_TMP_DIR/entitlements.toml" <<'EOF'
[[rules]]
id = "ecs"
can_view_ecs = true
allowed_accounts = [
  { account_id = "123456789012", account_name = "prod", role_arn = "arn:aws:iam::123456789012:role/CanopyRole" },
]
EOF

cat > "$REPO_TMP_DIR/infra/terraform.tfvars" <<'EOF'
project = "canopy"
cpu_architecture = "X86_64"
enable_direct_access = false
assumable_role_arns = [
  "arn:aws:iam::123456789012:role/CanopyRole",
]
EOF

cat > "$REPO_TMP_DIR/bin/aws" <<'SH'
#!/usr/bin/env bash
echo "ERROR: aws should not be called for --plan-only" >&2
exit 1
SH
chmod +x "$REPO_TMP_DIR/bin/aws"

cat > "$REPO_TMP_DIR/bin/docker" <<'SH'
#!/usr/bin/env bash
echo "ERROR: docker should not be called for --plan-only" >&2
exit 1
SH
chmod +x "$REPO_TMP_DIR/bin/docker"

cat > "$REPO_TMP_DIR/bin/terraform" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

chdir="."
if [[ "${1:-}" == -chdir=* ]]; then
  chdir="${1#-chdir=}"
  shift
fi

cmd="${1:-}"
shift || true

case "$cmd" in
  output)
    exit 1
    ;;
  init|test)
    exit 0
    ;;
  plan)
    out=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -out=*) out="${1#-out=}" ;;
      esac
      shift
    done
    [ -n "$out" ] && printf 'stub plan\n' > "$chdir/$out"
    ;;
  show)
    printf '%s\n' "${CANOPY_TERRAFORM_SHOW_TEXT:-No changes. Infrastructure is up-to-date.}"
    ;;
  *)
    echo "unexpected terraform command: $cmd" >&2
    exit 1
    ;;
esac
SH
chmod +x "$REPO_TMP_DIR/bin/terraform"

run_plan_only() {
  local output="$1"
  shift

  env \
    PATH="$REPO_TMP_DIR/bin:$PATH" \
    TERRAFORM_DIR=".canopy-test-deploy-$$/infra" \
    "$@" \
    "$DEPLOY_SCRIPT" cp-v0.1.0 \
    --plan-only \
    --profile test-profile \
    --entitlements ".canopy-test-deploy-$$/entitlements.toml" \
    --cluster canopy \
    --service control-plane \
    > "$output" 2>&1
}

PLAN_ONLY_OUT="$TMP_DIR/plan-only.out"
if ! run_plan_only "$PLAN_ONLY_OUT"; then
  cat "$PLAN_ONLY_OUT" >&2
  echo "ERROR: expected plan-only to pass without calling aws/docker." >&2
  exit 1
fi

grep -qF -- "Plan written to .canopy-test-deploy-$$/infra/tfplan.phase2" "$PLAN_ONLY_OUT"
if grep -qF -- "Resolve ECR repository" "$PLAN_ONLY_OUT"; then
  cat "$PLAN_ONLY_OUT" >&2
  echo "ERROR: --plan-only should stop before resolving ECR." >&2
  exit 1
fi

PLATFORM_MISMATCH_OUT="$TMP_DIR/platform-mismatch.out"
if env \
  PATH="$REPO_TMP_DIR/bin:$PATH" \
  TERRAFORM_DIR=".canopy-test-deploy-$$/infra" \
  "$DEPLOY_SCRIPT" cp-v0.1.0 \
  --plan-only \
  --profile test-profile \
  --entitlements ".canopy-test-deploy-$$/entitlements.toml" \
  --cluster canopy \
  --service control-plane \
  --platform linux/arm64 \
  > "$PLATFORM_MISMATCH_OUT" 2>&1; then
  cat "$PLATFORM_MISMATCH_OUT" >&2
  echo "ERROR: expected mismatched Docker platform to fail." >&2
  exit 1
fi
grep -qF -- "--platform linux/arm64 does not match Terraform cpu_architecture=X86_64" "$PLATFORM_MISMATCH_OUT"
if grep -qF -- "Terraform Phase 2 plan" "$PLATFORM_MISMATCH_OUT"; then
  cat "$PLATFORM_MISMATCH_OUT" >&2
  echo "ERROR: platform mismatch should stop before Terraform plan." >&2
  exit 1
fi

DESTROY_PLAN_OUT="$TMP_DIR/plan-destroy.out"
if run_plan_only "$DESTROY_PLAN_OUT" CANOPY_TERRAFORM_SHOW_TEXT='aws_ecs_service.control_plane will be destroyed'; then
  cat "$DESTROY_PLAN_OUT" >&2
  echo "ERROR: expected destroy plan to fail." >&2
  exit 1
fi
grep -qF -- "Terraform plan includes destroy actions" "$DESTROY_PLAN_OUT"
if grep -qF -- "Resolve ECR repository" "$DESTROY_PLAN_OUT"; then
  cat "$DESTROY_PLAN_OUT" >&2
  echo "ERROR: destroy plan should stop before resolving ECR." >&2
  exit 1
fi

REPLACE_PLAN_OUT="$TMP_DIR/plan-replace.out"
if ! run_plan_only "$REPLACE_PLAN_OUT" CANOPY_TERRAFORM_SHOW_TEXT='aws_ecs_task_definition.control_plane must be replaced'; then
  cat "$REPLACE_PLAN_OUT" >&2
  echo "ERROR: expected replacement plan to warn and pass." >&2
  exit 1
fi
grep -qF -- "WARNING: Terraform plan includes replacement actions" "$REPLACE_PLAN_OUT"
grep -qF -- "Plan written to .canopy-test-deploy-$$/infra/tfplan.phase2" "$REPLACE_PLAN_OUT"

echo "deploy-control-plane-local validation tests passed."
