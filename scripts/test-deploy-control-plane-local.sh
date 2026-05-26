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
aws_region = "us-west-2"
cpu_architecture = "X86_64"
enable_direct_access = false
assumable_role_arns = [
  "arn:aws:iam::123456789012:role/CanopyRole",
]
EOF

cat > "$REPO_TMP_DIR/bin/aws" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

if [ "${CANOPY_EXPECT_AWS_PROFILE_UNSET:-0}" = "1" ] && [ "${AWS_PROFILE+x}" = "x" ]; then
  echo "expected AWS_PROFILE to be unset" >&2
  exit 1
fi

if [ "${CANOPY_ALLOW_AWS:-0}" != "1" ]; then
  echo "ERROR: aws should not be called for --plan-only" >&2
  exit 1
fi

service="${1:-}"
operation="${2:-}"
case "$service:$operation" in
  ecr:describe-images)
    state_dir="${CANOPY_AWS_STATE_DIR:?}"
    count_file="$state_dir/aws-describe-images-count"
    count=0
    [ -f "$count_file" ] && count="$(cat "$count_file")"
    count=$((count + 1))
    printf '%s\n' "$count" > "$count_file"
    if [ "$count" -eq 1 ]; then
      echo "An error occurred (ImageNotFoundException) when calling the DescribeImages operation: image not found" >&2
      exit 254
    fi
    printf 'stub describe-images table\n'
    ;;
  ecr:get-login-password)
    printf 'stub-password\n'
    ;;
  ecs:wait|ecs:describe-services|elbv2:describe-target-health)
    printf 'stub %s %s\n' "$service" "$operation"
    ;;
  *)
    echo "unexpected aws command: $*" >&2
    exit 1
    ;;
esac
SH
chmod +x "$REPO_TMP_DIR/bin/aws"

cat > "$REPO_TMP_DIR/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

if [ "${CANOPY_ALLOW_DOCKER:-0}" != "1" ]; then
  echo "ERROR: docker should not be called for --plan-only" >&2
  exit 1
fi

case "${1:-}" in
  login)
    cat >/dev/null
    ;;
  build|push)
    ;;
  *)
    echo "unexpected docker command: $*" >&2
    exit 1
    ;;
esac
SH
chmod +x "$REPO_TMP_DIR/bin/docker"

cat > "$REPO_TMP_DIR/bin/terraform" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

if [ "${CANOPY_EXPECT_AWS_PROFILE_UNSET:-0}" = "1" ] && [ "${AWS_PROFILE+x}" = "x" ]; then
  echo "expected AWS_PROFILE to be unset" >&2
  exit 1
fi

chdir="."
if [[ "${1:-}" == -chdir=* ]]; then
  chdir="${1#-chdir=}"
  shift
fi

cmd="${1:-}"
shift || true

case "$cmd" in
  output)
    if [ "${CANOPY_ALLOW_TERRAFORM_OUTPUTS:-0}" != "1" ]; then
      exit 1
    fi
    if [ "${1:-}" = "-raw" ]; then
      shift
    fi
    case "${1:-}" in
      ecr_repository_url)
        printf '123456789012.dkr.ecr.us-west-2.amazonaws.com/canopy/control-plane\n'
        ;;
      log_group_name)
        printf '/ecs/canopy/control-plane\n'
        ;;
      alb_dns_name)
        printf 'canopy-alb.example.com\n'
        ;;
      *)
        exit 1
        ;;
    esac
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
  apply)
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
    AWS_REGION= \
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

grep -qF -- "AWS profile:       test-profile" "$PLAN_ONLY_OUT"
grep -qF -- "AWS region:        us-west-2" "$PLAN_ONLY_OUT"
grep -qF -- "Plan written to .canopy-test-deploy-$$/infra/tfplan.phase2" "$PLAN_ONLY_OUT"
if grep -qF -- "Resolve ECR repository" "$PLAN_ONLY_OUT"; then
  cat "$PLAN_ONLY_OUT" >&2
  echo "ERROR: --plan-only should stop before resolving ECR." >&2
  exit 1
fi

NO_PROFILE_OUT="$TMP_DIR/no-profile.out"
if ! env \
  PATH="$REPO_TMP_DIR/bin:$PATH" \
  TERRAFORM_DIR=".canopy-test-deploy-$$/infra" \
  AWS_PROFILE= \
  CANOPY_EXPECT_AWS_PROFILE_UNSET=1 \
  "$DEPLOY_SCRIPT" cp-v0.1.0 \
  --plan-only \
  --entitlements ".canopy-test-deploy-$$/entitlements.toml" \
  --cluster canopy \
  --service control-plane \
  > "$NO_PROFILE_OUT" 2>&1; then
  cat "$NO_PROFILE_OUT" >&2
  echo "ERROR: expected default AWS credential chain scenario to pass." >&2
  exit 1
fi
grep -qF -- "AWS profile:       default credential chain" "$NO_PROFILE_OUT"
grep -qF -- "Plan written to .canopy-test-deploy-$$/infra/tfplan.phase2" "$NO_PROFILE_OUT"

FULL_DEPLOY_OUT="$TMP_DIR/full-deploy.out"
rm -f "$TMP_DIR/aws-describe-images-count"
if ! env \
  PATH="$REPO_TMP_DIR/bin:$PATH" \
  TERRAFORM_DIR=".canopy-test-deploy-$$/infra" \
  AWS_PROFILE= \
  CANOPY_EXPECT_AWS_PROFILE_UNSET=1 \
  CANOPY_ALLOW_AWS=1 \
  CANOPY_ALLOW_DOCKER=1 \
  CANOPY_ALLOW_TERRAFORM_OUTPUTS=1 \
  CANOPY_AWS_STATE_DIR="$TMP_DIR" \
  "$DEPLOY_SCRIPT" cp-v0.1.0 \
  --yes \
  --entitlements ".canopy-test-deploy-$$/entitlements.toml" \
  --cluster canopy \
  --service control-plane \
  --target-group-arn "arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/canopy/abcdef1234567890" \
  > "$FULL_DEPLOY_OUT" 2>&1; then
  cat "$FULL_DEPLOY_OUT" >&2
  echo "ERROR: expected stubbed full deploy to pass with default AWS credential chain." >&2
  exit 1
fi
grep -qF -- "AWS profile:       default credential chain" "$FULL_DEPLOY_OUT"
grep -qF -- "Tag is available: cp-v0.1.0" "$FULL_DEPLOY_OUT"
grep -qF -- "Image deployed: 123456789012.dkr.ecr.us-west-2.amazonaws.com/canopy/control-plane:cp-v0.1.0" "$FULL_DEPLOY_OUT"
grep -qF -- "CloudWatch:     aws logs tail /ecs/canopy/control-plane --region us-west-2 --since 30m --follow" "$FULL_DEPLOY_OUT"
if grep -qF -- "AWS_PROFILE=" "$FULL_DEPLOY_OUT"; then
  cat "$FULL_DEPLOY_OUT" >&2
  echo "ERROR: default credential chain output should not suggest AWS_PROFILE=." >&2
  exit 1
fi
if [ "$(cat "$TMP_DIR/aws-describe-images-count")" != "2" ]; then
  cat "$FULL_DEPLOY_OUT" >&2
  echo "ERROR: expected ECR describe-images to run before and after push." >&2
  exit 1
fi

TF_VAR_REGION_OUT="$TMP_DIR/tf-var-region.out"
if ! run_plan_only "$TF_VAR_REGION_OUT" TF_VAR_aws_region=ap-southeast-1; then
  cat "$TF_VAR_REGION_OUT" >&2
  echo "ERROR: expected terraform.tfvars region to take precedence over TF_VAR_aws_region." >&2
  exit 1
fi
grep -qF -- "AWS region:        us-west-2" "$TF_VAR_REGION_OUT"

REGION_OVERRIDE_OUT="$TMP_DIR/region-override.out"
if ! run_plan_only "$REGION_OVERRIDE_OUT" AWS_REGION=eu-central-1; then
  cat "$REGION_OVERRIDE_OUT" >&2
  echo "ERROR: expected AWS_REGION override to pass." >&2
  exit 1
fi
grep -qF -- "AWS region:        eu-central-1" "$REGION_OVERRIDE_OUT"

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
