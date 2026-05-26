#!/usr/bin/env bash
# Build the control-plane Docker image locally, push it to ECR, then deploy it
# to ECS through Terraform Phase 2.
#
# Usage:
#   ./scripts/deploy-control-plane-local.sh cp-v0.1.0
#   ./scripts/deploy-control-plane-local.sh cp-v0.1.0 --yes
#   AWS_PROFILE=your-aws-profile ./scripts/deploy-control-plane-local.sh cp-v0.1.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Default is a placeholder so the script never ships an internal profile
# name. Override with AWS_PROFILE env var or --profile flag.
AWS_PROFILE_NAME="${AWS_PROFILE:-your-aws-profile}"
AWS_REGION="${AWS_REGION:-ap-northeast-1}"
TERRAFORM_DIR="${TERRAFORM_DIR:-infra}"
ENTITLEMENTS_FILE="${ENTITLEMENTS_FILE:-entitlements.toml}"
DOCKER_PLATFORM="${DOCKER_PLATFORM:-}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
ECS_CLUSTER="${ECS_CLUSTER:-canopy}"
ECS_SERVICE="${ECS_SERVICE:-control-plane}"
TARGET_GROUP_NAME="${TARGET_GROUP_NAME:-canopy-tg}"
PLAN_FILE="${PLAN_FILE:-tfplan.phase2}"

IMAGE_TAG=""
YES=0
PLAN_ONLY=0
TAIL_LOGS=0

usage() {
  cat <<EOF
Usage:
  $0 <image-tag> [options]

Example:
  $0 cp-v0.1.0
  $0 cp-v0.1.0 --yes

Options:
  --profile <name>        AWS CLI profile. Default: ${AWS_PROFILE_NAME}
  --region <region>       AWS region. Default: ${AWS_REGION}
  --entitlements <path>   Entitlements file in repo root. Default: ${ENTITLEMENTS_FILE}
  --platform <platform>   Docker platform. Default: auto from Terraform cpu_architecture
  --cargo-jobs <n>        Cargo parallel jobs inside Docker. Default: ${CARGO_BUILD_JOBS}
  --cluster <name>        ECS cluster name. Default: ${ECS_CLUSTER}
  --service <name>        ECS service name. Default: ${ECS_SERVICE}
  --target-group <name>   ALB target group name. Default: ${TARGET_GROUP_NAME}
  --plan-only             Stop after writing the Terraform plan. Does not build or push the image.
  --tail-logs             Tail CloudWatch logs after deploy.
  --yes                   Do not prompt before AWS-changing steps.
  -h, --help              Show this help.

Environment overrides:
  AWS_PROFILE, AWS_REGION, TERRAFORM_DIR, ENTITLEMENTS_FILE, DOCKER_PLATFORM,
  CARGO_BUILD_JOBS, ECS_CLUSTER, ECS_SERVICE, TARGET_GROUP_NAME, PLAN_FILE
EOF
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

confirm() {
  local prompt="$1"

  if [ "$YES" -eq 1 ]; then
    return 0
  fi

  printf '%s [y/N] ' "$prompt"
  read -r answer
  case "$answer" in
    y|Y|yes|YES) return 0 ;;
    *) fail "Cancelled." ;;
  esac
}

run_aws() {
  AWS_PROFILE="$AWS_PROFILE_NAME" aws "$@"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile)
      AWS_PROFILE_NAME="${2:-}"
      [ -n "$AWS_PROFILE_NAME" ] || fail "--profile requires a value"
      shift 2
      ;;
    --region)
      AWS_REGION="${2:-}"
      [ -n "$AWS_REGION" ] || fail "--region requires a value"
      shift 2
      ;;
    --entitlements)
      ENTITLEMENTS_FILE="${2:-}"
      [ -n "$ENTITLEMENTS_FILE" ] || fail "--entitlements requires a value"
      shift 2
      ;;
    --platform)
      DOCKER_PLATFORM="${2:-}"
      [ -n "$DOCKER_PLATFORM" ] || fail "--platform requires a value"
      shift 2
      ;;
    --cargo-jobs)
      CARGO_BUILD_JOBS="${2:-}"
      [ -n "$CARGO_BUILD_JOBS" ] || fail "--cargo-jobs requires a value"
      shift 2
      ;;
    --cluster)
      ECS_CLUSTER="${2:-}"
      [ -n "$ECS_CLUSTER" ] || fail "--cluster requires a value"
      shift 2
      ;;
    --service)
      ECS_SERVICE="${2:-}"
      [ -n "$ECS_SERVICE" ] || fail "--service requires a value"
      shift 2
      ;;
    --target-group)
      TARGET_GROUP_NAME="${2:-}"
      [ -n "$TARGET_GROUP_NAME" ] || fail "--target-group requires a value"
      shift 2
      ;;
    --plan-only)
      PLAN_ONLY=1
      shift
      ;;
    --tail-logs)
      TAIL_LOGS=1
      shift
      ;;
    --yes)
      YES=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --*)
      fail "Unknown option: $1"
      ;;
    *)
      if [ -n "$IMAGE_TAG" ]; then
        fail "Only one image tag is allowed. Already got '$IMAGE_TAG', extra argument '$1'."
      fi
      IMAGE_TAG="$1"
      shift
      ;;
  esac
done

[ -n "$IMAGE_TAG" ] || {
  usage
  exit 1
}

if [[ ! "$IMAGE_TAG" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
  fail "Invalid Docker image tag: $IMAGE_TAG"
fi

if [[ ! "$CARGO_BUILD_JOBS" =~ ^[1-9][0-9]*$ ]]; then
  fail "--cargo-jobs must be a positive integer: $CARGO_BUILD_JOBS"
fi

case "$ENTITLEMENTS_FILE" in
  /*|../*|*/../*) fail "--entitlements must be a path inside the repo root, for Docker build COPY safety." ;;
esac

cd "$REPO_ROOT"

need_cmd aws
need_cmd terraform
need_cmd shasum
if [ "$PLAN_ONLY" -eq 0 ]; then
  need_cmd docker
fi

[ -f "$ENTITLEMENTS_FILE" ] || fail "Entitlements file not found: $ENTITLEMENTS_FILE"
[ -f "$TERRAFORM_DIR/terraform.tfvars" ] || fail "Terraform tfvars not found: $TERRAFORM_DIR/terraform.tfvars"
[ -f "apps/control-plane/Dockerfile" ] || fail "Dockerfile not found: apps/control-plane/Dockerfile"

TF_CPU_ARCH="$(
  awk -F= '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*cpu_architecture[[:space:]]*=/ {
      value = $2
      sub(/#.*/, "", value)
      gsub(/[[:space:]"]/, "", value)
      print value
      exit
    }
  ' "$TERRAFORM_DIR/terraform.tfvars"
)"
TF_CPU_ARCH="${TF_CPU_ARCH:-X86_64}"

case "$TF_CPU_ARCH" in
  X86_64) EXPECTED_DOCKER_PLATFORM="linux/amd64" ;;
  ARM64) EXPECTED_DOCKER_PLATFORM="linux/arm64" ;;
  *) fail "Unsupported cpu_architecture in $TERRAFORM_DIR/terraform.tfvars: $TF_CPU_ARCH" ;;
esac

if [ -z "$DOCKER_PLATFORM" ]; then
  DOCKER_PLATFORM="$EXPECTED_DOCKER_PLATFORM"
elif [ "$DOCKER_PLATFORM" != "$EXPECTED_DOCKER_PLATFORM" ]; then
  fail "--platform $DOCKER_PLATFORM does not match Terraform cpu_architecture=$TF_CPU_ARCH (expected $EXPECTED_DOCKER_PLATFORM)"
fi

ENTITLEMENTS_SHA="$(shasum -a 256 "$ENTITLEMENTS_FILE" | awk '{print $1}')"

echo "== Canopy control-plane local deploy =="
echo "AWS profile:       $AWS_PROFILE_NAME"
echo "AWS region:        $AWS_REGION"
echo "Terraform dir:     $TERRAFORM_DIR"
echo "Image tag:         $IMAGE_TAG"
echo "Docker platform:   $DOCKER_PLATFORM"
echo "Terraform arch:    $TF_CPU_ARCH"
echo "Cargo build jobs:  $CARGO_BUILD_JOBS"
echo "Entitlements file: $ENTITLEMENTS_FILE"
echo "Entitlements SHA:  $ENTITLEMENTS_SHA"
echo "ECS cluster:       $ECS_CLUSTER"
echo "ECS service:       $ECS_SERVICE"
echo ""

echo "== Validate entitlements =="
"$SCRIPT_DIR/validate-entitlements.sh" "$ENTITLEMENTS_FILE" "$TERRAFORM_DIR/terraform.tfvars"

echo ""
echo "== Resolve ECR repository =="
ECR_URL="$(AWS_PROFILE="$AWS_PROFILE_NAME" terraform -chdir="$TERRAFORM_DIR" output -raw ecr_repository_url)"
[ -n "$ECR_URL" ] || fail "Terraform output ecr_repository_url is empty."
ECR_REGISTRY="${ECR_URL%%/*}"
ECR_REPOSITORY="${ECR_URL#*/}"

echo "ECR URL:      $ECR_URL"
echo "ECR registry: $ECR_REGISTRY"
echo "ECR repo:     $ECR_REPOSITORY"

echo ""
echo "== Check ECR tag availability =="
set +e
describe_output="$(run_aws ecr describe-images \
  --repository-name "$ECR_REPOSITORY" \
  --image-ids "imageTag=$IMAGE_TAG" \
  --region "$AWS_REGION" 2>&1)"
describe_status=$?
set -e

if [ "$describe_status" -eq 0 ]; then
  echo "$describe_output"
  fail "ECR image tag already exists and the repository is immutable: $IMAGE_TAG"
fi

if ! grep -q "ImageNotFoundException" <<< "$describe_output"; then
  echo "$describe_output" >&2
  fail "Unable to verify whether ECR image tag exists."
fi

echo "Tag is available: $IMAGE_TAG"

echo ""
echo "== Terraform Phase 2 plan =="
AWS_PROFILE="$AWS_PROFILE_NAME" terraform -chdir="$TERRAFORM_DIR" plan \
  -var="create_service=true" \
  -var="image_tag=$IMAGE_TAG" \
  -out="$PLAN_FILE"

PLAN_TEXT="$(AWS_PROFILE="$AWS_PROFILE_NAME" terraform -chdir="$TERRAFORM_DIR" show -no-color "$PLAN_FILE")"

if grep -Eq 'will be destroyed' <<< "$PLAN_TEXT"; then
  echo ""
  echo "ERROR: Terraform plan includes destroy actions. Refusing to continue."
  echo "Review $TERRAFORM_DIR/$PLAN_FILE and fix the inputs before applying."
  exit 1
fi

if grep -Eq 'must be replaced' <<< "$PLAN_TEXT"; then
  echo ""
  echo "WARNING: Terraform plan includes replacement actions."
  echo "Review the plan above carefully before applying."
fi

if [ "$PLAN_ONLY" -eq 1 ]; then
  echo ""
  echo "Plan written to $TERRAFORM_DIR/$PLAN_FILE. Stop because --plan-only was set."
  exit 0
fi

echo ""
echo "== Login to ECR =="
run_aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "$ECR_REGISTRY"

echo ""
echo "== Build Docker image =="
DOCKER_BUILDKIT=1 docker build \
  --platform "$DOCKER_PLATFORM" \
  --build-arg "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS" \
  --build-arg "ENTITLEMENTS_SHA=$ENTITLEMENTS_SHA" \
  --secret "id=entitlements_toml,src=$ENTITLEMENTS_FILE" \
  -t "$ECR_URL:$IMAGE_TAG" \
  -f apps/control-plane/Dockerfile .

echo ""
confirm "Push Docker image to ECR: $ECR_URL:$IMAGE_TAG ?"

echo "== Push Docker image =="
docker push "$ECR_URL:$IMAGE_TAG"

echo ""
echo "== Verify pushed image =="
run_aws ecr describe-images \
  --repository-name "$ECR_REPOSITORY" \
  --image-ids "imageTag=$IMAGE_TAG" \
  --region "$AWS_REGION" \
  --query 'imageDetails[0].{Tag:imageTags[0],Digest:imageDigest,PushedAt:imagePushedAt}' \
  --output table

echo ""
confirm "Apply Terraform Phase 2 plan and deploy ECS service '$ECS_SERVICE'?"

echo "== Terraform Phase 2 apply =="
AWS_PROFILE="$AWS_PROFILE_NAME" terraform -chdir="$TERRAFORM_DIR" apply "$PLAN_FILE"

echo ""
echo "== Wait for ECS service to become stable =="
run_aws ecs wait services-stable \
  --cluster "$ECS_CLUSTER" \
  --services "$ECS_SERVICE" \
  --region "$AWS_REGION"

echo ""
echo "== ECS service status =="
run_aws ecs describe-services \
  --cluster "$ECS_CLUSTER" \
  --services "$ECS_SERVICE" \
  --region "$AWS_REGION" \
  --query 'services[0].{Status:status,Desired:desiredCount,Running:runningCount,Pending:pendingCount,TaskDefinition:taskDefinition}' \
  --output table

echo ""
echo "== ALB target health =="
TG_ARN="$(run_aws elbv2 describe-target-groups \
  --names "$TARGET_GROUP_NAME" \
  --region "$AWS_REGION" \
  --query 'TargetGroups[0].TargetGroupArn' \
  --output text)"

run_aws elbv2 describe-target-health \
  --target-group-arn "$TG_ARN" \
  --region "$AWS_REGION" \
  --query 'TargetHealthDescriptions[*].{Target:Target.Id,Port:Target.Port,State:TargetHealth.State,Reason:TargetHealth.Reason,Description:TargetHealth.Description}' \
  --output table

echo ""
echo "== Done =="
echo "Image deployed: $ECR_URL:$IMAGE_TAG"

ALB_DNS="$(AWS_PROFILE="$AWS_PROFILE_NAME" terraform -chdir="$TERRAFORM_DIR" output -raw alb_dns_name 2>/dev/null || true)"
if [ -n "$ALB_DNS" ]; then
  echo "ALB DNS:        $ALB_DNS"
  echo "Health check:   curl -k -I https://$ALB_DNS/health"
fi
echo "CloudWatch:     AWS_PROFILE=$AWS_PROFILE_NAME aws logs tail /ecs/canopy/control-plane --region $AWS_REGION --since 30m --follow"

if [ "$TAIL_LOGS" -eq 1 ]; then
  echo ""
  echo "== Tail logs =="
  run_aws logs tail /ecs/canopy/control-plane \
    --region "$AWS_REGION" \
    --since 30m \
    --follow
fi
