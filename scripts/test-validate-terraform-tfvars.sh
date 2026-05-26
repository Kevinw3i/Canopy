#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VALIDATOR="$SCRIPT_DIR/validate-terraform-tfvars.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
export TF_PLUGIN_CACHE_DIR="$TMP_DIR/plugin-cache"
mkdir "$TF_PLUGIN_CACHE_DIR"

INFRA_DIR="$TMP_DIR/infra"
mkdir "$INFRA_DIR"
cp "$REPO_ROOT"/infra/*.tf "$INFRA_DIR"/
if [ -f "$REPO_ROOT/infra/.terraform.lock.hcl" ]; then
  cp "$REPO_ROOT/infra/.terraform.lock.hcl" "$INFRA_DIR"/
fi

write_tfvars() {
  local alb_allowed_cidrs="$1"
  local alb_internal="$2"
  local extra="${3:-}"

  cat > "$INFRA_DIR/terraform.tfvars" <<'EOF'
aws_region = "ap-northeast-1"

create_service = false
create_vpc         = false
vpc_id             = "vpc-00000000000000000"
public_subnet_ids  = ["subnet-00000000000000001", "subnet-00000000000000002"]
private_subnet_ids = ["subnet-00000000000000003", "subnet-00000000000000004"]

acm_certificate_arn = "arn:aws:acm:ap-northeast-1:123456789012:certificate/00000000-0000-0000-0000-000000000000"
image_tag           = ""

jwt_secret_arn = "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:canopy/jwt-secret-XXXXXX"

oidc_issuer_url = "https://accounts.google.com"
oidc_client_id  = "test-client-id"
EOF
  {
    printf 'alb_allowed_cidrs = %s\n' "$alb_allowed_cidrs"
    printf 'alb_internal      = %s\n' "$alb_internal"
    if [ -n "$extra" ]; then
      printf '%s\n' "$extra"
    fi
  } >> "$INFRA_DIR/terraform.tfvars"
}

write_valid_tfvars() {
  write_tfvars '["10.0.0.0/16"]' "true"
}

expect_success() {
  local name="$1"
  shift

  if ! "$VALIDATOR" "$INFRA_DIR" "$@" > "$TMP_DIR/$name.out" 2>&1; then
    cat "$TMP_DIR/$name.out" >&2
    echo "ERROR: expected $name to pass." >&2
    exit 1
  fi
}

expect_failure() {
  local name="$1"
  local expected="$2"
  shift 2

  if "$VALIDATOR" "$INFRA_DIR" "$@" > "$TMP_DIR/$name.out" 2>&1; then
    cat "$TMP_DIR/$name.out" >&2
    echo "ERROR: expected $name to fail." >&2
    exit 1
  fi

  grep -qF -- "$expected" "$TMP_DIR/$name.out"
}

expect_failure_in_dir() {
  local name="$1"
  local expected="$2"
  local terraform_dir="$3"
  shift 3

  if "$VALIDATOR" "$terraform_dir" "$@" > "$TMP_DIR/$name.out" 2>&1; then
    cat "$TMP_DIR/$name.out" >&2
    echo "ERROR: expected $name to fail." >&2
    exit 1
  fi

  grep -qF -- "$expected" "$TMP_DIR/$name.out"
}

expect_failure_in_dir "missing-terraform-dir" "Terraform dir not found" "$TMP_DIR/missing-infra"

MISSING_TFVARS_DIR="$TMP_DIR/missing-tfvars"
mkdir "$MISSING_TFVARS_DIR"
expect_failure_in_dir "missing-tfvars" "Terraform tfvars not found" "$MISSING_TFVARS_DIR"

write_valid_tfvars
expect_success "valid-tfvars"

write_valid_tfvars
cat >> "$INFRA_DIR/terraform.tfvars" <<'EOF'
jwt_secret_version_id = "00000000-0000-0000-0000-000000000000"
EOF
expect_success \
  "phase-two-overrides" \
  -var="create_service=true" \
  -var="image_tag=cp-v0.1.0"

write_valid_tfvars
expect_failure \
  "phase-two-missing-jwt-version" \
  "jwt_secret_version_id is required" \
  -var="create_service=true" \
  -var="image_tag=cp-v0.1.0"

write_tfvars '["0.0.0.0/0"]' "false"
expect_failure "public-world-cidr" "Public ALB cannot allow 0.0.0.0/0"

write_tfvars '["10.0.0.0/16"]' "true" 'domain_name = "canopy.example.com"'
expect_failure "domain-without-zone" "route53_zone_id and domain_name must be set together"

echo "Terraform deployment tfvars validation tests passed."
