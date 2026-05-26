#!/usr/bin/env bash
set -euo pipefail

TERRAFORM_DIR="${1:-infra}"
TFVARS_PATH="$TERRAFORM_DIR/terraform.tfvars"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

command -v terraform >/dev/null 2>&1 || fail "Missing required command: terraform"
[ -d "$TERRAFORM_DIR" ] || fail "Terraform dir not found: $TERRAFORM_DIR"
[ -f "$TFVARS_PATH" ] || fail "Terraform tfvars not found: $TFVARS_PATH"

TEST_DIR=".canopy-tfvars-validation-$$"
TF_DATA_DIR_PATH="$(mktemp -d)"

cleanup() {
  rm -rf "$TERRAFORM_DIR/$TEST_DIR" "$TF_DATA_DIR_PATH"
}
trap cleanup EXIT

mkdir "$TERRAFORM_DIR/$TEST_DIR"
cat > "$TERRAFORM_DIR/$TEST_DIR/deployment_tfvars.tftest.hcl" <<'EOF'
mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["ap-northeast-1a", "ap-northeast-1c", "ap-northeast-1d"]
    }
  }
}

run "deployment_tfvars_plan" {
  command = plan
}
EOF

TF_DATA_DIR="$TF_DATA_DIR_PATH" terraform -chdir="$TERRAFORM_DIR" init -backend=false -input=false >/dev/null
TF_DATA_DIR="$TF_DATA_DIR_PATH" terraform -chdir="$TERRAFORM_DIR" test -test-directory="$TEST_DIR"

echo "Terraform deployment tfvars validation passed."
