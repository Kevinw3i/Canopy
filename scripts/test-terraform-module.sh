#!/usr/bin/env bash
set -euo pipefail

TERRAFORM_DIR="${1:-infra}"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

command -v terraform >/dev/null 2>&1 || fail "Missing required command: terraform"
[ -d "$TERRAFORM_DIR" ] || fail "Terraform dir not found: $TERRAFORM_DIR"

if [ -z "${TF_PLUGIN_CACHE_DIR:-}" ] && [ -d "$TERRAFORM_DIR/.terraform/providers" ]; then
  TF_PLUGIN_CACHE_DIR="$(cd "$TERRAFORM_DIR/.terraform/providers" && pwd -P)"
  export TF_PLUGIN_CACHE_DIR
fi

TF_DATA_DIR_PATH="$(mktemp -d)"

cleanup() {
  rm -rf "$TF_DATA_DIR_PATH"
}
trap cleanup EXIT

terraform -chdir="$TERRAFORM_DIR" fmt -check
TF_DATA_DIR="$TF_DATA_DIR_PATH" terraform -chdir="$TERRAFORM_DIR" init -backend=false -input=false >/dev/null
TF_DATA_DIR="$TF_DATA_DIR_PATH" terraform -chdir="$TERRAFORM_DIR" validate
TF_DATA_DIR="$TF_DATA_DIR_PATH" terraform -chdir="$TERRAFORM_DIR" test

echo "Terraform module validation passed."
