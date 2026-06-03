#!/usr/bin/env bash
set -euo pipefail

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CATALOG="$TMP_DIR/entitlements.catalog.toml"
RUNTIME="$TMP_DIR/entitlements.generated.toml"
TFVARS="$TMP_DIR/terraform.tfvars"
VALIDATE_SCRIPT="$TMP_DIR/validate-entitlements.sh"

cat > "$CATALOG" <<'EOF'
[[accounts]]
id = "prod"
account_id = "123456789012"
name = "production"

[[roles]]
id = "canopy"
role_arn = "arn:aws:iam::{account_id}:role/CanopyRole"

[[scopes]]
id = "prod-ec2"
accounts = ["prod"]
regions = ["ap-northeast-1"]

[[packages]]
id = "ec2-readonly"
features = ["ec2:view"]
scope = "prod-ec2"
role = "canopy"

[[bindings]]
group = "platform-engineering"
package = "ec2-readonly"

[[group_mappings]]
external_group = "canopy-platform-engineering"
canopy_group = "platform-engineering"
EOF

cat > "$TFVARS" <<'EOF'
enable_direct_access = false
EOF

cat > "$VALIDATE_SCRIPT" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$VALIDATE_SCRIPT"

cargo run -q -p canopy-entitlements -- generate \
  --catalog "$CATALOG" \
  --output "$RUNTIME" \
  --format json >/dev/null

CANOPY_VALIDATE_ENTITLEMENTS_SCRIPT="$VALIDATE_SCRIPT" \
  cargo run -q -p canopy-entitlements -- validate \
    --catalog "$CATALOG" \
    --runtime-file "$RUNTIME" \
    --tfvars "$TFVARS" \
    --format json >/dev/null

printf '\n# drift\n' >> "$RUNTIME"
if CANOPY_VALIDATE_ENTITLEMENTS_SCRIPT="$VALIDATE_SCRIPT" \
  cargo run -q -p canopy-entitlements -- validate \
    --catalog "$CATALOG" \
    --runtime-file "$RUNTIME" \
    --tfvars "$TFVARS" \
    --format json >"$TMP_DIR/drift.out" 2>"$TMP_DIR/drift.err"; then
  cat "$TMP_DIR/drift.out" >&2
  cat "$TMP_DIR/drift.err" >&2
  echo "ERROR: expected validate to fail after generated runtime drift." >&2
  exit 1
fi

grep -q "runtime file drift" "$TMP_DIR/drift.err"

echo "canopy-entitlements CLI tests passed."
