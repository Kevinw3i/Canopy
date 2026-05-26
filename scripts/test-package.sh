#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER_SNIPPET="$(mktemp)"
trap 'rm -f "$INSTALLER_SNIPPET"' EXIT

bash -n "$SCRIPT_DIR/package.sh"

awk '
  /^cat > "\$DIST_DIR\/install.sh" << '\''INSTALLER'\''/ { in_installer = 1; next }
  /^INSTALLER$/ { in_installer = 0 }
  in_installer { print }
' "$SCRIPT_DIR/package.sh" > "$INSTALLER_SNIPPET"

test -s "$INSTALLER_SNIPPET"
bash -n "$INSTALLER_SNIPPET"

grep -q "verify_macos_pkg_signature" "$INSTALLER_SNIPPET"
grep -q "verify_aws_cli_zip_signature" "$INSTALLER_SNIPPET"
grep -q -- "--proto-redir '=https'" "$INSTALLER_SNIPPET"
grep -q "Linux Session Manager Plugin 自動安裝已停用" "$INSTALLER_SNIPPET"

echo "package script validation passed."
