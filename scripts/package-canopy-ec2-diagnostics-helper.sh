#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

TARGET=""
OUT_DIR="$REPO_ROOT/dist/canopy-ec2-diagnostics-helper"

usage() {
  cat >&2 <<'USAGE'
Usage: scripts/package-canopy-ec2-diagnostics-helper.sh [--target <rust-target>] [--out-dir <dir>]

Builds and packages the Canopy EC2 diagnostics helper binary. Run this on a
Linux builder or pass a Linux Rust target that is installed in the toolchain.

The generated tarball is intended for installation on target EC2 instances at:

  /usr/local/bin/canopy-ec2-diagnostics
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --target)
      TARGET="${2:-}"
      if [ -z "$TARGET" ]; then
        echo "ERROR: --target requires a value." >&2
        exit 1
      fi
      shift 2
      ;;
    --out-dir)
      OUT_DIR="${2:-}"
      if [ -z "$OUT_DIR" ]; then
        echo "ERROR: --out-dir requires a value." >&2
        exit 1
      fi
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

CARGO_ARGS=(build -p control-plane --release --bin canopy-ec2-diagnostics)
if [ -n "$TARGET" ]; then
  CARGO_ARGS+=(--target "$TARGET")
  BIN_PATH="$REPO_ROOT/target/$TARGET/release/canopy-ec2-diagnostics"
  PACKAGE_SUFFIX="$TARGET"
else
  BIN_PATH="$REPO_ROOT/target/release/canopy-ec2-diagnostics"
  PACKAGE_SUFFIX="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
fi

(cd "$REPO_ROOT" && cargo "${CARGO_ARGS[@]}")

if [ ! -x "$BIN_PATH" ]; then
  echo "ERROR: helper binary was not produced at $BIN_PATH" >&2
  exit 1
fi

PACKAGE_DIR="$OUT_DIR/canopy-ec2-diagnostics-helper-$PACKAGE_SUFFIX"
rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR"
install -m 0755 "$BIN_PATH" "$PACKAGE_DIR/canopy-ec2-diagnostics"

cat > "$PACKAGE_DIR/INSTALL.md" <<'INSTALL'
# Canopy EC2 Diagnostics Helper

Install on each EC2 instance that may run the `Canopy-Ec2Diagnostics` SSM
document:

```sh
sudo install -o root -g root -m 0755 canopy-ec2-diagnostics /usr/local/bin/canopy-ec2-diagnostics
sudo install -o root -g root -m 0600 mcp-ec2-command-spec-key /etc/canopy/mcp-ec2-command-spec-key
```

The key file content must match the control-plane
`mcp.ec2_diagnostic_command_spec_key` configuration. Do not bake this key into
public images or commit it to source control.
INSTALL

TARBALL="$OUT_DIR/canopy-ec2-diagnostics-helper-$PACKAGE_SUFFIX.tar.gz"
mkdir -p "$OUT_DIR"
tar -C "$OUT_DIR" -czf "$TARBALL" "canopy-ec2-diagnostics-helper-$PACKAGE_SUFFIX"

if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$TARBALL" > "$TARBALL.sha256"
else
  sha256sum "$TARBALL" > "$TARBALL.sha256"
fi

printf 'helper_package=%s\n' "$TARBALL"
printf 'helper_sha256=%s\n' "$TARBALL.sha256"
