#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_ROOT="$PROJECT_DIR/dist/tui-release"
BINARY_NAME="canopy"
PACKAGE_NAME="tui-client"

VERSION=""
TARGET=""
REPO=""
NOTES="Manual TUI release"
YES=0
PACKAGE_ONLY=0
SKIP_TESTS=0
ALLOW_VERSION_MISMATCH=0
ALLOW_DIRTY=0
DRAFT=0
PRERELEASE=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/release-tui-local.sh [VERSION] [options]

Builds the TUI locally, packages the asset expected by the updater, generates
SHA256, then optionally creates or updates the GitHub Release with gh.

Examples:
  scripts/release-tui-local.sh
  scripts/release-tui-local.sh 0.1.5
  scripts/release-tui-local.sh 0.1.5 --repo Kevinw3i/Canopy --yes
  scripts/release-tui-local.sh 0.1.5 --package-only

Options:
  --target TARGET              Rust target triple. Defaults to rustc host.
  --repo OWNER/REPO            GitHub repository. Defaults to gh repo view.
  --notes TEXT                 Release notes. Default: "Manual TUI release".
  --package-only               Build/package only; do not call gh.
  --skip-tests                 Skip cargo test -p tui-client.
  --allow-version-mismatch     Allow VERSION to differ from Cargo.toml version.
  --allow-dirty                Allow releasing from a dirty git worktree.
  --draft                      Create a draft release when release does not exist.
  --prerelease                 Mark release as prerelease.
  --stable                     Force release to not be marked prerelease.
  -y, --yes                    Do not prompt before gh release changes.
  -h, --help                   Show this help.

Supported updater asset targets:
  aarch64-apple-darwin      -> canopy-darwin-arm64.tar.gz
  x86_64-apple-darwin       -> canopy-darwin-amd64.tar.gz
  x86_64-unknown-linux-gnu  -> canopy-linux-amd64.tar.gz
  aarch64-unknown-linux-gnu -> canopy-linux-arm64.tar.gz
USAGE
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

info() {
  printf '\n== %s ==\n' "$*"
}

confirm() {
  if [ "$YES" = "1" ]; then
    return 0
  fi

  printf '%s [y/N] ' "$1"
  read -r answer
  case "$answer" in
    y|Y|yes|YES) ;;
    *) fail "Aborted" ;;
  esac
}

workspace_version() {
  sed -nE '/^\[workspace\.package\]/,/^\[/{s/^version = "([^"]+)".*/\1/p;}' "$PROJECT_DIR/Cargo.toml" | head -n 1
}

host_target() {
  rustc -vV | awk '/^host:/ {print $2}'
}

asset_suffix_for_target() {
  case "$1" in
    aarch64-apple-darwin) echo "darwin-arm64" ;;
    x86_64-apple-darwin) echo "darwin-amd64" ;;
    x86_64-unknown-linux-gnu) echo "linux-amd64" ;;
    aarch64-unknown-linux-gnu) echo "linux-arm64" ;;
    *) return 1 ;;
  esac
}

sha256_file() {
  local file="$1"
  local dir
  local base
  dir="$(cd "$(dirname "$file")" && pwd)"
  base="$(basename "$file")"

  (
    cd "$dir"
    if command -v shasum >/dev/null 2>&1; then
      shasum -a 256 "$base" > "$base.sha256"
    elif command -v sha256sum >/dev/null 2>&1; then
      sha256sum "$base" > "$base.sha256"
    else
      fail "Neither shasum nor sha256sum is available"
    fi
  )
}

auto_prerelease() {
  case "$1" in
    *alpha*|*beta*|*rc*) echo "1" ;;
    *) echo "0" ;;
  esac
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --target)
      [ "$#" -ge 2 ] || fail "--target requires a value"
      TARGET="$2"
      shift 2
      ;;
    --repo)
      [ "$#" -ge 2 ] || fail "--repo requires a value"
      REPO="$2"
      shift 2
      ;;
    --notes)
      [ "$#" -ge 2 ] || fail "--notes requires a value"
      NOTES="$2"
      shift 2
      ;;
    --package-only)
      PACKAGE_ONLY=1
      shift
      ;;
    --skip-tests)
      SKIP_TESTS=1
      shift
      ;;
    --allow-version-mismatch)
      ALLOW_VERSION_MISMATCH=1
      shift
      ;;
    --allow-dirty)
      ALLOW_DIRTY=1
      shift
      ;;
    --draft)
      DRAFT=1
      shift
      ;;
    --prerelease)
      PRERELEASE=1
      shift
      ;;
    --stable)
      PRERELEASE=0
      shift
      ;;
    -y|--yes)
      YES=1
      shift
      ;;
    --*)
      fail "Unknown option: $1"
      ;;
    *)
      if [ -n "$VERSION" ]; then
        fail "Unexpected argument: $1"
      fi
      VERSION="$1"
      shift
      ;;
  esac
done

cd "$PROJECT_DIR"

if [ "$ALLOW_DIRTY" != "1" ] && [ -n "$(git status --porcelain)" ]; then
  fail "Git worktree has uncommitted changes. Commit/stash them or pass --allow-dirty."
fi

CARGO_VERSION="$(workspace_version)"
[ -n "$CARGO_VERSION" ] || fail "Could not read [workspace.package] version from Cargo.toml"

if [ -z "$VERSION" ]; then
  VERSION="$CARGO_VERSION"
fi

if [ "$ALLOW_VERSION_MISMATCH" != "1" ] && [ "$VERSION" != "$CARGO_VERSION" ]; then
  fail "VERSION ($VERSION) does not match Cargo.toml workspace version ($CARGO_VERSION). Update Cargo.toml or pass --allow-version-mismatch."
fi

case "$VERSION" in
  tui-v*) fail "Pass version without tag prefix, e.g. 0.1.5, not $VERSION" ;;
esac

if [ -z "$TARGET" ]; then
  TARGET="$(host_target)"
fi

SUFFIX="$(asset_suffix_for_target "$TARGET")" || fail "Unsupported target for updater asset: $TARGET"
TAG="tui-v$VERSION"
RELEASE_TARGET="$(git rev-parse HEAD)"
ARCHIVE_NAME="$BINARY_NAME-$SUFFIX.tar.gz"
OUT_DIR="$DIST_ROOT/$VERSION/$TARGET"
STAGE_DIR="$OUT_DIR/stage"
ARCHIVE_PATH="$OUT_DIR/$ARCHIVE_NAME"
SHA_PATH="$ARCHIVE_PATH.sha256"
BINARY_PATH="$PROJECT_DIR/target/$TARGET/release/$PACKAGE_NAME"

if [ -z "$PRERELEASE" ]; then
  PRERELEASE="$(auto_prerelease "$VERSION")"
fi

info "Release settings"
echo "Version:      $VERSION"
echo "Cargo.toml:   $CARGO_VERSION"
echo "Tag:          $TAG"
echo "Commit:       $RELEASE_TARGET"
echo "Target:       $TARGET"
echo "Asset:        $ARCHIVE_NAME"
echo "Output dir:   $OUT_DIR"

if [ "$SKIP_TESTS" != "1" ]; then
  info "Run TUI tests"
  cargo test -p "$PACKAGE_NAME"
fi

info "Build TUI"
CANOPY_BUILD_VERSION="$VERSION" cargo build --release -p "$PACKAGE_NAME" --target "$TARGET"

[ -f "$BINARY_PATH" ] || fail "Built binary not found: $BINARY_PATH"

info "Package asset"
rm -rf "$OUT_DIR"
mkdir -p "$STAGE_DIR"
cp "$BINARY_PATH" "$STAGE_DIR/$BINARY_NAME"
chmod +x "$STAGE_DIR/$BINARY_NAME"
tar -C "$STAGE_DIR" -czf "$ARCHIVE_PATH" "$BINARY_NAME"
sha256_file "$ARCHIVE_PATH"
rm -rf "$STAGE_DIR"

echo "Archive:      $ARCHIVE_PATH"
echo "SHA256:       $SHA_PATH"

if [ "$PACKAGE_ONLY" = "1" ]; then
  info "Package-only mode complete"
  exit 0
fi

command -v gh >/dev/null 2>&1 || fail "GitHub CLI 'gh' is not installed"
gh auth status >/dev/null 2>&1 || fail "gh is not authenticated. Run: gh auth login"

if [ -z "$REPO" ]; then
  REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
fi
[ -n "$REPO" ] || fail "Could not determine GitHub repo. Pass --repo OWNER/REPO."

info "GitHub Release"
echo "Repo:         $REPO"
echo "Release:      $TAG"
echo "Assets:"
echo "  $ARCHIVE_PATH"
echo "  $SHA_PATH"
echo
echo "Note: if .github/workflows/release-tui.yml is still enabled for tui-v* tags,"
echo "GitHub may still run that workflow when a new release tag is created."

if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
  confirm "Release $TAG already exists. Upload/replace this platform asset?"
  gh release upload "$TAG" "$ARCHIVE_PATH" "$SHA_PATH" --repo "$REPO" --clobber
else
  confirm "Create GitHub Release $TAG and upload this platform asset?"
  GH_ARGS=(release create "$TAG" "$ARCHIVE_PATH" "$SHA_PATH" --repo "$REPO" --target "$RELEASE_TARGET" --title "TUI Client $VERSION" --notes "$NOTES")
  if [ "$DRAFT" = "1" ]; then
    GH_ARGS+=(--draft)
  fi
  if [ "$PRERELEASE" = "1" ]; then
    GH_ARGS+=(--prerelease)
  fi
  gh "${GH_ARGS[@]}"
fi

info "Done"
echo "Published asset:"
echo "  $ARCHIVE_NAME"
