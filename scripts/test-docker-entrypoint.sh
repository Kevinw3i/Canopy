#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENTRYPOINT="$REPO_ROOT/scripts/docker-entrypoint.sh"
TMP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if ! python3 - <<'PY' >/dev/null 2>&1
import tomllib
PY
then
  echo "ERROR: scripts/test-docker-entrypoint.sh requires python3 with tomllib (Python 3.11+)." >&2
  exit 1
fi

cat > "$TMP_DIR/control-plane" <<'SH'
#!/bin/sh
cat "$CONFIG_PATH"
SH
chmod +x "$TMP_DIR/control-plane"

expect_entrypoint_failure() {
  local name="$1"
  local expected="$2"
  shift 2

  set +e
  env \
    PATH="$TMP_DIR:$PATH" \
    GENERATE_CONFIG=1 \
    "$@" \
    sh "$ENTRYPOINT" > "$TMP_DIR/$name.out" 2> "$TMP_DIR/$name.err"
  status=$?
  set -e

  if [ "$status" -eq 0 ]; then
    echo "ERROR: expected $name to fail." >&2
    cat "$TMP_DIR/$name.out" >&2
    exit 1
  fi

  grep -q -- "$expected" "$TMP_DIR/$name.err"
}

CONFIG_OUT="$TMP_DIR/generated.toml"

env \
  PATH="$TMP_DIR:$PATH" \
  GENERATE_CONFIG=1 \
  JWT_SECRET='jwt"sec\ret' \
  OIDC_ISSUER_URL='https://issuer.example/a"b' \
  OIDC_CLIENT_ID='client\id' \
  OIDC_CLIENT_SECRET='oidc"secret\x' \
  CORS_ALLOWED_ORIGINS='https://one.example, https://two.example/path?x="y"' \
  JWT_EXPIRY_SECONDS=7200 \
  AWS_SESSION_DURATION_SECONDS=1800 \
  AWS_DEFAULT_REGION='ap-northeast-1' \
  STS_EXTERNAL_ID='canopy"external' \
  sh "$ENTRYPOINT" > "$CONFIG_OUT"

python3 - <<'PY' "$CONFIG_OUT"
import sys
import tomllib

with open(sys.argv[1], "rb") as f:
    data = tomllib.load(f)

assert data["bind_address"] == "0.0.0.0:8443"
assert data["entitlements_file"] == "/etc/canopy/entitlements.toml"
assert data["oidc"]["issuer_url"] == 'https://issuer.example/a"b'
assert data["oidc"]["client_id"] == "client\\id"
assert data["oidc"]["client_secret"] == 'oidc"secret\\x'
assert data["jwt"]["secret"] == 'jwt"sec\\ret'
assert data["jwt"]["expiry_seconds"] == 7200
assert data["aws"]["default_region"] == "ap-northeast-1"
assert data["aws"]["session_duration_seconds"] == 1800
assert data["aws"]["sts_external_id"] == 'canopy"external'
assert data["cors_allowed_origins"] == [
    "https://one.example",
    'https://two.example/path?x="y"',
]
PY

expect_entrypoint_failure \
  "missing-jwt-secret" \
  "JWT_SECRET is not set and no JWT_SECRET_ARN configured" \
  OIDC_ISSUER_URL='https://issuer.example' \
  OIDC_CLIENT_ID='client'

expect_entrypoint_failure \
  "missing-oidc-issuer" \
  "OIDC_ISSUER_URL is required in generated config mode" \
  JWT_SECRET='jwt' \
  OIDC_CLIENT_ID='client'

expect_entrypoint_failure \
  "missing-oidc-client-id" \
  "OIDC_CLIENT_ID is required in generated config mode" \
  JWT_SECRET='jwt' \
  OIDC_ISSUER_URL='https://issuer.example'

expect_entrypoint_failure \
  "newline" \
  "TOML string values must not contain newlines" \
  JWT_SECRET='jwt' \
  OIDC_ISSUER_URL='https://issuer.example' \
  OIDC_CLIENT_ID=$'client\nid'

expect_entrypoint_failure \
  "expiry" \
  "JWT_EXPIRY_SECONDS must be a positive integer" \
  JWT_SECRET='jwt' \
  OIDC_ISSUER_URL='https://issuer.example' \
  OIDC_CLIENT_ID='client' \
  JWT_EXPIRY_SECONDS='3600x'

echo "docker-entrypoint generated config tests passed."
