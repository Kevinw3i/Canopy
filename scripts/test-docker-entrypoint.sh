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
if [ -n "${CANOPY_TEST_CONFIG_MODE_FILE:-}" ]; then
  if mode=$(stat -f '%Lp' "$CONFIG_PATH" 2>/dev/null); then
    :
  else
    mode=$(stat -c '%a' "$CONFIG_PATH")
  fi
  printf '%s\n' "$mode" > "$CANOPY_TEST_CONFIG_MODE_FILE"
fi
cat "$CONFIG_PATH"
SH
chmod +x "$TMP_DIR/control-plane"

cat > "$TMP_DIR/aws" <<'SH'
#!/bin/sh
if [ "$1" = "secretsmanager" ] && [ "$2" = "get-secret-value" ]; then
  printf '%s\n' 'jwt-from-arn'
  exit 0
fi
echo "unexpected aws call: $*" >&2
exit 1
SH
chmod +x "$TMP_DIR/aws"

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

  grep -qF -- "$expected" "$TMP_DIR/$name.err"
}

CONFIG_OUT="$TMP_DIR/generated.toml"
CONFIG_MODE_OUT="$TMP_DIR/generated.mode"

env \
  PATH="$TMP_DIR:$PATH" \
  CANOPY_TEST_CONFIG_MODE_FILE="$CONFIG_MODE_OUT" \
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

grep -qxF '600' "$CONFIG_MODE_OUT"

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

ARN_CONFIG_OUT="$TMP_DIR/generated-from-arn.toml"
env \
  PATH="$TMP_DIR:$PATH" \
  GENERATE_CONFIG=1 \
  JWT_SECRET_ARN='arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:canopy/jwt-secret-XXXXXX' \
  OIDC_ISSUER_URL='https://issuer.example' \
  OIDC_CLIENT_ID='client-id' \
  sh "$ENTRYPOINT" > "$ARN_CONFIG_OUT"

python3 - <<'PY' "$ARN_CONFIG_OUT"
import sys
import tomllib

with open(sys.argv[1], "rb") as f:
    data = tomllib.load(f)

assert data["jwt"]["secret"] == "jwt-from-arn"
assert data["oidc"]["issuer_url"] == "https://issuer.example"
assert data["oidc"]["client_id"] == "client-id"
PY

cat > "$TMP_DIR/aws" <<'SH'
#!/bin/sh
echo "ERROR: aws should not be called when JWT_SECRET is set" >&2
exit 1
SH
chmod +x "$TMP_DIR/aws"

DIRECT_SECRET_OUT="$TMP_DIR/generated-direct-secret.toml"
env \
  PATH="$TMP_DIR:$PATH" \
  GENERATE_CONFIG=1 \
  JWT_SECRET='direct-jwt-secret' \
  JWT_SECRET_ARN='arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:canopy/jwt-secret-XXXXXX' \
  OIDC_ISSUER_URL='https://issuer.example' \
  OIDC_CLIENT_ID='client-id' \
  sh "$ENTRYPOINT" > "$DIRECT_SECRET_OUT"

python3 - <<'PY' "$DIRECT_SECRET_OUT"
import sys
import tomllib

with open(sys.argv[1], "rb") as f:
    data = tomllib.load(f)

assert data["jwt"]["secret"] == "direct-jwt-secret"
PY

PATCH_CONFIG="$TMP_DIR/existing-config.toml"
cat > "$PATCH_CONFIG" <<'TOML'
bind_address = "127.0.0.1:8443"
entitlements_file = "/etc/canopy/entitlements.toml"

[oidc]
issuer_url = "https://issuer.example"
client_id = "client-id"

[jwt]
secret = "old-secret"
expiry_seconds = 3600

[aws]
default_region = "ap-northeast-1"
session_duration_seconds = 3600
sts_external_id = "canopy"
TOML

PATCH_OUT="$TMP_DIR/patched.toml"
PATCH_MODE_OUT="$TMP_DIR/patched.mode"
env \
  PATH="$TMP_DIR:$PATH" \
  CANOPY_TEST_CONFIG_MODE_FILE="$PATCH_MODE_OUT" \
  CONFIG_PATH="$PATCH_CONFIG" \
  JWT_SECRET='patched"jwt\secret' \
  OIDC_CLIENT_SECRET='patched"oidc\secret' \
  sh "$ENTRYPOINT" > "$PATCH_OUT"

grep -qxF '600' "$PATCH_MODE_OUT"

python3 - <<'PY' "$PATCH_OUT"
import sys
import tomllib

with open(sys.argv[1], "rb") as f:
    data = tomllib.load(f)

assert data["oidc"]["client_secret"] == 'patched"oidc\\secret'
assert data["jwt"]["secret"] == 'patched"jwt\\secret'
assert data["jwt"]["expiry_seconds"] == 3600
assert data["aws"]["session_duration_seconds"] == 3600
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

expect_entrypoint_failure \
  "aws-session-duration" \
  "AWS_SESSION_DURATION_SECONDS must be a positive integer" \
  JWT_SECRET='jwt' \
  OIDC_ISSUER_URL='https://issuer.example' \
  OIDC_CLIENT_ID='client' \
  AWS_SESSION_DURATION_SECONDS='0'

expect_entrypoint_failure \
  "aws-session-duration-too-short" \
  "AWS_SESSION_DURATION_SECONDS must be between 900 and 43200" \
  JWT_SECRET='jwt' \
  OIDC_ISSUER_URL='https://issuer.example' \
  OIDC_CLIENT_ID='client' \
  AWS_SESSION_DURATION_SECONDS='899'

expect_entrypoint_failure \
  "aws-session-duration-too-long" \
  "AWS_SESSION_DURATION_SECONDS must be between 900 and 43200" \
  JWT_SECRET='jwt' \
  OIDC_ISSUER_URL='https://issuer.example' \
  OIDC_CLIENT_ID='client' \
  AWS_SESSION_DURATION_SECONDS='43201'

echo "docker-entrypoint generated config tests passed."
