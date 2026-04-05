#!/bin/sh
set -e

CONFIG_PATH="${CONFIG_PATH:-/etc/canopy/config.toml}"

# ── Helper: escape a value for TOML double-quoted strings ──
escape_toml() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

# ── Resolve JWT secret ─────────────────────────────────────
# Prefer JWT_SECRET (set directly, e.g. via ECS native secrets injection).
# Fall back to JWT_SECRET_ARN (fetched via AWS CLI; needs task-role access).
if [ -z "$JWT_SECRET" ] && [ -n "$JWT_SECRET_ARN" ]; then
  JWT_SECRET=$(aws secretsmanager get-secret-value \
    --secret-id "$JWT_SECRET_ARN" \
    --query SecretString --output text)
fi

# ── Generate or patch config ───────────────────────────────
if [ ! -f "$CONFIG_PATH" ] || [ "${GENERATE_CONFIG:-0}" = "1" ]; then

  # Fail closed: refuse to start without required config
  if [ -z "$JWT_SECRET" ]; then
    echo "FATAL: JWT_SECRET is not set and no JWT_SECRET_ARN configured." >&2
    exit 1
  fi
  if [ -z "$OIDC_ISSUER_URL" ]; then
    echo "FATAL: OIDC_ISSUER_URL is required in generated config mode." >&2
    exit 1
  fi
  if [ -z "$OIDC_CLIENT_ID" ]; then
    echo "FATAL: OIDC_CLIENT_ID is required in generated config mode." >&2
    exit 1
  fi

  WRITABLE_CONFIG="/tmp/canopy-config.toml"

  # Escape secret values for safe TOML embedding
  SAFE_JWT_SECRET=$(escape_toml "$JWT_SECRET")

  CLIENT_SECRET_LINE=""
  if [ -n "$OIDC_CLIENT_SECRET" ]; then
    SAFE_OIDC_SECRET=$(escape_toml "$OIDC_CLIENT_SECRET")
    CLIENT_SECRET_LINE="client_secret = \"${SAFE_OIDC_SECRET}\""
  fi

  # Default to the path baked into the image by the Dockerfile
  ENTITLEMENTS_FILE="${ENTITLEMENTS_FILE:-/etc/canopy/entitlements.toml}"
  ENTITLEMENTS_LINE="entitlements_file = \"${ENTITLEMENTS_FILE}\""

  cat > "$WRITABLE_CONFIG" <<TOML
bind_address = "${BIND_ADDRESS:-0.0.0.0:8443}"
${ENTITLEMENTS_LINE}

[oidc]
issuer_url = "${OIDC_ISSUER_URL}"
client_id  = "${OIDC_CLIENT_ID}"
${CLIENT_SECRET_LINE}

[jwt]
secret         = "${SAFE_JWT_SECRET}"
expiry_seconds = ${JWT_EXPIRY_SECONDS:-3600}

[aws]
default_region           = "${AWS_DEFAULT_REGION:-ap-northeast-1}"
session_duration_seconds = ${AWS_SESSION_DURATION_SECONDS:-3600}
sts_external_id          = "${STS_EXTERNAL_ID:-canopy}"
TOML

  # Append CORS origins at top level (before first [section])
  if [ -n "$CORS_ALLOWED_ORIGINS" ]; then
    # Trim whitespace around each comma-separated origin
    CORS_ARRAY=$(printf '%s' "$CORS_ALLOWED_ORIGINS" | sed 's/[[:space:]]*,[[:space:]]*/", "/g')
    sed -i "1a\\
cors_allowed_origins = [\"${CORS_ARRAY}\"]" "$WRITABLE_CONFIG"
  fi

  CONFIG_PATH="$WRITABLE_CONFIG"
  export CONFIG_PATH

elif [ -n "$JWT_SECRET" ] || [ -n "$OIDC_CLIENT_SECRET" ]; then
  # Config file exists but we need to inject secrets into it.
  WRITABLE_CONFIG="/tmp/canopy-config.toml"
  cp "$CONFIG_PATH" "$WRITABLE_CONFIG"

  if [ -n "$JWT_SECRET" ]; then
    ESCAPED_SECRET=$(escape_toml "$JWT_SECRET" | sed -e 's/&/\\&/g' -e 's/|/\\|/g')
    # Replace existing secret line, or insert after [jwt] header if missing
    if grep -q '^[[:space:]]*secret[[:space:]]*=' "$WRITABLE_CONFIG"; then
      sed -i "s|^[[:space:]]*secret[[:space:]]*=.*|secret = \"${ESCAPED_SECRET}\"|" "$WRITABLE_CONFIG"
    else
      sed -i "/^\[jwt\]/a\\
secret = \"${ESCAPED_SECRET}\"" "$WRITABLE_CONFIG"
    fi
  fi

  if [ -n "$OIDC_CLIENT_SECRET" ]; then
    SAFE_CS=$(escape_toml "$OIDC_CLIENT_SECRET" | sed -e 's/&/\\&/g' -e 's/|/\\|/g')
    # Insert client_secret after client_id line if not already present
    if grep -q '^[[:space:]]*client_secret[[:space:]]*=' "$WRITABLE_CONFIG"; then
      sed -i "s|^[[:space:]]*client_secret[[:space:]]*=.*|client_secret = \"${SAFE_CS}\"|" "$WRITABLE_CONFIG"
    else
      sed -i "/^[[:space:]]*client_id[[:space:]]*=/a\\
client_secret = \"${SAFE_CS}\"" "$WRITABLE_CONFIG"
    fi
  fi

  CONFIG_PATH="$WRITABLE_CONFIG"
  export CONFIG_PATH
fi

exec control-plane "$@"
