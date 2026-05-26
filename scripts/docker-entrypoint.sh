#!/bin/sh
set -e

CONFIG_PATH="${CONFIG_PATH:-/etc/canopy/config.toml}"
JWT_SECRET="${JWT_SECRET:-}"
JWT_SECRET_ARN="${JWT_SECRET_ARN:-}"
OIDC_ISSUER_URL="${OIDC_ISSUER_URL:-}"
OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-}"
OIDC_CLIENT_SECRET="${OIDC_CLIENT_SECRET:-}"
CORS_ALLOWED_ORIGINS="${CORS_ALLOWED_ORIGINS:-}"

fatal() {
  echo "FATAL: $*" >&2
  exit 1
}

# ── Helper: escape a value for TOML double-quoted strings ──
escape_toml() {
  line_count=$(printf '%s\n' "$1" | wc -l | tr -d '[:space:]')
  if [ "$line_count" != "1" ]; then
    fatal "TOML string values must not contain newlines."
  fi

  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

trim() {
  printf '%s' "$1" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

toml_array_from_csv() {
  rest="$1"
  out=""

  while :; do
    case "$rest" in
      *,*)
        item=${rest%%,*}
        rest=${rest#*,}
        more=1
        ;;
      *)
        item=$rest
        more=0
        ;;
    esac

    item=$(trim "$item")
    if [ -n "$item" ]; then
      escaped=$(escape_toml "$item")
      if [ -n "$out" ]; then
        out="${out}, "
      fi
      out="${out}\"${escaped}\""
    fi

    [ "$more" -eq 1 ] || break
  done

  printf '[%s]' "$out"
}

positive_int() {
  name="$1"
  value="$2"

  case "$value" in
    ''|*[!0-9]*)
      fatal "$name must be a positive integer."
      ;;
  esac

  if [ "$value" -le 0 ]; then
    fatal "$name must be a positive integer."
  fi

  printf '%s' "$value"
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
  SAFE_BIND_ADDRESS=$(escape_toml "${BIND_ADDRESS:-0.0.0.0:8443}")
  SAFE_OIDC_ISSUER_URL=$(escape_toml "$OIDC_ISSUER_URL")
  SAFE_OIDC_CLIENT_ID=$(escape_toml "$OIDC_CLIENT_ID")
  SAFE_AWS_DEFAULT_REGION=$(escape_toml "${AWS_DEFAULT_REGION:-ap-northeast-1}")
  SAFE_STS_EXTERNAL_ID=$(escape_toml "${STS_EXTERNAL_ID:-canopy}")
  SAFE_JWT_EXPIRY_SECONDS=$(positive_int "JWT_EXPIRY_SECONDS" "${JWT_EXPIRY_SECONDS:-3600}")
  SAFE_AWS_SESSION_DURATION_SECONDS=$(positive_int "AWS_SESSION_DURATION_SECONDS" "${AWS_SESSION_DURATION_SECONDS:-3600}")

  CLIENT_SECRET_LINE=""
  if [ -n "$OIDC_CLIENT_SECRET" ]; then
    SAFE_OIDC_SECRET=$(escape_toml "$OIDC_CLIENT_SECRET")
    CLIENT_SECRET_LINE="client_secret = \"${SAFE_OIDC_SECRET}\""
  fi

  # Default to the path baked into the image by the Dockerfile
  ENTITLEMENTS_FILE="${ENTITLEMENTS_FILE:-/etc/canopy/entitlements.toml}"
  SAFE_ENTITLEMENTS_FILE=$(escape_toml "$ENTITLEMENTS_FILE")
  ENTITLEMENTS_LINE="entitlements_file = \"${SAFE_ENTITLEMENTS_FILE}\""

  CORS_LINE=""
  if [ -n "$CORS_ALLOWED_ORIGINS" ]; then
    CORS_LINE="cors_allowed_origins = $(toml_array_from_csv "$CORS_ALLOWED_ORIGINS")"
  fi

  cat > "$WRITABLE_CONFIG" <<TOML
bind_address = "${SAFE_BIND_ADDRESS}"
${CORS_LINE}
${ENTITLEMENTS_LINE}

[oidc]
issuer_url = "${SAFE_OIDC_ISSUER_URL}"
client_id  = "${SAFE_OIDC_CLIENT_ID}"
${CLIENT_SECRET_LINE}

[jwt]
secret         = "${SAFE_JWT_SECRET}"
expiry_seconds = ${SAFE_JWT_EXPIRY_SECONDS}

[aws]
default_region           = "${SAFE_AWS_DEFAULT_REGION}"
session_duration_seconds = ${SAFE_AWS_SESSION_DURATION_SECONDS}
sts_external_id          = "${SAFE_STS_EXTERNAL_ID}"
TOML

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
