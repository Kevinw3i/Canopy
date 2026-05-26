#!/bin/sh
set -e
umask 077

CONFIG_PATH="${CONFIG_PATH:-/etc/canopy/config.toml}"
JWT_SECRET="${JWT_SECRET:-}"
JWT_SECRET_ARN="${JWT_SECRET_ARN:-}"
OIDC_ISSUER_URL="${OIDC_ISSUER_URL:-}"
OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-}"
OIDC_CLIENT_SECRET="${OIDC_CLIENT_SECRET:-}"
CORS_ALLOWED_ORIGINS="${CORS_ALLOWED_ORIGINS:-}"
AUDIT_CLOUDWATCH_LOG_GROUP="${AUDIT_CLOUDWATCH_LOG_GROUP:-}"
AUDIT_CLOUDWATCH_LOG_STREAM="${AUDIT_CLOUDWATCH_LOG_STREAM:-canopy-audit}"
AUDIT_S3_BUCKET="${AUDIT_S3_BUCKET:-}"
AUDIT_S3_PREFIX="${AUDIT_S3_PREFIX:-}"

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

bounded_int() {
  name="$1"
  value="$2"
  min="$3"
  max="$4"

  value=$(positive_int "$name" "$value")
  if [ "$value" -lt "$min" ] || [ "$value" -gt "$max" ]; then
    fatal "$name must be between $min and $max."
  fi

  printf '%s' "$value"
}

patch_config_line() {
  section_re="$1"
  match_re="$2"
  after_re="$3"
  line="$4"
  file="$5"
  tmp="${file}.tmp.$$"

  if PATCH_SECTION="$section_re" PATCH_MATCH="$match_re" PATCH_AFTER="$after_re" PATCH_LINE="$line" awk '
    BEGIN {
      section_re = ENVIRON["PATCH_SECTION"]
      match_re = ENVIRON["PATCH_MATCH"]
      after_re = ENVIRON["PATCH_AFTER"]
      line = ENVIRON["PATCH_LINE"]
    }
    {
      lines[NR] = $0
      if ($0 ~ /^[[:space:]]*\[[^]]+\][[:space:]]*$/) {
        if (!section_start && $0 ~ section_re) {
          in_section = 1
          section_start = NR
        } else {
          in_section = 0
        }
      }
      if (!in_section) {
        next
      }
      if (!match_line && $0 ~ match_re) {
        match_line = NR
      }
      if (!after_line && $0 ~ after_re) {
        after_line = NR
      }
    }
    END {
      if (!section_start || (!match_line && !after_line)) {
        exit 1
      }
      if (match_line) {
        for (i = 1; i <= NR; i++) {
          if (i == match_line) {
            print line
          } else {
            print lines[i]
          }
        }
        exit 0
      }
      if (after_line) {
        for (i = 1; i <= NR; i++) {
          print lines[i]
          if (i == after_line) {
            print line
          }
        }
        exit 0
      }
      exit 1
    }
  ' "$file" > "$tmp"; then
    mv "$tmp" "$file"
  else
    rm -f "$tmp"
    fatal "Unable to patch generated runtime config."
  fi
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
  SAFE_AWS_SESSION_DURATION_SECONDS=$(
    bounded_int "AWS_SESSION_DURATION_SECONDS" "${AWS_SESSION_DURATION_SECONDS:-3600}" 900 43200
  )

  CLIENT_SECRET_LINE=""
  if [ -n "$OIDC_CLIENT_SECRET" ]; then
    SAFE_OIDC_SECRET=$(escape_toml "$OIDC_CLIENT_SECRET")
    CLIENT_SECRET_LINE="client_secret = \"${SAFE_OIDC_SECRET}\""
  fi

  # Default to the path baked into the image by the Dockerfile. A SQLite
  # entitlement database can be selected instead, but the two backends are
  # mutually exclusive.
  if [ -n "${ENTITLEMENTS_DATABASE_URL:-}" ]; then
    if [ -n "${ENTITLEMENTS_FILE:-}" ]; then
      fatal "ENTITLEMENTS_FILE and ENTITLEMENTS_DATABASE_URL are mutually exclusive."
    fi
    SAFE_ENTITLEMENTS_DATABASE_URL=$(escape_toml "$ENTITLEMENTS_DATABASE_URL")
    ENTITLEMENTS_LINE="entitlements_database_url = \"${SAFE_ENTITLEMENTS_DATABASE_URL}\""
  else
    ENTITLEMENTS_FILE="${ENTITLEMENTS_FILE:-/etc/canopy/entitlements.toml}"
    SAFE_ENTITLEMENTS_FILE=$(escape_toml "$ENTITLEMENTS_FILE")
    ENTITLEMENTS_LINE="entitlements_file = \"${SAFE_ENTITLEMENTS_FILE}\""
  fi

  CORS_LINE=""
  if [ -n "$CORS_ALLOWED_ORIGINS" ]; then
    CORS_LINE="cors_allowed_origins = $(toml_array_from_csv "$CORS_ALLOWED_ORIGINS")"
  fi

  AUDIT_EXPORT_CONFIG=""
  if [ -n "$AUDIT_CLOUDWATCH_LOG_GROUP" ] || [ -n "$AUDIT_S3_BUCKET" ]; then
    SAFE_AUDIT_EXPORT_QUEUE_SIZE=$(positive_int "AUDIT_EXPORT_QUEUE_SIZE" "${AUDIT_EXPORT_QUEUE_SIZE:-1024}")
    AUDIT_EXPORT_CONFIG=$(cat <<TOML
[audit_export]
queue_size = ${SAFE_AUDIT_EXPORT_QUEUE_SIZE}
TOML
)
  fi

  if [ -n "$AUDIT_CLOUDWATCH_LOG_GROUP" ]; then
    SAFE_AUDIT_CLOUDWATCH_LOG_GROUP=$(escape_toml "$AUDIT_CLOUDWATCH_LOG_GROUP")
    SAFE_AUDIT_CLOUDWATCH_LOG_STREAM=$(escape_toml "$AUDIT_CLOUDWATCH_LOG_STREAM")
    AUDIT_EXPORT_CONFIG="${AUDIT_EXPORT_CONFIG}

[audit_export.cloudwatch_logs]
log_group_name = \"${SAFE_AUDIT_CLOUDWATCH_LOG_GROUP}\"
log_stream_name = \"${SAFE_AUDIT_CLOUDWATCH_LOG_STREAM}\"
create_log_stream = true"
  fi

  if [ -n "$AUDIT_S3_BUCKET" ]; then
    SAFE_AUDIT_S3_BUCKET=$(escape_toml "$AUDIT_S3_BUCKET")
    SAFE_AUDIT_S3_PREFIX=$(escape_toml "$AUDIT_S3_PREFIX")
    AUDIT_EXPORT_CONFIG="${AUDIT_EXPORT_CONFIG}

[audit_export.s3]
bucket = \"${SAFE_AUDIT_S3_BUCKET}\"
prefix = \"${SAFE_AUDIT_S3_PREFIX}\""
  fi

  cat > "$WRITABLE_CONFIG" <<TOML
bind_address = "${SAFE_BIND_ADDRESS}"
${CORS_LINE}
${ENTITLEMENTS_LINE}
${AUDIT_EXPORT_CONFIG}

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
  chmod 0600 "$WRITABLE_CONFIG"

  CONFIG_PATH="$WRITABLE_CONFIG"
  export CONFIG_PATH

elif [ -n "$JWT_SECRET" ] || [ -n "$OIDC_CLIENT_SECRET" ]; then
  # Config file exists but we need to inject secrets into it.
  WRITABLE_CONFIG="/tmp/canopy-config.toml"
  cp "$CONFIG_PATH" "$WRITABLE_CONFIG"

  if [ -n "$JWT_SECRET" ]; then
    ESCAPED_SECRET=$(escape_toml "$JWT_SECRET")
    # Replace existing secret line, or insert after [jwt] header if missing
    patch_config_line \
      '^[[:space:]]*\[jwt\][[:space:]]*$' \
      '^[[:space:]]*secret[[:space:]]*=' \
      '^[[:space:]]*\[jwt\][[:space:]]*$' \
      "secret = \"${ESCAPED_SECRET}\"" \
      "$WRITABLE_CONFIG"
  fi

  if [ -n "$OIDC_CLIENT_SECRET" ]; then
    SAFE_CS=$(escape_toml "$OIDC_CLIENT_SECRET")
    # Insert client_secret after client_id line if not already present
    patch_config_line \
      '^[[:space:]]*\[oidc\][[:space:]]*$' \
      '^[[:space:]]*client_secret[[:space:]]*=' \
      '^[[:space:]]*client_id[[:space:]]*=' \
      "client_secret = \"${SAFE_CS}\"" \
      "$WRITABLE_CONFIG"
  fi

  chmod 0600 "$WRITABLE_CONFIG"

  CONFIG_PATH="$WRITABLE_CONFIG"
  export CONFIG_PATH
fi

exec control-plane "$@"
