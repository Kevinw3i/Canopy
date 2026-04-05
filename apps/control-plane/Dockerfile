# ── Builder ──────────────────────────────────────────────
# Build from workspace root:
#   docker build -t canopy/control-plane -f apps/control-plane/Dockerfile .

FROM rust:1.85-bookworm AS builder

WORKDIR /build

# 1) Cache dependencies — copy manifests first, then do a dummy build
COPY Cargo.toml Cargo.lock ./
COPY crates/shared/Cargo.toml crates/shared/Cargo.toml
COPY apps/control-plane/Cargo.toml apps/control-plane/Cargo.toml
COPY apps/tui-client/Cargo.toml apps/tui-client/Cargo.toml

# Create stub lib/main files so cargo can resolve the workspace
RUN mkdir -p crates/shared/src && echo "pub fn _stub(){}" > crates/shared/src/lib.rs \
 && mkdir -p apps/control-plane/src && echo "fn main(){}" > apps/control-plane/src/main.rs \
 && mkdir -p apps/tui-client/src && echo "fn main(){}" > apps/tui-client/src/main.rs \
 && cargo build --release -p control-plane 2>/dev/null || true

# 2) Copy real source and build for real
COPY crates/ crates/
COPY apps/control-plane/ apps/control-plane/

# Touch main.rs so cargo sees it changed after the stub
RUN touch apps/control-plane/src/main.rs \
 && cargo build --release -p control-plane

# ── Runtime ─────────────────────────────────────────────

FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip \
 && ARCH=$(dpkg --print-architecture) \
 && if [ "$ARCH" = "arm64" ]; then \
      AWS_CLI_URL="https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip"; \
    else \
      AWS_CLI_URL="https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip"; \
    fi \
 && curl -fsSL "$AWS_CLI_URL" -o /tmp/awscliv2.zip \
 && unzip -q /tmp/awscliv2.zip -d /tmp \
 && /tmp/aws/install \
 && rm -rf /tmp/aws /tmp/awscliv2.zip \
 && apt-get purge -y --auto-remove unzip \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd -r canopy && useradd -r -g canopy -d /etc/canopy -s /sbin/nologin canopy \
 && mkdir -p /etc/canopy && chown canopy:canopy /etc/canopy

COPY --from=builder /build/target/release/control-plane /usr/local/bin/control-plane
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Entitlements config — REQUIRED for production builds.
# Build with: --build-arg ENTITLEMENTS_FILE=entitlements.toml
# Omitting this arg or using entitlements.sample.toml will fail the build.
ARG ENTITLEMENTS_FILE
RUN test -n "${ENTITLEMENTS_FILE}" || { echo "ERROR: ENTITLEMENTS_FILE build-arg is required. Use --build-arg ENTITLEMENTS_FILE=entitlements.toml"; exit 1; }
RUN test "${ENTITLEMENTS_FILE}" != "entitlements.sample.toml" || { echo "ERROR: entitlements.sample.toml is not allowed for production builds."; exit 1; }
COPY ${ENTITLEMENTS_FILE} /etc/canopy/entitlements.toml

ENV CONFIG_PATH=/etc/canopy/config.toml \
    RUST_LOG=control_plane=info,tower_http=info

EXPOSE 8443

USER canopy

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8443/health || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
