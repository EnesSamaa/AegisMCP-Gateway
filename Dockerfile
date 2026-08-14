# ==============================================================================
# AegisMCP-Gateway Multi-Stage Distroless Production Dockerfile
# Optimized with cargo-chef for layer caching & Google Distroless for security.
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Cargo Chef Planner
# Computes the dependency lock/recipe file to maximize build cache reuse.
# ------------------------------------------------------------------------------
FROM lukemathwalker/cargo-chef:latest-rust-1-bookworm AS planner
WORKDIR /app
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ------------------------------------------------------------------------------
# Stage 2: Cargo Chef Builder
# Cooks dependencies and builds release binaries with LTO & symbol stripping.
# ------------------------------------------------------------------------------
FROM lukemathwalker/cargo-chef:latest-rust-1-bookworm AS builder
WORKDIR /app

# Cook and cache dependency layers
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Copy application source tree
COPY . .

# Build production binaries
RUN cargo build --release --bin aegis-gateway --bin aegis-cli --exclude plugin-pii-filter

# ------------------------------------------------------------------------------
# Stage 3: Ultra-Minimal Distroless Runtime
# Runs as non-root user with zero package managers or shells.
# ------------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

WORKDIR /app

# Copy production binaries
COPY --from=builder --chown=nonroot:nonroot /app/target/release/aegis-gateway /usr/local/bin/aegis-gateway
COPY --from=builder --chown=nonroot:nonroot /app/target/release/aegis-cli /usr/local/bin/aegis-cli

# Copy default gateway configuration
COPY --from=builder --chown=nonroot:nonroot /app/aegis.yaml /app/aegis.yaml

# Set runtime environment defaults
ENV LISTEN_ADDR="0.0.0.0:8080" \
    UPSTREAM_URL="http://127.0.0.1:9090" \
    RUST_LOG="info"

# Expose HTTP proxy & Prometheus metrics port
EXPOSE 8080

# Enforce non-root execution
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/aegis-gateway"]
