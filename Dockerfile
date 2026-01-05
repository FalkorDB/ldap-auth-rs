# Build stage
FROM rust:alpine AS builder

WORKDIR /app

# Install build dependencies for Alpine including cargo-chef
RUN apk add --no-cache \
    musl-dev \
    pkgconfig \
    openssl-dev \
    openssl-libs-static && \
    cargo install cargo-chef

# Planner stage - analyze dependencies
FROM builder AS planner
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo chef prepare --recipe-path recipe.json

# Cook stage - build dependencies separately
FROM builder AS cook
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Final build stage
FROM builder AS final-builder
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
COPY --from=cook /app/target target
COPY --from=cook /usr/local/cargo /usr/local/cargo

# Build the actual application (only app code, dependencies already compiled)
RUN cargo build --release

# Build the CLI tool
RUN cargo build --release --bin ldap-auth-cli

# Runtime stage - Using Alpine for minimal size and security
FROM alpine:3.21

WORKDIR /app

# Install only runtime dependencies (OpenSSL, curl, and CA certificates)
RUN apk add --no-cache \
    ca-certificates \
    curl \
    libgcc \
    openssl \
    tzdata

# Copy binaries from builder
COPY --from=final-builder /app/target/release/ldap-auth-rs /app/ldap-auth-rs
COPY --from=final-builder /app/target/release/ldap-auth-cli /usr/local/bin/ldap-auth-cli

# Create non-root user
RUN adduser -D -u 1000 appuser && \
    chown -R appuser:appuser /app

USER appuser

# Expose ports
EXPOSE 8080 3389

# Set environment variables
ENV RUST_LOG=info
ENV REDIS_HOST=redis
ENV REDIS_PORT=6379
ENV API_PORT=8080
ENV LDAP_PORT=3389
ENV LDAP_BASE_DN=dc=example,dc=com

CMD ["/app/ldap-auth-rs"]
