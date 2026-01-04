# Build stage
FROM rust:alpine AS builder

WORKDIR /app

# Install build dependencies for Alpine
RUN apk add --no-cache \
    musl-dev \
    pkgconfig \
    openssl-dev \
    openssl-libs-static

# Copy manifest files
COPY Cargo.toml Cargo.lock ./

# Create dummy main to cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy source code
COPY src ./src
COPY tests ./tests

# Build the actual application
RUN touch src/main.rs && cargo build --release

# Build the CLI tool
RUN cargo build --release --bin ldap-auth-cli

# Runtime stage - Using Alpine for minimal size and security
FROM alpine:3.21

WORKDIR /app

# Install only runtime dependencies (OpenSSL and CA certificates)
RUN apk add --no-cache \
    ca-certificates \
    libgcc \
    openssl \
    tzdata

# Copy binaries from builder
COPY --from=builder /app/target/release/ldap-auth-rs /app/ldap-auth-rs
COPY --from=builder /app/target/release/ldap-auth-cli /usr/local/bin/ldap-auth-cli

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
