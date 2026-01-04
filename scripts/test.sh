#!/bin/bash

# Test script for ldap-auth-rs

set -e

echo "🧪 Running LDAP Auth RS tests..."

# Start Redis for testing if not running
if ! docker ps | grep -q ldap-auth-redis-test; then
    echo "🐳 Starting test Redis container..."
    docker run -d \
        --name ldap-auth-redis-test \
        -p 6380:6379 \
        redis:7-alpine
    
    # Wait for Redis to be ready
    sleep 2
fi

export TEST_REDIS_URL="redis://127.0.0.1:6380"

# Run unit tests
echo "📋 Running unit tests..."
cargo test --lib

# Run integration tests
echo "🔗 Running integration tests..."
cargo test --test integration_test

# Run all tests with coverage (if tarpaulin is installed)
if command -v cargo-tarpaulin &> /dev/null; then
    echo "📊 Running tests with coverage..."
    cargo tarpaulin --out Html --output-dir coverage
    echo "✅ Coverage report generated in coverage/index.html"
fi

# Cleanup
echo "🧹 Cleaning up test container..."
docker stop ldap-auth-redis-test || true
docker rm ldap-auth-redis-test || true

echo ""
echo "✅ All tests passed!"
