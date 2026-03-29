#!/bin/bash

# Test script for ldap-auth-rs

set -euo pipefail

echo "🧪 Running LDAP Auth RS tests..."

cleanup() {
    echo "🧹 Cleaning up compose stack..."
    docker compose down -v || true
}

trap cleanup EXIT

echo "🐳 Starting Redis primary/replica test stack..."
docker compose up -d redis redis-replica

echo "⏳ Waiting for Redis services to be ready..."
redis_ready=false
for _ in $(seq 1 30); do
    if docker compose exec -T redis redis-cli -p 6390 ping | grep -q PONG && \
       docker compose exec -T redis-replica redis-cli -p 6391 ping | grep -q PONG; then
        redis_ready=true
        break
    fi
    sleep 1
done

if [ "$redis_ready" != true ]; then
    echo "❌ Redis primary/replica did not become ready after 30 seconds. Aborting tests."
    exit 1
fi
export TEST_REDIS_URL="redis://127.0.0.1:6390/15"

# Run unit tests
echo "📋 Running unit tests..."
cargo test --lib

# Run integration tests
echo "🔗 Running integration tests..."
cargo test --tests -- --test-threads=1

echo "🛑 Stopping shared Redis services before isolated failover compose test..."
docker compose stop redis redis-replica

echo "🔁 Running compose-backed replica failover test..."
bash tests/ldap_replica_failover_test.sh

# Run all tests with coverage (if tarpaulin is installed)
if command -v cargo-tarpaulin &> /dev/null; then
    echo "📊 Running tests with coverage..."
    cargo tarpaulin --out Html --output-dir coverage
    echo "✅ Coverage report generated in coverage/index.html"
fi

echo ""
echo "✅ All tests passed!"
