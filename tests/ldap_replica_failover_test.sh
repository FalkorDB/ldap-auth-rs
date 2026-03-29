#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
API_URL="${API_URL:-http://127.0.0.1:8080}"
LDAP_URL="${LDAP_URL:-ldap://127.0.0.1:3389}"
API_TOKEN="${API_TOKEN:-asdf}"
TEST_ORG="${TEST_ORG:-replicaorg}"
TEST_USER="${TEST_USER:-replicauser}"
TEST_PASSWORD="${TEST_PASSWORD:-replicapass123}"
BASE_DN="${BASE_DN:-dc=example,dc=com}"

cleanup() {
  docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}

container_api() {
  docker compose -f "$COMPOSE_FILE" exec -T ldap-auth curl -fsS "$@"
}

wait_for_api() {
  for _ in $(seq 1 60); do
    if container_api "http://127.0.0.1:8080/health" >/dev/null; then
      return 0
    fi
    sleep 1
  done

  echo "API did not become ready in time" >&2
  return 1
}

wait_for_replication() {
  for _ in $(seq 1 30); do
    if docker compose -f "$COMPOSE_FILE" exec -T redis-replica redis-cli -p 6391 GET "user:${TEST_ORG}:${TEST_USER}" | grep -q 'organization'; then
      return 0
    fi
    sleep 1
  done

  echo "Replica did not receive test user in time" >&2
  return 1
}

create_test_user() {
  local payload
  payload=$(cat <<JSON
{"organization":"${TEST_ORG}","username":"${TEST_USER}","password":"${TEST_PASSWORD}","email":"${TEST_USER}@${TEST_ORG}.com"}
JSON
)

  local response
  response=$(docker compose -f "$COMPOSE_FILE" exec -T ldap-auth curl -sS -o /tmp/ldap-replica-create-user.out -w "%{http_code}" \
    -X POST "http://127.0.0.1:8080/api/users" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_TOKEN" \
    -d "$payload")

  if [[ "$response" != "201" && "$response" != "409" ]]; then
    docker compose -f "$COMPOSE_FILE" exec -T ldap-auth cat /tmp/ldap-replica-create-user.out >&2 || true
    echo "Failed to create test user, HTTP $response" >&2
    return 1
  fi
}

assert_health_degraded() {
  local body
  body=$(container_api "http://127.0.0.1:8080/health")
  echo "$body" | grep -q '"status":"degraded"'
}

assert_ldap_bind_works() {
  local bind_dn="cn=${TEST_USER},ou=${TEST_ORG},${BASE_DN}"

  ldapsearch -x -H "$LDAP_URL" \
    -D "$bind_dn" \
    -w "$TEST_PASSWORD" \
    -b "$BASE_DN" \
    -s base '(objectclass=*)' >/tmp/ldap-replica-bind.out 2>&1
}

trap cleanup EXIT

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

if ! command -v ldapsearch >/dev/null 2>&1; then
  echo "ldapsearch is required" >&2
  exit 1
fi

echo "Starting compose stack with Redis primary and replica..."
docker compose -f "$COMPOSE_FILE" up -d --build redis redis-replica ldap-auth

echo "Waiting for API..."
wait_for_api

echo "Creating LDAP test user through the primary..."
create_test_user

echo "Waiting for data to reach replica..."
wait_for_replication

echo "Stopping Redis primary to simulate failure..."
docker compose -f "$COMPOSE_FILE" stop redis >/dev/null
sleep 2

echo "Checking health degraded mode..."
assert_health_degraded

echo "Checking LDAP bind through replica fallback..."
assert_ldap_bind_works

echo "Replica failover LDAP bind test passed"