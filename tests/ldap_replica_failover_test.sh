#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
API_TOKEN="${API_TOKEN:-asdf}"
TEST_ORG="${TEST_ORG:-replicaorg}"
TEST_USER="${TEST_USER:-replicauser}"
TEST_PASSWORD="${TEST_PASSWORD:-replicapass123}"
BASE_DN="${BASE_DN:-dc=example,dc=com}"

# Resolve compose file to absolute path before we cd elsewhere
COMPOSE_FILE="$(cd "$(dirname "$0")/.." && pwd)/${COMPOSE_FILE##*/}"

# Choose LDAP host port: use 3389 if free, otherwise pick an ephemeral port.
# All API calls run inside the container via docker exec, so port 8080 never
# needs to be bound on the host. We generate a temp compose file that removes
# port 8080 from the ldap-auth service binding entirely.
if lsof -i tcp:3389 -sTCP:LISTEN >/dev/null 2>&1; then
  LDAP_HOST_PORT=13389
else
  LDAP_HOST_PORT=3389
fi
LDAP_URL="${LDAP_URL:-ldap://127.0.0.1:${LDAP_HOST_PORT}}"

# Build a temp compose file that binds only the LDAP port (no API port needed
# from host since all API probes go through docker exec).
_TMPDIR=$(mktemp -d)
_TEST_COMPOSE="${_TMPDIR}/docker-compose.failover.yml"
_REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

python3 - <<PYEOF
import yaml, os

with open("${COMPOSE_FILE}") as f:
    cfg = yaml.safe_load(f)

svc = cfg["services"]["ldap-auth"]

# Make build context absolute so the generated file works from any cwd
build = svc.get("build", {})
if isinstance(build, dict):
    ctx = build.get("context", ".")
    if not os.path.isabs(ctx):
        build["context"] = os.path.normpath(os.path.join("${_REPO_ROOT}", ctx))
    svc["build"] = build
elif isinstance(build, str):
    if not os.path.isabs(build):
        svc["build"] = os.path.normpath(os.path.join("${_REPO_ROOT}", build))

# Replace ports: only expose LDAP port on the chosen host port
svc["ports"] = ["${LDAP_HOST_PORT}:3389"]

with open("${_TEST_COMPOSE}", "w") as f:
    yaml.dump(cfg, f, default_flow_style=False)
PYEOF

cleanup() {
  docker compose -f "$_TEST_COMPOSE" down -v >/dev/null 2>&1 || true
  rm -rf "$_TMPDIR"
}

container_api() {
  docker compose -f "$_TEST_COMPOSE" exec -T ldap-auth curl -fsS "$@"
}

container_api_with_status() {
  docker compose -f "$_TEST_COMPOSE" exec -T ldap-auth curl -sS -o /tmp/ldap-replica-health.out -w "%{http_code}" "$@"
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
    if docker compose -f "$_TEST_COMPOSE" exec -T redis-replica redis-cli -p 6391 GET "user:${TEST_ORG}:${TEST_USER}" | grep -q 'organization'; then
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
  response=$(docker compose -f "$_TEST_COMPOSE" exec -T ldap-auth curl -sS -o /tmp/ldap-replica-create-user.out -w "%{http_code}" \
    -X POST "http://127.0.0.1:8080/api/users" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_TOKEN" \
    -d "$payload")

  if [[ "$response" != "201" && "$response" != "409" ]]; then
    docker compose -f "$_TEST_COMPOSE" exec -T ldap-auth cat /tmp/ldap-replica-create-user.out >&2 || true
    echo "Failed to create test user, HTTP $response" >&2
    return 1
  fi
}

assert_health_degraded() {
  for _ in $(seq 1 20); do
    local status_code
    status_code=$(container_api_with_status "http://127.0.0.1:8080/health" 2>/dev/null || true)
    if [[ "$status_code" == "503" ]]; then
      local body
      body=$(docker compose -f "$_TEST_COMPOSE" exec -T ldap-auth cat /tmp/ldap-replica-health.out 2>/dev/null || true)
      if echo "$body" | grep -q '"status":"degraded"'; then
        return 0
      fi
    fi
    sleep 1
  done
  echo "Health status did not transition to degraded within 20 seconds" >&2
  docker compose -f "$_TEST_COMPOSE" exec -T ldap-auth cat /tmp/ldap-replica-health.out >&2 2>/dev/null || true
  return 1
}

assert_ldap_bind_works() {
  local bind_dn="cn=${TEST_USER},ou=${TEST_ORG},${BASE_DN}"

  for _ in $(seq 1 20); do
    if ldapsearch -x -H "$LDAP_URL" \
      -D "$bind_dn" \
      -w "$TEST_PASSWORD" \
      -b "$BASE_DN" \
      -s base '(objectclass=*)' >/tmp/ldap-replica-bind.out 2>&1; then
      return 0
    fi
    sleep 1
  done

  echo "LDAP bind did not succeed within 20 seconds after primary shutdown" >&2
  cat /tmp/ldap-replica-bind.out >&2 || true
  return 1
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
docker compose -f "$_TEST_COMPOSE" up -d --build redis redis-replica ldap-auth

echo "Waiting for API..."
wait_for_api

echo "Creating LDAP test user through the primary..."
create_test_user

echo "Waiting for data to reach replica..."
wait_for_replication

echo "Stopping Redis primary to simulate failure..."
docker compose -f "$_TEST_COMPOSE" stop redis >/dev/null
sleep 2

echo "Checking health degraded mode..."
assert_health_degraded

echo "Checking LDAP bind through replica fallback..."
assert_ldap_bind_works

echo "Replica failover LDAP bind test passed"