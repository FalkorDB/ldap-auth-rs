# Configuration Guide

## Environment Variables

### Required Configuration

| Variable | Description | Example |
|----------|-------------|---------|
| `API_BEARER_TOKEN` | Bearer token for API authentication | `your-secure-token-here` |
| `REDIS_URL` | Redis connection URL | `redis://127.0.0.1:6379` |

### Optional Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `API_HOST` | `0.0.0.0` | API server bind address |
| `API_PORT` | `8080` | API server port |
| `LDAP_HOST` | `0.0.0.0` | LDAP server bind address |
| `LDAP_PORT` | `3893` | LDAP server port |
| `LDAP_BASE_DN` | `dc=example,dc=com` | LDAP base DN |
| `LDAP_SEARCH_BIND_ORG` | - | Organization authorized to perform LDAP searches (see LDAP Search Authorization) |
| `RUST_LOG` | `info` | Log level (trace, debug, info, warn, error) |
| `TLS_CERT_PATH` | - | Path to TLS certificate (enables TLS) |
| `TLS_KEY_PATH` | - | Path to TLS private key (enables TLS) |

## Configuration Methods

### 1. Environment Variables

```bash
export API_BEARER_TOKEN="my-secure-token"
export REDIS_URL="redis://127.0.0.1:6379"
export API_PORT="8080"
export RUST_LOG="debug"
```

### 2. .env File

Create a `.env` file in the project root:

```env
API_BEARER_TOKEN=my-secure-token
REDIS_URL=redis://127.0.0.1:6379
API_PORT=8080
LDAP_PORT=3893
RUST_LOG=info
```

### 3. Docker Environment

```bash
docker run -d \
  -e API_BEARER_TOKEN=my-token \
  -e REDIS_URL=redis://redis:6379 \
  -e RUST_LOG=info \
  -p 8080:8080 \
  ldap-auth-rs:latest
```

### 4. Docker Compose

```yaml
services:
  ldap-auth:
    image: ldap-auth-rs:latest
    environment:
      API_BEARER_TOKEN: my-secure-token
      REDIS_URL: redis://redis:6379
      API_PORT: 8080
      RUST_LOG: info
```

### 5. Kubernetes ConfigMap/Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ldap-auth-secrets
type: Opaque
stringData:
  API_BEARER_TOKEN: my-secure-token
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: ldap-auth-config
data:
  REDIS_URL: redis://redis:6379
  API_PORT: "8080"
  RUST_LOG: info
```

## Configuration Validation

The application validates configuration on startup and will **fail fast** if:
- Required environment variables are missing
- Redis connection cannot be established
- TLS certificate/key paths are invalid
- Port numbers are out of range

This ensures deployment issues are caught immediately.

## Security Best Practices

### Bearer Token

- **Minimum length**: 32 characters recommended
- **Character set**: Use alphanumeric + special characters
- **Rotation**: Rotate tokens periodically
- **Storage**: Use secrets management (Vault, K8s Secrets, etc.)

Example generation:
```bash
# Generate secure token
openssl rand -base64 32
```

### Redis Security

- Use Redis authentication: `redis://:password@host:port`
- Enable Redis TLS: `rediss://host:port` (note the 's')
- Use Redis ACLs for fine-grained access control
- Run Redis in a private network

### TLS Configuration

For production, always enable TLS:

```bash
# Generate self-signed certificate (dev only)
openssl req -x509 -newkey rsa:4096 \
  -keyout key.pem -out cert.pem \
  -days 365 -nodes \
  -subj "/CN=localhost"

# Use in production with real certificates
export TLS_CERT_PATH=/etc/ssl/certs/server.crt
export TLS_KEY_PATH=/etc/ssl/private/server.key
```

## Logging Configuration

### Log Levels

| Level | Use Case | Example |
|-------|----------|---------|
| `trace` | Very detailed debugging | Request/response bodies |
| `debug` | General debugging | Function calls, flow |
| `info` | Production default | Important events |
| `warn` | Warnings | Recoverable errors |
| `error` | Errors only | Failed operations |

### Structured Logging

Set specific module levels:

```bash
# Only errors from hyper, debug from app
RUST_LOG=hyper=error,ldap_auth_rs=debug
```

### JSON Logging

For log aggregation (ELK, Splunk):

```bash
# Use tracing-subscriber JSON format
RUST_LOG_FORMAT=json cargo run
```

## Redis Configuration

### Connection String Format

```
redis://[username:password@]host[:port][/database]
```

Examples:
```bash
# Basic
redis://127.0.0.1:6379

# With password
redis://:mypassword@127.0.0.1:6379

# With username and password (Redis 6+)
redis://username:password@127.0.0.1:6379

# TLS enabled
rediss://127.0.0.1:6380

# Select database
redis://127.0.0.1:6379/2
```

### Connection Pool Settings

Currently using default pool settings:
- Max size: CPU cores * 4
- Timeout: 30 seconds
- Recycle timeout: 1 hour

To customize, modify `src/redis_db.rs`.

## Performance Tuning

### Cache Configuration

Bearer token cache settings in `src/cache.rs`:
- Cache size: 10,000 tokens
- TTL: 5 minutes
- Eviction: LRU

### Metrics

Prometheus metrics are always enabled. Scrape configuration:

```yaml
scrape_configs:
  - job_name: 'ldap-auth'
    scrape_interval: 15s
    metrics_path: '/metrics'
    static_configs:
      - targets: ['ldap-auth:8080']
```

## Example Configurations

### Development

```env
API_BEARER_TOKEN=dev-token-123
REDIS_URL=redis://127.0.0.1:6379
API_PORT=8080
LDAP_PORT=3893
RUST_LOG=debug
```

### Staging

```env
API_BEARER_TOKEN=<from-secrets-manager>
REDIS_URL=redis://:password@redis-staging:6379
API_HOST=0.0.0.0
API_PORT=8080
LDAP_PORT=3893
RUST_LOG=info
TLS_CERT_PATH=/etc/ssl/certs/staging.crt
TLS_KEY_PATH=/etc/ssl/private/staging.key
```

### Production

```env
API_BEARER_TOKEN=<from-secrets-manager>
REDIS_URL=rediss://:password@redis-prod:6380
API_HOST=0.0.0.0
API_PORT=8080
LDAP_PORT=636
RUST_LOG=warn
TLS_CERT_PATH=/etc/ssl/certs/prod.crt
TLS_KEY_PATH=/etc/ssl/private/prod.key
```

## LDAP Search Authorization

By default, any authenticated LDAP user can perform search operations. To restrict search access to a specific organization (useful for service accounts), set the `LDAP_SEARCH_BIND_ORG` environment variable:

```bash
export LDAP_SEARCH_BIND_ORG="service_accounts"
```

### How It Works

1. **Without `LDAP_SEARCH_BIND_ORG`**: Any user who successfully binds (authenticates) can search for users and groups
2. **With `LDAP_SEARCH_BIND_ORG`**: Only users from the specified organization can perform searches

### Use Case Example

Similar to Valkey-LDAP module's `ldap.search_bind_dn` configuration:

```bash
# Create a service organization for LDAP search operations
export LDAP_SEARCH_BIND_ORG="ldap_service"

# Then create a user in this organization via the API
curl -X POST http://localhost:8080/api/v1/organizations/ldap_service/users \
  -H "Authorization: Bearer $API_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "search_user",
    "password": "secure_password",
    "email": "search@service.com"
  }'
```

Now only `cn=search_user,ou=ldap_service,dc=example,dc=com` can perform LDAP searches. Other users can still bind but cannot search.

### Configuration in LDAP Clients

Configure your LDAP client to use the search bind user:

```properties
# Example: Valkey LDAP module configuration
ldap.search_bind_dn "cn=search_user,ou=ldap_service,dc=example,dc=com"
ldap.search_bind_passwd "secure_password"
```

```yaml
# Example: Application LDAP config
ldap:
  url: ldap://localhost:3389
  bind_dn: cn=search_user,ou=ldap_service,dc=example,dc=com
  bind_password: secure_password
  base_dn: dc=example,dc=com
```

## Troubleshooting

### Redis Connection Issues

```bash
# Test Redis connectivity
redis-cli -h 127.0.0.1 -p 6379 ping

# Check Redis logs
docker logs redis-container
```

### TLS Issues

```bash
# Verify certificate
openssl x509 -in cert.pem -text -noout

# Test TLS connection
openssl s_client -connect localhost:8080
```

### Configuration Validation

The app validates on startup and logs:
```
INFO ldap_auth_rs: Configuration validated successfully
INFO ldap_auth_rs: Redis connection established
INFO ldap_auth_rs: API server listening on 0.0.0.0:8080
INFO ldap_auth_rs: LDAP server listening on 0.0.0.0:3893
```

Check logs for validation errors if startup fails.
