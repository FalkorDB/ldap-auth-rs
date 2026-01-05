# Configuration Guide

## Environment Variables

### Required Configuration

| Variable | Description | Example |
|----------|-------------|---------|
| `API_BEARER_TOKEN` | Bearer token for API authentication | `your-secure-token-here` |

### Redis Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_HOST` | `127.0.0.1` | Redis server hostname or IP |
| `REDIS_PORT` | `6379` | Redis server port |
| `REDIS_USERNAME` | - | Redis username (optional, for ACL) |
| `REDIS_PASSWORD` | - | Redis password (optional) |

### Optional Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `API_PORT` | `8080` | API server port |
| `LDAP_PORT` | `3389` | LDAP server port |
| `LDAP_BASE_DN` | `dc=example,dc=com` | LDAP base DN |
| `LDAP_SEARCH_BIND_ORG` | - | Organization authorized to perform LDAP searches (see LDAP Search Authorization) |
| `RUST_LOG` | `info` | Log level (trace, debug, info, warn, error) |
| `ENABLE_TLS` | `false` | Enable TLS for both API and LDAP servers |
| `TLS_CERT_PATH` | - | Path to TLS certificate file (required when `ENABLE_TLS=true`) |
| `TLS_KEY_PATH` | - | Path to TLS private key file (required when `ENABLE_TLS=true`) |

## Configuration Methods

### 1. Environment Variables

```bash
export API_BEARER_TOKEN="my-secure-token"
export REDIS_HOST="127.0.0.1"
export REDIS_PORT="6379"
export API_PORT="8080"
export RUST_LOG="debug"
```

### 2. .env File

Create a `.env` file in the project root:

```env
API_BEARER_TOKEN=my-secure-token
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
API_PORT=8080
LDAP_PORT=3389
RUST_LOG=info
```

### 3. Docker Environment

```bash
docker run -d \
  -e API_BEARER_TOKEN=my-token \
  -e REDIS_HOST=redis \
  -e REDIS_PORT=6379 \
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
      REDIS_HOST: redis
      REDIS_PORT: 6379
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
  REDIS_HOST: redis
  REDIS_PORT: "6379"
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

The application constructs the Redis connection URL internally from the individual components:

```
redis://[username:password@]host:port
```

Examples:
```bash
# Basic connection (no auth)
REDIS_HOST=redis.example.com
REDIS_PORT=6379

# With password authentication
REDIS_HOST=redis.example.com
REDIS_PORT=6379
REDIS_PASSWORD=my-secure-password
# Results in: redis://:my-secure-password@redis.example.com:6379

# With username and password (Redis ACL)
REDIS_HOST=redis.example.com
REDIS_PORT=6379
REDIS_USERNAME=myuser
REDIS_PASSWORD=my-secure-password
# Results in: redis://myuser:my-secure-password@redis.example.com:6379
```

**Security best practices:**
- Use Redis authentication with strong passwords
- Use Redis ACLs for fine-grained access control
- Run Redis in a private network
- For TLS connections, see your Redis client library documentation

### TLS Configuration

#### Development (Self-Signed Certificates)

For development and testing:

```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt \
  -days 365 -subj "/CN=localhost"

# Configure application
export ENABLE_TLS=true
export TLS_CERT_PATH=./server.crt
export TLS_KEY_PATH=./server.key
```

#### Production (Real Certificates)

Use certificates from a trusted CA (Let's Encrypt, DigiCert, etc.):

```bash
# Configure with real certificates
export ENABLE_TLS=true
export TLS_CERT_PATH=/etc/ssl/certs/ldap-auth.crt
export TLS_KEY_PATH=/etc/ssl/private/ldap-auth.key
```

#### Kubernetes with cert-manager

For Kubernetes deployments, TLS is automatically configured using cert-manager:

```bash
# TLS is enabled by default in k8s/base/configmap.yaml
ENABLE_TLS: "true"
TLS_CERT_PATH: "/etc/tls/tls.crt"
TLS_KEY_PATH: "/etc/tls/tls.key"

# Certificate is auto-generated and mounted via k8s/base/certificate.yaml
# No manual configuration needed
```

See [k8s/README.md](../k8s/README.md#-tls-configuration) for Kubernetes TLS options.

#### TLS Requirements

When `ENABLE_TLS=true`:
- Both `TLS_CERT_PATH` and `TLS_KEY_PATH` must be set
- Certificate and key files must exist and be readable
- Certificate must be in PEM format
- Private key must be in PKCS#1 or PKCS#8 PEM format
- Application will fail to start if TLS configuration is invalid

#### TLS Applies To

When TLS is enabled, it secures both:
- **API Server** (HTTP): Serves on HTTPS instead of HTTP
- **LDAP Server**: Serves LDAPS (LDAP over TLS)

Example client connections with TLS:
```bash
# API with TLS
curl -H "Authorization: Bearer $TOKEN" https://localhost:8080/api/users

# LDAP with TLS
ldapsearch -H ldaps://localhost:3389 -D "uid=admin,ou=people,dc=example,dc=com" -W
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
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
API_PORT=8080
LDAP_PORT=3389
RUST_LOG=debug
```

### Staging

```env
API_BEARER_TOKEN=<from-secrets-manager>
REDIS_HOST=redis-staging
REDIS_PORT=6379
REDIS_PASSWORD=<from-secrets-manager>
API_PORT=8080
LDAP_PORT=3389
RUST_LOG=info
ENABLE_TLS=true
TLS_CERT_PATH=/etc/ssl/certs/staging.crt
TLS_KEY_PATH=/etc/ssl/private/staging.key
```

### Production

```env
API_BEARER_TOKEN=<from-secrets-manager>
REDIS_HOST=redis-prod
REDIS_PORT=6380
REDIS_PASSWORD=<from-secrets-manager>
API_PORT=8080
LDAP_PORT=636
RUST_LOG=warn
ENABLE_TLS=true
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
