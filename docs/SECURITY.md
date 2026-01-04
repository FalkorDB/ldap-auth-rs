# Security Features

This document describes the authentication and TLS security features implemented in the LDAP Auth RS application.

## Authentication

### API Bearer Token Authentication

All API endpoints (except `/health`) are protected with Bearer token authentication.

#### Configuration

Set the `API_BEARER_TOKEN` environment variable:

```bash
export API_BEARER_TOKEN="your-secret-token-here"
```

#### Usage

Include the token in the Authorization header:

```bash
curl -H "Authorization: Bearer your-secret-token-here" \
  http://localhost:8080/api/users/myorg
```

#### Protected Endpoints

All endpoints under `/api/*` require authentication:
- User management: `POST /api/users`, `GET /api/users/:org`, etc.
- Group management: `POST /api/groups`, `GET /api/groups/:org`, etc.
- Member management: `POST /api/groups/:org/:name/members`, etc.

#### Public Endpoints

- `GET /health` - Health check endpoint (no authentication required)

#### Error Responses

- **401 Unauthorized** - Missing or invalid token
  - Missing token: `"Missing authorization token"`
  - Invalid format: `"Invalid authorization format. Expected: Bearer <token>"`
  - Invalid token: `"Invalid authorization token"`

### LDAP Authentication

LDAP bind operations authenticate users against the Redis database:

1. **Bind Request**: Client sends DN and password
2. **Credential Verification**: Server verifies against stored password hashes (Argon2)
3. **Session Management**: Authenticated sessions can perform search operations

## TLS Support

### Configuration

Enable TLS by setting environment variables:

```bash
export ENABLE_TLS=true
export TLS_CERT_PATH=/path/to/certificate.pem
export TLS_KEY_PATH=/path/to/private-key.pem
```

### API Server TLS

When TLS is enabled, the API server will:
- Listen on HTTPS instead of HTTP
- Require valid TLS certificates
- Support modern TLS protocols (TLS 1.2+)

Example with TLS:
```bash
curl --cacert ca.pem \
  -H "Authorization: Bearer your-token" \
  https://localhost:8080/api/users/myorg
```

### LDAP Server TLS

The LDAP server supports:
- **LDAPS**: Direct TLS connection (configurable)
- **StartTLS**: Upgrade from plain LDAP to TLS (future enhancement)

### Certificate Management

For production:
1. Use certificates from a trusted CA (e.g., Let's Encrypt)
2. Rotate certificates before expiration
3. Store private keys securely with restricted permissions

For development/testing:
```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=localhost"
```

## Security Best Practices

### API Token Management

1. **Use Strong Tokens**: Generate cryptographically random tokens
   ```bash
   openssl rand -hex 32
   ```

2. **Rotate Regularly**: Change tokens periodically

3. **Secure Storage**: 
   - Use environment variables or secret management systems
   - Never commit tokens to version control
   - Use different tokens for different environments

4. **Least Privilege**: Use separate tokens for different services

### Password Security

- Passwords are hashed using **Argon2** (memory-hard algorithm)
- Salt is automatically generated per password
- Resistant to brute-force and rainbow table attacks

### Network Security

1. **Use TLS in Production**: Always enable TLS for production deployments
2. **Firewall Rules**: Restrict access to API and LDAP ports
3. **Reverse Proxy**: Consider using nginx or similar for additional security

### Monitoring

Monitor for:
- Failed authentication attempts
- Unusual API access patterns
- Certificate expiration warnings

## Testing

### Authentication Tests

```bash
# Run auth integration tests
cargo test --test auth_integration_test -- --test-threads=1

# Test missing token
curl -v http://localhost:8080/api/users/testorg

# Test valid token
curl -v -H "Authorization: Bearer valid-token" \
  http://localhost:8080/api/users/testorg
```

### TLS Tests

```bash
# Test TLS connection
openssl s_client -connect localhost:8080 -showcerts
```

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `API_BEARER_TOKEN` | Yes | - | Bearer token for API authentication |
| `ENABLE_TLS` | No | `false` | Enable TLS for API and LDAP servers |
| `TLS_CERT_PATH` | If TLS enabled | - | Path to TLS certificate file |
| `TLS_KEY_PATH` | If TLS enabled | - | Path to TLS private key file |
| `REDIS_HOST` | No | `127.0.0.1` | Redis server hostname |
| `REDIS_PORT` | No | `6379` | Redis server port |
| `REDIS_USERNAME` | No | - | Redis username (optional) |
| `REDIS_PASSWORD` | No | - | Redis password (optional) |
| `API_PORT` | No | `8080` | API server port |
| `LDAP_PORT` | No | `3389` | LDAP server port |
| `LDAP_BASE_DN` | No | `dc=example,dc=com` | LDAP base DN |

## Troubleshooting

### Authentication Fails

1. Check `API_BEARER_TOKEN` is set correctly
2. Verify token matches exactly (no extra spaces)
3. Check Authorization header format: `Bearer <token>`

### TLS Connection Fails

1. Verify certificate and key paths are correct
2. Check certificate hasn't expired: `openssl x509 -in cert.pem -noout -dates`
3. Ensure private key matches certificate
4. Check file permissions (private key should be 600)

### LDAP Bind Fails

1. Verify user exists in database
2. Check password is correct
3. Verify DN format: `cn=username,ou=organization,dc=example,dc=com`
4. Check Redis connection is working
