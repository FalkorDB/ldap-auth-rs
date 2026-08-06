# LDAP Auth CLI

A command-line interface tool for interacting with the LDAP Auth Service REST API.

## Installation

The CLI tool is bundled with the Docker image and can be accessed directly:

```bash
docker run --rm ldap-auth-rs:latest ldap-auth-cli --help
```

Or build it locally:

```bash
cargo build --release --bin ldap-auth-cli
# Binary will be at: target/release/ldap-auth-cli
```

## Configuration

The CLI can be configured using command-line flags or environment variables:

- `--url` / `LDAP_AUTH_URL`: API base URL (default: http://localhost:8080)
- `--token` / `LDAP_AUTH_TOKEN`: Bearer token for authentication

## Usage Examples

### Health Check

```bash
ldap-auth-cli health
```

### TLS Operations

**Get CA Certificate:**

Retrieve the CA certificate from the server (only when TLS is enabled). This is useful for establishing secure LDAPS connections without using insecure mode.

```bash
# Print CA certificate to stdout
ldap-auth-cli tls get-ca-cert

# Save CA certificate to a file
ldap-auth-cli tls get-ca-cert --output ca.pem

# Use the CA certificate with ldapsearch
ldap-auth-cli tls get-ca-cert -o ca.pem
ldapsearch -H ldaps://localhost:3389 -x \
  -D "cn=alice,ou=myorg,dc=example,dc=com" \
  -w password123 \
  -b "dc=example,dc=com" \
  -o TLS_CACERT=ca.pem
```

**Note:** This command will fail with an error if TLS is not enabled on the server.

### User Management

**Create a user:**
```bash
ldap-auth-cli --token $TOKEN user create \
  --org myorg \
  --username jdoe \
  --password secret123 \
  --email jdoe@example.com \
  --name "John Doe"
```

**Get a user:**
```bash
ldap-auth-cli --token $TOKEN user get --org myorg --username jdoe
```

**List users in an organization:**
```bash
ldap-auth-cli --token $TOKEN user list --org myorg
```

**Update a user:**
```bash
ldap-auth-cli --token $TOKEN user update \
  --org myorg \
  --username jdoe \
  --email newemail@example.com \
  --name "John D. Doe"
```

**Delete a user:**
```bash
ldap-auth-cli --token $TOKEN user delete --org myorg --username jdoe
```

**Get user's groups:**
```bash
ldap-auth-cli --token $TOKEN user groups --org myorg --username jdoe
```

### Group Management

**Create a group:**
```bash
ldap-auth-cli --token $TOKEN group create \
  --org myorg \
  --name developers \
  --description "Development team"
```

**Get a group:**
```bash
ldap-auth-cli --token $TOKEN group get --org myorg --name developers
```

**List groups in an organization:**
```bash
ldap-auth-cli --token $TOKEN group list --org myorg
```

**Update a group:**
```bash
ldap-auth-cli --token $TOKEN group update \
  --org myorg \
  --name developers \
  --description "Development and DevOps team"
```

**Delete a group:**
```bash
ldap-auth-cli --token $TOKEN group delete --org myorg --name developers
```

**Add a member to a group:**
```bash
ldap-auth-cli --token $TOKEN group add-member \
  --org myorg \
  --name developers \
  --username jdoe
```

**Remove a member from a group:**
```bash
ldap-auth-cli --token $TOKEN group remove-member \
  --org myorg \
  --name developers \
  --username jdoe
```

## Using from Docker

When using the CLI from the Docker container, you can create an alias:

```bash
alias ldap-auth-cli='docker run --rm -e LDAP_AUTH_URL -e LDAP_AUTH_TOKEN --network host ldap-auth-rs:latest ldap-auth-cli'
```

Then use it normally:

```bash
export LDAP_AUTH_TOKEN="your-token-here"
export LDAP_AUTH_URL="http://localhost:8080"

ldap-auth-cli health
ldap-auth-cli user list --org myorg
```

## Output Format

The CLI returns JSON responses from the API, formatted for easy reading:

```json
{
  "username": "jdoe",
  "email": "jdoe@example.com",
  "full_name": "John Doe",
  "organization": "myorg",
  "created_at": "2024-01-04T10:30:00Z",
  "updated_at": "2024-01-04T10:30:00Z"
}
```

Errors are printed to stderr:

```
✗ Error: User not found
```

## Environment Variables

You can set environment variables to avoid repeating flags:

```bash
export LDAP_AUTH_URL="http://api.example.com:8080"
export LDAP_AUTH_TOKEN="your-bearer-token"

# Now you can use the CLI without --url and --token flags
ldap-auth-cli user list --org myorg
```

## Exit Codes

- `0`: Success
- `1`: Error (network error, API error, invalid input, etc.)
