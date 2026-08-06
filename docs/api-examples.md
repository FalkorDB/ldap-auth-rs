# API Usage Examples

## User Management

### Create a User

```bash
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "organization": "acme",
    "username": "john",
    "password": "secure_password_123",
    "email": "john@acme.com",
    "full_name": "John Doe"
  }'
```

### Get a User

```bash
curl http://localhost:8080/api/users/acme/john
```

### Update a User

```bash
curl -X PUT http://localhost:8080/api/users/acme/john \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@acme.com",
    "full_name": "John M. Doe"
  }'
```

### Delete a User

```bash
curl -X DELETE http://localhost:8080/api/users/acme/john
```

### List Users in Organization

```bash
curl http://localhost:8080/api/users/acme
```

## Group Management

### Create a Group

```bash
curl -X POST http://localhost:8080/api/groups \
  -H "Content-Type: application/json" \
  -d '{
    "organization": "acme",
    "name": "developers",
    "description": "Development team"
  }'
```

### Get a Group

```bash
curl http://localhost:8080/api/groups/acme/developers
```

### Update a Group

```bash
curl -X PUT http://localhost:8080/api/groups/acme/developers \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Software development team"
  }'
```

### Delete a Group

```bash
curl -X DELETE http://localhost:8080/api/groups/acme/developers
```

### List Groups in Organization

```bash
curl http://localhost:8080/api/groups/acme
```

### Add User to Group

```bash
curl -X POST http://localhost:8080/api/groups/acme/developers/members \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john"
  }'
```

### Remove User from Group

```bash
curl -X DELETE http://localhost:8080/api/groups/acme/developers/members/john
```

### Get User's Groups

```bash
curl http://localhost:8080/api/users/acme/john/groups
```

## LDAP Examples

### Test LDAP Bind with ldapsearch

```bash
ldapsearch -x -H ldap://localhost:3389 \
  -D "cn=john,ou=acme,dc=example,dc=com" \
  -w secure_password_123 \
  -b "dc=example,dc=com" \
  "(objectClass=*)"
```

### WhoAmI Extended Operation

```bash
ldapwhoami -x -H ldap://localhost:3389 \
  -D "cn=john,ou=acme,dc=example,dc=com" \
  -w secure_password_123
```

### Python LDAP Client Example

```python
import ldap3

server = ldap3.Server('localhost', port=3389)
conn = ldap3.Connection(
    server,
    user='cn=john,ou=acme,dc=example,dc=com',
    password='secure_password_123',
    auto_bind=True
)

# Perform search
conn.search(
    'dc=example,dc=com',
    '(objectClass=*)',
    attributes=['cn', 'ou']
)

for entry in conn.entries:
    print(entry)

conn.unbind()
```

## Health Check

```bash
curl http://localhost:8080/health
```

## TLS Operations

### Get CA Certificate

Retrieve the CA certificate from the server when TLS is enabled. This allows clients to trust the server's certificate without using insecure mode.

```bash
# Get CA certificate to stdout
curl http://localhost:8080/api/v1/ca-certificate

# Save CA certificate to file
curl http://localhost:8080/api/v1/ca-certificate -o ca.pem

# Use the CA certificate with ldapsearch
ldapsearch -H ldaps://localhost:3389 -x \
  -D "cn=alice,ou=acme,dc=example,dc=com" \
  -w pass123 \
  -b "dc=example,dc=com" \
  -o TLS_CACERT=ca.pem
```

**Note:** This endpoint returns a 400 error if TLS is not enabled on the server.

## Complete Workflow Example

```bash
#!/bin/bash

# 1. Create an organization and users
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{"organization": "acme", "username": "alice", "password": "pass123", "email": "alice@acme.com"}'

curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{"organization": "acme", "username": "bob", "password": "pass456", "email": "bob@acme.com"}'

# 2. Create a group
curl -X POST http://localhost:8080/api/groups \
  -H "Content-Type: application/json" \
  -d '{"organization": "acme", "name": "engineering", "description": "Engineering team"}'

# 3. Add users to the group
curl -X POST http://localhost:8080/api/groups/acme/engineering/members \
  -H "Content-Type: application/json" \
  -d '{"username": "alice"}'

curl -X POST http://localhost:8080/api/groups/acme/engineering/members \
  -H "Content-Type: application/json" \
  -d '{"username": "bob"}'

# 4. Verify the group membership
curl http://localhost:8080/api/groups/acme/engineering

# 5. Test LDAP authentication
ldapwhoami -x -H ldap://localhost:3389 \
  -D "cn=alice,ou=acme,dc=example,dc=com" \
  -w pass123
```
