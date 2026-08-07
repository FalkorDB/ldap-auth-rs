# Architecture

## Overview

LDAP Auth RS is a lightweight authentication service that provides both REST API and LDAP interfaces for user and group management, with Redis as the persistence layer.

## Components

### 1. Data Models (`models.rs`)

- **User**: Represents a user with organization, username, password hash, email, and metadata
- **Group**: Represents a group with organization, name, description, and member list
- **Create/Update DTOs**: Request objects for API operations

### 2. Database Interface (`db.rs`)

The `DbService` trait defines the contract for all database operations:

- User CRUD operations
- Group CRUD operations
- Group membership management
- Search operations
- Password verification
- Health checks

This abstraction allows for:
- Easy testing with mock implementations
- Potential support for multiple backends
- Clean separation of concerns

### 3. Redis Implementation (`redis_db.rs`)

`RedisDbService` implements `DbService` using Redis as the backend:

**Data Structure:**
```
user:{org}:{username} -> JSON(User)
group:{org}:{name} -> JSON(Group)
org:{org}:users -> Set[username]
org:{org}:groups -> Set[group_name]
user:{org}:{username}:groups -> Set[group_name]
```

**Key Operations:**
- Atomic operations for consistency
- Set-based indexes for efficient queries
- JSON serialization for complex objects

### 4. Password Security (`password.rs`)

- Uses Argon2 for password hashing
- Automatic salt generation
- Constant-time verification

### 5. REST API (`api.rs`)

Built with Axum web framework:

**Endpoints:**
- `POST /api/users` - Create user
- `GET /api/users/:org/:username` - Get user
- `PUT /api/users/:org/:username` - Update user
- `DELETE /api/users/:org/:username` - Delete user
- `GET /api/users/:org` - List users
- Similar endpoints for groups
- Group membership endpoints

**Features:**
- JSON request/response
- Proper HTTP status codes
- Error handling with custom error types
- Shared state for database access

### 6. LDAP Server (`ldap.rs`)

Custom LDAP server implementation:

**Supported Operations:**
- Bind (Simple authentication)
- Unbind
- Search (basic implementation)
- Extended operations (WhoAmI)
- StartTLS (framework for implementation)

**Protocol:**
- BER/DER encoding for LDAP messages
- Asynchronous connection handling
- Per-connection authentication state

### 7. Configuration (`config.rs`)

Environment-based configuration:
- Redis connection URL
- API and LDAP ports
- LDAP base DN
- Logging levels

### 8. Error Handling (`error.rs`)

Centralized error handling with `AppError`:
- Database errors
- Not found
- Already exists
- Invalid input
- Authentication failures

## Data Flow

### User Creation via API

```
Client -> POST /api/users
  -> api::create_user()
    -> password::hash_password()
    -> db.create_user()
      -> RedisDbService::create_user()
        -> Redis: SET user:org:username
        -> Redis: SADD org:org:users username
  -> Response: 201 Created
```

### LDAP Bind

```
LDAP Client -> BIND request
  -> ldap::handle_connection()
    -> ldap::handle_bind_request()
      -> db.verify_user_password()
        -> RedisDbService::verify_user_password()
          -> Get user from Redis
          -> password::verify_password()
      -> Return bind response (success/failure)
```

### Group Membership

```
Client -> POST /api/groups/:org/:name/members
  -> api::add_member_to_group()
    -> db.add_user_to_group()
      -> Verify user exists
      -> Get group
      -> Add member to group.members
      -> Update group in Redis
      -> Add group to user's groups set
  -> Response: 200 OK with updated group
```

## Security Considerations

1. **Password Storage**: Argon2 with automatic salting
2. **Authentication**: LDAP bind verifies credentials before operations
3. **Input Validation**: Proper error handling for invalid data
4. **Non-root Container**: Docker container runs as non-privileged user
5. **Dependency Scanning**: CI/CD includes vulnerability scanning

## Scalability

**Current Architecture:**
- Single Redis instance
- Stateless application (can run multiple instances)
- Connection pooling with Redis ConnectionManager

**Future Enhancements:**
- Redis Cluster support for horizontal scaling
- Read replicas for improved read performance
- Caching layer for frequently accessed data
- Rate limiting for API endpoints

## Testing Strategy

1. **Unit Tests**: Individual component testing
   - Models
   - Password utilities
   - Key generation

2. **Integration Tests**: End-to-end API testing
   - User CRUD operations
   - Group management
   - Group membership

3. **Mock Testing**: Database abstraction testing
   - Using MockDbService for API layer tests

4. **CI/CD Testing**:
   - Automated test runs on push/PR
   - Redis service container for integration tests
   - Security scanning with cargo-audit and Trivy

## Deployment

**Docker Deployment:**
- Multi-stage build for minimal image size
- Health checks for container orchestration
- Environment-based configuration
- Non-root user execution

**Kubernetes Ready:**
- Stateless design
- Health check endpoints
- Configurable via environment variables
- Horizontal scaling support
