# ``SecurityKit``

A modular security package for Vapor 4 with RBAC, authentication, tokens, and composable authorization policies.

## Overview

SecurityKit provides a complete authentication and authorization system for Vapor applications. It is divided into modules you can adopt incrementally:

- **SecurityCore**: Protocols, DTOs, errors, authorization policies
- **SecurityFluent**: Fluent-based implementation with models, migrations, and services
- **SecurityJWT**: JWT-based authentication service

All modules are re-exported through ``SecurityKit``, so `import SecurityKit` gives you everything.

## Topics

### Essentials
- <doc:getting-started>
- <doc:auth-setup>
- <doc:rbac-guide>

### Authentication
- ``AuthServiceProtocol``
- ``LoginDTO``
- ``RegisterDTO``
- ``TokenResponse``
- ``RefreshDTO``
- ``ChangePasswordDTO``

### Authorization
- ``AuthorizationPolicy``
- ``RequirePermission``
- ``RequireRole``
- ``RequireAnyRole``
- ``AndPolicy``
- ``OrPolicy``
- ``NotPolicy``

### Middleware
- ``BearerTokenMiddleware``
- ``RoleMiddleware``
- ``PermissionMiddleware``

### Services
- ``SecurityUser``
- ``UserServiceProtocol``
- ``RoleServiceProtocol``
- ``PermissionServiceProtocol``
- ``TokenServiceProtocol``
- ``SecurityPasswordHasher``
- ``TokenGenerator``

### Security Configuration
- ``SecurityConfiguration``
- ``TokenKind``

### Events
- ``SecurityEventBus``
- ``SecurityEvent``

### Tutorials
- <doc:Tutorials>
