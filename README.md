# SecurityKit

A modular, reusable security package for [Vapor 4](https://vapor.codes) applications. Provides RBAC (Role-Based Access Control), authentication, authorization, and token management — all accessible through `app.security.*` and `req.security.*`.

[![Swift 6](https://img.shields.io/badge/Swift-6-orange.svg)](https://swift.org)
[![Vapor 4](https://img.shields.io/badge/Vapor-4-blue.svg)](https://vapor.codes)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Features

- 🔐 **RBAC** — Users, roles, permissions with N–M relationships
- 🔑 **Authentication** — Email/password login with bcrypt (Argon2 pluggable)
- 🎫 **Token management** — Opaque tokens with SHA-256 storage, expiration, revocation, and rotation
- 🛡️ **Authorization** — Composable policies with `&&`, `||`, `!` operators
- 📡 **Event bus** — Subscribe to login, logout, role changes, and more
- 🪪 **Optional JWT** — Stateless tokens via `SecurityJWT` for microservices
- 📦 **Modular** — Use only what you need
- 🗄️ **Versioned migrations** — Safe upgrades across package versions
- ⚡ **Vapor-native** — Integrates via `app.security.*` and `req.security.*`

## Requirements

- Swift 6.0+
- Vapor 4.92+
- Fluent 4.9+ (for the Fluent backend)
- macOS 13+ / Linux
- A Fluent-compatible database driver (PostgreSQL recommended for production)

## Installation

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/devswiftzone/Security.git", from: "0.1.0")
],
targets: [
    .executableTarget(
        name: "App",
        dependencies: [
            .product(name: "SecurityKit", package: "Security"),
        ]
    )
]
```

## Quick start

### 1. Configure

```swift
import Vapor
import Fluent
import FluentPostgresDriver
import SecurityKit

public func configure(_ app: Application) async throws {
    // Database
    app.databases.use(.postgres(/* ... */), as: .psql)

    // Security setup — sensible defaults, customize via configuration
    app.security.configuration = .init(
        tokenLifetimes: .init(
            access: 30 * 60,           // 30 min
            refresh: 60 * 60 * 24 * 14 // 14 days
        ),
        passwordPolicy: .init(minLength: 14)
    )

    app.security.useFluent()

    try await app.autoMigrate()
}
```

### 2. Routes

```swift
import Vapor
import SecurityKit

func routes(_ app: Application) throws {
    // Public
    app.post("auth", "register") { req async throws -> TokenResponse in
        let dto = try req.content.decode(RegisterDTO.self)
        return try await req.application.security.auth.register(dto, on: req.db)
    }

    app.post("auth", "login") { req async throws -> TokenResponse in
        let dto = try req.content.decode(LoginDTO.self)
        return try await req.application.security.auth.login(dto, on: req.db)
    }

    app.post("auth", "refresh") { req async throws -> TokenResponse in
        let dto = try req.content.decode(RefreshDTO.self)
        return try await req.application.security.auth.refresh(dto, on: req.db)
    }

    // Protected (any authenticated user)
    let authed = app.grouped(BearerTokenMiddleware())

    authed.get("me") { req async throws -> User in
        try req.security.require(User.self)
    }

    authed.post("auth", "logout") { req async throws -> HTTPStatus in
        let user = try req.security.require(User.self)
        try await req.application.security.auth.logout(user, on: req.db)
        return .noContent
    }

    // Permission-gated
    let admin = authed.grouped(PermissionMiddleware("users.delete"))
    admin.delete("users", ":id") { req async throws -> HTTPStatus in
        guard let id = req.parameters.get("id", as: UUID.self) else {
            throw Abort(.badRequest)
        }
        let user = try await req.application.security.users.require(id: id, on: req.db)
        try await req.application.security.users.delete(user, on: req.db)
        return .noContent
    }
}
```

### 3. Seed roles and permissions

```swift
let admin = try await app.security.roles.create(
    name: "admin",
    description: "Full access",
    on: app.db
)

try await app.security.permissions.register([
    "users.read",
    "users.write",
    "users.delete",
], on: app.db)

try await app.security.roles.grant("users.delete", to: admin, on: app.db)

// Attach the role to a user
let user = try await app.security.users.require(email: "asiel@example.com", on: app.db)
try await app.security.roles.attach(admin, to: user, on: app.db)
```

## Modules

| Module | Description |
|---|---|
| `SecurityKit` | Umbrella — re-exports all modules below |
| `SecurityCore` | Protocols, DTOs, errors, policies, event bus (storage-agnostic) |
| `SecurityFluent` | Fluent backend: models, migrations, services, middleware |
| `SecurityJWT` | Optional JWT-based auth (stateless tokens) |

Import the umbrella for everything, or pick individual modules to keep binaries lean.

## Authorization

### Inline checks in handlers

```swift
app.get("posts", ":id") { req async throws -> Post in
    try await req.security.require(permission: "posts.read")
    // ...
}

// Non-throwing branching
app.get("dashboard") { req async throws -> View in
    if await req.security.can("admin.access") {
        return try await renderAdminDashboard(req)
    }
    return try await renderUserDashboard(req)
}
```

### Composable policies

```swift
let policy = (RequireRole("admin") || RequirePermission("users.edit"))
          && !RequireRole("suspended")

app.grouped(policy.middleware())
   .patch("users", ":id") { req in /* ... */ }
```

### Custom policies

```swift
struct CanEditPost: AuthorizationPolicy {
    let postID: UUID

    func evaluate(_ req: Request) async throws -> Bool {
        let user = try req.auth.require(User.self)
        let post = try await Post.find(postID, on: req.db)
        return post?.authorID == user.id
            || (try await user.permissions(on: req.db))
                .contains(Permission("posts.edit.any"))
    }
}

app.patch("posts", ":id") { req async throws -> Post in
    let postID = try req.parameters.require("id", as: UUID.self)
    try await req.security.require(CanEditPost(postID: postID))
    // ...
}
```

## Events

Subscribe to security events for auditing, metrics, or notifications:

```swift
await app.security.events.on("auth.login.failed") { event in
    if case .loginFailed(let email, let ip, let reason) = event {
        app.logger.warning("Failed login: \(email) from \(ip ?? "?") — \(reason)")
    }
}

// Or subscribe to a whole namespace
await app.security.events.on(prefix: "token.*") { event in
    app.logger.info("\(event.name)")
}

// All events
await app.security.events.onAny { event in
    auditWriter.write(event)
}
```

Available events: `user.registered`, `user.activated`, `user.deactivated`, `user.deleted`, `auth.login.succeeded`, `auth.login.failed`, `auth.logout.all`, `password.changed`, `password.reset.requested`, `token.issued`, `token.revoked`, `token.reuse_detected`, `role.assigned`, `role.revoked`, `permission.granted`, `permission.revoked`.

## Configuration

All options are tunable via `SecurityConfiguration`:

```swift
app.security.configuration = .init(
    tokenLifetimes: .init(
        access: 30 * 60,
        refresh: 60 * 60 * 24 * 14,
        api: 60 * 60 * 24 * 365,
        oneTime: 60 * 15
    ),
    passwordPolicy: .init(
        minLength: 14,
        maxLength: 128,
        requireMixedCase: false,
        requireDigit: false,
        requireSymbol: false
    ),
    refreshRotation: .init(
        enabled: true,
        detectReuse: true
    ),
    loginThrottle: .init(
        enabled: true,
        maxAttempts: 5,
        window: 60 * 15,
        lockoutDuration: 60 * 15
    ),
    bcryptCost: 12
)
```

Defaults follow current OWASP and NIST SP 800-63B guidance (length over composition for passwords; refresh token rotation with reuse detection).

## Custom password hasher

```swift
struct Argon2Hasher: SecurityPasswordHasher {
    let algorithm = "argon2id"

    func hash(_ password: String) throws -> String { /* ... */ }
    func verify(_ password: String, against hash: String) throws -> Bool { /* ... */ }
    func needsRehash(_ hash: String) -> Bool { /* ... */ }
}

app.security.useFluent(passwordHasher: Argon2Hasher())
```

## JWT (optional)

For microservices or stateless validation, use `SecurityJWT` alongside `SecurityFluent`:

```swift
import SecurityKit  // already includes SecurityJWT

await app.security.useJWT(hmacSecret: "your-very-long-secret-at-least-32-bytes")

// Issue a JWT after password auth
app.post("auth", "jwt-login") { req async throws -> [String: String] in
    let dto = try req.content.decode(LoginDTO.self)
    let user = try await req.application.security.users.require(email: dto.email, on: req.db)
    let matches = try await user.verifyPassword(
        dto.password,
        using: req.application.security.passwordHasher,
        on: req.db
    )
    guard matches else { throw SecurityError.invalidCredentials }

    let roles = try await user.roleNames(on: req.db)
    let jwt = req.application.security.jwt(issuer: "api.example.com")
    let token = try await jwt.issue(
        userID: user.id!,
        email: user.email,
        kind: .access,
        roles: Array(roles)
    )
    return ["token": token]
}
```

**JWT vs. opaque tokens trade-off:** JWTs validate without DB lookups (faster, statelessly verifiable across services) but cannot be revoked until expiry. Use short TTLs (15–30 min) for access tokens. Combine with opaque refresh tokens from `SecurityFluent` for the best of both worlds.

## Database schema

All tables are prefixed `security_` to avoid collisions with consumer schemas:

- `security_users`
- `security_user_passwords`
- `security_roles`
- `security_permissions`
- `security_user_roles`
- `security_role_permissions`
- `security_tokens`

Migrations are versioned (`Security_V1_CreateUsers`, etc.) and applied via:

```swift
app.security.migrations.add(to: app.migrations)
// or
app.security.useFluent()  // registers them automatically
```

## Security model

- **Passwords** are hashed with bcrypt (cost 12 by default). The `algorithm` is stored alongside the hash to enable transparent migration to newer algorithms (Argon2id) on the next successful login.
- **Tokens** are 256-bit CSPRNG values, stored as SHA-256 hashes in the DB. The plaintext is returned to the client only at issuance. A stolen DB dump yields no usable tokens.
- **Refresh tokens** rotate on use. Replaying a consumed refresh token triggers reuse detection: all of the user's tokens are revoked and a `token.reuse_detected` event is emitted.
- **Login failures** report a single `invalidCredentials` error to clients regardless of cause (unknown email vs. wrong password) to prevent user enumeration. Audit-level reasons go to the event bus.
- **Password changes** require the current password (defense against stolen session tokens) and revoke all of the user's active tokens.

## Development

```bash
git clone https://github.com/devswiftzone/Security.git
cd Security
swift test
```

The test suite runs in-memory with SQLite (no setup required) and uses bcrypt cost 4 to stay fast.

## License

MIT — see [LICENSE](LICENSE).

## Author

Built by [@asielcabrera](https://github.com/asielcabrera) at [devswiftzone](https://github.com/devswiftzone).
