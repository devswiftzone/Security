# Security

A reusable, modular security package for Vapor 4 applications. Provides RBAC (Role-Based Access Control), authentication, authorization, and token management out of the box, accessible through `app.security.*`.

[![Swift 5.10+](https://img.shields.io/badge/Swift-5.10+-orange.svg)](https://swift.org)
[![Vapor 4](https://img.shields.io/badge/Vapor-4-blue.svg)](https://vapor.codes)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Features

- 🔐 **RBAC** — Users, roles, permissions with N–M relationships
- 🔑 **Authentication** — Email/password login with bcrypt (Argon2 pluggable)
- 🎫 **Token management** — Opaque tokens with hashing, expiration, and revocation
- 🛡️ **Authorization** — Composable policies, middleware, and `require(permission:)` API
- 📦 **Modular** — Use only what you need: `SecurityCore`, `SecurityFluent`, `SecurityJWT`
- 🔌 **Extensible** — Protocol-based services, custom hashers, event hooks
- 🗄️ **Versioned migrations** — Safe upgrades across package versions
- ⚡ **Vapor-native** — Integrates via `app.security.*` and `req.security.*`

## Requirements

- Swift 5.10+
- Vapor 4.92+
- macOS 13+ / Linux
- Fluent 4.9+ (for `SecurityFluent`)
- A Fluent-compatible database driver (PostgreSQL recommended)

## Installation

Add the package to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/devswiftzone/Security.git", from: "0.1.0")
],
targets: [
    .executableTarget(
        name: "App",
        dependencies: [
            .product(name: "Security", package: "Security"),
            // Or import only what you need:
            // .product(name: "SecurityCore", package: "Security"),
            // .product(name: "SecurityFluent", package: "Security"),
        ]
    )
]
```

## Quick Start

### 1. Configure in `configure.swift`

```swift
import Vapor
import Fluent
import FluentPostgresDriver
import Security

public func configure(_ app: Application) async throws {
    // Database
    app.databases.use(.postgres(/* ... */), as: .psql)

    // Security configuration
    app.security.configuration = .init(
        tokenLifetime: .hours(2),
        refreshTokenLifetime: .days(30),
        passwordMinLength: 12
    )

    // Register migrations
    app.security.migrations.add(to: app.migrations)
    try await app.autoMigrate()

    // Routes
    try routes(app)
}
```

### 2. Add authentication routes

```swift
import Vapor
import Security

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

    // Protected
    let authenticated = app.grouped(BearerTokenMiddleware())

    authenticated.get("me") { req async throws -> User in
        try req.security.require(User.self)
    }

    // Permission-gated
    let admin = authenticated.grouped(RequirePermission("users.delete"))
    admin.delete("users", ":id") { req async throws -> HTTPStatus in
        // ...
        return .noContent
    }
}
```

### 3. Seed initial roles and permissions

```swift
let adminRole = try await app.security.roles.create(name: "admin", on: app.db)
try await app.security.permissions.create(name: "users.delete", on: app.db)
try await app.security.roles.attach(permission: "users.delete", to: adminRole, on: app.db)
```

## Modules

| Module | Description | Depends on |
|---|---|---|
| `Security` | Umbrella — re-exports everything | All below |
| `SecurityCore` | Protocols, DTOs, errors, policies | Vapor |
| `SecurityFluent` | Fluent models, migrations, services | SecurityCore, Fluent |
| `SecurityJWT` | JWT-based auth service (optional) | SecurityCore, JWT |

Import only what you need to keep your binary lean.

## Architecture

```
┌─────────────────────────────────────┐
│       Your Vapor Application        │
├─────────────────────────────────────┤
│       app.security.* API            │
├──────────┬────────────┬─────────────┤
│   Auth   │    RBAC    │   Tokens    │
├──────────┴────────────┴─────────────┤
│      SecurityCore (protocols)       │
├─────────────────────────────────────┤
│  SecurityFluent    │  SecurityJWT   │
│  (Postgres/MySQL)  │  (stateless)   │
└─────────────────────────────────────┘
```

## Usage

### Checking permissions in a route

```swift
app.get("posts", ":id") { req async throws -> Post in
    try await req.security.require(permission: "posts.read")
    // ...
}
```

### Checking roles

```swift
try await req.security.require(role: "admin")
```

### Custom authorization policies

```swift
struct CanEditPost: AuthorizationPolicy {
    let postID: UUID

    func evaluate(_ req: Request) async throws -> Bool {
        let user = try req.auth.require(User.self)
        let post = try await Post.find(postID, on: req.db)
        return post?.authorID == user.id
            || (try await user.permissions(on: req.db)).contains("posts.edit.any")
    }
}
```

### Custom password hasher

```swift
struct Argon2Hasher: PasswordHasher {
    func hash(_ password: String) throws -> String { /* ... */ }
    func verify(_ password: String, against hash: String) throws -> Bool { /* ... */ }
}

app.security.passwordHasher = Argon2Hasher()
```

### Subscribing to security events

```swift
app.security.events.on(.loginFailed) { event in
    app.logger.warning("Failed login for \(event.email) from \(event.ip ?? "unknown")")
}
```

## Database Schema

All tables are prefixed with `security_` to avoid collisions:

- `security_users`
- `security_user_passwords`
- `security_roles`
- `security_permissions`
- `security_user_roles`
- `security_role_permissions`
- `security_tokens`

See [docs/SCHEMA.md](docs/SCHEMA.md) for the full ERD.

## Security Considerations

- **Passwords** are hashed with bcrypt (cost 12) by default. Argon2id is pluggable.
- **Tokens** are stored as SHA-256 hashes; plain values are returned only at creation.
- **Refresh token rotation** is enabled by default with reuse detection.
- **Rate limiting** on login is enforced at 5 attempts / 15 min per IP+email.
- This package follows [OWASP ASVS Level 2](https://owasp.org/www-project-application-security-verification-standard/) where applicable.

Found a vulnerability? Please email security@devswiftzone.com instead of opening a public issue.

## Roadmap

- [ ] OAuth2 / OpenID Connect provider
- [ ] WebAuthn / passkeys
- [ ] MFA (TOTP)
- [ ] Audit log target
- [ ] Redis-backed token store
- [ ] HIBP password breach check

## Contributing

Contributions welcome. Please open an issue first to discuss substantial changes.

```bash
git clone https://github.com/devswiftzone/Security.git
cd Security
swift test
```

## License

MIT — see [LICENSE](LICENSE).

## Author

Built by [@asielcabrera](https://github.com/asielcabrera) at [devswiftzone](https://github.com/devswiftzone).
