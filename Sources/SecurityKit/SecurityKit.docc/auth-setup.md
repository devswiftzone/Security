# Authentication Setup

SecurityKit provides a complete authentication system with registration, login, token management, and password hashing.

## Auth Service

The ``SecurityCore/AuthServiceProtocol`` defines the core authentication operations. The default implementation is ``SecurityFluent/FluentAuthService`` which uses Fluent for persistence.

### Register a User

```swift
let dto = RegisterRequest(
    email: "user@example.com",
    password: "securePassword123"
)
let response = try await req.application.security.auth.register(dto, on: req.db)
// response.accessToken -> access token
// response.refreshToken -> refresh token
```

### Login

```swift
let dto = LoginRequest(
    email: "user@example.com",
    password: "securePassword123"
)
let response = try await req.application.security.auth.login(dto, on: req.db)
```

### Token Refresh

```swift
let dto = RefreshRequest(refreshToken: "...")
let response = try await req.application.security.auth.refresh(dto, on: req.db)
```

### Change Password

```swift
let user = try req.security.require(User.self)
let dto = ChangePasswordRequest(
    currentPassword: "oldPassword123",
    newPassword: "newPassword456"
)
try await req.application.security.auth.changePassword(dto, for: user, on: req.db)
```

## Password Hashing

By default, passwords are hashed with bcrypt (cost 12). You can provide a custom hasher:

```swift
struct Argon2Hasher: SecurityPasswordHasher {
    var algorithm: String { "argon2id" }

    func hash(_ password: String) throws -> String { ... }
    func verify(_ password: String, against hash: String) throws -> Bool { ... }
}

app.security.passwordHasher = Argon2Hasher()
```

## Token Management

Tokens are automatically issued on registration and login. The ``SecurityCore/TokenServiceProtocol`` provides direct access:

```swift
// Issue an access token
let (plaintext, _) = try await req.application.security.tokens
    .issue(kind: .access, for: user, lifetime: nil, on: req.db)

// Revoke all tokens for a user (e.g. on password change)
try await req.application.security.tokens.revokeAll(for: user, kind: nil, on: req.db)
```

## Security Events

Subscribe to authentication events:

```swift
await app.security.events.on("auth.login.failed") { event in
    if case .loginFailed(let email, let ip, _) = event {
        app.logger.warning("Failed login for \(email) from \(ip ?? "unknown")")
    }
}

await app.security.events.on("user.registered") { event in
    if case .userRegistered(let ctx) = event {
        app.logger.info("New user registered: \(ctx.email)")
    }
}
```

## Next Steps

- <doc:rbac-guide> — Add roles and permissions
