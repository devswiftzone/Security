# Authentication Setup

SecurityKit provides a complete authentication system with registration, login, token management, and password hashing.

## Auth Service

The ``SecurityCore/AuthServiceProtocol`` defines the core authentication operations. The default implementation is ``SecurityFluent/FluentAuthService`` which uses Fluent for persistence.

### Register a User

```swift
let dto = RegisterDTO(
    email: "user@example.com",
    password: "securePassword123",
    name: "John Doe"
)
let response = try await req.security.auth.register(dto, on: req.db)
// response.token -> access token
// response.refreshToken -> refresh token
```

### Login

```swift
let dto = LoginDTO(
    email: "user@example.com",
    password: "securePassword123"
)
let response = try await req.security.auth.login(dto, on: req.db)
```

### Token Refresh

```swift
let dto = RefreshDTO(refreshToken: "...")
let response = try await req.security.auth.refresh(dto, on: req.db)
```

### Change Password

```swift
let dto = ChangePasswordDTO(
    currentPassword: "oldPassword123",
    newPassword: "newPassword456"
)
try await req.security.auth.changePassword(dto, on: req.db)
```

## Password Hashing

By default, passwords are hashed with bcrypt (cost 12). You can provide a custom hasher:

```swift
struct Argon2Hasher: PasswordHasher {
    var algorithm: PasswordHasherAlgorithm { .argon2 }

    func hash(_ password: String) throws -> String { ... }
    func verify(_ password: String, against hash: String) throws -> Bool { ... }
}

app.security.passwordHasher = Argon2Hasher()
```

## Token Management

Tokens are automatically issued on registration and login. The ``SecurityCore/TokenServiceProtocol`` provides direct access:

```swift
// Issue a token
let token = try await req.security.tokens.issue(for: user, on: req.db)

// Revoke all user tokens
try await req.security.tokens.revokeAll(for: user, on: req.db)
```

## Security Events

Subscribe to authentication events:

```swift
app.security.events.on(.loginFailed) { event in
    app.logger.warning("Failed login for \(event.email) from \(event.ip ?? "unknown")")
}

app.security.events.on(.userRegistered) { event in
    app.logger.info("New user registered: \(event.email)")
}
```

## Next Steps

- <doc:rbac-guide> — Add roles and permissions
