# Getting Started with SecurityKit

Learn how to add SecurityKit to your Vapor project, configure it, and run your first authentication flow.

## Add the Dependency

Add SecurityKit to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/devswiftzone/Security.git", from: "0.1.0")
]
```

Then add the product to your target:

```swift
.target(
    name: "App",
    dependencies: [
        .product(name: "SecurityKit", package: "Security")
    ]
)
```

## Configure in `configure.swift`

Import and configure the security module:

```swift
import Vapor
import Fluent
import SecurityKit

public func configure(_ app: Application) async throws {
    // Database setup
    app.databases.use(.postgres(...), as: .psql)

    // Security configuration (optional — shown here to override defaults)
    app.security.configuration = .init(
        tokenLifetimes: .init(access: 2 * 60 * 60, refresh: 30 * 24 * 60 * 60),
        passwordPolicy: .init(minLength: 12)
    )

    // Register password hasher, token generator, and migrations
    app.security.useFluent()
    try await app.autoMigrate()

    // Routes
    try routes(app)
}
```

## Add Authentication Routes

Create register and login endpoints:

```swift
import Vapor
import SecurityKit

func routes(_ app: Application) throws {
    // Register
    app.post("auth", "register") { req async throws -> TokenResponse in
        let dto = try req.content.decode(RegisterRequest.self)
        return try await req.application.security.auth.register(dto, on: req.db)
    }

    // Login
    app.post("auth", "login") { req async throws -> TokenResponse in
        let dto = try req.content.decode(LoginRequest.self)
        return try await req.application.security.auth.login(dto, on: req.db)
    }

    // Protected routes
    let authenticated = app.grouped(BearerTokenMiddleware())
    authenticated.get("me") { req async throws -> User in
        try req.security.require(User.self)
    }
}
```

## Next Steps

- <doc:auth-setup> — Deep dive into authentication
- <doc:rbac-guide> — Set up roles and permissions
- <doc:Tutorials> — Step-by-step tutorials
