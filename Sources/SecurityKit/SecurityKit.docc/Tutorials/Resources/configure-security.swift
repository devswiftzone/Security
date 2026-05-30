import Vapor
import Fluent
import SecurityKit

public func configure(_ app: Application) async throws {
    // Database setup
    app.databases.use(.postgres(
        hostname: "localhost",
        username: "vapor",
        password: "password",
        database: "vapor"
    ), as: .psql)

    // Security configuration (optional — shown here to override defaults)
    app.security.configuration = .init(
        tokenLifetimes: .init(access: 2 * 60 * 60, refresh: 30 * 24 * 60 * 60),
        passwordPolicy: .init(minLength: 12)
    )

    // Register password hasher, token generator, and migrations
    app.security.useFluent()
    try await app.autoMigrate()

    // Register routes
    try routes(app)
}
