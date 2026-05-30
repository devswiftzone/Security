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

    // Security configuration
    app.security.configuration = .init(
        tokenLifetime: .hours(2),
        refreshTokenLifetime: .days(30),
        passwordMinLength: 12
    )

    // Register and run migrations
    app.security.migrations.add(to: app.migrations)
    try await app.autoMigrate()

    // Register routes
    try routes(app)
}
