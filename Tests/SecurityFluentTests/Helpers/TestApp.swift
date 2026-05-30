//
//  TestApp.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import FluentSQLiteDriver
import SecurityCore
import SecurityFluent

/// Builds a fresh `Application` configured with SQLite in memory, Security
/// migrations applied, and the Fluent backend wired up. Each call returns
/// a brand-new app — tests share no state.
///
/// Always shut down with `try await app.asyncShutdown()` when done.
/// Use `withFresh(_:)` to make that automatic.
@MainActor
enum TestApp {

    /// Returns a fully configured Application ready for tests.
    static func fresh() async throws -> Application {
        let app = try await Application.make(.testing)

        // In-memory SQLite for isolated, fast tests.
        app.databases.use(.sqlite(.memory), as: .sqlite)

        // Use a low bcrypt cost to keep tests fast.
        app.security.configuration = SecurityConfiguration(
            tokenLifetimes: .init(
                access: 60 * 60,
                refresh: 60 * 60 * 24,
                api: 60 * 60 * 24,
                oneTime: 60 * 15
            ),
            bcryptCost: 4
        )

        app.security.useFluent()

        try await app.autoMigrate()

        return app
    }

    /// Convenience: provides a fresh app to a block and tears it down
    /// afterwards, awaiting the shutdown properly.
    @discardableResult
    static func withFresh<T>(
        _ block: (Application) async throws -> T
    ) async throws -> T {
        let app = try await fresh()
        do {
            let result = try await block(app)
            try await app.asyncShutdown()
            return result
        } catch {
            try? await app.asyncShutdown()
            throw error
        }
    }
}
