//
//  Application+SecurityFluent.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import SecurityCore

public extension Application.Security {

    /// Configures the Security package to use the Fluent-based backend
    /// with sensible defaults.
    ///
    /// Registers:
    /// - `BcryptHasher` (or a custom `SecurityPasswordHasher`) as the
    ///   password hasher
    /// - `DefaultTokenGenerator` (or a custom `TokenGenerator`) as the
    ///   token generator
    /// - All Security migrations
    ///
    /// Should be called once during `configure(_:)`, before
    /// `app.autoMigrate()` or the equivalent.
    ///
    /// Usage:
    ///
    ///     app.security.useFluent()
    ///     try await app.autoMigrate()
    ///
    /// To customize parts:
    ///
    ///     app.security.useFluent(
    ///         passwordHasher: Argon2Hasher(),
    ///         registerMigrations: false  // I want to register them manually
    ///     )
    ///
    /// - Parameters:
    ///   - passwordHasher: Override the default `BcryptHasher`. Pass
    ///     `nil` to use the default.
    ///   - tokenGenerator: Override the default token generator. Pass
    ///     `nil` to use the default.
    ///   - bcryptCost: The bcrypt cost factor for the default
    ///     `BcryptHasher`. Ignored if `passwordHasher` is provided.
    ///     Defaults to `SecurityConfiguration.default.bcryptCost`.
    ///   - registerMigrations: Whether to add all package migrations to
    ///     `app.migrations`. Set to `false` if you want to register
    ///     migrations selectively or run them in a specific order.
    func useFluent(
        passwordHasher: SecurityPasswordHasher? = nil,
        tokenGenerator: TokenGenerator? = nil,
        bcryptCost: Int? = nil,
        registerMigrations: Bool = true
    ) {
        // Password hasher: explicit override > config-driven default.
        if let passwordHasher {
            self.passwordHasher = passwordHasher
        } else {
            let cost = bcryptCost ?? configuration.bcryptCost
            self.passwordHasher = BcryptHasher(cost: cost)
        }

        // Token generator: explicit override > package default.
        self.tokenGenerator = tokenGenerator ?? DefaultTokenGenerator()

        // Migrations: register all unless opted out.
        if registerMigrations {
            migrations.add(to: application.migrations)
        }
    }
}

public extension Application.Security {

    /// Returns true if `useFluent()` (or equivalent manual configuration)
    /// has been called. Useful in tests and assertions.
    var isConfigured: Bool {
        application.storage[FluentConfiguredKey.self] ?? false
    }

    private struct FluentConfiguredKey: StorageKey {
        typealias Value = Bool
    }
}
