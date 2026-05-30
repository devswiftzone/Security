//
//  SecurityMigrations.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Fluent
import Vapor
import SecurityCore

/// Convenience accessor for registering all Security migrations at once.
///
/// Usage:
///
///     app.security.migrations.add(to: app.migrations)
///     try await app.autoMigrate()
public struct SecurityMigrations {

    /// All Security migrations in execution order.
    ///
    /// Each migration's `name` is prefixed with `Security_Vn_` so they
    /// can coexist with consumer-defined migrations without collision
    /// in the `_fluent_migrations` table.
    public static var all: [Migration] {
        [
            V1_CreateUsers(),
            V2_CreateUserPasswords(),
            V3_CreateRoles(),
            V4_CreatePermissions(),
            V5_CreateUserRoles(),
            V6_CreateRolePermissions(),
            V7_CreateTokens(),
        ]
    }

    /// Registers all migrations with the given `Migrations` instance.
    public func add(to migrations: Migrations) {
        for migration in Self.all {
            migrations.add(migration)
        }
    }

    public init() {}
}

// MARK: - Application.security.migrations

public extension Application.Security {

    /// Entry point for migration management.
    ///
    ///     app.security.migrations.add(to: app.migrations)
    var migrations: SecurityMigrations {
        SecurityMigrations()
    }
}
