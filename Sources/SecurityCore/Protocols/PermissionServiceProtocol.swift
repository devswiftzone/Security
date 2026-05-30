//
//  PermissionServiceProtocol.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent

/// Manages the permission catalog — the set of all permissions known to
/// the system.
///
/// While permissions are referenced by string anywhere in the application,
/// the catalog records them so that admin UIs, documentation generators,
/// and seeders have a single source of truth.
public protocol PermissionServiceProtocol: Sendable {

    /// Registers a new permission in the catalog, or returns the existing
    /// one if already present. Idempotent.
    func register(
        _ permission: Permission,
        description: String?,
        on db: Database
    ) async throws

    /// Registers multiple permissions in a single call. Useful for seeding.
    func register(
        _ permissions: [Permission],
        on db: Database
    ) async throws

    /// Removes a permission from the catalog. Cascades to all roles that
    /// hold it.
    func unregister(_ permission: Permission, on db: Database) async throws

    /// Returns the full catalog of known permissions.
    func catalog(on db: Database) async throws -> [Permission]

    /// Returns whether the catalog contains the given permission.
    func exists(_ permission: Permission, on db: Database) async throws -> Bool
}
