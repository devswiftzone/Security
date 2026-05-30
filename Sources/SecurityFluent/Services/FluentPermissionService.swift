//
//  FluentPermissionService.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import Foundation
import SecurityCore

/// Fluent-backed implementation of `PermissionServiceProtocol`.
///
/// Manages the catalog of known permissions. Operations are idempotent:
/// re-registering an existing permission is a no-op, not an error.
public struct FluentPermissionService: PermissionServiceProtocol, Sendable {

    let application: Application

    public init(application: Application) {
        self.application = application
    }

    // MARK: - Register

    public func register(
        _ permission: Permission,
        description: String?,
        on db: Database
    ) async throws {
        // Idempotent: only insert if it doesn't already exist.
        let existing = try await PermissionModel.query(on: db)
            .filter(\.$name == permission.name)
            .first()
        if existing != nil { return }

        let model = PermissionModel(
            value: permission,
            description: description,
            isSystem: false
        )
        try await model.save(on: db)
    }

    public func register(
        _ permissions: [Permission],
        on db: Database
    ) async throws {
        // Load existing names in one query to avoid N round trips.
        let names = permissions.map(\.name)
        let existingNames = try await PermissionModel.query(on: db)
            .filter(\.$name ~~ names)
            .all()
            .map(\.name)
        let existingSet = Set(existingNames)

        let toInsert = permissions
            .filter { !existingSet.contains($0.name) }
            .map { PermissionModel(value: $0, isSystem: false) }

        guard !toInsert.isEmpty else { return }
        try await toInsert.create(on: db)
    }

    // MARK: - Unregister

    public func unregister(
        _ permission: Permission,
        on db: Database
    ) async throws {
        try await PermissionModel.query(on: db)
            .filter(\.$name == permission.name)
            .delete()
        // Cascade FK on role_permissions handles pivot cleanup automatically.
    }

    // MARK: - Read

    public func catalog(on db: Database) async throws -> [Permission] {
        let models = try await PermissionModel.query(on: db)
            .sort(\.$name)
            .all()
        return models.map { $0.toValue() }
    }

    public func exists(
        _ permission: Permission,
        on db: Database
    ) async throws -> Bool {
        try await PermissionModel.query(on: db)
            .filter(\.$name == permission.name)
            .count() > 0
    }
}

// MARK: - Application accessor

public extension Application.Security {

    /// Entry point for permission catalog management.
    ///
    /// Usage:
    ///
    ///     try await app.security.permissions.register(
    ///         ["users.read", "users.write", "users.delete"],
    ///         on: app.db
    ///     )
    var permissions: FluentPermissionService {
        FluentPermissionService(application: application)
    }
}
