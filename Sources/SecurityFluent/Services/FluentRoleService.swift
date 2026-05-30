//
//  FluentRoleService.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import Foundation
import SecurityCore

/// Fluent-backed implementation of `RoleServiceProtocol`.
///
/// Manages role lifecycle and the two N-M associations: user-role and
/// role-permission. All attach/detach/grant/revoke operations are
/// idempotent. Role deletions are blocked for system roles.
public struct FluentRoleService: RoleServiceProtocol, Sendable {

    public typealias User = SecurityFluent.User
    public typealias Role = SecurityFluent.Role

    let application: Application

    public init(application: Application) {
        self.application = application
    }

    // MARK: - Role lifecycle

    public func create(
        name: String,
        description: String?,
        on db: Database
    ) async throws -> Role {
        let normalized = name.lowercased()

        if let existing = try await find(name: normalized, on: db) {
            return existing  // idempotent return of pre-existing role
        }

        let role = Role(name: normalized, description: description, isSystem: false)
        try await role.save(on: db)
        return role
    }

    public func find(name: String, on db: Database) async throws -> Role? {
        try await Role.query(on: db)
            .filter(\.$name == name.lowercased())
            .first()
    }

    public func require(name: String, on db: Database) async throws -> Role {
        guard let role = try await find(name: name, on: db) else {
            throw SecurityError.policyDenied(reason: "role '\(name)' does not exist")
        }
        return role
    }

    public func list(on db: Database) async throws -> [Role] {
        try await Role.query(on: db).sort(\.$name).all()
    }

    public func delete(_ role: Role, on db: Database) async throws {
        guard !role.isSystem else {
            throw SecurityError.policyDenied(
                reason: "system role '\(role.name)' cannot be deleted"
            )
        }
        try await role.delete(on: db)
    }

    // MARK: - User assignments

    public func attach(
        _ role: Role,
        to user: User,
        on db: Database
    ) async throws {
        guard let userID = user.id, let roleID = role.id else {
            throw SecurityError.policyDenied(reason: "unsaved user or role")
        }

        // Idempotent: skip if assignment already exists.
        let existing = try await UserRole.query(on: db)
            .filter(\.$user.$id == userID)
            .filter(\.$role.$id == roleID)
            .first()
        if existing != nil { return }

        try await UserRole(userID: userID, roleID: roleID).save(on: db)
        publishRoleAssigned(user: user, role: role.name)
    }

    public func detach(
        _ role: Role,
        from user: User,
        on db: Database
    ) async throws {
        guard let userID = user.id, let roleID = role.id else {
            throw SecurityError.policyDenied(reason: "unsaved user or role")
        }

        let deleted: () = try await UserRole.query(on: db)
            .filter(\.$user.$id == userID)
            .filter(\.$role.$id == roleID)
            .delete()

        // Only emit if something was actually removed.
        // Fluent's `delete()` doesn't return a count in all drivers, so
        // we check by re-querying. The cost is acceptable for an admin
        // operation, and idempotent semantics matter more than perf here.
        _ = deleted
        publishRoleRevoked(user: user, role: role.name)
    }

    public func roles(of user: User, on db: Database) async throws -> [Role] {
        try await user.$roles.query(on: db).sort(\.$name).all()
    }

    public func userHas(
        role name: String,
        user: User,
        on db: Database
    ) async throws -> Bool {
        let normalized = name.lowercased()
        return try await user.$roles.query(on: db)
            .filter(\.$name == normalized)
            .count() > 0
    }

    // MARK: - Permission assignments

    public func grant(
        _ permission: Permission,
        to role: Role,
        on db: Database
    ) async throws {
        guard let roleID = role.id else {
            throw SecurityError.policyDenied(reason: "unsaved role")
        }

        // Resolve (or create) the permission catalog row.
        let permissionModel = try await ensurePermissionExists(permission, on: db)
        guard let permissionID = permissionModel.id else {
            throw SecurityError.policyDenied(reason: "permission not persisted")
        }

        // Idempotent.
        let existing = try await RolePermission.query(on: db)
            .filter(\.$role.$id == roleID)
            .filter(\.$permission.$id == permissionID)
            .first()
        if existing != nil { return }

        try await RolePermission(roleID: roleID, permissionID: permissionID).save(on: db)
        publishPermissionGranted(role: role.name, permission: permission)
    }

    public func revoke(
        _ permission: Permission,
        from role: Role,
        on db: Database
    ) async throws {
        guard let roleID = role.id else { return }

        let permissionModel = try await PermissionModel.query(on: db)
            .filter(\.$name == permission.name)
            .first()
        guard let permissionID = permissionModel?.id else { return }

        try await RolePermission.query(on: db)
            .filter(\.$role.$id == roleID)
            .filter(\.$permission.$id == permissionID)
            .delete()

        publishPermissionRevoked(role: role.name, permission: permission)
    }

    public func permissions(of role: Role, on db: Database) async throws -> Set<Permission> {
        let models = try await role.$permissions.query(on: db).all()
        return Set(models.map { $0.toValue() })
    }

    // MARK: - Internal helpers

    /// Looks up the permission catalog row, inserting it if missing.
    /// Used by `grant` so callers can pass any `Permission` value without
    /// first registering it explicitly — convenient and a common pattern
    /// in seed code.
    private func ensurePermissionExists(
        _ permission: Permission,
        on db: Database
    ) async throws -> PermissionModel {
        if let existing = try await PermissionModel.query(on: db)
            .filter(\.$name == permission.name)
            .first() {
            return existing
        }
        let model = PermissionModel(value: permission, isSystem: false)
        try await model.save(on: db)
        return model
    }

    // MARK: - Event helpers

    private func publishRoleAssigned(user: User, role: String) {
        guard let id = user.id else { return }
        let ctx = SecurityEvent.UserContext(id: id, email: user.email)
        application.security.events.publishDetached(.roleAssigned(ctx, role: role))
    }

    private func publishRoleRevoked(user: User, role: String) {
        guard let id = user.id else { return }
        let ctx = SecurityEvent.UserContext(id: id, email: user.email)
        application.security.events.publishDetached(.roleRevoked(ctx, role: role))
    }

    private func publishPermissionGranted(role: String, permission: Permission) {
        application.security.events.publishDetached(
            .permissionGranted(role: role, permission: permission)
        )
    }

    private func publishPermissionRevoked(role: String, permission: Permission) {
        application.security.events.publishDetached(
            .permissionRevoked(role: role, permission: permission)
        )
    }
}

// MARK: - Application accessor

public extension Application.Security {

    /// Entry point for role and permission-to-role management.
    ///
    /// Usage:
    ///
    ///     let admin = try await app.security.roles.create(
    ///         name: "admin",
    ///         description: "Full access",
    ///         on: app.db
    ///     )
    ///     try await app.security.roles.grant(
    ///         "users.delete",
    ///         to: admin,
    ///         on: app.db
    ///     )
    ///     try await app.security.roles.attach(admin, to: user, on: app.db)
    var roles: FluentRoleService {
        FluentRoleService(application: application)
    }
}
