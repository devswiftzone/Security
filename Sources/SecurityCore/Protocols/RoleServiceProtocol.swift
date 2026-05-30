//
//  RoleServiceProtocol.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import Foundation

/// Manages roles and user-role assignments.
public protocol RoleServiceProtocol: Sendable {

    associatedtype User: SecurityUser
    associatedtype Role: Sendable

    // MARK: - Role lifecycle

    /// Creates a new role with the given name. Names are unique.
    func create(name: String, description: String?, on db: Database) async throws -> Role

    /// Finds a role by name.
    func find(name: String, on db: Database) async throws -> Role?

    /// Returns a role by name or throws.
    func require(name: String, on db: Database) async throws -> Role

    /// Lists all roles.
    func list(on db: Database) async throws -> [Role]

    /// Deletes a role. Cascades to user-role and role-permission pivots.
    func delete(_ role: Role, on db: Database) async throws

    // MARK: - User assignments

    /// Assigns a role to a user. Idempotent — assigning twice is a no-op.
    func attach(_ role: Role, to user: User, on db: Database) async throws

    /// Removes a role from a user. Idempotent.
    func detach(_ role: Role, from user: User, on db: Database) async throws

    /// Returns all roles assigned to the given user.
    func roles(of user: User, on db: Database) async throws -> [Role]

    /// Returns whether the user has the named role.
    func userHas(role: String, user: User, on db: Database) async throws -> Bool

    // MARK: - Permission assignments

    /// Grants a permission to a role. Idempotent.
    func grant(_ permission: Permission, to role: Role, on db: Database) async throws

    /// Revokes a permission from a role. Idempotent.
    func revoke(_ permission: Permission, from role: Role, on db: Database) async throws

    /// Returns all permissions held by a role.
    func permissions(of role: Role, on db: Database) async throws -> Set<Permission>
}
