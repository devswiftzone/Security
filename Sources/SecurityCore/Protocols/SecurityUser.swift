//
//  SecurityUser.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import Foundation

/// A user that can authenticate and be authorized within the Security package.
///
/// Conforming types are typically `Model & Authenticatable` (when using
/// `SecurityFluent`) but the protocol itself does not require Fluent so
/// alternative storage backends can be plugged in.
///
/// The roles and permissions methods are async because they typically
/// require a database round-trip. Implementations should cache results
/// per-request when possible to avoid N+1 queries.
public protocol SecurityUser: Authenticatable, Sendable {

    /// Unique identifier for the user.
    var id: UUID? { get }

    /// Login email. Treated as the primary identifier for authentication.
    var email: String { get }

    /// Whether the account is active and allowed to authenticate.
    var isActive: Bool { get }

    /// Returns the names of all roles assigned to this user.
    ///
    /// - Parameter db: Database context for the query.
    /// - Returns: Set of role names (e.g. `["admin", "editor"]`).
    func roleNames(on db: Database) async throws -> Set<String>

    /// Returns all permissions granted to this user through their roles.
    ///
    /// - Parameter db: Database context for the query.
    /// - Returns: Set of `Permission` values.
    func permissions(on db: Database) async throws -> Set<Permission>

    /// Convenience: returns whether the user has the given permission.
    func has(permission: Permission, on db: Database) async throws -> Bool

    /// Convenience: returns whether the user has the given role.
    func has(role: String, on db: Database) async throws -> Bool
}

// MARK: - Default implementations

public extension SecurityUser {

    func has(permission: Permission, on db: Database) async throws -> Bool {
        try await permissions(on: db).contains(permission)
    }

    func has(role: String, on db: Database) async throws -> Bool {
        try await roleNames(on: db).contains(role)
    }
}
