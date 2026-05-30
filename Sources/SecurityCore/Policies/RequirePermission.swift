//
//  RequirePermission.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent

/// Authorization policy that requires the authenticated user to hold a
/// specific permission.
public struct RequirePermission: AuthorizationPolicy {

    public let permission: Permission

    public init(_ permission: Permission) {
        self.permission = permission
    }

    public init(_ name: String) {
        self.permission = Permission(name)
    }

    public var name: String {
        "RequirePermission(\(permission.name))"
    }

    public func evaluate(_ req: Request) async throws -> Bool {
        // Resolve the authenticated user via Vapor's auth API. We don't
        // constrain to a specific User type here; the request must have
        // *some* SecurityUser authenticated by an upstream middleware.
        guard let user = req.auth.get(AnySecurityUser.self) else {
            return false
        }
        return try await user.has(permission: permission, on: req.db)
    }
}

/// Type-erased wrapper used internally so policies don't need to know
/// the concrete User type.
///
/// Authentication middleware should call
/// `req.auth.login(AnySecurityUser(user))` in addition to (or instead of)
/// the typed `req.auth.login(user)` so policies can resolve users
/// generically.
public struct AnySecurityUser: Authenticatable, Sendable {

    public let id: UUID?
    public let email: String
    public let isActive: Bool

    private let _roleNames: @Sendable (Database) async throws -> Set<String>
    private let _permissions: @Sendable (Database) async throws -> Set<Permission>

    public init<U: SecurityUser>(_ user: U) {
        self.id = user.id
        self.email = user.email
        self.isActive = user.isActive
        self._roleNames = { try await user.roleNames(on: $0) }
        self._permissions = { try await user.permissions(on: $0) }
    }

    public func roleNames(on db: Database) async throws -> Set<String> {
        try await _roleNames(db)
    }

    public func permissions(on db: Database) async throws -> Set<Permission> {
        try await _permissions(db)
    }

    public func has(permission: Permission, on db: Database) async throws -> Bool {
        try await permissions(on: db).contains(permission)
    }

    public func has(role: String, on db: Database) async throws -> Bool {
        try await roleNames(on: db).contains(role)
    }
}
