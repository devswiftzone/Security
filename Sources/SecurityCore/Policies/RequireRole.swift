//
//  RequireRole.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor

/// Authorization policy that requires the authenticated user to have a
/// specific role.
public struct RequireRole: AuthorizationPolicy {

    public let role: String

    public init(_ role: String) {
        self.role = role
    }

    public var name: String {
        "RequireRole(\(role))"
    }

    public func evaluate(_ req: Request) async throws -> Bool {
        guard let user = req.auth.get(AnySecurityUser.self) else {
            return false
        }
        return try await user.has(role: role, on: req.db)
    }
}

/// Authorization policy that requires the user to have any one of several
/// roles. Equivalent to `RequireRole("a") || RequireRole("b")` but more
/// efficient for many roles (single DB hit).
public struct RequireAnyRole: AuthorizationPolicy {

    public let roles: Set<String>

    public init(_ roles: String...) {
        self.roles = Set(roles)
    }

    public init(_ roles: Set<String>) {
        self.roles = roles
    }

    public var name: String {
        "RequireAnyRole(\(roles.sorted().joined(separator: ", ")))"
    }

    public func evaluate(_ req: Request) async throws -> Bool {
        guard let user = req.auth.get(AnySecurityUser.self) else {
            return false
        }
        let userRoles = try await user.roleNames(on: req.db)
        return !userRoles.isDisjoint(with: roles)
    }
}

/// Authorization policy that requires the user to have all of several roles.
public struct RequireAllRoles: AuthorizationPolicy {

    public let roles: Set<String>

    public init(_ roles: String...) {
        self.roles = Set(roles)
    }

    public init(_ roles: Set<String>) {
        self.roles = roles
    }

    public var name: String {
        "RequireAllRoles(\(roles.sorted().joined(separator: ", ")))"
    }

    public func evaluate(_ req: Request) async throws -> Bool {
        guard let user = req.auth.get(AnySecurityUser.self) else {
            return false
        }
        let userRoles = try await user.roleNames(on: req.db)
        return roles.isSubset(of: userRoles)
    }
}
