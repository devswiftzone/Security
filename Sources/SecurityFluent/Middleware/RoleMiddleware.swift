//
//  RoleMiddleware.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import SecurityCore

/// Gates a route group on a specific role.
///
/// Usage:
///
///     let admin = app.grouped(BearerTokenMiddleware())
///                    .grouped(RoleMiddleware("admin"))
///     admin.get("dashboard") { req in /* ... */ }
public struct RoleMiddleware: AsyncMiddleware {

    public let role: String

    public init(_ role: String) {
        self.role = role
    }

    public func respond(
        to request: Request,
        chainingTo next: AsyncResponder
    ) async throws -> Response {
        try await request.security.require(role: role)
        return try await next.respond(to: request)
    }
}

/// Gates a route group on having any of the listed roles.
public struct AnyRoleMiddleware: AsyncMiddleware {

    public let roles: Set<String>

    public init(_ roles: String...) {
        self.roles = Set(roles)
    }

    public init(_ roles: Set<String>) {
        self.roles = roles
    }

    public func respond(
        to request: Request,
        chainingTo next: AsyncResponder
    ) async throws -> Response {
        try await request.security.require(RequireAnyRole(roles))
        return try await next.respond(to: request)
    }
}
