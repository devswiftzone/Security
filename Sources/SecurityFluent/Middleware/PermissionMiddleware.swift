//
//  PermissionMiddleware.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import SecurityCore

/// Gates a route group on a specific permission.
///
/// Convenient when you want the policy expressed directly in route
/// configuration rather than wrapped in a custom AuthorizationPolicy:
///
///     let admin = app.grouped(BearerTokenMiddleware())
///                    .grouped(PermissionMiddleware("users.delete"))
///     admin.delete("users", ":id") { req in /* ... */ }
///
/// For composed conditions, use `AuthorizationPolicy.middleware()`:
///
///     let policy = RequireRole("admin") || RequirePermission("users.delete")
///     app.grouped(policy.middleware())
public struct PermissionMiddleware: AsyncMiddleware {

    public let permission: Permission

    public init(_ permission: Permission) {
        self.permission = permission
    }

    public init(_ name: String) {
        self.permission = Permission(name)
    }

    public func respond(
        to request: Request,
        chainingTo next: AsyncResponder
    ) async throws -> Response {
        try await request.security.require(permission: permission)
        return try await next.respond(to: request)
    }
}
