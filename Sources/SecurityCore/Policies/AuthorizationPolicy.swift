//
//  AuthorizationPolicy.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor

/// A reusable, composable authorization rule.
///
/// Policies evaluate against a `Request` (which carries the authenticated
/// user, database access, and request context) and return a Boolean.
/// They throw only on infrastructural errors (DB failure, etc.), not on
/// "access denied" — that's expressed by returning `false`.
///
/// Compose policies with the `&&`, `||`, and `!` operators, or wrap one
/// in a `Middleware` via `.middleware()`.
public protocol AuthorizationPolicy: Sendable {

    /// Evaluates whether the request satisfies this policy.
    ///
    /// - Parameter req: The incoming request. Must have an authenticated
    ///   user available via `req.auth.require`.
    /// - Returns: `true` if access is granted, `false` if denied.
    /// - Throws: Only for infrastructural failures, never for denials.
    func evaluate(_ req: Request) async throws -> Bool

    /// Optional human-readable name used in error messages and debugging.
    var name: String { get }
}

public extension AuthorizationPolicy {
    var name: String { String(describing: type(of: self)) }
}

// MARK: - Middleware bridge

public extension AuthorizationPolicy {

    /// Wraps this policy as a Vapor `Middleware`.
    ///
    /// Use in route groups to gate access:
    ///
    ///     let admin = app.grouped(RequireRole("admin").middleware())
    ///     admin.delete("users", ":id") { ... }
    func middleware() -> Middleware {
        AuthorizationPolicyMiddleware(policy: self)
    }
}

/// Internal middleware that evaluates an `AuthorizationPolicy` for each
/// request, denying with `SecurityError.policyDenied` on `false`.
struct AuthorizationPolicyMiddleware: AsyncMiddleware {
    let policy: AuthorizationPolicy

    func respond(
        to request: Request,
        chainingTo next: AsyncResponder
    ) async throws -> Response {
        let granted = try await policy.evaluate(request)
        guard granted else {
            throw SecurityError.policyDenied(reason: policy.name)
        }
        return try await next.respond(to: request)
    }
}
