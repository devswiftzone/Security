//
//  Request+Security.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Foundation

public extension Request {

    /// Per-request entry point for Security APIs.
    ///
    /// Used inside route handlers and middleware:
    ///
    ///     app.get("posts", ":id") { req async throws -> Post in
    ///         try await req.security.require(permission: "posts.read")
    ///         // ...
    ///     }
    var security: Security {
        .init(request: self)
    }

    /// Namespace struct for request-scoped Security operations.
    struct Security: Sendable {

        public let request: Request

        public init(request: Request) {
            self.request = request
        }

        // MARK: - User access

        /// Returns the typed authenticated user, or throws if not authenticated.
        ///
        /// Equivalent to `req.auth.require(U.self)` but throws a
        /// `SecurityError` instead of Vapor's generic auth error so error
        /// responses are consistent across the package.
        public func require<U: SecurityUser>(_ type: U.Type) throws -> U {
            do {
                return try request.auth.require(U.self)
            } catch {
                throw SecurityError.tokenInvalid
            }
        }

        /// Returns the type-erased authenticated user, or nil if no user
        /// is logged in. Used by authorization policies internally.
        public func user() -> AnySecurityUser? {
            request.auth.get(AnySecurityUser.self)
        }

        // MARK: - Authorization helpers

        /// Asserts that the authenticated user has the given permission.
        ///
        /// - Throws: `SecurityError.missingPermission` if not authorized,
        ///   `SecurityError.tokenInvalid` if no user is authenticated.
        public func require(permission: Permission) async throws {
            guard let user = user() else { throw SecurityError.tokenInvalid }
            let granted = try await user.has(permission: permission, on: request.db)
            guard granted else {
                throw SecurityError.missingPermission(permission.name)
            }
        }

        /// Asserts that the authenticated user has the given permission.
        public func require(permission name: String) async throws {
            try await require(permission: Permission(name))
        }

        /// Asserts that the authenticated user has the given role.
        public func require(role: String) async throws {
            guard let user = user() else { throw SecurityError.tokenInvalid }
            let granted = try await user.has(role: role, on: request.db)
            guard granted else {
                throw SecurityError.missingRole(role)
            }
        }

        /// Evaluates an authorization policy. Throws `policyDenied` if it
        /// returns false.
        public func require(_ policy: AuthorizationPolicy) async throws {
            let granted = try await policy.evaluate(request)
            guard granted else {
                throw SecurityError.policyDenied(reason: policy.name)
            }
        }

        // MARK: - Boolean checks (non-throwing)

        /// Returns whether the authenticated user has the permission.
        /// Returns false if no user is authenticated (does not throw).
        public func can(_ permission: Permission) async -> Bool {
            guard let user = user() else { return false }
            return (try? await user.has(permission: permission, on: request.db)) ?? false
        }

        /// Returns whether the authenticated user has the permission.
        public func can(_ name: String) async -> Bool {
            await can(Permission(name))
        }

        /// Returns whether the authenticated user has the role.
        public func `is`(_ role: String) async -> Bool {
            guard let user = user() else { return false }
            return (try? await user.has(role: role, on: request.db)) ?? false
        }
    }
}
