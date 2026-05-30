//
//  BearerTokenMiddleware.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import Foundation
import SecurityCore

/// Authenticates requests carrying `Authorization: Bearer <token>`.
///
/// Looks up the presented token by its SHA-256 hash (the storage form),
/// validates it (not revoked, not expired), loads the owning user, and
/// logs both the typed User and the type-erased AnySecurityUser into the
/// request's auth state so policies and `req.security.require(_:)` work.
///
/// Updates `Token.lastUsedAt` best-effort for session-listing UIs. The
/// update is fire-and-forget — a failure does not break the request.
///
/// This middleware supersedes Vapor's default `Token.authenticator()`
/// because we store hashes, not plaintext.
public struct BearerTokenMiddleware: AsyncMiddleware {

    /// If true, missing or invalid tokens cause the request to fail.
    /// If false, the request continues unauthenticated. Default: true.
    public let requireAuthentication: Bool

    public init(requireAuthentication: Bool = true) {
        self.requireAuthentication = requireAuthentication
    }

    public func respond(
        to request: Request,
        chainingTo next: AsyncResponder
    ) async throws -> Response {
        // Extract bearer token from Authorization header.
        guard let bearer = request.headers.bearerAuthorization else {
            return try await passOrFail(request: request, next: next)
        }

        let tokens = request.application.security.tokens

        // Validate token (hash internally, check expiry/revocation).
        guard let token = try await tokens.find(plaintext: bearer.token, on: request.db) else {
            return try await passOrFail(request: request, next: next)
        }

        // Load owning user.
        let user = try await tokens.owner(of: token, on: request.db)

        guard user.isActive else {
            // Token belongs to a deactivated user — treat as invalid.
            return try await passOrFail(request: request, next: next)
        }

        // Log both forms so handlers can use req.auth.require(User.self)
        // and policies can use req.auth.get(AnySecurityUser.self).
        request.auth.login(user)
        request.auth.login(AnySecurityUser(user))

        // Best-effort update of lastUsedAt. Detached so request latency
        // isn't affected by the extra write.
        let tokenID = token.id
        let db = request.db
        Task.detached(priority: .background) {
            guard let tokenID else { return }
            try? await Token.query(on: db)
                .filter(\.$id == tokenID)
                .set(\.$lastUsedAt, to: Date())
                .update()
        }

        return try await next.respond(to: request)
    }

    private func passOrFail(
        request: Request,
        next: AsyncResponder
    ) async throws -> Response {
        if requireAuthentication {
            throw SecurityError.tokenInvalid
        }
        return try await next.respond(to: request)
    }
}
