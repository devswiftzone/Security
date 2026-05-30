//
//  JWTAuthService.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import JWT
import Foundation
import SecurityCore

/// JWT-based authentication service.
///
/// Issues self-contained JWTs instead of opaque tokens. Validation is
/// stateless: presented JWTs are verified cryptographically with the
/// configured signer; no DB lookup is needed for the validation step
/// itself.
///
/// Trade-offs vs. opaque tokens (the default in SecurityFluent):
/// - PRO: stateless validation = lower latency, no DB load per request
/// - PRO: shareable across services without coordinating revocation
/// - CON: revocation is delayed until the token's natural expiration
///        (mitigate with short TTLs, typically 15-30 min for access)
/// - CON: any data embedded in the token is stale until the next refresh
///
/// JWTAuthService is intentionally narrow — it issues and verifies JWTs
/// but does not manage users, roles, or password storage. Combine it
/// with FluentUserService and FluentRoleService for a complete flow.
public struct JWTAuthService: Sendable {

    let application: Application
    let issuer: String

    public init(application: Application, issuer: String) {
        self.application = application
        self.issuer = issuer
    }

    // MARK: - Issue

    /// Issues a JWT for the given user.
    ///
    /// - Parameters:
    ///   - userID: The user identifier (subject).
    ///   - email: User's email, embedded for display purposes.
    ///   - kind: Token kind.
    ///   - roles: Roles to embed for stateless authorization.
    ///   - lifetime: TTL in seconds. Defaults to the configured value
    ///     for the given kind.
    /// - Returns: The signed JWT string.
    public func issue(
        userID: UUID,
        email: String,
        kind: TokenKind,
        roles: [String],
        lifetime: TimeInterval? = nil
    ) async throws -> String {
        let ttl = lifetime
            ?? application.security.configuration.tokenLifetimes.lifetime(for: kind)
        let now = Date()

        let payload = SecurityJWTPayload(
            userID: userID,
            email: email,
            kind: kind,
            roles: roles,
            issuer: issuer,
            issuedAt: now,
            expiresAt: now.addingTimeInterval(ttl)
        )

        return try await application.jwt.keys.sign(payload)
    }

    // MARK: - Verify

    /// Verifies a JWT and returns its payload.
    ///
    /// - Throws: `SecurityError.tokenInvalid` if the signature is invalid,
    ///   `SecurityError.tokenExpired` if the token has expired.
    public func verify(_ token: String) async throws -> SecurityJWTPayload {
        do {
            return try await application.jwt.keys.verify(
                token,
                as: SecurityJWTPayload.self
            )
        } catch let error as JWTError where error.errorType == .claimVerificationFailure {
            throw SecurityError.tokenExpired
        } catch {
            throw SecurityError.tokenInvalid
        }
    }
}

// MARK: - Application accessor

public extension Application.Security {

    /// JWT-based auth service. Requires JWT signers to be configured via
    /// `app.jwt.signers.use(...)`.
    ///
    /// Usage:
    ///
    ///     app.jwt.signers.use(.hs256(key: "your-secret"))
    ///     let jwtAuth = app.security.jwt(issuer: "api.example.com")
    ///     let token = try await jwtAuth.issue(
    ///         userID: user.id!,
    ///         email: user.email,
    ///         kind: .access,
    ///         roles: ["admin"]
    ///     )
    ///
    /// - Parameter issuer: The issuer claim to embed in tokens.
    func jwt(issuer: String) -> JWTAuthService {
        JWTAuthService(application: application, issuer: issuer)
    }
}
