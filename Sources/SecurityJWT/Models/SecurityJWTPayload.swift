//
//  SecurityJWTPayload.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Foundation
import JWT
import SecurityCore

/// Standard JWT payload used by the Security package's JWT module.
///
/// Includes the conventional RFC 7519 claims (`sub`, `exp`, `iat`, `iss`)
/// plus security-specific claims for user identification and authorization
/// (`email`, `roles`, `kind`).
///
/// Roles are embedded in the token so authorization checks can run without
/// a DB query. This is the main reason to use JWTs over opaque tokens.
/// The tradeoff: when a role is revoked, the change only takes effect
/// when the user's current JWT expires. Choose JWT TTL accordingly
/// (15-30 min is a common balance).
public struct SecurityJWTPayload: JWTPayload, Sendable {

    // MARK: - Standard claims

    /// Subject — the user ID.
    public var sub: SubjectClaim

    /// Issuer — identifies the system that issued the token.
    public var iss: IssuerClaim

    /// Expiration time.
    public var exp: ExpirationClaim

    /// Issued at.
    public var iat: IssuedAtClaim

    // MARK: - Security-specific claims

    /// User's email at issuance time.
    public var email: String

    /// Token kind (access / refresh / api / oneTime) as raw string.
    public var kind: String

    /// User's roles at issuance time. Empty array if none.
    public var roles: [String]

    // MARK: - Init

    public init(
        userID: UUID,
        email: String,
        kind: TokenKind,
        roles: [String],
        issuer: String,
        issuedAt: Date = Date(),
        expiresAt: Date
    ) {
        self.sub = SubjectClaim(value: userID.uuidString)
        self.iss = IssuerClaim(value: issuer)
        self.exp = ExpirationClaim(value: expiresAt)
        self.iat = IssuedAtClaim(value: issuedAt)
        self.email = email
        self.kind = kind.rawValue
        self.roles = roles
    }

    // MARK: - JWTPayload

    public func verify(using algorithm: some JWTAlgorithm) async throws {
        try self.exp.verifyNotExpired()
    }

    // MARK: - Convenience accessors

    /// Returns the subject as a `UUID`, or nil if it isn't a valid UUID
    /// string (e.g. tampered token).
    public var userID: UUID? {
        UUID(uuidString: sub.value)
    }

    /// Returns the strongly typed kind, or nil for unknown values.
    public var tokenKind: TokenKind? {
        TokenKind(rawValue: kind)
    }
}
