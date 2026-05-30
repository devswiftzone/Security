//
//  TokenServiceProtocol.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import Foundation

/// Manages issuance, validation, and revocation of tokens.
///
/// Tokens are opaque (random bytes) by default. The plaintext value is
/// returned **once** at issuance time; only the hash is stored. Lookups
/// happen by hashing the candidate and matching against stored hashes.
public protocol TokenServiceProtocol: Sendable {

    associatedtype User: SecurityUser
    associatedtype Token: Sendable

    /// Issues a new token of the given kind for the user.
    ///
    /// - Parameters:
    ///   - kind: The token kind. Determines TTL and rotation policy.
    ///   - user: The owning user.
    ///   - lifetime: Optional override for the TTL. Defaults to
    ///     `kind.defaultLifetime`.
    ///   - db: Database context.
    /// - Returns: A tuple containing the plaintext token (return to client)
    ///   and the persisted Token record.
    func issue(
        kind: TokenKind,
        for user: User,
        lifetime: TimeInterval?,
        on db: Database
    ) async throws -> (plaintext: String, token: Token)

    /// Looks up a token by its plaintext value. Returns nil if not found
    /// or already revoked/expired.
    func find(plaintext: String, on db: Database) async throws -> Token?

    /// Returns a valid (non-revoked, non-expired) token, or throws.
    func require(plaintext: String, on db: Database) async throws -> Token

    /// Revokes the given token.
    func revoke(_ token: Token, on db: Database) async throws

    /// Revokes all tokens belonging to a user, optionally filtered by kind.
    /// Used on password change or compromise detection.
    func revokeAll(
        for user: User,
        kind: TokenKind?,
        on db: Database
    ) async throws

    /// Rotates a token: revokes the input and issues a new one of the same
    /// kind. Used for refresh tokens.
    ///
    /// - Returns: The new plaintext value and Token record.
    func rotate(
        _ token: Token,
        on db: Database
    ) async throws -> (plaintext: String, token: Token)

    /// Returns the User who owns the token.
    func owner(of token: Token, on db: Database) async throws -> User
}
