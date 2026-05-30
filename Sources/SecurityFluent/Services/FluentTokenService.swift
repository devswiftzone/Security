//
//  FluentTokenService.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import Foundation
import SecurityCore

/// Fluent-backed implementation of `TokenServiceProtocol`.
///
/// Tokens are issued with a CSPRNG-generated plaintext value (256 bits
/// of entropy by default). The plaintext is returned to the caller once
/// — at issuance — and never stored. Only the SHA-256 hash is persisted
/// in `Token.value`.
///
/// Validation hashes the candidate token and performs an indexed lookup
/// on the stored hash. This is O(log n) and a stolen DB dump yields no
/// usable tokens, because reversing SHA-256 over 256 bits of entropy is
/// computationally infeasible.
public struct FluentTokenService: TokenServiceProtocol, Sendable {

    public typealias User = SecurityFluent.User
    public typealias Token = SecurityFluent.Token

    let application: Application

    public init(application: Application) {
        self.application = application
    }

    // MARK: - Issue

    public func issue(
        kind: TokenKind,
        for user: User,
        lifetime: TimeInterval?,
        on db: Database
    ) async throws -> (plaintext: String, token: Token) {
        guard let userID = user.id else {
            throw SecurityError.policyDenied(reason: "unsaved user")
        }

        let generator = application.security.tokenGenerator
        let plaintext = try generator.generate()
        let hashed = generator.hash(plaintext)

        let ttl = lifetime
            ?? application.security.configuration.tokenLifetimes.lifetime(for: kind)
        let expiresAt: Date? = ttl > 0 ? Date().addingTimeInterval(ttl) : nil

        let token = Token(
            userID: userID,
            hashedValue: hashed,
            kind: kind,
            expiresAt: expiresAt
        )
        try await token.save(on: db)

        publishIssued(user: user, kind: kind)
        return (plaintext, token)
    }

    // MARK: - Find

    public func find(plaintext: String, on db: Database) async throws -> Token? {
        let hashed = application.security.tokenGenerator.hash(plaintext)
        let token = try await Token.query(on: db)
            .filter(\.$value == hashed)
            .first()

        guard let token, token.isValid else { return nil }
        return token
    }

    public func require(plaintext: String, on db: Database) async throws -> Token {
        guard let token = try await find(plaintext: plaintext, on: db) else {
            throw SecurityError.tokenInvalid
        }
        return token
    }

    // MARK: - Revoke

    public func revoke(_ token: Token, on db: Database) async throws {
        guard token.revokedAt == nil else { return }  // idempotent
        token.revokedAt = Date()
        try await token.save(on: db)

        if let user = try? await token.$user.get(on: db) {
            publishRevoked(user: user, kind: TokenKind(rawValue: token.kind) ?? .access)
        }
    }

    public func revokeAll(
        for user: User,
        kind: TokenKind?,
        on db: Database
    ) async throws {
        guard let userID = user.id else { return }

        let query = Token.query(on: db)
            .filter(\.$user.$id == userID)
            .filter(\.$revokedAt == nil)

        if let kind {
            query.filter(\.$kind == kind.rawValue)
        }

        // Bulk update revokedAt. Note: Fluent's `set(...).update()` on
        // a query applies the update without loading each row, so this
        // is efficient for sessions-on-logout scenarios.
        try await query.set(\.$revokedAt, to: Date()).update()

        publishLogoutAll(user: user)
    }

    // MARK: - Rotate

    public func rotate(
        _ token: Token,
        on db: Database
    ) async throws -> (plaintext: String, token: Token) {
        guard token.isValid else {
            throw SecurityError.tokenInvalid
        }

        guard let kind = TokenKind(rawValue: token.kind) else {
            throw SecurityError.tokenInvalid
        }

        // Load owner before revoking — keeps the audit context intact.
        let owner = try await token.$user.get(on: db)

        // Revoke the consumed token first. If issue() throws, the
        // revocation has still happened; that's safer than the alternative
        // (issuing without revoking, which could leak two valid tokens).
        try await revoke(token, on: db)

        return try await issue(
            kind: kind,
            for: owner,
            lifetime: nil,
            on: db
        )
    }

    // MARK: - Owner

    public func owner(of token: Token, on db: Database) async throws -> User {
        try await token.$user.get(on: db)
    }

    // MARK: - Maintenance

    /// Deletes all revoked or expired tokens older than `olderThan`.
    /// Returns the number of rows removed.
    ///
    /// Not part of the protocol — exposed as an extension method for
    /// scheduled cleanup jobs. Call from a Vapor `Schedule` or a cron
    /// task to keep the tokens table from growing unbounded.
    @discardableResult
    public func purgeExpired(
        olderThan cutoff: Date = Date(),
        on db: Database
    ) async throws -> Int {
        let revokedOrExpired = try await Token.query(on: db)
            .group(.or) { group in
                group.filter(\.$revokedAt <= cutoff)
                group.filter(\.$expiresAt <= cutoff)
            }
            .all()

        let count = revokedOrExpired.count
        try await revokedOrExpired.delete(on: db)
        return count
    }

    // MARK: - Event helpers

    private func publishIssued(user: User, kind: TokenKind) {
        guard let id = user.id else { return }
        let ctx = SecurityEvent.UserContext(id: id, email: user.email)
        application.security.events.publishDetached(.tokenIssued(ctx, kind: kind))
    }

    private func publishRevoked(user: User, kind: TokenKind) {
        guard let id = user.id else { return }
        let ctx = SecurityEvent.UserContext(id: id, email: user.email)
        application.security.events.publishDetached(.tokenRevoked(ctx, kind: kind))
    }

    private func publishLogoutAll(user: User) {
        guard let id = user.id else { return }
        let ctx = SecurityEvent.UserContext(id: id, email: user.email)
        application.security.events.publishDetached(.logoutAll(ctx))
    }
}

// MARK: - Application accessor

public extension Application.Security {

    /// Entry point for token management.
    ///
    /// Usage:
    ///
    ///     let (plaintext, _) = try await app.security.tokens.issue(
    ///         kind: .access,
    ///         for: user,
    ///         lifetime: nil,
    ///         on: req.db
    ///     )
    ///     // Return plaintext to client; only the hash is stored.
    var tokens: FluentTokenService {
        FluentTokenService(application: application)
    }
}
