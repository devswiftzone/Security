//
//  FluentAuthService.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import Foundation
import SecurityCore

/// Fluent-backed implementation of `AuthServiceProtocol`.
///
/// Orchestrates the user, token, password, and event services to provide
/// the high-level auth flows: register, login, refresh, logout, password
/// change. Exposed via `app.security.auth`.
public struct FluentAuthService: AuthServiceProtocol, Sendable {

    public typealias User = SecurityFluent.User

    let application: Application

    public init(application: Application) {
        self.application = application
    }

    // MARK: - Register

    public func register(
        _ dto: RegisterRequest,
        on db: Database
    ) async throws -> TokenResponse {
        // Optional password confirmation check.
        if let confirmation = dto.passwordConfirmation,
           confirmation != dto.password {
            throw SecurityError.passwordTooWeak(
                reason: "password and confirmation do not match"
            )
        }

        // Apply configured password policy.
        let policy = application.security.configuration.passwordPolicy
        if let error = policy.validate(dto.password) {
            throw error
        }

        // Atomically create user + password. If anything fails, both
        // operations roll back so we never end up with a passwordless
        // ghost user from a half-completed registration.
        let user = try await db.transaction { tx in
            let user = try await application.security.users.create(
                email: dto.email,
                isActive: true,
                on: tx
            )

            guard let userID = user.id else {
                throw SecurityError.policyDenied(reason: "user not persisted")
            }

            let hasher = application.security.passwordHasher
            let hashed = try hasher.hash(dto.password)

            let password = UserPassword(
                userID: userID,
                hash: hashed,
                algorithm: hasher.algorithm
            )
            try await password.save(on: tx)

            return user
        }

        // Issue tokens outside the transaction. Token rows live in the
        // same DB but separating concerns keeps the registration
        // transaction tight and readable.
        return try await issueTokenPair(for: user, on: db)
    }

    // MARK: - Login

    public func login(
        _ dto: LoginRequest,
        on db: Database
    ) async throws -> TokenResponse {
        let user = try await application.security.users
            .find(email: dto.email, on: db)

        // No-user and wrong-password collapse to a single error to
        // prevent user enumeration. The event bus still records the
        // distinct reasons for audit purposes.
        guard let user else {
            publishLoginFailed(
                email: dto.email,
                reason: .unknownEmail
            )
            throw SecurityError.invalidCredentials
        }

        guard user.isActive else {
            publishLoginFailed(
                email: dto.email,
                reason: .userInactive
            )
            throw SecurityError.invalidCredentials
        }

        let hasher = application.security.passwordHasher
        let matches = try await user.verifyPassword(
            dto.password,
            using: hasher,
            on: db
        )
        guard matches else {
            publishLoginFailed(
                email: dto.email,
                reason: .wrongPassword
            )
            throw SecurityError.invalidCredentials
        }

        // Transparent rehash if the configured hasher's parameters
        // (e.g. bcrypt cost) have moved past what's stored. This is
        // best-effort: rehash failure does not block the login.
        try? await rehashIfNeeded(user: user, plaintext: dto.password, on: db)

        publishLoginSucceeded(user: user)
        return try await issueTokenPair(for: user, on: db)
    }

    // MARK: - Refresh

    public func refresh(
        _ dto: RefreshRequest,
        on db: Database
    ) async throws -> TokenResponse {
        let tokens = application.security.tokens

        // Look up the refresh token first by hash.
        let existing = try await Token.query(on: db)
            .filter(\.$value == application.security.tokenGenerator.hash(dto.refreshToken))
            .first()

        guard let token = existing else {
            throw SecurityError.tokenInvalid
        }

        // Only refresh tokens can be used to refresh.
        guard token.tokenKind == .refresh else {
            throw SecurityError.tokenInvalid
        }

        // Reuse detection: a refresh token that has already been revoked
        // is being presented again — that's a strong signal of
        // compromise. If detection is enabled, revoke everything for
        // this user and emit a dedicated event.
        if token.revokedAt != nil {
            if application.security.configuration.refreshRotation.detectReuse {
                let owner = try await tokens.owner(of: token, on: db)
                try await tokens.revokeAll(for: owner, kind: nil, on: db)

                let ctx = SecurityEvent.UserContext(
                    id: owner.id ?? UUID(),
                    email: owner.email
                )
                application.security.events
                    .publishDetached(.tokenReuseDetected(ctx))

                throw SecurityError.tokenReuseDetected
            }
            throw SecurityError.tokenInvalid
        }

        if let expiresAt = token.expiresAt, expiresAt <= Date() {
            throw SecurityError.tokenExpired
        }

        // Rotation is enabled by default — issue new access + refresh
        // and revoke the consumed refresh.
        let owner = try await tokens.owner(of: token, on: db)

        if application.security.configuration.refreshRotation.enabled {
            try await tokens.revoke(token, on: db)
        }

        return try await issueTokenPair(for: owner, on: db)
    }

    // MARK: - Logout

    public func logout(
        _ user: User,
        on db: Database
    ) async throws {
        try await application.security.tokens
            .revokeAll(for: user, kind: nil, on: db)
    }

    public func logout(
        accessToken: String,
        on db: Database
    ) async throws {
        let tokens = application.security.tokens

        // Revoke the presented access token plus any refresh token
        // associated with the same user. This logs out the current
        // session without touching other devices.
        guard let token = try await tokens.find(plaintext: accessToken, on: db) else {
            return  // nothing to do
        }

        try await tokens.revoke(token, on: db)

        // Best-effort revoke of refresh tokens for the same user. We
        // don't have a strict 1-1 mapping between access and refresh,
        // so this revokes all refresh tokens for the user. If that's
        // too aggressive for some apps, they can call the typed
        // logout(_ user:) overload with their own logic.
        let owner = try await tokens.owner(of: token, on: db)
        try await tokens.revokeAll(for: owner, kind: .refresh, on: db)
    }

    // MARK: - Change password

    public func changePassword(
        _ dto: ChangePasswordRequest,
        for user: User,
        on db: Database
    ) async throws {
        // Optional confirmation check.
        if let confirmation = dto.newPasswordConfirmation,
           confirmation != dto.newPassword {
            throw SecurityError.passwordTooWeak(
                reason: "new password and confirmation do not match"
            )
        }

        // Verify current password before allowing change.
        let hasher = application.security.passwordHasher
        let matches = try await user.verifyPassword(
            dto.currentPassword,
            using: hasher,
            on: db
        )
        guard matches else {
            throw SecurityError.invalidCredentials
        }

        // Apply policy to new password.
        let policy = application.security.configuration.passwordPolicy
        if let error = policy.validate(dto.newPassword) {
            throw error
        }

        // Persist new hash.
        guard let record = try await user.loadPassword(on: db) else {
            throw SecurityError.policyDenied(reason: "user has no password to change")
        }

        record.hash = try hasher.hash(dto.newPassword)
        record.algorithm = hasher.algorithm
        record.rotatedAt = Date()
        try await record.save(on: db)

        // Revoke all sessions to force re-authentication everywhere.
        try await application.security.tokens
            .revokeAll(for: user, kind: nil, on: db)

        publishPasswordChanged(user: user)
    }

    // MARK: - Internal helpers

    /// Issues an access + refresh token pair and packages them as a
    /// `TokenResponse` ready to return to the client.
    private func issueTokenPair(
        for user: User,
        on db: Database
    ) async throws -> TokenResponse {
        let tokens = application.security.tokens

        let (accessPlain, accessToken) = try await tokens.issue(
            kind: .access,
            for: user,
            lifetime: nil,
            on: db
        )

        let (refreshPlain, _) = try await tokens.issue(
            kind: .refresh,
            for: user,
            lifetime: nil,
            on: db
        )

        let lifetime = Int(accessToken.expiresAt
            .map { $0.timeIntervalSinceNow }
            ?? application.security.configuration.tokenLifetimes.access)

        return TokenResponse(
            accessToken: accessPlain,
            refreshToken: refreshPlain,
            expiresIn: max(lifetime, 0),
            userID: user.id
        )
    }

    /// Best-effort rehash when the stored hash's parameters lag behind
    /// the configured hasher. Failure is swallowed — login already
    /// succeeded.
    private func rehashIfNeeded(
        user: User,
        plaintext: String,
        on db: Database
    ) async throws {
        guard let record = try await user.loadPassword(on: db) else { return }
        let hasher = application.security.passwordHasher

        guard hasher.needsRehash(record.hash) else { return }

        record.hash = try hasher.hash(plaintext)
        record.algorithm = hasher.algorithm
        record.rotatedAt = Date()
        try await record.save(on: db)
    }

    // MARK: - Event helpers

    private func publishLoginSucceeded(user: User) {
        guard let id = user.id else { return }
        let ctx = SecurityEvent.UserContext(id: id, email: user.email)
        application.security.events
            .publishDetached(.loginSucceeded(ctx, ip: nil))
    }

    private func publishLoginFailed(
        email: String,
        reason: SecurityEvent.LoginFailureReason
    ) {
        application.security.events
            .publishDetached(.loginFailed(email: email, ip: nil, reason: reason))
    }

    private func publishPasswordChanged(user: User) {
        guard let id = user.id else { return }
        let ctx = SecurityEvent.UserContext(id: id, email: user.email)
        application.security.events
            .publishDetached(.passwordChanged(ctx))
    }
}

// MARK: - Application accessor

public extension Application.Security {

    /// Entry point for high-level authentication flows.
    ///
    /// Usage:
    ///
    ///     app.post("auth", "login") { req async throws -> TokenResponse in
    ///         let dto = try req.content.decode(LoginDTO.self)
    ///         return try await req.application.security.auth
    ///             .login(dto, on: req.db)
    ///     }
    var auth: FluentAuthService {
        FluentAuthService(application: application)
    }
}
