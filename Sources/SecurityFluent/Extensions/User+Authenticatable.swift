//
//  User+Authenticatable.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import SecurityCore

// MARK: - ModelAuthenticatable

/// Lets `User` participate in Vapor's HTTP Basic auth flow.
///
/// `ModelAuthenticatable` normally expects the hashed password to live
/// in a column on the same row as the user. Because we store passwords
/// in a separate `UserPassword` table for the reasons documented on that
/// model, the default `verify(password:)` behavior won't work — it would
/// look for a password field on `User` that doesn't exist.
///
/// We satisfy the protocol with stub fields and override the entire
/// authentication flow in `BearerTokenMiddleware` (commit 25) and the
/// `AuthService`. Code that uses Vapor's stock `User.authenticator()`
/// for HTTP Basic should rely on those paths instead.
///
/// We still conform here because:
/// 1. Some Vapor APIs require `ModelAuthenticatable` for type plumbing.
/// 2. Consumers may want to use the HTTP Basic path for admin tools.
extension User: ModelAuthenticatable {

        // Explicit type annotations are required: Swift 6 infers
        // `\User.$email` as `KeyPath<User, FieldProperty<User, String>> & Sendable`,
        // which doesn't match the protocol's plain `KeyPath<Self, FieldProperty<Self, String>>`.
    public static let usernameKey: KeyPath<User, FieldProperty<User, String>> = \User.$email
    
    /// The protocol requires a `passwordHashKey: KeyPath<Self, Field<String>>`
    /// but `User` has no such field. We point it at `email` as a harmless
    /// placeholder and override `verify` below.
    public static let passwordHashKey: KeyPath<User, FieldProperty<User, String>> = \User.$email

    public func verify(password: String) throws -> Bool {
        // Verification by `User` alone is intentionally unsupported.
        // Authentication goes through `AuthService.login`, which loads
        // the related `UserPassword` and verifies against it using the
        // configured `SecurityPasswordHasher`.
        //
        // Throwing here makes accidental use of the stock authenticator
        // surface as a clear runtime error instead of a silent denial.
        throw SecurityError.tokenInvalid
    }
}

// MARK: - Async helpers for the password relation

public extension User {

    /// Loads the related `UserPassword`, if any.
    ///
    /// - Parameter db: The database context.
    /// - Returns: The `UserPassword` record or `nil` if the user has no
    ///   password set (e.g. OAuth-only accounts).
    func loadPassword(on db: Database) async throws -> UserPassword? {
        try await $password.get(on: db)
    }

    /// Verifies a plaintext password against the user's stored hash.
    ///
    /// Uses the hasher registered on the `Application` (typically a
    /// `BcryptHasher`). If the user has no password record, returns
    /// `false` — passwordless accounts cannot authenticate via password.
    ///
    /// - Parameters:
    ///   - password: Plaintext candidate password.
    ///   - hasher: The hasher to use for verification.
    ///   - db: The database context.
    /// - Returns: `true` if the password matches the stored hash.
    func verifyPassword(
        _ password: String,
        using hasher: SecurityPasswordHasher,
        on db: Database
    ) async throws -> Bool {
        guard let record = try await loadPassword(on: db) else {
            return false
        }
        return try hasher.verify(password, against: record.hash)
    }
}
