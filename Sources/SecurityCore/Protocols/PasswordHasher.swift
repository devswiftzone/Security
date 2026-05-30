//
//  PasswordHasher.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Foundation

/// Hashes and verifies passwords.
///
/// Implementations should use a slow, salted, adaptive algorithm such as
/// bcrypt, Argon2id, or scrypt. Never use plain SHA-256 or MD5.
///
/// Conformance to `Sendable` is required because the hasher is stored on
/// `Application` and accessed from concurrent request handlers.
public protocol SecurityPasswordHasher: Sendable {

    /// Stable identifier for this hashing algorithm (e.g. `"bcrypt"`,
    /// `"argon2id"`). Stored alongside the hash so that future migrations
    /// to a different algorithm are possible.
    var algorithm: String { get }

    /// Produces a salted, hashed representation of the password.
    ///
    /// The returned string is opaque and includes all parameters needed
    /// to verify a candidate password against it (typically the algorithm
    /// embeds salt and cost into the output, e.g. bcrypt's `$2b$12$...`
    /// format).
    ///
    /// - Parameter password: The plaintext password to hash.
    /// - Returns: A string suitable for storage in `UserPassword.hash`.
    /// - Throws: `SecurityError.passwordTooWeak` or hasher-specific errors.
    func hash(_ password: String) throws -> String

    /// Verifies a candidate password against a stored hash.
    ///
    /// Implementations MUST use a constant-time comparison to prevent
    /// timing attacks.
    ///
    /// - Parameters:
    ///   - password: The plaintext password to verify.
    ///   - hash: The previously stored hash.
    /// - Returns: `true` if the password matches the hash.
    func verify(_ password: String, against hash: String) throws -> Bool
}

// MARK: - Optional rehash check

public extension SecurityPasswordHasher {

    /// Whether an existing hash should be regenerated (e.g. because cost
    /// parameters have increased or the algorithm has been upgraded).
    ///
    /// Default implementation returns `false`. Implementations are
    /// encouraged to override this and trigger a transparent rehash on
    /// the next successful login.
    func needsRehash(_ hash: String) -> Bool {
        false
    }
}
