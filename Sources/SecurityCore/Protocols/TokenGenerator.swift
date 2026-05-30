//
//  TokenGenerator.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Foundation

/// Generates the plaintext values for tokens.
///
/// The generated value is the secret that gets returned to the client
/// **once**, at creation time. The package stores only a hash of the value
/// in the database, so this generator is responsible for producing values
/// with enough entropy to be unguessable.
///
/// Implementations must be cryptographically secure — do not use
/// `Int.random(in:)` or other non-CSPRNG sources.
public protocol TokenGenerator: Sendable {

    /// The number of random bytes of entropy in each generated token.
    /// Must be at least 16 (128 bits). Recommended: 32 (256 bits).
    var byteCount: Int { get }

    /// Generates a new plaintext token value.
    ///
    /// Returned strings should be URL-safe and self-contained (no separate
    /// salt or metadata needed). Base64URL encoding of cryptographically
    /// random bytes is the typical choice.
    ///
    /// - Returns: A new opaque token string suitable for returning to clients.
    /// - Throws: If the underlying RNG is unavailable.
    func generate() throws -> String

    /// Computes a stable, deterministic hash of a token value for storage
    /// and lookup.
    ///
    /// This is **not** password hashing — token values already have high
    /// entropy, so a fast hash (SHA-256) is appropriate and necessary to
    /// allow O(1) lookups by hash. Do not use bcrypt/Argon2 here.
    ///
    /// - Parameter token: The plaintext token value.
    /// - Returns: A deterministic hash suitable for `Token.value` storage.
    func hash(_ token: String) -> String
}
