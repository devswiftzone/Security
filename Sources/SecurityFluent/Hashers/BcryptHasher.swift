//
//  BcryptHasher.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Foundation
import Vapor
import SecurityCore

/// `PasswordHasher` implementation using bcrypt (via Vapor's `Bcrypt`).
///
/// Bcrypt is a slow, adaptive, salted hash designed for passwords. Each
/// hash includes the algorithm version, cost factor, and 128-bit random
/// salt inline (e.g. `$2b$12$...`), so the same plaintext password
/// produces different hashes every time and no separate salt column is
/// needed.
///
/// The `cost` parameter controls the work factor: each unit doubles the
/// time. Cost 12 takes ~250ms on modern hardware (2025). Increase to 13
/// or 14 for tighter security tolerance; decrease to 10 only for tests.
/// Range: 4–31. Below 10 is insecure.
public struct BcryptHasher: SecurityPasswordHasher {

    public let algorithm: String = "bcrypt"

    /// The bcrypt cost factor (work parameter). Defaults to 12.
    public let cost: Int

    public init(cost: Int = 12) {
        // Clamp to bcrypt's valid range to avoid mysterious failures.
        // Bcrypt enforces 4..31 internally; we surface that here.
        precondition((4...31).contains(cost), "bcrypt cost must be between 4 and 31")
        self.cost = cost
    }

    // MARK: - PasswordHasher

    public func hash(_ password: String) throws -> String {
        try Bcrypt.hash(password, cost: cost)
    }

    public func verify(_ password: String, against hash: String) throws -> Bool {
        try Bcrypt.verify(password, created: hash)
    }

    /// Inspects the hash's cost prefix and returns true if it differs
    /// from this hasher's configured cost. Used by `AuthService` to
    /// transparently rehash on successful login when cost has been
    /// increased.
    public func needsRehash(_ hash: String) -> Bool {
        guard let parsedCost = parseCost(from: hash) else {
            // Unknown format → conservatively flag for rehash.
            return true
        }
        return parsedCost != cost
    }

    // MARK: - Internal

    /// Parses the cost factor from a bcrypt hash like `$2b$12$...`.
    /// Returns nil if the format is not recognized.
    private func parseCost(from hash: String) -> Int? {
        // Format: $<algo>$<cost>$<22 chars salt><31 chars hash>
        // Split on '$' to extract the 2nd component (cost).
        let parts = hash.split(separator: "$", omittingEmptySubsequences: true)
        guard parts.count >= 3 else { return nil }
        return Int(parts[1])
    }
}
