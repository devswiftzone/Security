//
//  DefaultTokenGenerator.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Foundation
import Crypto
import SecurityCore

/// Default `TokenGenerator` using `SystemRandomNumberGenerator` for entropy
/// and SHA-256 for storage hashing.
///
/// Generated tokens are 32 random bytes (256 bits) encoded as base64url
/// without padding. This produces a 43-character URL-safe string that
/// fits in headers, cookies, and URLs without further encoding.
///
/// Storage hashing uses SHA-256 (not bcrypt). This is correct: the input
/// already has 256 bits of entropy, so password-strength hashing would
/// add latency without security benefit. SHA-256 also gives O(log n)
/// lookups by hash, which bcrypt cannot do because each hash uses its
/// own salt.
public struct DefaultTokenGenerator: TokenGenerator {

    public let byteCount: Int

    public init(byteCount: Int = 32) {
        precondition(byteCount >= 16, "byteCount must be at least 16 (128 bits) of entropy")
        self.byteCount = byteCount
    }

    // MARK: - TokenGenerator

    public func generate() throws -> String {
        var rng = SystemRandomNumberGenerator()
        var bytes = [UInt8](repeating: 0, count: byteCount)
        for index in bytes.indices {
            bytes[index] = UInt8.random(in: .min ... .max, using: &rng)
        }
        return Self.base64URLEncode(bytes)
    }

    public func hash(_ token: String) -> String {
        let digest = SHA256.hash(data: Data(token.utf8))
        return digest.compactMap { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Encoding helpers

    /// Base64URL without padding (RFC 4648 §5).
    static func base64URLEncode(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
