//
//  DefaultTokenGeneratorTests.swift
//  Security
//
//  Created by Asiel Cabrera on 5/30/26.
//

import Testing
import Foundation
@testable import SecurityFluent

@Suite("DefaultTokenGenerator")
struct DefaultTokenGeneratorTests {

    let generator = DefaultTokenGenerator()

    @Test("Generates tokens of expected length")
    func tokenLength() throws {
        let token = try generator.generate()
        // 32 bytes → base64url unpadded = ceil(32 * 4 / 3) chars = 43
        #expect(token.count == 43)
    }

    @Test("Generates URL-safe characters only")
    func urlSafe() throws {
        let token = try generator.generate()
        // base64url: A-Z, a-z, 0-9, -, _
        let allowed = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        #expect(token.allSatisfy { allowed.contains($0) })
    }

    @Test("No padding characters")
    func noPadding() throws {
        let token = try generator.generate()
        #expect(!token.contains("="))
    }

    @Test("Subsequent tokens differ (entropy sanity check)")
    func uniqueness() throws {
        var seen = Set<String>()
        for _ in 0..<100 {
            try seen.insert(generator.generate())
        }
        #expect(seen.count == 100)
    }

    @Test("Hash is a 64-character lowercase hex string")
    func hashFormat() {
        let hash = generator.hash("any token value")
        #expect(hash.count == 64)  // SHA-256 = 256 bits = 32 bytes = 64 hex chars
        let allowed = Set("0123456789abcdef")
        #expect(hash.allSatisfy { allowed.contains($0) })
    }

    @Test("Hash is deterministic")
    func hashDeterministic() {
        let token = "the same input"
        let h1 = generator.hash(token)
        let h2 = generator.hash(token)
        #expect(h1 == h2)
    }

    @Test("Different inputs produce different hashes")
    func hashCollisionResistance() {
        let h1 = generator.hash("input-a")
        let h2 = generator.hash("input-b")
        #expect(h1 != h2)
    }

    @Test("Custom byteCount produces longer tokens")
    func customByteCount() throws {
        let big = DefaultTokenGenerator(byteCount: 64)
        let token = try big.generate()
        // 64 bytes → base64url unpadded = 86 chars
        #expect(token.count == 86)
    }

    @Test(
        "Hashing known input produces known SHA-256",
        arguments: [
            // Known SHA-256 test vectors
            ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ]
    )
    func hashKnownVectors(input: String, expected: String) {
        #expect(generator.hash(input) == expected)
    }
}
