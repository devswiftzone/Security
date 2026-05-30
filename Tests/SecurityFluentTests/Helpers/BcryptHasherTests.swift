//
//  BcryptHasherTests.swift
//  Security
//
//  Created by Asiel Cabrera on 5/30/26.
//

import Testing
import Foundation
@testable import SecurityFluent

@Suite("BcryptHasher")
struct BcryptHasherTests {

    // Use a low cost in tests to keep them fast. Cost 4 still validates
    // correctness; production should always be >= 12.
    let hasher = BcryptHasher(cost: 4)

    @Test("Hashes a password to a non-empty string")
    func hashesNonEmpty() throws {
        let hash = try hasher.hash("correct horse battery staple")
        #expect(!hash.isEmpty)
        #expect(hash.hasPrefix("$2"))  // bcrypt prefix
    }

    @Test("Same password produces different hashes (salt is random)")
    func saltedHashesDiffer() throws {
        let h1 = try hasher.hash("hunter2")
        let h2 = try hasher.hash("hunter2")
        #expect(h1 != h2)
    }

    @Test("Verifies correct password against its hash")
    func verifiesCorrect() throws {
        let hash = try hasher.hash("correct horse battery staple")
        let matches = try hasher.verify("correct horse battery staple", against: hash)
        #expect(matches == true)
    }

    @Test("Rejects wrong password")
    func rejectsWrong() throws {
        let hash = try hasher.hash("correct horse battery staple")
        let matches = try hasher.verify("Tr0ub4dor&3", against: hash)
        #expect(matches == false)
    }

    @Test("Algorithm identifier is 'bcrypt'")
    func algorithmIdentifier() {
        #expect(hasher.algorithm == "bcrypt")
    }

    @Test("needsRehash returns false when cost matches")
    func needsRehashSameCost() throws {
        let hash = try hasher.hash("password123")
        #expect(hasher.needsRehash(hash) == false)
    }

    @Test("needsRehash returns true when cost increases")
    func needsRehashHigherCost() throws {
        let oldHasher = BcryptHasher(cost: 4)
        let newHasher = BcryptHasher(cost: 5)

        let oldHash = try oldHasher.hash("password123")
        #expect(newHasher.needsRehash(oldHash) == true)
    }

    @Test("needsRehash returns true for unrecognized format")
    func needsRehashUnknownFormat() {
        #expect(hasher.needsRehash("not-a-bcrypt-hash") == true)
        #expect(hasher.needsRehash("") == true)
        #expect(hasher.needsRehash("$2$invalid") == true)  // too few components
    }

    @Test("Cost out of range traps via precondition", .disabled("preconditions abort the test"))
    func costOutOfRangeTraps() {
        // Documented behavior, not testable cleanly without a wrapper
        // that catches preconditions. Skipped.
    }
}
