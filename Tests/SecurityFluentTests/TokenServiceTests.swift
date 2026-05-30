//
//  TokenServiceTests.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Testing
import Vapor
import Fluent
import Foundation
import Crypto
@testable import SecurityFluent
@testable import SecurityCore

@Suite("FluentTokenService")
struct TokenServiceTests {
    
    // MARK: - Helpers
    
    /// Creates a test user via the standard register flow and returns the
    /// User record. Used as setup for token-specific tests.
    @MainActor
    private static func makeUser(
        in app: Application,
        email: String = "tokens@example.com"
    ) async throws -> User {
        let response = try await app.security.auth.register(
            RegisterDTO(email: email, password: "correcthorsebatterystaple"),
            on: app.db
        )
        return try await app.security.users.require(id: response.userID!, on: app.db)
    }
    
    // MARK: - Storage
    
    @Test("issue stores SHA-256 hash, not plaintext")
    @MainActor
    func issueStoresHash() async throws {
        try await TestApp.withFresh { app in
            let user = try await Self.makeUser(in: app)
            
            let (plaintext, token) = try await app.security.tokens.issue(
                kind: .access,
                for: user,
                lifetime: nil,
                on: app.db
            )
            
            // The stored value must NOT equal the plaintext.
            #expect(token.value != plaintext)
            
            // It must equal the SHA-256 hex hash of the plaintext.
            let expected = SHA256.hash(data: Data(plaintext.utf8))
                .compactMap { String(format: "%02x", $0) }
                .joined()
            #expect(token.value == expected)
            #expect(token.value.count == 64)  // 256 bits hex = 64 chars
        }
    }
    
    @Test("plaintext token is not recoverable from the database")
    @MainActor
    func plaintextNotInDB() async throws {
        try await TestApp.withFresh { app in
            let user = try await Self.makeUser(in: app)
            
            let (plaintext, _) = try await app.security.tokens.issue(
                kind: .access,
                for: user,
                lifetime: nil,
                on: app.db
            )
            
            // Verify no row anywhere contains the plaintext.
            let raw = try await Token.query(on: app.db)
                .filter(\.$value == plaintext)
                .first()
            #expect(raw == nil)
        }
    }
    
    // MARK: - Validation
    
    @Test("find resolves the token from its plaintext value")
    @MainActor
    func findByPlaintext() async throws {
        try await TestApp.withFresh { app in
            let user = try await Self.makeUser(in: app)
            
            let (plaintext, original) = try await app.security.tokens.issue(
                kind: .access,
                for: user,
                lifetime: nil,
                on: app.db
            )
            
            let found = try await app.security.tokens.find(
                plaintext: plaintext,
                on: app.db
            )
            
            #expect(found?.id == original.id)
        }
    }
    
    @Test("find returns nil for unknown plaintext")
    @MainActor
    func findUnknownReturnsNil() async throws {
        try await TestApp.withFresh { app in
            let found = try await app.security.tokens.find(
                plaintext: "not-a-real-token-value",
                on: app.db
            )
            #expect(found == nil)
        }
    }
    
    @Test("find returns nil for expired token")
    @MainActor
    func findExpiredReturnsNil() async throws {
        try await TestApp.withFresh { app in
            let user = try await Self.makeUser(in: app)
            
            // Issue with negative lifetime so the token is already expired.
            let (plaintext, _) = try await app.security.tokens.issue(
                kind: .access,
                for: user,
                lifetime: -1,
                on: app.db
            )
            
            let found = try await app.security.tokens.find(
                plaintext: plaintext,
                on: app.db
            )
            #expect(found == nil)
        }
    }
    
    @Test("require throws tokenInvalid for missing token")
    @MainActor
    func requireThrowsOnMissing() async throws {
        try await TestApp.withFresh { app in
            await #expect(throws: SecurityError.tokenInvalid) {
                _ = try await app.security.tokens.require(
                    plaintext: "no-such-token",
                    on: app.db
                )
            }
        }
    }
    
    // MARK: - Revocation
    
    @Test("revoke marks token invalid")
    @MainActor
    func revokeMakesInvalid() async throws {
        try await TestApp.withFresh { app in
            let user = try await Self.makeUser(in: app)
            
            let (plaintext, token) = try await app.security.tokens.issue(
                kind: .access,
                for: user,
                lifetime: nil,
                on: app.db
            )
            
            try await app.security.tokens.revoke(token, on: app.db)
            
            let found = try await app.security.tokens.find(
                plaintext: plaintext,
                on: app.db
            )
            #expect(found == nil)
        }
    }
    
    @Test("revoke is idempotent")
    @MainActor
    func revokeIdempotent() async throws {
        try await TestApp.withFresh { app in
            let user = try await Self.makeUser(in: app)
            
            let (_, token) = try await app.security.tokens.issue(
                kind: .access,
                for: user,
                lifetime: nil,
                on: app.db
            )
            
            try await app.security.tokens.revoke(token, on: app.db)
            // Calling revoke again must not throw.
            try await app.security.tokens.revoke(token, on: app.db)
            try await app.security.tokens.revoke(token, on: app.db)
        }
    }
    
    @Test("revokeAll affects only the targeted user")
    @MainActor
    func revokeAllScopedToUser() async throws {
        try await TestApp.withFresh { app in
            let userA = try await Self.makeUser(in: app, email: "a@example.com")
            let userB = try await Self.makeUser(in: app, email: "b@example.com")
            
            let (plainA, _) = try await app.security.tokens.issue(
                kind: .access, for: userA, lifetime: nil, on: app.db
            )
            let (plainB, _) = try await app.security.tokens.issue(
                kind: .access, for: userB, lifetime: nil, on: app.db
            )
            
            try await app.security.tokens.revokeAll(for: userA, kind: nil, on: app.db)
            
            // A is revoked.
            #expect(try await app.security.tokens.find(plaintext: plainA, on: app.db) == nil)
            // B is still alive.
            #expect(try await app.security.tokens.find(plaintext: plainB, on: app.db) != nil)
        }
    }
    
    @Test("revokeAll with kind only revokes that kind")
    @MainActor
    func revokeAllByKind() async throws {
        try await TestApp.withFresh { app in
            let user = try await Self.makeUser(in: app)
            
            let (accessPlain, _) = try await app.security.tokens.issue(
                kind: .access, for: user, lifetime: nil, on: app.db
            )
            let (refreshPlain, _) = try await app.security.tokens.issue(
                kind: .refresh, for: user, lifetime: nil, on: app.db
            )
            
            try await app.security.tokens.revokeAll(
                for: user, kind: .refresh, on: app.db
            )
            
            // Access still valid.
            #expect(try await app.security.tokens.find(plaintext: accessPlain, on: app.db) != nil)
            // Refresh revoked.
            #expect(try await app.security.tokens.find(plaintext: refreshPlain, on: app.db) == nil)
        }
    }
    
    // MARK: - Multi-session
    
    @Test("user can have multiple concurrent tokens")
    @MainActor
    func multipleConcurrentTokens() async throws {
        try await TestApp.withFresh { app in
            let user = try await Self.makeUser(in: app)
            
            // Three "devices" each get their own access token.
            var plaintexts: [String] = []
            for _ in 0..<3 {
                let (plain, _) = try await app.security.tokens.issue(
                    kind: .access, for: user, lifetime: nil, on: app.db
                )
                plaintexts.append(plain)
            }
            
            // All three are valid simultaneously.
            for plain in plaintexts {
                let found = try await app.security.tokens.find(plaintext: plain, on: app.db)
                #expect(found != nil)
            }
            
            // Tokens are distinct (no collision in 100 bits of entropy).
            #expect(Set(plaintexts).count == 3)
        }
    }
    
    // MARK: - Rotation
    
    @Test("rotate issues new token and revokes the old one")
    @MainActor
    func rotateReplacesToken() async throws {
        try await TestApp.withFresh { app in
            let user = try await Self.makeUser(in: app)
            
            let (oldPlain, oldToken) = try await app.security.tokens.issue(
                kind: .refresh, for: user, lifetime: nil, on: app.db
            )
            
            let (newPlain, newToken) = try await app.security.tokens.rotate(
                oldToken, on: app.db
            )
            
            // New token is different.
            #expect(newPlain != oldPlain)
            #expect(newToken.id != oldToken.id)
            #expect(newToken.tokenKind == .refresh)
            
            // Old token no longer resolves.
            #expect(try await app.security.tokens.find(plaintext: oldPlain, on: app.db) == nil)
            // New token resolves.
            #expect(try await app.security.tokens.find(plaintext: newPlain, on: app.db) != nil)
        }
    }
    
    @Test("rotate fails on already-revoked token")
    @MainActor
    func rotateFailsOnRevoked() async throws {
        try await TestApp.withFresh { app in
            let user = try await Self.makeUser(in: app)
            
            let (_, token) = try await app.security.tokens.issue(
                kind: .refresh, for: user, lifetime: nil, on: app.db
            )
            
            try await app.security.tokens.revoke(token, on: app.db)
            
            await #expect(throws: SecurityError.tokenInvalid) {
                _ = try await app.security.tokens.rotate(token, on: app.db)
            }
        }
    }
    
    // MARK: - Owner resolution
    
    @Test("owner returns the User who owns the token")
    @MainActor
    func ownerResolves() async throws {
        try await TestApp.withFresh { app in
            let user = try await Self.makeUser(in: app, email: "owner@example.com")
            
            let (_, token) = try await app.security.tokens.issue(
                kind: .access, for: user, lifetime: nil, on: app.db
            )
            
            let resolved = try await app.security.tokens.owner(of: token, on: app.db)
            #expect(resolved.id == user.id)
            #expect(resolved.email == "owner@example.com")
        }
    }
    
    // MARK: - Purge
    
    @Test("purgeExpired removes only expired or revoked tokens")
    @MainActor
    func purgeRemovesExpired() async throws {
        try await TestApp.withFresh { app in
            let user = try await Self.makeUser(in: app)
            
            // Active token.
            let (activePlain, _) = try await app.security.tokens.issue(
                kind: .access, for: user, lifetime: nil, on: app.db
            )
            
            // Expired token (negative lifetime → already in the past).
            _ = try await app.security.tokens.issue(
                kind: .access, for: user, lifetime: -1, on: app.db
            )
            
            // Revoked token.
            let (_, revokedToken) = try await app.security.tokens.issue(
                kind: .access, for: user, lifetime: nil, on: app.db
            )
            try await app.security.tokens.revoke(revokedToken, on: app.db)
            
            let countBefore = try await Token.query(on: app.db).count()
            #expect(countBefore == 5)  // initial register's access+refresh + 3 we made
            
            let purged = try await app.security.tokens.purgeExpired(on: app.db)
            #expect(purged >= 2)  // at least the expired and revoked ones
            
            // Active token still resolves.
            #expect(try await app.security.tokens.find(plaintext: activePlain, on: app.db) != nil)
        }
    }
}
