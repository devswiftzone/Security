//
//  AuthServiceTests.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Testing
import Vapor
import Fluent
import Foundation
@testable import SecurityFluent
@testable import SecurityCore

@Suite("FluentAuthService")
struct AuthServiceTests {

    // MARK: - Register

    @Test("register creates user, password, and returns tokens")
    @MainActor
    func registerCreatesUserAndTokens() async throws {
        try await TestApp.withFresh { app in
            let dto = RegisterRequest(
                email: "asiel@example.com",
                password: "correcthorsebatterystaple"
            )

            let response = try await app.security.auth.register(dto, on: app.db)

            // Tokens returned
            #expect(!response.accessToken.isEmpty)
            #expect(!response.refreshToken.isEmpty)
            #expect(response.expiresIn > 0)
            #expect(response.userID != nil)

            // User persisted, normalized to lowercase
            let user = try await User.query(on: app.db)
                .filter(\.$email == "asiel@example.com")
                .first()
            #expect(user != nil)
            #expect(user?.isActive == true)

            // Password persisted with bcrypt algorithm
            let password = try await UserPassword.query(on: app.db)
                .filter(\.$user.$id == user!.id!)
                .first()
            #expect(password != nil)
            #expect(password?.algorithm == "bcrypt")
            #expect(password?.hash.hasPrefix("$2") == true)
        }
    }

    @Test("register normalizes email to lowercase")
    @MainActor
    func registerNormalizesEmail() async throws {
        try await TestApp.withFresh { app in
            let dto = RegisterRequest(
                email: "Asiel@EXAMPLE.com",
                password: "correcthorsebatterystaple"
            )
            _ = try await app.security.auth.register(dto, on: app.db)

            let user = try await User.query(on: app.db).first()
            #expect(user?.email == "asiel@example.com")
        }
    }

    @Test("register fails on duplicate email")
    @MainActor
    func registerFailsOnDuplicate() async throws {
        try await TestApp.withFresh { app in
            let dto = RegisterRequest(
                email: "dup@example.com",
                password: "correcthorsebatterystaple"
            )
            _ = try await app.security.auth.register(dto, on: app.db)

            await #expect(throws: SecurityError.userAlreadyExists) {
                _ = try await app.security.auth.register(dto, on: app.db)
            }
        }
    }

    @Test("register rejects weak password")
    @MainActor
    func registerRejectsWeakPassword() async throws {
        try await TestApp.withFresh { app in
            let dto = RegisterRequest(
                email: "weak@example.com",
                password: "short"  // below the 12-char default
            )

            await #expect(throws: SecurityError.self) {
                _ = try await app.security.auth.register(dto, on: app.db)
            }
        }
    }

    @Test("register rejects mismatched password confirmation")
    @MainActor
    func registerRejectsMismatchedConfirmation() async throws {
        try await TestApp.withFresh { app in
            let dto = RegisterRequest(
                email: "mismatch@example.com",
                password: "correcthorsebatterystaple",
                passwordConfirmation: "differentvalue123"
            )

            await #expect(throws: SecurityError.self) {
                _ = try await app.security.auth.register(dto, on: app.db)
            }
        }
    }

    // MARK: - Login

    @Test("login succeeds with correct credentials")
    @MainActor
    func loginSucceeds() async throws {
        try await TestApp.withFresh { app in
            let email = "login@example.com"
            let password = "correcthorsebatterystaple"

            _ = try await app.security.auth.register(
                RegisterRequest(email: email, password: password),
                on: app.db
            )

            let response = try await app.security.auth.login(
                LoginRequest(email: email, password: password),
                on: app.db
            )

            #expect(!response.accessToken.isEmpty)
            #expect(!response.refreshToken.isEmpty)
        }
    }

    @Test("login fails with wrong password")
    @MainActor
    func loginFailsWrongPassword() async throws {
        try await TestApp.withFresh { app in
            _ = try await app.security.auth.register(
                RegisterRequest(email: "wrong@example.com", password: "correcthorsebatterystaple"),
                on: app.db
            )

            await #expect(throws: SecurityError.invalidCredentials) {
                _ = try await app.security.auth.login(
                    LoginRequest(email: "wrong@example.com", password: "wrong_password_xxxx"),
                    on: app.db
                )
            }
        }
    }

    @Test("login fails with unknown email (same error as wrong password)")
    @MainActor
    func loginFailsUnknownEmail() async throws {
        try await TestApp.withFresh { app in
            await #expect(throws: SecurityError.invalidCredentials) {
                _ = try await app.security.auth.login(
                    LoginRequest(email: "nope@example.com", password: "anyvalue1234"),
                    on: app.db
                )
            }
        }
    }

    @Test("login fails on deactivated user")
    @MainActor
    func loginFailsInactiveUser() async throws {
        try await TestApp.withFresh { app in
            let response = try await app.security.auth.register(
                RegisterRequest(email: "inactive@example.com", password: "correcthorsebatterystaple"),
                on: app.db
            )

            let user = try await app.security.users.require(id: response.userID!, on: app.db)
            try await app.security.users.deactivate(user, on: app.db)

            await #expect(throws: SecurityError.invalidCredentials) {
                _ = try await app.security.auth.login(
                    LoginRequest(email: "inactive@example.com", password: "correcthorsebatterystaple"),
                    on: app.db
                )
            }
        }
    }

    @Test("login emits loginSucceeded event")
    @MainActor
    func loginEmitsEvent() async throws {
        try await TestApp.withFresh { app in
            let captured = EventCapture()
            await app.security.events.onAny { event in
                await captured.append(event)
            }

            _ = try await app.security.auth.register(
                RegisterRequest(email: "event@example.com", password: "correcthorsebatterystaple"),
                on: app.db
            )
            _ = try await app.security.auth.login(
                LoginRequest(email: "event@example.com", password: "correcthorsebatterystaple"),
                on: app.db
            )

            let landed = await captured.waitForEvent(named: "auth.login.succeeded")
            #expect(landed == true)
        }
    }

    // MARK: - Refresh

    @Test("refresh issues a new token pair and revokes the old refresh token")
    @MainActor
    func refreshRotatesTokens() async throws {
        try await TestApp.withFresh { app in
            let initial = try await app.security.auth.register(
                RegisterRequest(email: "refresh@example.com", password: "correcthorsebatterystaple"),
                on: app.db
            )

            let refreshed = try await app.security.auth.refresh(
                RefreshRequest(refreshToken: initial.refreshToken),
                on: app.db
            )

            // New tokens differ from old.
            #expect(refreshed.accessToken != initial.accessToken)
            #expect(refreshed.refreshToken != initial.refreshToken)

            // Old refresh token no longer works.
            await #expect(throws: SecurityError.self) {
                _ = try await app.security.auth.refresh(
                    RefreshRequest(refreshToken: initial.refreshToken),
                    on: app.db
                )
            }
        }
    }

    @Test("refresh with access token instead of refresh fails")
    @MainActor
    func refreshRejectsAccessToken() async throws {
        try await TestApp.withFresh { app in
            let tokens = try await app.security.auth.register(
                RegisterRequest(email: "wrongkind@example.com", password: "correcthorsebatterystaple"),
                on: app.db
            )

            await #expect(throws: SecurityError.tokenInvalid) {
                _ = try await app.security.auth.refresh(
                    RefreshRequest(refreshToken: tokens.accessToken),  // wrong kind!
                    on: app.db
                )
            }
        }
    }

    @Test("refresh reuse detection revokes all tokens and emits event")
    @MainActor
    func refreshReuseDetection() async throws {
        try await TestApp.withFresh { app in
            let captured = EventCapture()
            await app.security.events.onAny { event in
                await captured.append(event)
            }

            let initial = try await app.security.auth.register(
                RegisterRequest(email: "reuse@example.com", password: "correcthorsebatterystaple"),
                on: app.db
            )

            // First refresh consumes the token (now revoked).
            _ = try await app.security.auth.refresh(
                RefreshRequest(refreshToken: initial.refreshToken),
                on: app.db
            )

            // Replaying the same refresh token is the reuse scenario.
            await #expect(throws: SecurityError.tokenReuseDetected) {
                _ = try await app.security.auth.refresh(
                    RefreshRequest(refreshToken: initial.refreshToken),
                    on: app.db
                )
            }

            let reuseEvent = await captured.waitForEvent(named: "token.reuse_detected")
            #expect(reuseEvent == true)
        }
    }

    // MARK: - Logout

    @Test("logout(user:) revokes all tokens for the user")
    @MainActor
    func logoutUserRevokesAll() async throws {
        try await TestApp.withFresh { app in
            let tokens = try await app.security.auth.register(
                RegisterRequest(email: "logout@example.com", password: "correcthorsebatterystaple"),
                on: app.db
            )

            let user = try await app.security.users.require(id: tokens.userID!, on: app.db)
            try await app.security.auth.logout(user, on: app.db)

            // Access token is now invalid.
            let lookup = try await app.security.tokens.find(plaintext: tokens.accessToken, on: app.db)
            #expect(lookup == nil)

            // Refresh too.
            await #expect(throws: SecurityError.self) {
                _ = try await app.security.auth.refresh(
                    RefreshRequest(refreshToken: tokens.refreshToken),
                    on: app.db
                )
            }
        }
    }

    // MARK: - Change password

    @Test("changePassword updates hash and revokes existing sessions")
    @MainActor
    func changePasswordRevokesSessions() async throws {
        try await TestApp.withFresh { app in
            let email = "change@example.com"
            let oldPassword = "correcthorsebatterystaple"
            let newPassword = "newpasswordvalue123"

            let initial = try await app.security.auth.register(
                RegisterRequest(email: email, password: oldPassword),
                on: app.db
            )

            let user = try await app.security.users.require(id: initial.userID!, on: app.db)
            try await app.security.auth.changePassword(
                ChangePasswordRequest(
                    currentPassword: oldPassword,
                    newPassword: newPassword
                ),
                for: user,
                on: app.db
            )

            // Old password no longer works.
            await #expect(throws: SecurityError.invalidCredentials) {
                _ = try await app.security.auth.login(
                    LoginRequest(email: email, password: oldPassword),
                    on: app.db
                )
            }

            // New password works.
            _ = try await app.security.auth.login(
                LoginRequest(email: email, password: newPassword),
                on: app.db
            )

            // Previously issued tokens are revoked.
            let lookup = try await app.security.tokens.find(plaintext: initial.accessToken, on: app.db)
            #expect(lookup == nil)
        }
    }

    @Test("changePassword rejects wrong current password")
    @MainActor
    func changePasswordRequiresCurrent() async throws {
        try await TestApp.withFresh { app in
            let tokens = try await app.security.auth.register(
                RegisterRequest(email: "currentpw@example.com", password: "correcthorsebatterystaple"),
                on: app.db
            )

            let user = try await app.security.users.require(id: tokens.userID!, on: app.db)

            await #expect(throws: SecurityError.invalidCredentials) {
                try await app.security.auth.changePassword(
                    ChangePasswordRequest(
                        currentPassword: "wrong_old_password",
                        newPassword: "anotherstrongvalue1"
                    ),
                    for: user,
                    on: app.db
                )
            }
        }
    }
}
