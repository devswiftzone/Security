//
//  AuthServiceProtocol.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import Foundation

/// High-level authentication flows: register, login, refresh, logout,
/// password change.
///
/// Composes the lower-level services (`UserService`, `TokenService`) and
/// applies the configured `PasswordHasher` and `SecurityConfiguration`.
public protocol AuthServiceProtocol: Sendable {

    associatedtype User: SecurityUser

    /// Registers a new user with email and password. Returns tokens so
    /// that registration can log the user in immediately (common UX).
    ///
    /// - Throws: `userAlreadyExists`, `passwordTooWeak`, `invalidEmail`.
    func register(
        _ dto: RegisterRequest,
        on db: Database
    ) async throws -> TokenResponse

    /// Authenticates email + password. Returns an access/refresh token pair.
    ///
    /// - Throws: `invalidCredentials`, `userInactive`.
    func login(
        _ dto: LoginRequest,
        on db: Database
    ) async throws -> TokenResponse

    /// Exchanges a refresh token for a new access/refresh token pair.
    /// Rotates the refresh token (revokes the consumed one).
    ///
    /// - Throws: `tokenInvalid`, `tokenExpired`, `tokenReuseDetected`.
    func refresh(
        _ dto: RefreshRequest,
        on db: Database
    ) async throws -> TokenResponse

    /// Revokes all access and refresh tokens for the user. Effectively
    /// signs them out across all devices/sessions.
    func logout(
        _ user: User,
        on db: Database
    ) async throws

    /// Revokes only the access and refresh tokens identified by the given
    /// access token value. Signs out the current session only.
    func logout(
        accessToken: String,
        on db: Database
    ) async throws

    /// Changes the user's password. Requires the current password.
    /// On success, revokes all tokens to force re-authentication everywhere.
    ///
    /// - Throws: `invalidCredentials` if `currentPassword` is wrong,
    ///   `passwordTooWeak` if `newPassword` fails policy.
    func changePassword(
        _ dto: ChangePasswordRequest,
        for user: User,
        on db: Database
    ) async throws
}
