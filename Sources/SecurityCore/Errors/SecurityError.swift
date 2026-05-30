//
//  SecurityError.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor

/// Errors thrown by the Security package.
///
/// Conforms to `AbortError` so it integrates with Vapor's error middleware
/// and produces appropriate HTTP responses automatically.
public enum SecurityError: AbortError, Equatable {
    // MARK: - Authentication

    /// Email/password combination did not match any active user.
    case invalidCredentials

    /// No user exists with the given identifier.
    case userNotFound

    /// A user with this email already exists.
    case userAlreadyExists

    /// User account exists but is marked inactive.
    case userInactive

    // MARK: - Tokens

    /// Token has expired.
    case tokenExpired

    /// Token is malformed, unknown, or has been revoked.
    case tokenInvalid

    /// Refresh token reuse detected — possible compromise.
    case tokenReuseDetected

    // MARK: - Authorization

    /// Authenticated user is missing a required permission.
    case missingPermission(String)

    /// Authenticated user is missing a required role.
    case missingRole(String)

    /// Authorization policy evaluation denied access.
    case policyDenied(reason: String)

    // MARK: - Validation

    /// Password did not meet configured strength requirements.
    case passwordTooWeak(reason: String)

    /// Email is not in a valid format.
    case invalidEmail

    // MARK: - AbortError conformance

    public var status: HTTPStatus {
        switch self {
        case .invalidCredentials,
             .tokenExpired,
             .tokenInvalid,
             .tokenReuseDetected:
            return .unauthorized

        case .missingPermission,
             .missingRole,
             .policyDenied,
             .userInactive:
            return .forbidden

        case .userNotFound:
            return .notFound

        case .userAlreadyExists:
            return .conflict

        case .passwordTooWeak,
             .invalidEmail:
            return .badRequest
        }
    }

    public var reason: String {
        switch self {
        case .invalidCredentials:
            return "Invalid email or password."
        case .userNotFound:
            return "User not found."
        case .userAlreadyExists:
            return "A user with this email already exists."
        case .userInactive:
            return "This account is inactive."
        case .tokenExpired:
            return "The provided token has expired."
        case .tokenInvalid:
            return "The provided token is invalid."
        case .tokenReuseDetected:
            return "Token reuse detected. All sessions have been revoked."
        case .missingPermission(let name):
            return "Missing required permission: \(name)."
        case .missingRole(let name):
            return "Missing required role: \(name)."
        case .policyDenied(let reason):
            return "Access denied: \(reason)."
        case .passwordTooWeak(let reason):
            return "Password does not meet requirements: \(reason)."
        case .invalidEmail:
            return "Invalid email format."
        }
    }

    public var identifier: String {
        switch self {
        case .invalidCredentials:    return "security.invalid_credentials"
        case .userNotFound:          return "security.user_not_found"
        case .userAlreadyExists:     return "security.user_already_exists"
        case .userInactive:          return "security.user_inactive"
        case .tokenExpired:          return "security.token_expired"
        case .tokenInvalid:          return "security.token_invalid"
        case .tokenReuseDetected:    return "security.token_reuse_detected"
        case .missingPermission:     return "security.missing_permission"
        case .missingRole:           return "security.missing_role"
        case .policyDenied:          return "security.policy_denied"
        case .passwordTooWeak:       return "security.password_too_weak"
        case .invalidEmail:          return "security.invalid_email"
        }
    }
}
