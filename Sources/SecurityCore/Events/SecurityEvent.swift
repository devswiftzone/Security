//
//  SecurityEvent.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Foundation

/// An event emitted by the Security package.
///
/// Events are emitted at significant points in authentication and
/// authorization flows. Subscribers can react to them via
/// `app.security.events.on(_:handler:)` without coupling to the package
/// internals.
///
/// Events carry the minimum information needed for typical use cases
/// (auditing, metrics, alerting). Subscribers needing more context can
/// query the database using the IDs in the event payload.
public enum SecurityEvent: Sendable {

    // MARK: - User lifecycle

    /// A new user account was created.
    case userRegistered(UserContext)

    /// A user was activated.
    case userActivated(UserContext)

    /// A user was deactivated.
    case userDeactivated(UserContext)

    /// A user was permanently deleted.
    case userDeleted(UserContext)

    // MARK: - Authentication

    /// A user successfully logged in.
    case loginSucceeded(UserContext, ip: String?)

    /// A login attempt failed. `email` is included but the user may not
    /// exist — subscribers should treat it as user-supplied input.
    case loginFailed(email: String, ip: String?, reason: LoginFailureReason)

    /// All sessions for a user were terminated.
    case logoutAll(UserContext)

    // MARK: - Password

    /// A user changed their password.
    case passwordChanged(UserContext)

    /// A password reset was requested.
    case passwordResetRequested(UserContext)

    // MARK: - Tokens

    /// A new token was issued.
    case tokenIssued(UserContext, kind: TokenKind)

    /// A token was revoked.
    case tokenRevoked(UserContext, kind: TokenKind)

    /// Refresh token reuse was detected — possible compromise.
    case tokenReuseDetected(UserContext)

    // MARK: - Authorization

    /// A role was assigned to a user.
    case roleAssigned(UserContext, role: String)

    /// A role was removed from a user.
    case roleRevoked(UserContext, role: String)

    /// A permission was granted to a role.
    case permissionGranted(role: String, permission: Permission)

    /// A permission was revoked from a role.
    case permissionRevoked(role: String, permission: Permission)
}

// MARK: - Event payloads

public extension SecurityEvent {

    /// Lightweight user reference carried in events.
    ///
    /// Carries the minimum to identify the user; subscribers query the DB
    /// for full details if needed.
    struct UserContext: Sendable, Equatable {
        public let id: UUID
        public let email: String

        public init(id: UUID, email: String) {
            self.id = id
            self.email = email
        }
    }

    /// Reason a login attempt failed. Avoid exposing fine-grained reasons
    /// to clients (to prevent user enumeration), but they're useful in
    /// audit logs.
    enum LoginFailureReason: String, Sendable {
        case unknownEmail
        case wrongPassword
        case userInactive
        case throttled
    }
}

// MARK: - Event identity

public extension SecurityEvent {

    /// A stable, machine-friendly identifier for the event type.
    /// Useful for filtering subscriptions and structured logging.
    var name: String {
        switch self {
        case .userRegistered:        return "user.registered"
        case .userActivated:         return "user.activated"
        case .userDeactivated:       return "user.deactivated"
        case .userDeleted:           return "user.deleted"
        case .loginSucceeded:        return "auth.login.succeeded"
        case .loginFailed:           return "auth.login.failed"
        case .logoutAll:             return "auth.logout.all"
        case .passwordChanged:       return "password.changed"
        case .passwordResetRequested: return "password.reset.requested"
        case .tokenIssued:           return "token.issued"
        case .tokenRevoked:          return "token.revoked"
        case .tokenReuseDetected:    return "token.reuse_detected"
        case .roleAssigned:          return "role.assigned"
        case .roleRevoked:           return "role.revoked"
        case .permissionGranted:     return "permission.granted"
        case .permissionRevoked:     return "permission.revoked"
        }
    }
}
