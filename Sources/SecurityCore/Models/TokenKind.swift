//
//  TokenKind.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Foundation

/// Classification of tokens emitted by the Security package.
///
/// Different kinds have different lifetimes, scopes, and rotation
/// policies. The kind is persisted on each token so the service layer
/// can apply different rules per kind (e.g. only refresh tokens are
/// rotated on use, only access tokens have a short TTL).
public enum TokenKind: String, Codable, Sendable, CaseIterable {

    /// Short-lived token used to access protected resources. Typically
    /// expires in minutes to a few hours. Cannot be used to obtain
    /// other tokens.
    case access

    /// Long-lived token used exclusively to obtain new access tokens.
    /// Rotated on every use (the consumed refresh token is revoked and
    /// a new one is issued). Reuse of a consumed refresh token signals
    /// compromise.
    case refresh

    /// Programmatic, long-lived token for machine-to-machine access or
    /// scripts. Not rotated automatically. Should be scoped via permissions
    /// rather than relying on expiry.
    case api

    /// One-time token for password reset or email verification flows.
    /// Single-use and short-lived.
    case oneTime
}

// MARK: - Default lifetimes

public extension TokenKind {

    /// Default lifetime for this kind of token. Used by `SecurityConfiguration`
    /// when no explicit override is provided.
    var defaultLifetime: TimeInterval {
        switch self {
        case .access:  return 60 * 60          // 1 hour
        case .refresh: return 60 * 60 * 24 * 30 // 30 days
        case .api:     return 60 * 60 * 24 * 365 // 1 year (review periodically)
        case .oneTime: return 60 * 15          // 15 minutes
        }
    }

    /// Whether tokens of this kind should be rotated on each successful use.
    var rotatesOnUse: Bool {
        switch self {
        case .refresh, .oneTime: return true
        case .access, .api:      return false
        }
    }
}
