//
//  SecurityConfiguration.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Foundation

/// Top-level configuration for the Security package.
///
/// Defaults are chosen to be reasonable for a small-to-medium production
/// deployment. Adjust per-project via:
///
///     app.security.configuration = .init(
///         tokenLifetimes: .init(access: 15 * 60, refresh: 60 * 60 * 24 * 7),
///         passwordPolicy: .init(minLength: 14, requireMixedCase: true)
///     )
public struct SecurityConfiguration: Sendable {

    /// TTLs for each token kind.
    public var tokenLifetimes: TokenLifetimes

    /// Password complexity and length requirements.
    public var passwordPolicy: PasswordPolicy

    /// Refresh token rotation behavior.
    public var refreshRotation: RefreshRotation

    /// Login throttling (rate limiting) configuration.
    public var loginThrottle: LoginThrottle

    /// Bcrypt cost factor (work factor). Higher is slower but more secure.
    /// Range: 4–31. Default: 12 (~250ms on modern hardware).
    public var bcryptCost: Int

    public init(
        tokenLifetimes: TokenLifetimes = .init(),
        passwordPolicy: PasswordPolicy = .init(),
        refreshRotation: RefreshRotation = .init(),
        loginThrottle: LoginThrottle = .init(),
        bcryptCost: Int = 12
    ) {
        self.tokenLifetimes = tokenLifetimes
        self.passwordPolicy = passwordPolicy
        self.refreshRotation = refreshRotation
        self.loginThrottle = loginThrottle
        self.bcryptCost = bcryptCost
    }

    /// Sensible defaults. Equivalent to `init()`.
    public static let `default` = SecurityConfiguration()
}

// MARK: - Token lifetimes

public extension SecurityConfiguration {

    struct TokenLifetimes: Sendable {

        /// Access token TTL in seconds. Default: 1 hour.
        public var access: TimeInterval

        /// Refresh token TTL in seconds. Default: 30 days.
        public var refresh: TimeInterval

        /// API token TTL in seconds. Default: 1 year.
        public var api: TimeInterval

        /// One-time token TTL in seconds. Default: 15 minutes.
        public var oneTime: TimeInterval

        public init(
            access: TimeInterval = 60 * 60,
            refresh: TimeInterval = 60 * 60 * 24 * 30,
            api: TimeInterval = 60 * 60 * 24 * 365,
            oneTime: TimeInterval = 60 * 15
        ) {
            self.access = access
            self.refresh = refresh
            self.api = api
            self.oneTime = oneTime
        }

        /// Returns the configured lifetime for a given kind.
        public func lifetime(for kind: TokenKind) -> TimeInterval {
            switch kind {
            case .access:  return access
            case .refresh: return refresh
            case .api:     return api
            case .oneTime: return oneTime
            }
        }
    }
}

// MARK: - Password policy

public extension SecurityConfiguration {

    struct PasswordPolicy: Sendable {

        /// Minimum password length. Default: 12.
        ///
        /// NIST SP 800-63B recommends at least 8 for user-chosen passwords
        /// when combined with breach checks; 12 is a stronger default for
        /// systems without breach checking.
        public var minLength: Int

        /// Maximum password length. Default: 128. Long enough for passphrases
        /// while preventing DoS via expensive bcrypt of huge inputs.
        public var maxLength: Int

        /// Require at least one uppercase and one lowercase letter.
        public var requireMixedCase: Bool

        /// Require at least one digit.
        public var requireDigit: Bool

        /// Require at least one non-alphanumeric character.
        public var requireSymbol: Bool

        /// Reject passwords found in a known-breach list. The actual check
        /// must be implemented by the consumer (e.g. against HIBP); this
        /// flag signals intent.
        public var rejectBreached: Bool

        public init(
            minLength: Int = 12,
            maxLength: Int = 128,
            requireMixedCase: Bool = false,
            requireDigit: Bool = false,
            requireSymbol: Bool = false,
            rejectBreached: Bool = false
        ) {
            self.minLength = minLength
            self.maxLength = maxLength
            self.requireMixedCase = requireMixedCase
            self.requireDigit = requireDigit
            self.requireSymbol = requireSymbol
            self.rejectBreached = rejectBreached
        }

        /// Validates a password against this policy.
        ///
        /// - Returns: `nil` if the password is acceptable, or a
        ///   `SecurityError.passwordTooWeak` describing the first failure.
        public func validate(_ password: String) -> SecurityError? {
            if password.count < minLength {
                return .passwordTooWeak(
                    reason: "must be at least \(minLength) characters"
                )
            }
            if password.count > maxLength {
                return .passwordTooWeak(
                    reason: "must be at most \(maxLength) characters"
                )
            }
            if requireMixedCase {
                let hasUpper = password.contains { $0.isUppercase }
                let hasLower = password.contains { $0.isLowercase }
                if !hasUpper || !hasLower {
                    return .passwordTooWeak(
                        reason: "must contain both uppercase and lowercase letters"
                    )
                }
            }
            if requireDigit, !password.contains(where: { $0.isNumber }) {
                return .passwordTooWeak(reason: "must contain at least one digit")
            }
            if requireSymbol {
                let hasSymbol = password.contains { c in
                    !c.isLetter && !c.isNumber
                }
                if !hasSymbol {
                    return .passwordTooWeak(
                        reason: "must contain at least one symbol"
                    )
                }
            }
            return nil
        }
    }
}

// MARK: - Refresh rotation

public extension SecurityConfiguration {

    struct RefreshRotation: Sendable {

        /// Whether to rotate refresh tokens on use. When `true`, every call
        /// to `refresh` revokes the consumed refresh token and issues a new
        /// one. Default: `true`. Strongly recommended.
        public var enabled: Bool

        /// Whether to detect refresh token reuse and revoke all of the
        /// user's tokens when it occurs. Requires `enabled == true`.
        /// Default: `true`.
        public var detectReuse: Bool

        public init(
            enabled: Bool = true,
            detectReuse: Bool = true
        ) {
            self.enabled = enabled
            self.detectReuse = detectReuse
        }
    }
}

// MARK: - Login throttle

public extension SecurityConfiguration {

    struct LoginThrottle: Sendable {

        /// Whether login throttling is active. Default: `true`.
        public var enabled: Bool

        /// Maximum failed attempts before lockout. Default: 5.
        public var maxAttempts: Int

        /// Sliding window in seconds for counting attempts. Default: 15 min.
        public var window: TimeInterval

        /// Lockout duration in seconds after `maxAttempts` is reached.
        /// Default: 15 min.
        public var lockoutDuration: TimeInterval

        public init(
            enabled: Bool = true,
            maxAttempts: Int = 5,
            window: TimeInterval = 60 * 15,
            lockoutDuration: TimeInterval = 60 * 15
        ) {
            self.enabled = enabled
            self.maxAttempts = maxAttempts
            self.window = window
            self.lockoutDuration = lockoutDuration
        }
    }
}
