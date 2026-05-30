//
//  Token.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import Foundation
import SecurityCore

/// Persisted token record.
///
/// Stores a SHA-256 hash of the plaintext token value in `value`. The
/// plaintext itself is only ever returned to the client at issuance time
/// (by `TokenService.issue`) and never stored. To validate a candidate
/// token from a request, the service hashes it and looks up by hash —
/// this is O(1) on an indexed column and prevents stolen DB dumps from
/// yielding usable tokens.
///
/// One model serves all `TokenKind`s (access, refresh, api, oneTime).
/// Differentiation is via the `kind` column. Different kinds have
/// different lifetimes, rotation rules, and revocation semantics — those
/// rules live in `TokenService`, not in the model.
public final class Token: Model, @unchecked Sendable {

    public static let schema = SchemaPrefix.name("tokens")

    @ID(key: .id)
    public var id: UUID?

    /// The owning user.
    @Parent(key: "user_id")
    public var user: User

    /// SHA-256 hex hash of the plaintext token value.
    @Field(key: "value")
    public var value: String

    /// Token classification. Stored as the raw string of `TokenKind`.
    @Field(key: "kind")
    public var kind: String

    /// When the token expires. Nullable for tokens that never expire
    /// (rare; reserved for special API tokens with manual revocation).
    @OptionalField(key: "expires_at")
    public var expiresAt: Date?

    /// When the token was revoked. Nil for active tokens.
    @OptionalField(key: "revoked_at")
    public var revokedAt: Date?

    /// When the token was last used to authenticate a request. Updated
    /// best-effort, used for session listing in admin UIs.
    @OptionalField(key: "last_used_at")
    public var lastUsedAt: Date?

    /// Optional IP address captured at issuance. Best-effort audit trail.
    @OptionalField(key: "issued_ip")
    public var issuedIP: String?

    /// Optional user-agent captured at issuance. Best-effort audit trail.
    @OptionalField(key: "issued_user_agent")
    public var issuedUserAgent: String?

    @Timestamp(key: "created_at", on: .create)
    public var createdAt: Date?

    // MARK: - Init

    public init() {}

    public init(
        id: UUID? = nil,
        userID: UUID,
        hashedValue: String,
        kind: TokenKind,
        expiresAt: Date?,
        issuedIP: String? = nil,
        issuedUserAgent: String? = nil
    ) {
        self.id = id
        self.$user.id = userID
        self.value = hashedValue
        self.kind = kind.rawValue
        self.expiresAt = expiresAt
        self.issuedIP = issuedIP
        self.issuedUserAgent = issuedUserAgent
    }

    // MARK: - Computed helpers

    /// The token kind as the strongly typed enum, derived from the
    /// `kind` string column. Returns nil if the column holds an unknown
    /// value (shouldn't happen, but defensive).
    public var tokenKind: TokenKind? {
        TokenKind(rawValue: kind)
    }

    /// Whether the token is currently valid: not revoked and not expired.
    /// Also satisfies the `ModelTokenAuthenticatable.isValid` requirement.
    public var isValid: Bool {
        if revokedAt != nil { return false }
        if let expiresAt, expiresAt <= Date() { return false }
        return true
    }
}

// MARK: - ModelTokenAuthenticatable

/// Conformance that lets Vapor's bearer auth middleware authenticate
/// requests using this model.
///
/// The default Vapor implementation performs `WHERE value = <bearer-token>`
/// against plaintext. Because we store SHA-256 hashes, the package's
/// `BearerTokenMiddleware` (commit 25) hashes the candidate first and
/// supersedes the default middleware. The conformance is still useful so
/// `Token` can be used as the token type by any code that expects
/// `ModelTokenAuthenticatable` (including Vapor's own auth helpers).
extension Token: ModelTokenAuthenticatable {
    public typealias User = SecurityFluent.User

    public static let valueKey: KeyPath<Token, Field<String>> = \Token.$value
    public static let userKey: KeyPath<Token, Parent<User>> = \Token.$user
}
