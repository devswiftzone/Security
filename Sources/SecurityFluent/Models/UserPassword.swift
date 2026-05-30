//
//  UserPassword.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import Foundation
import SecurityCore

/// Stores the hashed password for a user, separately from the User row.
///
/// Why a separate table? Three reasons:
/// 1. Users can exist without a password (OAuth, magic links, SSO).
/// 2. Password rotation can be audited by keeping history (future feature).
/// 3. The hash never accidentally leaks via `User: Content` serialization,
///    because the password is a relation, not a column on User.
public final class UserPassword: Model, @unchecked Sendable {

    public static let schema = SchemaPrefix.name("user_passwords")

    @ID(key: .id)
    public var id: UUID?

    @Parent(key: "user_id")
    public var user: User

    /// The opaque hashed password (e.g. bcrypt's `$2b$12$...` format).
    /// Includes algorithm parameters; the `algorithm` field below stores
    /// just the identifier for quick filtering and migration logic.
    @Field(key: "hash")
    public var hash: String

    /// Algorithm identifier (e.g. `"bcrypt"`, `"argon2id"`). Lets us
    /// detect outdated hashes and rehash them transparently on next login.
    @Field(key: "algorithm")
    public var algorithm: String

    @Timestamp(key: "created_at", on: .create)
    public var createdAt: Date?

    /// Timestamp of the most recent rotation (password change). Distinct
    /// from `updatedAt` because in the future we may keep historical
    /// password rows; this field on the active row records when it
    /// became active.
    @OptionalField(key: "rotated_at")
    public var rotatedAt: Date?

    // MARK: - Init

    public init() {}

    public init(
        id: UUID? = nil,
        userID: UUID,
        hash: String,
        algorithm: String
    ) {
        self.id = id
        self.$user.id = userID
        self.hash = hash
        self.algorithm = algorithm
    }
}
