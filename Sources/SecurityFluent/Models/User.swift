//
//  User.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import Foundation
import SecurityCore

/// Fluent model for users managed by the Security package.
///
/// This is the canonical user record. It carries only authentication-related
/// fields; consumer projects extend it by adding their own related models
/// (Profile, Settings, etc.) referencing `User.id`.
///
/// Conforms to `SecurityCore.SecurityUser` so it integrates with policies,
/// middleware, and `req.security.*`. Password is stored separately in
/// `UserPassword` to enable rotation and to allow passwordless accounts
/// (OAuth, magic links, etc.) without forcing a nullable password column.
public final class User: Model, Content, @unchecked Sendable {

    public static let schema = SchemaPrefix.name("users")

    @ID(key: .id)
    public var id: UUID?

    /// Login email. Stored lowercase for case-insensitive uniqueness.
    @Field(key: "email")
    public var email: String

    /// Whether the user is allowed to authenticate. Inactive users have
    /// their data preserved but cannot log in.
    @Field(key: "is_active")
    public var isActive: Bool

    /// Optional display name. The Security package itself does not use it
    /// but it's a near-universal field worth providing out of the box.
    @OptionalField(key: "display_name")
    public var displayName: String?

    @Timestamp(key: "created_at", on: .create)
    public var createdAt: Date?

    @Timestamp(key: "updated_at", on: .update)
    public var updatedAt: Date?

    /// Soft-delete timestamp. When set, the row is excluded from default
    /// queries. Use `.withDeleted()` to include soft-deleted rows.
    @Timestamp(key: "deleted_at", on: .delete)
    public var deletedAt: Date?

    // MARK: - Relations

    /// One-to-one with `UserPassword`. Optional because the user may
    /// authenticate via OAuth or other passwordless methods.
    @OptionalChild(for: \.$user)
    public var password: UserPassword?

    // MARK: - Init

    public init() {}

    public init(
        id: UUID? = nil,
        email: String,
        isActive: Bool = true,
        displayName: String? = nil
    ) {
        self.id = id
        self.email = email.lowercased()
        self.isActive = isActive
        self.displayName = displayName
    }
}

// MARK: - SecurityUser conformance

extension User: SecurityUser {

    public func roleNames(on db: Database) async throws -> Set<String> {
        // Concrete implementation lands when Role + UserRole pivot exist.
        // For now, return an empty set so the model
        // compiles and conforms to the protocol.
        []
    }

    public func permissions(on db: Database) async throws -> Set<Permission> {
        // Concrete implementation lands when Permission + RolePermission
        // pivot exist.
        []
    }
}
