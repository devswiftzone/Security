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

    @Field(key: "email")
    public var email: String

    @Field(key: "is_active")
    public var isActive: Bool

    @OptionalField(key: "display_name")
    public var displayName: String?

    @Timestamp(key: "created_at", on: .create)
    public var createdAt: Date?

    @Timestamp(key: "updated_at", on: .update)
    public var updatedAt: Date?

    @Timestamp(key: "deleted_at", on: .delete)
    public var deletedAt: Date?

    // MARK: - Relations

    @OptionalChild(for: \.$user)
    public var password: UserPassword?

    /// Roles assigned to this user through the `UserRole` pivot.
    @Siblings(through: UserRole.self, from: \.$user, to: \.$role)
    public var roles: [Role]

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
        let assigned = try await $roles.query(on: db).all()
        return Set(assigned.map(\.name))
    }

    public func permissions(on db: Database) async throws -> Set<Permission> {
        let userRoles = try await $roles.query(on: db).all()
        guard !userRoles.isEmpty else { return [] }
        let roleIDs = userRoles.compactMap(\.id)

        let pivots = try await RolePermission.query(on: db)
            .filter(\.$role.$id ~~ roleIDs)
            .with(\.$permission)
            .all()

        let names = pivots.map(\.permission.name)
        return Set(names.map { Permission($0) })
    }
}
