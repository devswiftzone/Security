//
//  Role.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import Foundation
import SecurityCore

/// Fluent model for a role in the RBAC system.
///
/// A role is a named bundle of permissions that can be assigned to users.
/// Examples: "admin", "editor", "viewer". Role names are globally unique.
public final class Role: Model, Content, @unchecked Sendable {

    public static let schema = SchemaPrefix.name("roles")

    @ID(key: .id)
    public var id: UUID?

    @Field(key: "name")
    public var name: String

    @OptionalField(key: "description")
    public var description: String?

    @Field(key: "is_system")
    public var isSystem: Bool

    @Timestamp(key: "created_at", on: .create)
    public var createdAt: Date?

    @Timestamp(key: "updated_at", on: .update)
    public var updatedAt: Date?

    // MARK: - Relations

    /// Users assigned to this role, through the `UserRole` pivot.
    @Siblings(through: UserRole.self, from: \.$role, to: \.$user)
    public var users: [User]

    /// Permissions granted to this role, through `RolePermission`.
    @Siblings(through: RolePermission.self, from: \.$role, to: \.$permission)
    public var permissions: [PermissionModel]

    // MARK: - Init

    public init() {}

    public init(
        id: UUID? = nil,
        name: String,
        description: String? = nil,
        isSystem: Bool = false
    ) {
        self.id = id
        self.name = name.lowercased()
        self.description = description
        self.isSystem = isSystem
    }
}
