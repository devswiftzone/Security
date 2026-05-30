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
///
/// Roles relate to users through `UserRole` (many-to-many) and to
/// permissions through `RolePermission` (many-to-many). Both pivots are
/// added in commit 16.
public final class Role: Model, Content, @unchecked Sendable {

    public static let schema = SchemaPrefix.name("roles")

    @ID(key: .id)
    public var id: UUID?

    /// Unique role name (e.g. `"admin"`, `"editor"`). Stored lowercase
    /// for case-insensitive uniqueness; normalize at the init level.
    @Field(key: "name")
    public var name: String

    /// Optional human-readable description for admin UIs.
    @OptionalField(key: "description")
    public var description: String?

    /// Whether this role is built-in (created by seeding) vs user-created
    /// at runtime. Built-in roles cannot be deleted via the standard API.
    @Field(key: "is_system")
    public var isSystem: Bool

    @Timestamp(key: "created_at", on: .create)
    public var createdAt: Date?

    @Timestamp(key: "updated_at", on: .update)
    public var updatedAt: Date?

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
