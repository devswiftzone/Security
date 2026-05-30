//
//  UserRole.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import Foundation

/// Pivot row linking a User to a Role.
///
/// Composite uniqueness on (user_id, role_id) is enforced at the
/// migration level so the same role isn't attached twice to the same user.
/// Both sides cascade-delete: removing a user or a role removes the
/// corresponding pivot rows.
public final class UserRole: Model, @unchecked Sendable {

    public static let schema = SchemaPrefix.name("user_roles")

    @ID(key: .id)
    public var id: UUID?

    @Parent(key: "user_id")
    public var user: User

    @Parent(key: "role_id")
    public var role: Role

    /// Audit field: when this assignment was created. Useful for "user X
    /// has been an admin since Y" displays in admin UIs.
    @Timestamp(key: "created_at", on: .create)
    public var createdAt: Date?

    // MARK: - Init

    public init() {}

    public init(userID: UUID, roleID: UUID) {
        self.$user.id = userID
        self.$role.id = roleID
    }
}
