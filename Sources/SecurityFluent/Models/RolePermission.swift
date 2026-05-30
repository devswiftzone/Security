//
//  RolePermission.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import Foundation

/// Pivot row linking a Role to a PermissionModel.
///
/// Composite uniqueness on (role_id, permission_id) is enforced at the
/// migration level. Cascade-deletes from both sides.
public final class RolePermission: Model, @unchecked Sendable {

    public static let schema = SchemaPrefix.name("role_permissions")

    @ID(key: .id)
    public var id: UUID?

    @Parent(key: "role_id")
    public var role: Role

    @Parent(key: "permission_id")
    public var permission: PermissionModel

    @Timestamp(key: "created_at", on: .create)
    public var createdAt: Date?

    // MARK: - Init

    public init() {}

    public init(roleID: UUID, permissionID: UUID) {
        self.$role.id = roleID
        self.$permission.id = permissionID
    }
}
