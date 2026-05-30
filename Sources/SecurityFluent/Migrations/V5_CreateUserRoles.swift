//
//  V5_CreateUserRoles.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Fluent
import SecurityCore

/// Creates the `security_user_roles` pivot table.
///
/// Composite unique index on (user_id, role_id) prevents the same role
/// from being attached twice to the same user. Both sides cascade-delete.
struct V5_CreateUserRoles: AsyncMigration {

    var name: String { "Security_V5_CreateUserRoles" }

    func prepare(on database: Database) async throws {
        try await database.schema(SchemaPrefix.name("user_roles"))
            .id()
            .field("user_id",    .uuid, .required, .references(SchemaPrefix.name("users"), "id", onDelete: .cascade))
            .field("role_id",    .uuid, .required, .references(SchemaPrefix.name("roles"), "id", onDelete: .cascade))
            .field("created_at", .datetime)
            .unique(on: "user_id", "role_id")
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema(SchemaPrefix.name("user_roles")).delete()
    }
}
