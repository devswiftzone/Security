//
//  V6_CreateRolePermissions.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Fluent
import SecurityCore

struct V6_CreateRolePermissions: AsyncMigration {

    var name: String { "Security_V6_CreateRolePermissions" }

    func prepare(on database: Database) async throws {
        try await database.schema(SchemaPrefix.name("role_permissions"))
            .id()
            .field("role_id",       .uuid, .required, .references(SchemaPrefix.name("roles"), "id", onDelete: .cascade))
            .field("permission_id", .uuid, .required, .references(SchemaPrefix.name("permissions"), "id", onDelete: .cascade))
            .field("created_at",    .datetime)
            .unique(on: "role_id", "permission_id")
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema(SchemaPrefix.name("role_permissions")).delete()
    }
}
