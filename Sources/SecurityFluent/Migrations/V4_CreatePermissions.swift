//
//  V4_CreatePermissions.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Fluent
import SecurityCore

struct V4_CreatePermissions: AsyncMigration {

    var name: String { "Security_V4_CreatePermissions" }

    func prepare(on database: Database) async throws {
        try await database.schema(SchemaPrefix.name("permissions"))
            .id()
            .field("name",        .string, .required)
            .field("description", .string)
            .field("is_system",   .bool, .required)
            .field("created_at",  .datetime)
            .unique(on: "name")
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema(SchemaPrefix.name("permissions")).delete()
    }
}
