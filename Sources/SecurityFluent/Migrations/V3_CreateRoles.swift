//
//  V3_CreateRoles.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Fluent
import SecurityCore

struct V3_CreateRoles: AsyncMigration {

    var name: String { "Security_V3_CreateRoles" }

    func prepare(on database: Database) async throws {
        try await database.schema(SchemaPrefix.name("roles"))
            .id()
            .field("name",        .string, .required)
            .field("description", .string)
            .field("is_system",   .bool, .required)
            .field("created_at",  .datetime)
            .field("updated_at",  .datetime)
            .unique(on: "name")
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema(SchemaPrefix.name("roles")).delete()
    }
}
