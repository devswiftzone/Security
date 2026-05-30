//
//  V1_CreateUsers.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Fluent
import SecurityCore

/// Creates the `security_users` table.
///
/// Email has a unique index for case-insensitive lookup (we normalize to
/// lowercase at the model level, so a simple unique index is sufficient).
struct V1_CreateUsers: AsyncMigration {

    var name: String { "Security_V1_CreateUsers" }

    func prepare(on database: Database) async throws {
        try await database.schema(SchemaPrefix.name("users"))
            .id()
            .field("email",         .string, .required)
            .field("is_active",     .bool, .required)
            .field("display_name",  .string)
            .field("created_at",    .datetime)
            .field("updated_at",    .datetime)
            .field("deleted_at",    .datetime)
            .unique(on: "email")
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema(SchemaPrefix.name("users")).delete()
    }
}
