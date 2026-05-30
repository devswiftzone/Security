//
//  V2_CreateUserPasswords.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Fluent
import SecurityCore

/// Creates the `security_user_passwords` table.
///
/// One-to-one with users (enforced by unique index on user_id).
/// Foreign key cascades on user delete: removing a user removes the
/// password record.
struct V2_CreateUserPasswords: AsyncMigration {

    var name: String { "Security_V2_CreateUserPasswords" }

    func prepare(on database: Database) async throws {
        try await database.schema(SchemaPrefix.name("user_passwords"))
            .id()
            .field("user_id",    .uuid, .required, .references(SchemaPrefix.name("users"), "id", onDelete: .cascade))
            .field("hash",       .string, .required)
            .field("algorithm",  .string, .required)
            .field("created_at", .datetime)
            .field("rotated_at", .datetime)
            .unique(on: "user_id")
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema(SchemaPrefix.name("user_passwords")).delete()
    }
}   
