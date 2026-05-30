//
//  V7_CreateTokens.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Fluent
import SecurityCore

/// Creates the `security_tokens` table.
///
/// Includes indices on (value), (user_id), and (user_id, kind) to support
/// the common lookup patterns:
///   - bearer-token authentication (lookup by value hash)
///   - listing user's tokens, revoke-all
///   - finding active tokens of a specific kind for a user
struct V7_CreateTokens: AsyncMigration {

    var name: String { "Security_V7_CreateTokens" }

    func prepare(on database: Database) async throws {
        try await database.schema(SchemaPrefix.name("tokens"))
            .id()
            .field("user_id",           .uuid, .required, .references(SchemaPrefix.name("users"), "id", onDelete: .cascade))
            .field("value",             .string, .required)
            .field("kind",              .string, .required)
            .field("expires_at",        .datetime)
            .field("revoked_at",        .datetime)
            .field("last_used_at",      .datetime)
            .field("issued_ip",         .string)
            .field("issued_user_agent", .string)
            .field("created_at",        .datetime)
            .unique(on: "value")
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema(SchemaPrefix.name("tokens")).delete()
    }
}
