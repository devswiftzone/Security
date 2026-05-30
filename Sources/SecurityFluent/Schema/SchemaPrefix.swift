//
//  SchemaPrefix.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Foundation

/// Centralizes the table-name prefix used by all Security models.
///
/// All tables created by `SecurityFluent` are prefixed with this string so
/// they don't collide with tables in the consumer project. Changing this
/// is technically possible but requires regenerating migrations.
public enum SchemaPrefix {
    public static let value = "security_"

    /// Builds a prefixed schema name from a bare suffix.
    ///
    ///     SchemaPrefix.name("users") // "security_users"
    public static func name(_ suffix: String) -> String {
        value + suffix
    }
}
