//
//  Permission.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Foundation

/// A named permission identifier used for RBAC checks.
///
/// Permissions use a dot-namespaced convention (e.g. `"users.read"`,
/// `"posts.delete"`) to make them readable, groupable, and easy to scope.
///
/// `Permission` is a lightweight value type — it wraps a `String` but
/// participates in `Hashable`/`Codable`/`Sendable` so it can be stored
/// in sets, sent over the wire, and passed across actor boundaries.
public struct Permission: Hashable, Sendable, Codable, ExpressibleByStringLiteral, CustomStringConvertible {

    /// The string identifier (e.g. `"users.read"`).
    public let name: String

    public init(_ name: String) {
        self.name = name
    }

    public init(stringLiteral value: String) {
        self.name = value
    }

    public var description: String { name }

    // MARK: - Codable

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.name = try container.decode(String.self)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(name)
    }

    // MARK: - Namespace helpers

    /// The namespace portion (everything before the first dot), or the full
    /// name if no dot is present.
    ///
    ///     Permission("users.read").namespace // "users"
    ///     Permission("admin").namespace      // "admin"
    public var namespace: String {
        guard let dot = name.firstIndex(of: ".") else { return name }
        return String(name[..<dot])
    }

    /// The action portion (everything after the first dot), or `nil` if no
    /// dot is present.
    ///
    ///     Permission("users.read").action // "read"
    ///     Permission("admin").action      // nil
    public var action: String? {
        guard let dot = name.firstIndex(of: ".") else { return nil }
        return String(name[name.index(after: dot)...])
    }
}

// MARK: - Convenience constructors

extension Permission {
    /// Builds a permission from namespace and action parts.
    ///
    ///     Permission(namespace: "users", action: "read")
    ///     // Permission("users.read")
    public init(namespace: String, action: String) {
        self.init("\(namespace).\(action)")
    }
}
