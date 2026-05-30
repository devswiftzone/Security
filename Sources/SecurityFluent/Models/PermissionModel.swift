//
//  PermissionModel.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import Foundation
import SecurityCore

/// Fluent model for the permission catalog.
///
/// Note the naming: `SecurityCore.Permission` is a `Hashable`/`Codable`
/// value type used throughout policies and API contracts. This class —
/// `PermissionModel` — is the persisted row in the catalog table. The
/// distinction lets the value type stay lightweight while the model
/// carries DB-specific concerns (id, timestamps, description).
///
/// Convert between them with `PermissionModel.toValue()` and
/// `PermissionModel.init(value:description:)`.
public final class PermissionModel: Model, Content, @unchecked Sendable {

    public static let schema = SchemaPrefix.name("permissions")

    @ID(key: .id)
    public var id: UUID?

    /// The permission identifier (e.g. `"users.read"`). Globally unique.
    @Field(key: "name")
    public var name: String

    /// Optional description shown in admin UIs.
    @OptionalField(key: "description")
    public var description: String?

    /// System permissions are seeded by the application and cannot be
    /// removed via the standard API.
    @Field(key: "is_system")
    public var isSystem: Bool

    @Timestamp(key: "created_at", on: .create)
    public var createdAt: Date?

    // MARK: - Init

    public init() {}

    public init(
        id: UUID? = nil,
        name: String,
        description: String? = nil,
        isSystem: Bool = false
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.isSystem = isSystem
    }

    /// Convenience: build from a `SecurityCore.Permission` value.
    public convenience init(
        value: Permission,
        description: String? = nil,
        isSystem: Bool = false
    ) {
        self.init(
            name: value.name,
            description: description,
            isSystem: isSystem
        )
    }

    /// Returns the corresponding value type.
    public func toValue() -> Permission {
        Permission(name)
    }
}
