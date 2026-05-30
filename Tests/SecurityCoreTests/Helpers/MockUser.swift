//
//  MockUser.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import Foundation
@testable import SecurityCore

/// In-memory `SecurityUser` used in policy and request tests.
///
/// Roles and permissions are stored on the instance instead of being
/// fetched from a database, so tests don't need a Fluent stack.
final class MockUser: SecurityUser, @unchecked Sendable {

    let id: UUID?
    let email: String
    let isActive: Bool

    private let _roleNames: Set<String>
    private let _permissions: Set<Permission>

    init(
        id: UUID = UUID(),
        email: String = "test@example.com",
        isActive: Bool = true,
        roles: Set<String> = [],
        permissions: Set<Permission> = []
    ) {
        self.id = id
        self.email = email
        self.isActive = isActive
        self._roleNames = roles
        self._permissions = permissions
    }

    func roleNames(on db: Database) async throws -> Set<String> {
        _roleNames
    }

    func permissions(on db: Database) async throws -> Set<Permission> {
        _permissions
    }
}
