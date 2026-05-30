//
//  UserServiceProtocol.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import Foundation

/// Manages user lifecycle: creation, lookup, activation, deletion.
///
/// Does NOT handle authentication or password verification — that
/// belongs to `AuthServiceProtocol`. This service is concerned only with
/// the user record itself.
public protocol UserServiceProtocol: Sendable {

    /// The concrete user type managed by this service.
    associatedtype User: SecurityUser

    /// Creates a new user record.
    ///
    /// - Parameters:
    ///   - email: Login email. Must be unique.
    ///   - isActive: Initial active flag (default `true`).
    ///   - db: Database context.
    /// - Returns: The newly created user.
    /// - Throws: `SecurityError.userAlreadyExists`, `SecurityError.invalidEmail`.
    func create(email: String, isActive: Bool, on db: Database) async throws -> User

    /// Finds a user by their primary identifier.
    func find(id: UUID, on db: Database) async throws -> User?

    /// Finds a user by their login email.
    func find(email: String, on db: Database) async throws -> User?

    /// Returns a user by ID, or throws `userNotFound` if absent.
    func require(id: UUID, on db: Database) async throws -> User

    /// Returns a user by email, or throws `userNotFound` if absent.
    func require(email: String, on db: Database) async throws -> User

    /// Marks the user as active.
    func activate(_ user: User, on db: Database) async throws

    /// Marks the user as inactive. Inactive users cannot authenticate but
    /// their data is preserved.
    func deactivate(_ user: User, on db: Database) async throws

    /// Permanently deletes a user. Cascades to associated passwords,
    /// tokens, and pivot rows. Use `deactivate` for soft-disable.
    func delete(_ user: User, on db: Database) async throws

    /// Lists users with simple pagination.
    func list(limit: Int, offset: Int, on db: Database) async throws -> [User]
}
