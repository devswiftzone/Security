//
//  FluentUserService.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import Foundation
import SecurityCore

/// Fluent-backed implementation of `UserServiceProtocol`.
///
/// All write operations publish corresponding `SecurityEvent`s on the
/// `Application.security.events` bus. Subscribers can observe user
/// lifecycle without coupling to this service.
public struct FluentUserService: UserServiceProtocol, Sendable {

    public typealias User = SecurityFluent.User

    let application: Application

    public init(application: Application) {
        self.application = application
    }

    // MARK: - Create

    public func create(
        email: String,
        isActive: Bool,
        on db: Database
    ) async throws -> User {
        let normalized = email.lowercased()

        // Pre-check for an existing user. The unique index still protects
        // us against races, but checking first lets us throw a clean
        // userAlreadyExists instead of a raw DB constraint violation.
        let existing = try await User.query(on: db)
            .filter(\.$email == normalized)
            .first()
        guard existing == nil else {
            throw SecurityError.userAlreadyExists
        }

        let user = User(email: normalized, isActive: isActive)
        try await user.save(on: db)

        publishCreated(user)
        return user
    }

    // MARK: - Find

    public func find(id: UUID, on db: Database) async throws -> User? {
        try await User.find(id, on: db)
    }

    public func find(email: String, on db: Database) async throws -> User? {
        try await User.query(on: db)
            .filter(\.$email == email.lowercased())
            .first()
    }

    public func require(id: UUID, on db: Database) async throws -> User {
        guard let user = try await find(id: id, on: db) else {
            throw SecurityError.userNotFound
        }
        return user
    }

    public func require(email: String, on db: Database) async throws -> User {
        guard let user = try await find(email: email, on: db) else {
            throw SecurityError.userNotFound
        }
        return user
    }

    // MARK: - Activate / Deactivate

    public func activate(_ user: User, on db: Database) async throws {
        guard !user.isActive else { return }
        user.isActive = true
        try await user.save(on: db)
        publishActivated(user)
    }

    public func deactivate(_ user: User, on db: Database) async throws {
        guard user.isActive else { return }
        user.isActive = false
        try await user.save(on: db)
        publishDeactivated(user)
    }

    // MARK: - Delete

    public func delete(_ user: User, on db: Database) async throws {
        // Capture context before delete clears the model.
        let context = context(for: user)
        try await user.delete(on: db)
        publishDeleted(context)
    }

    // MARK: - List

    public func list(limit: Int, offset: Int, on db: Database) async throws -> [User] {
        let clampedLimit = max(1, min(limit, 200))  // hard ceiling to avoid abuse
        let clampedOffset = max(0, offset)

        return try await User.query(on: db)
            .sort(\.$createdAt, .descending)
            .range(clampedOffset ..< (clampedOffset + clampedLimit))
            .all()
    }

    // MARK: - Event helpers

    private func context(for user: User) -> SecurityEvent.UserContext? {
        guard let id = user.id else { return nil }
        return .init(id: id, email: user.email)
    }

    private func publishCreated(_ user: User) {
        guard let ctx = context(for: user) else { return }
        application.security.events.publishDetached(.userRegistered(ctx))
    }

    private func publishActivated(_ user: User) {
        guard let ctx = context(for: user) else { return }
        application.security.events.publishDetached(.userActivated(ctx))
    }

    private func publishDeactivated(_ user: User) {
        guard let ctx = context(for: user) else { return }
        application.security.events.publishDetached(.userDeactivated(ctx))
    }

    private func publishDeleted(_ context: SecurityEvent.UserContext?) {
        guard let ctx = context else { return }
        application.security.events.publishDetached(.userDeleted(ctx))
    }
}

// MARK: - Application accessor

public extension Application.Security {

    /// Entry point for user management operations.
    ///
    /// Usage:
    ///
    ///     let user = try await app.security.users.create(
    ///         email: "asiel@example.com",
    ///         isActive: true,
    ///         on: app.db
    ///     )
    var users: FluentUserService {
        FluentUserService(application: application)
    }
}
