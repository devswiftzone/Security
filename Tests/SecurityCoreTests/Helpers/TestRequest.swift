//
//  TestRequest.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Fluent
import FluentSQLiteDriver
import Foundation
@testable import SecurityCore

/// Builds a minimal `Request` for testing policies and request extensions.
///
/// Creates an `Application` in `.testing` mode with an in-memory SQLite
/// database (needed because `req.db` traps if no database is configured,
/// even when the test code doesn't actually query it). Then attaches a
/// `Request` to the app and logs in the given user — both typed and
/// erased — so `req.auth.get(AnySecurityUser.self)` and
/// `req.auth.require(MockUser.self)` both resolve.
@MainActor
enum TestRequest {

    /// Returns (application, request). Caller is responsible for shutting
    /// down the application when finished.
    static func make(authenticated user: MockUser? = nil) async throws -> (Application, Request) {
        let app = try await Application.make(.testing)

        // Configure an in-memory SQLite as the default database so that
        // `req.db` (which policies access) doesn't trap. The mock user
        // doesn't actually issue queries, but materializing req.db
        // requires a configured default database.
        app.databases.use(.sqlite(.memory), as: .sqlite)

        let req = Request(application: app, on: app.eventLoopGroup.next())

        if let user {
            req.auth.login(user)
            req.auth.login(AnySecurityUser(user))
        }
        return (app, req)
    }
    
    /// Convenience: runs the given block with a fresh app+request, and
     /// shuts the app down properly afterwards (awaited, not detached).
     static func withRequest<T>(
         authenticated user: MockUser? = nil,
         _ block: (Application, Request) async throws -> T
     ) async throws -> T {
         let (app, req) = try await make(authenticated: user)
         do {
             let result = try await block(app, req)
             try await app.asyncShutdown()
             return result
         } catch {
             try? await app.asyncShutdown()
             throw error
         }
     }
}
