import Vapor
import SecurityKit

func seedRolesAndPermissions(app: Application) async throws {
    let adminRole = try await app.security.roles.create(name: "admin", on: app.db)
    let editorRole = try await app.security.roles.create(name: "editor", on: app.db)
    let viewerRole = try await app.security.roles.create(name: "viewer", on: app.db)
}
