import Vapor
import SecurityKit

func seedRolesAndPermissions(app: Application) async throws {
    let adminRole = try await app.security.roles.create(name: "admin", on: app.db)
    let editorRole = try await app.security.roles.create(name: "editor", on: app.db)
    let viewerRole = try await app.security.roles.create(name: "viewer", on: app.db)

    try await app.security.permissions.create(name: "posts.create", on: app.db)
    try await app.security.permissions.create(name: "posts.read", on: app.db)
    try await app.security.permissions.create(name: "posts.update", on: app.db)
    try await app.security.permissions.create(name: "posts.delete", on: app.db)
    try await app.security.permissions.create(name: "users.manage", on: app.db)

    for perm in ["posts.create", "posts.read", "posts.update", "posts.delete", "users.manage"] {
        try await app.security.roles.attach(permission: perm, to: adminRole, on: app.db)
    }
    for perm in ["posts.create", "posts.read", "posts.update"] {
        try await app.security.roles.attach(permission: perm, to: editorRole, on: app.db)
    }
    try await app.security.roles.attach(permission: "posts.read", to: viewerRole, on: app.db)
}
