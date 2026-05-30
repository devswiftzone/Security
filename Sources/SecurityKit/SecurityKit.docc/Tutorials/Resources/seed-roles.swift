import Vapor
import SecurityKit

func seedRolesAndPermissions(app: Application) async throws {
    // @snippet(create-roles)
    let adminRole = try await app.security.roles.create(name: "admin", on: app.db)
    let editorRole = try await app.security.roles.create(name: "editor", on: app.db)
    let viewerRole = try await app.security.roles.create(name: "viewer", on: app.db)
    // @endSnippet(create-roles)

    // @snippet(create-permissions)
    try await app.security.permissions.create(name: "posts.create", on: app.db)
    try await app.security.permissions.create(name: "posts.read", on: app.db)
    try await app.security.permissions.create(name: "posts.update", on: app.db)
    try await app.security.permissions.create(name: "posts.delete", on: app.db)
    try await app.security.permissions.create(name: "users.manage", on: app.db)
    // @endSnippet(create-permissions)

    // @snippet(attach-permissions)
    // Admin gets all permissions
    for perm in ["posts.create", "posts.read", "posts.update", "posts.delete", "users.manage"] {
        try await app.security.roles.attach(permission: perm, to: adminRole, on: app.db)
    }

    // Editor gets read, create, update
    for perm in ["posts.create", "posts.read", "posts.update"] {
        try await app.security.roles.attach(permission: perm, to: editorRole, on: app.db)
    }

    // Viewer gets read only
    try await app.security.roles.attach(permission: "posts.read", to: viewerRole, on: app.db)
    // @endSnippet(attach-permissions)

    // @snippet(assign-roles)
    let user = try await app.security.users.find(email: "admin@example.com", on: app.db)
    try await app.security.roles.assign(role: adminRole, to: user, on: app.db)
    // @endSnippet(assign-roles)
}
