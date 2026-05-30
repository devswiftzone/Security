import Vapor
import SecurityKit

func routes(_ app: Application) throws {
    let authenticated = app.grouped(BearerTokenMiddleware())

    // @snippet(permission-middleware)
    let deletePosts = authenticated.grouped(RequirePermission("posts.delete"))
    deletePosts.delete("posts", ":id") { req async throws -> HTTPStatus in
        let postID = try req.parameters.require("id", UUID.self)
        // Delete post logic...
        return .noContent
    }
    // @endSnippet(permission-middleware)

    // @snippet(role-middleware)
    let adminRoutes = authenticated.grouped(RequireRole("admin"))
    adminRoutes.get("admin", "dashboard") { req async throws -> String in
        return "Welcome to the admin dashboard"
    }
    // @endSnippet(role-middleware)

    // @snippet(helper-checks)
    authenticated.get("posts", ":id") { req async throws -> Post in
        try await req.security.require(permission: "posts.read")

        let canEdit = try await req.security.has(permission: "posts.update")
        if canEdit {
            // Show edit button
        }

        // ...
        fatalError("implement")
    }
    // @endSnippet(helper-checks)
}
