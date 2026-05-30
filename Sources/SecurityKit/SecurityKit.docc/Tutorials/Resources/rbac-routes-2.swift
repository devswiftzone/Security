import Vapor
import SecurityKit

func routes(_ app: Application) throws {
    let authenticated = app.grouped(BearerTokenMiddleware())

    let deletePosts = authenticated.grouped(PermissionMiddleware("posts.delete"))
    deletePosts.delete("posts", ":id") { req async throws -> HTTPStatus in
        let postID = try req.parameters.require("id", UUID.self)
        // Delete post logic...
        return .noContent
    }

    let adminRoutes = authenticated.grouped(RoleMiddleware("admin"))
    adminRoutes.get("admin", "dashboard") { req async throws -> String in
        return "Welcome to the admin dashboard"
    }
}
