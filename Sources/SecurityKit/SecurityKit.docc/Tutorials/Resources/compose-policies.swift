import Vapor
import SecurityKit

func routes(_ app: Application) throws {
    let authenticated = app.grouped(BearerTokenMiddleware())

    // Combined policy: user must be admin OR have the delete permission
    let adminOrDeletePermission = RequireRole("admin") || RequirePermission("posts.delete")

    authenticated.delete("posts", ":id") { req async throws -> HTTPStatus in
        try await req.security.require(adminOrDeletePermission)
        // Delete post logic...
        return .noContent
    }

    // Complex policy: user must have BOTH permissions
    let canManagePosts = RequirePermission("posts.read") && RequirePermission("posts.update")
    authenticated.put("posts", ":id") { req async throws -> Post in
        try await req.security.require(canManagePosts)
        // Update post logic...
        fatalError("implement")
    }
}
