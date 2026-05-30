import Vapor
import SecurityKit

// @snippet(policy-definition)
struct CanEditPost: AuthorizationPolicy {
    let postID: UUID

    func evaluate(_ req: Request) async throws -> Bool {
        let user = try req.auth.require(User.self)
        let post = try await Post.find(postID, on: req.db)

        // Allow if user owns the post OR has the global edit permission
        return post?.authorID == user.id
            || (try await user.permissions(on: req.db)).contains("posts.edit.any")
    }
}
// @endSnippet(policy-definition)

// @snippet(policy-usage)
app.put("posts", ":id") { req async throws -> Post in
    let postID = try req.parameters.require("id", UUID.self)
    try await req.security.require(CanEditPost(postID: postID))

    let updatedPost = try req.content.decode(Post.self)
    // Save logic...
    return updatedPost
}
// @endSnippet(policy-usage)
