# Role-Based Access Control (RBAC)

SecurityKit provides a complete RBAC system with roles, permissions, and composable authorization policies.

## Core Concepts

- **Users** — Authenticated entities
- **Roles** — Named collections of permissions (e.g., "admin", "editor")
- **Permissions** — Fine-grained access rights (e.g., "posts.create", "users.delete")
- **Policies** — Composable authorization rules

## Creating Roles and Permissions

```swift
// Create a role
let adminRole = try await app.security.roles.create(name: "admin", on: app.db)

// Create permissions
try await app.security.permissions.create(name: "posts.create", on: app.db)
try await app.security.permissions.create(name: "posts.delete", on: app.db)

// Assign permissions to role
try await app.security.roles.attach(permission: "posts.delete", to: adminRole, on: app.db)
```

## Assigning Roles to Users

```swift
let user = try await app.security.users.find(email: "user@example.com", on: app.db)
let role = try await app.security.roles.find(name: "admin", on: app.db)
try await app.security.roles.assign(role: role, to: user, on: app.db)
```

## Checking Permissions

### Via Middleware

```swift
let adminGroup = app.grouped(
    BearerTokenMiddleware(),
    PermissionMiddleware("users.delete")
)
adminGroup.delete("users", ":id") { req async throws -> HTTPStatus in
    // Only users with "users.delete" permission can access
    return .noContent
}
```

### Via Request Helper

```swift
app.get("posts", ":id") { req async throws -> Post in
    try await req.security.require(permission: "posts.read")
    // ...
}

app.get("admin") { req async throws -> String in
    try await req.security.require(role: "admin")
    return "Welcome, admin!"
}
```

### Check without throwing

```swift
let canDelete = await req.security.can("posts.delete")
if canDelete { ... }
```

## Custom Authorization Policies

Create reusable policies by implementing ``SecurityCore/AuthorizationPolicy``:

```swift
struct CanEditPost: AuthorizationPolicy {
    let postID: UUID

    func evaluate(_ req: Request) async throws -> Bool {
        let user = try req.auth.require(User.self)
        let post = try await Post.find(postID, on: req.db)
        return post?.authorID == user.id
            || (try await user.permissions(on: req.db)).contains("posts.edit.any")
    }
}

// Usage
app.put("posts", ":id") { req async throws -> Post in
    let postID = try req.parameters.require("id", UUID.self)
    try await req.security.require(CanEditPost(postID: postID))
    // ...
}
```

## Composing Policies

```swift
let policy = RequireRole("admin") || RequirePermission("posts.delete")
try await req.security.require(policy)
```

The ``SecurityCore/PolicyOperators`` provides `&&` and `||` for combining policies.

## Database Schema

All tables use the `security_` prefix:

- `security_users`
- `security_user_passwords`
- `security_roles`
- `security_permissions`
- `security_user_roles`
- `security_role_permissions`
- `security_tokens`

## Next Steps

- <doc:Tutorials> — Follow step-by-step tutorials
