import Vapor
import SecurityKit

func routes(_ app: Application) throws {
    // @snippet(register)
    app.post("auth", "register") { req async throws -> TokenResponse in
        let dto = try req.content.decode(RegisterDTO.self)
        return try await req.application.security.auth.register(dto, on: req.db)
    }
    // @endSnippet(register)

    // @snippet(login)
    app.post("auth", "login") { req async throws -> TokenResponse in
        let dto = try req.content.decode(LoginDTO.self)
        return try await req.application.security.auth.login(dto, on: req.db)
    }
    // @endSnippet(login)

    // @snippet(protected)
    let authenticated = app.grouped(BearerTokenMiddleware())

    authenticated.get("me") { req async throws -> User in
        try req.security.require(User.self)
    }

    authenticated.post("auth", "refresh") { req async throws -> TokenResponse in
        let dto = try req.content.decode(RefreshDTO.self)
        return try await req.application.security.auth.refresh(dto, on: req.db)
    }

    authenticated.post("auth", "logout") { req async throws -> HTTPStatus in
        let dto = try req.content.decode(RefreshDTO.self)
        try await req.application.security.auth.logout(dto, on: req.db)
        return .noContent
    }
    // @endSnippet(protected)
}
