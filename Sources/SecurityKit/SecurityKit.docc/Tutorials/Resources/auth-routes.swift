import Vapor
import SecurityKit

func routes(_ app: Application) throws {
    app.post("auth", "register") { req async throws -> TokenResponse in
        let dto = try req.content.decode(RegisterDTO.self)
        return try await req.application.security.auth.register(dto, on: req.db)
    }

    app.post("auth", "login") { req async throws -> TokenResponse in
        let dto = try req.content.decode(LoginDTO.self)
        return try await req.application.security.auth.login(dto, on: req.db)
    }

    let authenticated = app.grouped(BearerTokenMiddleware())

    authenticated.get("me") { req async throws -> User in
        try req.security.require(User.self)
    }

    authenticated.post("auth", "refresh") { req async throws -> TokenResponse in
        let dto = try req.content.decode(RefreshDTO.self)
        return try await req.application.security.auth.refresh(dto, on: req.db)
    }

    authenticated.post("auth", "logout") { req async throws -> HTTPStatus in
        guard let token = req.headers.bearerAuthorization?.token else {
            throw SecurityError.tokenInvalid
        }
        try await req.application.security.auth.logout(accessToken: token, on: req.db)
        return .noContent
    }
}
