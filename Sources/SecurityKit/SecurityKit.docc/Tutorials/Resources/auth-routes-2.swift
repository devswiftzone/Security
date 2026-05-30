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
}
