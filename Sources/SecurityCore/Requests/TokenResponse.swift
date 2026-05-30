//
//  TokenResponse.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Foundation
import Vapor

/// Response body returned after a successful authentication or token refresh.
public struct TokenResponse: Content, Sendable {

    /// The access token. Send as `Authorization: Bearer <token>`.
    public let accessToken: String

    /// The refresh token. Used only to obtain new access tokens via the
    /// refresh endpoint. Store securely on the client.
    public let refreshToken: String

    /// The token type. Always `"Bearer"` for this package.
    public let tokenType: String

    /// Seconds until the access token expires, counted from issuance.
    public let expiresIn: Int

    /// User identifier for client-side use. Optional — clients can also
    /// derive it from the access token payload (when using JWT) or from
    /// a separate `/me` endpoint.
    public let userID: UUID?

    public init(
        accessToken: String,
        refreshToken: String,
        expiresIn: Int,
        userID: UUID? = nil,
        tokenType: String = "Bearer"
    ) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.tokenType = tokenType
        self.expiresIn = expiresIn
        self.userID = userID
    }

    // MARK: - Codable

    private enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case userID = "user_id"
    }
}
