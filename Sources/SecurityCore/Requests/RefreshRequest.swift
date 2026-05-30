//
//  RefreshRequest.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor

/// Request body for the refresh token endpoint.
///
/// The client sends the refresh token (NOT the access token) to obtain a
/// fresh access token plus a rotated refresh token.
public struct RefreshRequest: Content, Sendable {

    /// The refresh token previously issued to the client.
    public let refreshToken: String

    public init(refreshToken: String) {
        self.refreshToken = refreshToken
    }

    private enum CodingKeys: String, CodingKey {
        case refreshToken = "refresh_token"
    }
}
