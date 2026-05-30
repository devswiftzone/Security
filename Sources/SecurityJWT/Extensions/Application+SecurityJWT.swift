//
//  Application+SecurityJWT.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import JWT
import SecurityCore

public extension Application.Security {

    /// Registers a JWT HMAC signer for use with `JWTAuthService`.
    ///
    /// Convenience wrapper around `app.jwt.keys.add(hmac:digestAlgorithm:)`.
    /// For other algorithms (RSA, ECDSA), use the Vapor JWT API directly.
    ///
    /// Must be called from an async context (typically `configure(_:)`),
    /// because JWT key registration is actor-isolated in Vapor JWT.
    ///
    /// - Parameter secret: The shared secret. Must be at least 32 bytes
    ///   for HS256 to provide its full security margin.
    func useJWT(hmacSecret secret: String) async {
        precondition(
            secret.utf8.count >= 32,
            "HMAC secret must be at least 32 bytes for HS256 security"
        )
        await application.jwt.keys.add(
            hmac: HMACKey(stringLiteral: secret),
            digestAlgorithm: .sha256
        )
    }
}
