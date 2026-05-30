//
//  LoginDTO.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor

/// Request body for the login endpoint.
public struct LoginRequest: Content, Sendable {

    /// User's login email.
    public let email: String

    /// Plaintext password.
    public let password: String

    public init(email: String, password: String) {
        self.email = email
        self.password = password
    }
}

// MARK: - Validatable

extension LoginRequest: Validatable {

    public static func validations(_ validations: inout Validations) {
        validations.add("email", as: String.self, is: .email)
        validations.add("password", as: String.self, is: !.empty)
    }
}
