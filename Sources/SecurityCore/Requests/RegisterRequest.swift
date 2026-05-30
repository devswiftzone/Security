//
//  RegisterDTO.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor

/// Request body for the registration endpoint.
public struct RegisterRequest: Content, Sendable {

    /// User's email. Must be unique across the system.
    public let email: String

    /// Plaintext password. Must meet `SecurityConfiguration.passwordPolicy`.
    public let password: String

    /// Optional confirmation field — if provided, must match `password`.
    /// When omitted, no confirmation is required (useful for API clients
    /// that do not collect confirmation).
    public let passwordConfirmation: String?

    public init(
        email: String,
        password: String,
        passwordConfirmation: String? = nil
    ) {
        self.email = email
        self.password = password
        self.passwordConfirmation = passwordConfirmation
    }
}

// MARK: - Validatable

extension RegisterRequest: Validatable {

    public static func validations(_ validations: inout Validations) {
        validations.add("email", as: String.self, is: .email)
        validations.add("password", as: String.self, is: .count(8...))
    }
}
