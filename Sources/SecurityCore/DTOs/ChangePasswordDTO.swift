//
//  ChangePasswordDTO.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor

/// Request body for password change.
///
/// Requires the current password to prevent abuse if a session token is
/// stolen but the attacker doesn't know the password. Always require this
/// even when the user is authenticated.
public struct ChangePasswordDTO: Content, Sendable {

    /// The user's current password.
    public let currentPassword: String

    /// The new password. Must meet `SecurityConfiguration.passwordPolicy`.
    public let newPassword: String

    /// Optional confirmation of the new password.
    public let newPasswordConfirmation: String?

    public init(
        currentPassword: String,
        newPassword: String,
        newPasswordConfirmation: String? = nil
    ) {
        self.currentPassword = currentPassword
        self.newPassword = newPassword
        self.newPasswordConfirmation = newPasswordConfirmation
    }

    private enum CodingKeys: String, CodingKey {
        case currentPassword = "current_password"
        case newPassword = "new_password"
        case newPasswordConfirmation = "new_password_confirmation"
    }
}

// MARK: - Validatable

extension ChangePasswordDTO: Validatable {

    public static func validations(_ validations: inout Validations) {
        validations.add("current_password", as: String.self, is: !.empty)
        validations.add("new_password", as: String.self, is: .count(8...))
    }
}
