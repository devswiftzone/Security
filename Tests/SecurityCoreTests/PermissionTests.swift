//
//  PermissionTests.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Testing
import Foundation
@testable import SecurityCore

@Suite("Permission")
struct PermissionTests {

    // MARK: - Initialization

    @Test("Initializes from string")
    func initFromString() {
        let perm = Permission("users.read")
        #expect(perm.name == "users.read")
    }

    @Test("Initializes from string literal")
    func initFromStringLiteral() {
        let perm: Permission = "users.write"
        #expect(perm.name == "users.write")
    }

    @Test("Initializes from namespace and action")
    func initFromNamespaceAndAction() {
        let perm = Permission(namespace: "posts", action: "delete")
        #expect(perm.name == "posts.delete")
    }

    // MARK: - Namespace parsing

    @Test(
        "Extracts namespace from dotted name",
        arguments: [
            ("users.read", "users"),
            ("posts.delete.any", "posts"),
            ("admin", "admin"),
            ("", ""),
        ]
    )
    func namespaceParsing(input: String, expected: String) {
        #expect(Permission(input).namespace == expected)
    }

    @Test(
        "Extracts action from dotted name",
        arguments: [
            ("users.read", "read"),
            ("posts.delete.any", "delete.any"),
            ("admin", nil),
            ("", nil),
        ]
    )
    func actionParsing(input: String, expected: String?) {
        #expect(Permission(input).action == expected)
    }

    // MARK: - Equality and hashing

    @Test("Equal permissions compare equal")
    func equality() {
        #expect(Permission("users.read") == Permission("users.read"))
        #expect(Permission("users.read") != Permission("users.write"))
    }

    @Test("Permissions are case-sensitive")
    func caseSensitivity() {
        #expect(Permission("Users.Read") != Permission("users.read"))
    }

    @Test("Permissions can be stored in a Set")
    func hashableInSet() {
        let set: Set<Permission> = [
            "users.read",
            "users.write",
            "users.read", // duplicate
        ]
        #expect(set.count == 2)
        #expect(set.contains("users.read"))
        #expect(set.contains("users.write"))
        #expect(!set.contains("users.delete"))
    }

    // MARK: - Codable

    @Test("Encodes as a plain string, not an object")
    func encodingProducesString() throws {
        let perm = Permission("users.read")
        let data = try JSONEncoder().encode(perm)
        let json = String(data: data, encoding: .utf8)
        #expect(json == "\"users.read\"")
    }

    @Test("Decodes from a plain string")
    func decodingFromString() throws {
        let json = "\"posts.delete\"".data(using: .utf8)!
        let perm = try JSONDecoder().decode(Permission.self, from: json)
        #expect(perm == Permission("posts.delete"))
    }

    @Test("Round-trips through JSON")
    func roundTrip() throws {
        let original = Permission("api.tokens.revoke")
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(Permission.self, from: data)
        #expect(decoded == original)
    }

    @Test("Decodes inside an array of permissions")
    func decodingInArray() throws {
        let json = "[\"users.read\", \"users.write\", \"users.delete\"]"
            .data(using: .utf8)!
        let perms = try JSONDecoder().decode([Permission].self, from: json)
        #expect(perms.count == 3)
        #expect(perms[0] == "users.read")
        #expect(perms[2] == "users.delete")
    }

    // MARK: - CustomStringConvertible

    @Test("Description returns the raw name")
    func description() {
        let perm = Permission("users.read")
        #expect("\(perm)" == "users.read")
        #expect(perm.description == "users.read")
    }
}
