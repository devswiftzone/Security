//
//  PolicyTests.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Testing
import Vapor
import Foundation
@testable import SecurityCore

@Suite("Authorization Policies")
struct PolicyTests {

    // MARK: - RequirePermission

    @Suite("RequirePermission")
    struct RequirePermissionTests {

        @Test("Grants when user has the permission")
        @MainActor
        func grantsWhenUserHasIt() async throws {
            let user = MockUser(permissions: ["users.read", "users.write"])
            try await TestRequest.withRequest(authenticated: user) { _, req in
                let policy = RequirePermission("users.read")
                let granted = try await policy.evaluate(req)
                #expect(granted == true)
            }
        }

        @Test("Denies when user lacks the permission")
        @MainActor
        func deniesWhenUserLacksIt() async throws {
            let user = MockUser(permissions: ["users.read"])
            try await TestRequest.withRequest(authenticated: user) { _, req in
                let policy = RequirePermission("users.delete")
                let granted = try await policy.evaluate(req)
                #expect(granted == false)
            }
        }

        @Test("Denies when no user is authenticated")
        @MainActor
        func deniesWhenUnauthenticated() async throws {
            try await TestRequest.withRequest(authenticated: nil) { _, req in
                let policy = RequirePermission("users.read")
                let granted = try await policy.evaluate(req)
                #expect(granted == false)
            }
        }

        @Test("Accepts String and Permission inits identically")
        @MainActor
        func stringAndPermissionInits() async throws {
            let user = MockUser(permissions: ["users.read"])
            try await TestRequest.withRequest(authenticated: user) { _, req in
                let p1 = RequirePermission("users.read")
                let p2 = RequirePermission(Permission("users.read"))
                let r1 = try await p1.evaluate(req)
                let r2 = try await p2.evaluate(req)
                #expect(r1 == true)
                #expect(r2 == true)
            }
        }

        @Test("Name renders the permission for debugging")
        func name() {
            #expect(RequirePermission("users.delete").name == "RequirePermission(users.delete)")
        }
    }

    // MARK: - RequireRole

    @Suite("RequireRole")
    struct RequireRoleTests {

        @Test("Grants when user has the role")
        @MainActor
        func grants() async throws {
            let user = MockUser(roles: ["admin", "editor"])
            try await TestRequest.withRequest(authenticated: user) { _, req in
                let granted = try await RequireRole("admin").evaluate(req)
                #expect(granted == true)
            }
        }

        @Test("Denies when user lacks the role")
        @MainActor
        func denies() async throws {
            let user = MockUser(roles: ["viewer"])
            try await TestRequest.withRequest(authenticated: user) { _, req in
                let granted = try await RequireRole("admin").evaluate(req)
                #expect(granted == false)
            }
        }
    }

    // MARK: - RequireAnyRole

    @Suite("RequireAnyRole")
    struct RequireAnyRoleTests {

        @Test("Grants when user has at least one of the roles")
        @MainActor
        func grantsOnIntersection() async throws {
            let user = MockUser(roles: ["editor"])
            try await TestRequest.withRequest(authenticated: user) { _, req in
                let policy = RequireAnyRole("admin", "editor", "owner")
                let granted = try await policy.evaluate(req)
                #expect(granted == true)
            }
        }

        @Test("Denies when user has none of the roles")
        @MainActor
        func deniesOnEmptyIntersection() async throws {
            let user = MockUser(roles: ["viewer"])
            try await TestRequest.withRequest(authenticated: user) { _, req in
                let policy = RequireAnyRole("admin", "editor")
                let granted = try await policy.evaluate(req)
                #expect(granted == false)
            }
        }
    }

    // MARK: - RequireAllRoles

    @Suite("RequireAllRoles")
    struct RequireAllRolesTests {

        @Test("Grants when user has all required roles")
        @MainActor
        func grantsOnSubset() async throws {
            let user = MockUser(roles: ["admin", "editor", "auditor"])
            try await TestRequest.withRequest(authenticated: user) { _, req in
                let policy = RequireAllRoles("admin", "editor")
                let granted = try await policy.evaluate(req)
                #expect(granted == true)
            }
        }

        @Test("Denies when user is missing any required role")
        @MainActor
        func deniesWhenIncomplete() async throws {
            let user = MockUser(roles: ["admin"])
            try await TestRequest.withRequest(authenticated: user) { _, req in
                let policy = RequireAllRoles("admin", "editor")
                let granted = try await policy.evaluate(req)
                #expect(granted == false)
            }
        }
    }

    // MARK: - Operators

    @Suite("Composition operators")
    struct OperatorTests {

        @Test("AND grants when both grant")
        @MainActor
        func andBothTrue() async throws {
            let user = MockUser(roles: ["admin"], permissions: ["users.read"])
            try await TestRequest.withRequest(authenticated: user) { _, req in
                let policy = RequireRole("admin") && RequirePermission("users.read")
                let granted = try await policy.evaluate(req)
                #expect(granted == true)
            }
        }

        @Test("AND denies when either denies")
        @MainActor
        func andEitherFalse() async throws {
            let user = MockUser(roles: ["admin"])
            try await TestRequest.withRequest(authenticated: user) { _, req in
                let p1 = RequireRole("admin") && RequirePermission("users.delete")
                let p2 = RequireRole("viewer") && RequirePermission("users.read")
                let r1 = try await p1.evaluate(req)
                let r2 = try await p2.evaluate(req)
                #expect(r1 == false)
                #expect(r2 == false)
            }
        }

        @Test("OR grants when either grants")
        @MainActor
        func orEitherTrue() async throws {
            let user = MockUser(permissions: ["users.read"])
            try await TestRequest.withRequest(authenticated: user) { _, req in
                let policy = RequireRole("admin") || RequirePermission("users.read")
                let granted = try await policy.evaluate(req)
                #expect(granted == true)
            }
        }

        @Test("OR denies when both deny")
        @MainActor
        func orBothFalse() async throws {
            let user = MockUser()
            try await TestRequest.withRequest(authenticated: user) { _, req in
                let policy = RequireRole("admin") || RequirePermission("users.read")
                let granted = try await policy.evaluate(req)
                #expect(granted == false)
            }
        }

        @Test("NOT inverts the result")
        @MainActor
        func notInverts() async throws {
            let user = MockUser(roles: ["admin"])
            try await TestRequest.withRequest(authenticated: user) { _, req in
                let r1 = try await (!RequireRole("admin")).evaluate(req)
                let r2 = try await (!RequireRole("viewer")).evaluate(req)
                #expect(r1 == false)
                #expect(r2 == true)
            }
        }

        @Test("Nested composition: (A || B) && C")
        @MainActor
        func nestedComposition() async throws {
            let user = MockUser(roles: ["editor"], permissions: ["posts.publish"])
            try await TestRequest.withRequest(authenticated: user) { _, req in
                let policy = (RequireRole("admin") || RequireRole("editor"))
                          && RequirePermission("posts.publish")
                let granted = try await policy.evaluate(req)
                #expect(granted == true)
            }
        }

        @Test("Name renders nested structure")
        func compositeName() {
            let policy = (RequireRole("admin") || RequireRole("editor"))
                      && RequirePermission("posts.publish")
            #expect(policy.name.contains("&&"))
            #expect(policy.name.contains("||"))
            #expect(policy.name.contains("admin"))
            #expect(policy.name.contains("editor"))
            #expect(policy.name.contains("posts.publish"))
        }
    }

    // MARK: - Always / Never

    @Suite("AlwaysAllow / AlwaysDeny")
    struct AlwaysPolicyTests {

        @Test("AlwaysAllow always returns true")
        @MainActor
        func alwaysAllow() async throws {
            try await TestRequest.withRequest(authenticated: nil) { _, req in
                let granted = try await AlwaysAllow().evaluate(req)
                #expect(granted == true)
            }
        }

        @Test("AlwaysDeny always returns false")
        @MainActor
        func alwaysDeny() async throws {
            let user = MockUser(roles: ["admin"])
            try await TestRequest.withRequest(authenticated: user) { _, req in
                let granted = try await AlwaysDeny().evaluate(req)
                #expect(granted == false)
            }
        }
    }
}
