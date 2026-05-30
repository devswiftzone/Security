//
//  PolicyOperators.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor

// MARK: - AND

/// Logical AND of two authorization policies. Both must grant access.
public struct AndPolicy: AuthorizationPolicy {
    let lhs: AuthorizationPolicy
    let rhs: AuthorizationPolicy

    public var name: String { "(\(lhs.name) && \(rhs.name))" }

    public func evaluate(_ req: Request) async throws -> Bool {
        guard try await lhs.evaluate(req) else { return false }
        return try await rhs.evaluate(req)
    }
}

public func && (
    lhs: any AuthorizationPolicy,
    rhs: any AuthorizationPolicy
) -> AndPolicy {
    AndPolicy(lhs: lhs, rhs: rhs)
}

// MARK: - OR

/// Logical OR of two authorization policies. Either grants access.
public struct OrPolicy: AuthorizationPolicy {
    let lhs: AuthorizationPolicy
    let rhs: AuthorizationPolicy

    public var name: String { "(\(lhs.name) || \(rhs.name))" }

    public func evaluate(_ req: Request) async throws -> Bool {
        if try await lhs.evaluate(req) { return true }
        return try await rhs.evaluate(req)
    }
}

public func || (
    lhs: any AuthorizationPolicy,
    rhs: any AuthorizationPolicy
) -> OrPolicy {
    OrPolicy(lhs: lhs, rhs: rhs)
}

// MARK: - NOT

/// Logical NOT of an authorization policy.
public struct NotPolicy: AuthorizationPolicy {
    let wrapped: AuthorizationPolicy

    public var name: String { "!(\(wrapped.name))" }

    public func evaluate(_ req: Request) async throws -> Bool {
        try await !wrapped.evaluate(req)
    }
}

public prefix func ! (policy: any AuthorizationPolicy) -> NotPolicy {
    NotPolicy(wrapped: policy)
}

// MARK: - Always / Never (useful for tests and conditionals)

/// Policy that always grants access. Useful for tests and conditional gating.
public struct AlwaysAllow: AuthorizationPolicy {
    public init() {}
    public var name: String { "AlwaysAllow" }
    public func evaluate(_ req: Request) async throws -> Bool { true }
}

/// Policy that always denies access.
public struct AlwaysDeny: AuthorizationPolicy {
    public init() {}
    public var name: String { "AlwaysDeny" }
    public func evaluate(_ req: Request) async throws -> Bool { false }
}
