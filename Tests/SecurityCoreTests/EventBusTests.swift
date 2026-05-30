//
//  EventBusTests.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Testing
import Foundation
@testable import SecurityCore

@Suite("SecurityEventBus")
struct EventBusTests {

    @Test("Handler receives matching event")
    func handlerReceivesEvent() async {
        let bus = SecurityEventBus()
        let captured = Capture<SecurityEvent>()

        await bus.onAny { event in
            await captured.set(event)
        }

        let userCtx = SecurityEvent.UserContext(id: UUID(), email: "a@b.com")
        await bus.publish(.userRegistered(userCtx))

        let received = await captured.get()
        if case .userRegistered(let ctx) = received {
            #expect(ctx == userCtx)
        } else {
            Issue.record("Expected .userRegistered, got \(String(describing: received))")
        }
    }

    @Test("Multiple handlers all receive the event")
    func multipleHandlers() async {
        let bus = SecurityEventBus()
        let count = Counter()

        await bus.onAny { _ in await count.increment() }
        await bus.onAny { _ in await count.increment() }
        await bus.onAny { _ in await count.increment() }

        let ctx = SecurityEvent.UserContext(id: UUID(), email: "x@y.com")
        await bus.publish(.userRegistered(ctx))

        #expect(await count.value == 3)
    }

    @Test("Named subscription only fires for matching event")
    func namedSubscriptionFilters() async {
        let bus = SecurityEventBus()
        let count = Counter()

        await bus.on("auth.login.succeeded") { _ in
            await count.increment()
        }

        let ctx = SecurityEvent.UserContext(id: UUID(), email: "x@y.com")
        await bus.publish(.loginSucceeded(ctx, ip: nil))     // match
        await bus.publish(.userRegistered(ctx))              // no match
        await bus.publish(.loginFailed(email: "x@y.com", ip: nil, reason: .wrongPassword))  // no match

        #expect(await count.value == 1)
    }

    @Test("Prefix subscription matches all events under the prefix")
    func prefixSubscription() async {
        let bus = SecurityEventBus()
        let count = Counter()

        await bus.on(prefix: "auth.*") { _ in
            await count.increment()
        }

        let ctx = SecurityEvent.UserContext(id: UUID(), email: "x@y.com")
        await bus.publish(.loginSucceeded(ctx, ip: nil))                                   // match
        await bus.publish(.loginFailed(email: "x@y.com", ip: nil, reason: .wrongPassword)) // match
        await bus.publish(.logoutAll(ctx))                                                 // match
        await bus.publish(.userRegistered(ctx))                                            // no match (user.*)
        await bus.publish(.tokenIssued(ctx, kind: .access))                                // no match (token.*)

        #expect(await count.value == 3)
    }

    @Test("Off removes the subscription")
    func unsubscribe() async {
        let bus = SecurityEventBus()
        let count = Counter()

        let sub = await bus.onAny { _ in await count.increment() }

        let ctx = SecurityEvent.UserContext(id: UUID(), email: "x@y.com")
        await bus.publish(.userRegistered(ctx))
        #expect(await count.value == 1)

        await bus.off(sub)
        await bus.publish(.userRegistered(ctx))
        #expect(await count.value == 1)  // unchanged
    }

    @Test("Event name follows the documented namespace convention")
    func eventNames() {
        let ctx = SecurityEvent.UserContext(id: UUID(), email: "x@y.com")
        #expect(SecurityEvent.userRegistered(ctx).name == "user.registered")
        #expect(SecurityEvent.loginSucceeded(ctx, ip: nil).name == "auth.login.succeeded")
        #expect(SecurityEvent.tokenReuseDetected(ctx).name == "token.reuse_detected")
        #expect(SecurityEvent.permissionGranted(role: "x", permission: "y").name == "permission.granted")
    }
}

// MARK: - Test helpers

/// Captures the latest value received. Actor-based for safe async access.
private actor Capture<T: Sendable> {
    private var value: T?
    func set(_ v: T) { value = v }
    func get() -> T? { value }
}

private actor Counter {
    private(set) var value: Int = 0
    func increment() { value += 1 }
}
