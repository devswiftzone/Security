//
//  SecurityEventBus.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor
import Foundation

/// Subscriber callback type for security events.
///
/// Handlers are async to allow DB writes, HTTP calls (webhooks), etc.
/// Handlers should not throw — failures in event handlers must not break
/// the primary security flow. Use try? or log internally instead.
public typealias SecurityEventHandler = @Sendable (SecurityEvent) async -> Void

/// Publishes security events to registered subscribers.
///
/// The bus is intentionally simple: in-process, fire-and-forget,
/// best-effort delivery. For durable event handling (delivery guarantees,
/// retries), use the bus to forward events to a queue (SQS, Kafka, Redis
/// streams) and let those systems handle reliability.
///
/// The bus is thread-safe: handlers can be added concurrently with
/// publishes, and publishes from concurrent contexts are serialized
/// internally by an actor.
public actor SecurityEventBus {

    /// Subscription handle returned from `on(_:handler:)`. Hold onto it to
    /// later remove the subscription, or discard if you don't need to.
    public struct Subscription: Sendable, Hashable {
        let id: UUID
        public static func == (lhs: Subscription, rhs: Subscription) -> Bool {
            lhs.id == rhs.id
        }
        public func hash(into hasher: inout Hasher) { hasher.combine(id) }
    }

    private struct Registration {
        let id: UUID
        let filter: String?   // event name prefix, or nil for "all"
        let handler: SecurityEventHandler
    }

    private var registrations: [Registration] = []

    public init() {}

    // MARK: - Subscribing

    /// Subscribes to all events.
    @discardableResult
    public func onAny(_ handler: @escaping SecurityEventHandler) -> Subscription {
        let reg = Registration(id: UUID(), filter: nil, handler: handler)
        registrations.append(reg)
        return Subscription(id: reg.id)
    }

    /// Subscribes to a specific event by name (e.g. `"auth.login.failed"`).
    @discardableResult
    public func on(
        _ eventName: String,
        handler: @escaping SecurityEventHandler
    ) -> Subscription {
        let reg = Registration(id: UUID(), filter: eventName, handler: handler)
        registrations.append(reg)
        return Subscription(id: reg.id)
    }

    /// Subscribes to all events with a name starting with the given prefix.
    /// E.g. `"auth.*"` matches `auth.login.succeeded`, `auth.login.failed`.
    @discardableResult
    public func on(
        prefix: String,
        handler: @escaping SecurityEventHandler
    ) -> Subscription {
        let trimmed = prefix.hasSuffix(".*")
            ? String(prefix.dropLast(2))
            : prefix
        let reg = Registration(id: UUID(), filter: trimmed, handler: handler)
        registrations.append(reg)
        return Subscription(id: reg.id)
    }

    /// Removes a previously installed subscription.
    public func off(_ subscription: Subscription) {
        registrations.removeAll { $0.id == subscription.id }
    }

    /// Removes all subscriptions. Primarily for tests.
    public func removeAll() {
        registrations.removeAll()
    }

    // MARK: - Publishing

    /// Publishes an event to all matching subscribers.
    ///
    /// Handlers run concurrently. This call awaits all of them — if any
    /// hang, the publish hangs. For fully fire-and-forget behavior, use
    /// `publishDetached(_:)` instead.
    public func publish(_ event: SecurityEvent) async {
        let matched = registrations.filter { matches($0, event: event) }
        await withTaskGroup(of: Void.self) { group in
            for reg in matched {
                group.addTask {
                    await reg.handler(event)
                }
            }
        }
    }

    /// Publishes an event without awaiting handler completion.
    ///
    /// Handlers run in detached tasks. Useful in hot paths (login, token
    /// issuance) where you don't want event handlers to add latency.
    public nonisolated func publishDetached(_ event: SecurityEvent) {
        Task.detached(priority: .background) {
            await self.publish(event)
        }
    }

    // MARK: - Matching

    private func matches(_ reg: Registration, event: SecurityEvent) -> Bool {
        guard let filter = reg.filter else { return true }
        let name = event.name
        return name == filter || name.hasPrefix(filter + ".")
    }
}
