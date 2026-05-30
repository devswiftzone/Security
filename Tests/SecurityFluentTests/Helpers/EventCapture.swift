//
//  EventCapture.swift
//  Security
//
//  Created by Asiel Cabrera on 5/30/26.
//

import Foundation
import SecurityCore

/// Captures published security events for assertion in tests.
///
/// Usage:
///
///     let captured = EventCapture()
///     await app.security.events.onAny { event in await captured.append(event) }
///     // ... perform action ...
///     try await captured.waitForEvent(named: "auth.login.succeeded")
actor EventCapture {

    private(set) var events: [SecurityEvent] = []

    func append(_ event: SecurityEvent) {
        events.append(event)
    }

    func names() -> [String] {
        events.map(\.name)
    }

    func contains(_ name: String) -> Bool {
        events.contains { $0.name == name }
    }

    /// Polls every 10ms (up to `timeout` total) for an event with the
    /// given name. Returns true if found, false on timeout. Needed
    /// because events are published via publishDetached and may arrive
    /// after the awaited operation completes.
    func waitForEvent(
        named name: String,
        timeout: Duration = .milliseconds(500)
    ) async -> Bool {
        let deadline = ContinuousClock.now.advanced(by: timeout)
        while ContinuousClock.now < deadline {
            if contains(name) { return true }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return false
    }
}
