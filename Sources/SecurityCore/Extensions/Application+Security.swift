//
//  Application+Security.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Vapor

public extension Application {

    /// Entry point for all Security package APIs.
    ///
    /// Configure with:
    ///
    ///     app.security.configuration = .init(
    ///         tokenLifetimes: .init(access: 15 * 60)
    ///     )
    ///     app.security.passwordHasher = MyArgon2Hasher()
    ///
    /// Subscribe to events with:
    ///
    ///     await app.security.events.on("auth.login.failed") { event in
    ///         app.logger.warning("\(event)")
    ///     }
    ///
    /// Concrete service accessors (`app.security.auth`, `app.security.users`,
    /// etc.) are provided by `SecurityFluent` or another backend module.
    var security: Security {
        .init(application: self)
    }

    /// Namespace struct holding all Security APIs.
    ///
    /// This is a value type that holds a reference to the `Application`.
    /// Settings are persisted via `Application.storage` so they survive
    /// across `app.security` accesses.
    struct Security: Sendable {

        public let application: Application

        public init(application: Application) {
            self.application = application
        }

        // MARK: - Configuration

        /// The active configuration. Defaults to `SecurityConfiguration.default`.
        public var configuration: SecurityConfiguration {
            get {
                application.storage[ConfigurationKey.self] ?? .default
            }
            nonmutating set {
                application.storage[ConfigurationKey.self] = newValue
            }
        }

        // MARK: - Password hasher

        /// The active password hasher. Concrete implementations are provided
        /// by backend modules (e.g. `BcryptHasher` from `SecurityFluent`).
        ///
        /// Accessing this property before a hasher has been registered is
        /// a programmer error and will trap.
        public var passwordHasher: SecurityPasswordHasher {
            get {
                guard let hasher = application.storage[PasswordHasherKey.self] else {
                    fatalError(
                        """
                        No PasswordHasher has been registered.

                        Did you forget to import SecurityFluent and call \
                        app.security.use(...) in configure()?

                        Example:
                            import SecurityFluent
                            app.security.passwordHasher = BcryptHasher(cost: 12)
                        """
                    )
                }
                return hasher
            }
            nonmutating set {
                application.storage[PasswordHasherKey.self] = newValue
            }
        }

        // MARK: - Token generator

        /// The active token generator. Concrete implementations are provided
        /// by backend modules.
        public var tokenGenerator: TokenGenerator {
            get {
                guard let gen = application.storage[TokenGeneratorKey.self] else {
                    fatalError(
                        """
                        No TokenGenerator has been registered.

                        Did you forget to import SecurityFluent?

                        Example:
                            app.security.tokenGenerator = DefaultTokenGenerator()
                        """
                    )
                }
                return gen
            }
            nonmutating set {
                application.storage[TokenGeneratorKey.self] = newValue
            }
        }

        // MARK: - Event bus

        /// The event bus. Created lazily on first access and stored on the
        /// application, so subscriptions persist across requests.
        public var events: SecurityEventBus {
            if let existing = application.storage[EventBusKey.self] {
                return existing
            }
            let bus = SecurityEventBus()
            application.storage[EventBusKey.self] = bus
            return bus
        }

        // MARK: - Storage keys

        private struct ConfigurationKey: StorageKey {
            typealias Value = SecurityConfiguration
        }

        private struct PasswordHasherKey: StorageKey {
            typealias Value = SecurityPasswordHasher
        }

        private struct TokenGeneratorKey: StorageKey {
            typealias Value = TokenGenerator
        }

        private struct EventBusKey: StorageKey {
            typealias Value = SecurityEventBus
        }
    }
}
