//
//  PasswordPolicyTests.swift
//  Security
//
//  Created by Asiel Cabrera on 5/29/26.
//

import Testing
@testable import SecurityCore

@Suite("PasswordPolicy")
struct PasswordPolicyTests {

    typealias Policy = SecurityConfiguration.PasswordPolicy

    @Test("Accepts password meeting minimum length")
    func acceptsValidPassword() {
        let policy = Policy(minLength: 8)
        #expect(policy.validate("password123") == nil)
    }

    @Test("Rejects password below minimum length")
    func rejectsShortPassword() {
        let policy = Policy(minLength: 12)
        let result = policy.validate("short")
        #expect(result != nil)
        if case .passwordTooWeak(let reason) = result {
            #expect(reason.contains("12"))
        } else {
            Issue.record("Expected .passwordTooWeak, got \(String(describing: result))")
        }
    }

    @Test("Rejects password above maximum length")
    func rejectsLongPassword() {
        let policy = Policy(maxLength: 20)
        let long = String(repeating: "a", count: 21)
        #expect(policy.validate(long) != nil)
    }

    @Test("Mixed case requirement")
    func mixedCase() {
        let policy = Policy(minLength: 4, requireMixedCase: true)
        #expect(policy.validate("alllower") != nil)
        #expect(policy.validate("ALLUPPER") != nil)
        #expect(policy.validate("MixedCase") == nil)
    }

    @Test("Digit requirement")
    func digitRequired() {
        let policy = Policy(minLength: 4, requireDigit: true)
        #expect(policy.validate("nodigits") != nil)
        #expect(policy.validate("has1digit") == nil)
    }

    @Test("Symbol requirement")
    func symbolRequired() {
        let policy = Policy(minLength: 4, requireSymbol: true)
        #expect(policy.validate("nosymbols123") != nil)
        #expect(policy.validate("with!symbol") == nil)
    }

    @Test("Combined requirements")
    func combined() {
        let policy = Policy(
            minLength: 8,
            requireMixedCase: true,
            requireDigit: true,
            requireSymbol: true
        )
        #expect(policy.validate("short") != nil)               // too short
        #expect(policy.validate("longenoughbutweak") != nil)   // no upper/digit/sym
        #expect(policy.validate("LongEnoughButWeak") != nil)   // no digit/symbol
        #expect(policy.validate("LongEnough1") != nil)         // no symbol
        #expect(policy.validate("Str0ng!Password") == nil)     // all satisfied
    }

    @Test("Default policy is reasonable")
    func defaultPolicy() {
        let policy = Policy()
        #expect(policy.minLength == 12)
        #expect(policy.maxLength == 128)
        #expect(policy.requireMixedCase == false)
        #expect(policy.validate("simplelongpassword") == nil)  // 18 chars, OK
        #expect(policy.validate("short1!") != nil)             // 7 chars, fails
    }
}
