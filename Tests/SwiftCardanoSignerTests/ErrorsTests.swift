import Foundation
import Testing
@testable import SwiftCardanoSigner

@Suite("SignerError cases and equality")
struct ErrorsTests {

    @Test("All cases pattern-match distinctly")
    func patternMatching() {
        let cases: [SignerError] = [
            .invalidSigningKey("a"),
            .invalidVerificationKey("b"),
            .malformedSignature("c"),
            .cipError("d"),
            .invalidDerivationPath("e"),
        ]
        // Each case has a unique tag — quick smoke test that a future
        // refactor doesn't silently collapse two cases.
        for (i, error) in cases.enumerated() {
            for (j, other) in cases.enumerated() where i != j {
                #expect(error != other)
            }
        }
    }

    @Test("Equatable distinguishes payload strings")
    func equatablePayloadStrings() {
        #expect(SignerError.invalidSigningKey("a") == SignerError.invalidSigningKey("a"))
        #expect(SignerError.invalidSigningKey("a") != SignerError.invalidSigningKey("b"))
    }

    @Test("Error conforms to Sendable")
    func sendableConformance() {
        func acceptSendable<T: Sendable>(_ x: T) {}
        acceptSendable(SignerError.invalidSigningKey("x"))
    }

    @Test("invalidSigningKey carries the failure context string")
    func invalidSigningKeyMessage() {
        let err = SignerError.invalidSigningKey("seed length wrong")
        guard case let .invalidSigningKey(message) = err else {
            Issue.record("Expected invalidSigningKey")
            return
        }
        #expect(message == "seed length wrong")
    }

    @Test("malformedSignature, invalidVerificationKey, cipError, invalidDerivationPath each carry context")
    func allCasesCarryContext() {
        guard case let .malformedSignature(a) = SignerError.malformedSignature("bad sig length") else {
            Issue.record("malformedSignature pattern mismatch")
            return
        }
        guard case let .invalidVerificationKey(b) = SignerError.invalidVerificationKey("bad vkey") else {
            Issue.record("invalidVerificationKey pattern mismatch")
            return
        }
        guard case let .cipError(c) = SignerError.cipError("cip delegate failed") else {
            Issue.record("cipError pattern mismatch")
            return
        }
        guard case let .invalidDerivationPath(d) = SignerError.invalidDerivationPath("bad path") else {
            Issue.record("invalidDerivationPath pattern mismatch")
            return
        }
        #expect(a == "bad sig length")
        #expect(b == "bad vkey")
        #expect(c == "cip delegate failed")
        #expect(d == "bad path")
    }
}
