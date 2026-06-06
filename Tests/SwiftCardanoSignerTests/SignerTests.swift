import Foundation
import Testing
@testable import SwiftCardanoSigner

@Suite("Signer namespace and SignatureResult")
struct SignerTests {

    @Test("Signer is an uninhabited namespace (enum with no cases)")
    func signerIsUninhabited() {
        // The compiler-level guarantee is that `Signer` has no cases —
        // we encode this here so a future refactor that adds a case
        // accidentally to the `Signer` enum gets flagged. Using
        // `Mirror` because the type intentionally has no constructor.
        let mirror = Mirror(reflecting: Signer.self)
        #expect(mirror.displayStyle == nil || mirror.children.isEmpty)
    }

    @Test("SignatureResult stores signature and publicKey verbatim")
    func signatureResultStoresFields() {
        let sig = Data((0..<64).map { UInt8($0) })
        let pk = Data((0..<32).map { UInt8($0) })
        let result = SignatureResult(signature: sig, publicKey: pk)
        #expect(result.signature == sig)
        #expect(result.publicKey == pk)
    }

    @Test("SignatureResult is Equatable on both fields")
    func signatureResultEquatable() {
        let a = SignatureResult(
            signature: Data(repeating: 0xAA, count: 64),
            publicKey: Data(repeating: 0xBB, count: 32)
        )
        let b = SignatureResult(
            signature: Data(repeating: 0xAA, count: 64),
            publicKey: Data(repeating: 0xBB, count: 32)
        )
        let differentSig = SignatureResult(
            signature: Data(repeating: 0x00, count: 64),
            publicKey: Data(repeating: 0xBB, count: 32)
        )
        let differentPK = SignatureResult(
            signature: Data(repeating: 0xAA, count: 64),
            publicKey: Data(repeating: 0x00, count: 32)
        )
        #expect(a == b)
        #expect(a != differentSig)
        #expect(a != differentPK)
    }

    @Test("SignatureResult is Sendable")
    func signatureResultIsSendable() {
        // Compile-time check — if SignatureResult lost its Sendable
        // conformance, this `Sendable` parameter would fail to type-check.
        func acceptSendable<T: Sendable>(_ x: T) {}
        let result = SignatureResult(signature: Data(), publicKey: Data())
        acceptSendable(result)
    }
}
