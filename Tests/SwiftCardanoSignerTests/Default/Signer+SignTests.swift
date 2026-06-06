import Foundation
import Testing
import SwiftCardanoCore
@testable import SwiftCardanoSigner

@Suite("Signer.sign — default Ed25519")
struct DefaultSignerSignTests {

    @Test("RFC 8032 Test 1 — produces the canonical Ed25519 signature")
    func rfc8032CanonicalSignature() throws {
        let signingKey = try SigningKey(payload: TestFixtures.RFC8032.seed)
        let result = try Signer.sign(
            payload: Data(),
            signingKey: .signingKey(signingKey)
        )
        #expect(result.signature == TestFixtures.RFC8032.signature)
        #expect(result.publicKey == TestFixtures.RFC8032.publicKey)
    }

    @Test("Returns 64-byte signature + 32-byte publicKey for regular keys")
    func resultByteLengths() throws {
        let signingKey = try SigningKey(payload: TestFixtures.RFC8032.seed)
        let result = try Signer.sign(
            payload: Data("hello".utf8),
            signingKey: .signingKey(signingKey)
        )
        #expect(result.signature.count == 64)
        #expect(result.publicKey.count == 32)
    }

    @Test("Extended signing keys produce 64-byte signature + 32-byte (chain-code stripped) publicKey")
    func extendedSigningKey() throws {
        // Derive a payment extended key from the canonical test mnemonic
        // via the Shelley keygen path — that's the most direct way to
        // get a real BIP32-Ed25519 extended key into the test.
        let bundle = try Signer.Keygen.shelley(
            mnemonic: TestFixtures.testMnemonic,
            kind: .payment()
        )
        let result = try Signer.sign(
            payload: Data("extended sign".utf8),
            signingKey: .extendedSigningKey(bundle.signingKey)
        )
        #expect(result.signature.count == 64)
        #expect(result.publicKey.count == 32, "Chain code should be stripped from the publicKey field")
    }

    @Test("Same key + same message produces the same signature (Ed25519 is deterministic)")
    func deterministic() throws {
        let signingKey = try SigningKey(payload: TestFixtures.RFC8032.seed)
        let payload = Data("repeat me".utf8)
        let a = try Signer.sign(payload: payload, signingKey: .signingKey(signingKey))
        let b = try Signer.sign(payload: payload, signingKey: .signingKey(signingKey))
        #expect(a.signature == b.signature)
        #expect(a.publicKey == b.publicKey)
    }

    @Test("Empty payload signs successfully")
    func emptyPayload() throws {
        let signingKey = try SigningKey(payload: TestFixtures.RFC8032.seed)
        let result = try Signer.sign(
            payload: Data(),
            signingKey: .signingKey(signingKey)
        )
        #expect(result.signature.count == 64)
    }
}
