import Foundation
import Testing
import SwiftCardanoCore
import SwiftCardanoCIPs
@testable import SwiftCardanoSigner

@Suite("Signer.CIP8 — message signing facade")
struct SignerCIP8Tests {

    @Test("verify accepts a canonical Pycardano-signed message")
    func verifyPycardanoFixture() throws {
        let result = try Signer.CIP8.verify(
            SignedMessage(signature: TestFixtures.pycardanoSignedMessage)
        )
        #expect(result.verified)
        #expect(result.message == "Pycardano is cool.")
    }

    @Test("sign + verify — string payload round-trip")
    func stringPayloadRoundTrip() throws {
        let payload = "the night is young"
        let signed = try Signer.CIP8.sign(
            message: payload,
            signingKey: .signingKey(TestFixtures.paymentSK),
            attachCoseKey: false,
            network: .mainnet
        )
        let result = try Signer.CIP8.verify(signed)
        #expect(result.verified)
        #expect(result.message == payload)
    }

    @Test("sign + verify — byte payload round-trip")
    func bytePayloadRoundTrip() throws {
        let payload = Data([0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF])
        let signed = try Signer.CIP8.sign(
            payload: payload,
            signingKey: .signingKey(TestFixtures.paymentSK)
        )
        let result = try Signer.CIP8.verify(signed)
        #expect(result.verified)
    }

    @Test("sign is deterministic across calls with identical inputs")
    func deterministic() throws {
        // The fix landed in `SwiftCardanoCIPs.CIP8.sign`: signing routes
        // through libsodium's RFC 8032 deterministic Ed25519 and the
        // attached COSE_Key is emitted in canonical CBOR map order.
        let payload = Data("deterministic check".utf8)
        let a = try Signer.CIP8.sign(payload: payload, signingKey: .signingKey(TestFixtures.paymentSK))
        let b = try Signer.CIP8.sign(payload: payload, signingKey: .signingKey(TestFixtures.paymentSK))
        #expect(a.signature == b.signature)
        #expect(a.key == b.key)
    }

    @Test("attachCoseKey: false produces a nil `key`")
    func unattachedCoseKey() throws {
        let signed = try Signer.CIP8.sign(
            payload: Data("plain".utf8),
            signingKey: .signingKey(TestFixtures.paymentSK),
            attachCoseKey: false
        )
        #expect(signed.key == nil)
    }

    @Test("attachCoseKey: true produces a non-nil `key`")
    func attachedCoseKey() throws {
        let signed = try Signer.CIP8.sign(
            payload: Data("with key".utf8),
            signingKey: .signingKey(TestFixtures.paymentSK),
            attachCoseKey: true
        )
        #expect(signed.key != nil)
    }
}
