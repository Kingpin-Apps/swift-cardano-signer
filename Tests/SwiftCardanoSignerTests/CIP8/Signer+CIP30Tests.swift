import Foundation
import Testing
import SwiftCardanoCore
import SwiftCardanoCIPs
@testable import SwiftCardanoSigner

@Suite("Signer.CIP30 — dApp signData facade")
struct SignerCIP30Tests {

    @Test("signData = CIP8.sign(attachCoseKey: true) — byte-identical")
    func cip30MatchesCIP8WithKey() throws {
        let payload = Data("hello dApp".utf8)

        let viaCIP30 = try Signer.CIP30.signData(
            payload: payload,
            signingKey: .signingKey(TestFixtures.paymentSK)
        )
        let viaCIP8 = try Signer.CIP8.sign(
            payload: payload,
            signingKey: .signingKey(TestFixtures.paymentSK),
            attachCoseKey: true
        )

        // CIP-30 is defined as "CIP-8 with the COSE key attached" — same
        // inputs must produce the same wire output bit-for-bit so a dApp
        // wallet that delegates either way produces the same envelope.
        #expect(viaCIP30.signature == viaCIP8.signature)
        #expect(viaCIP30.key == viaCIP8.key)
        #expect(viaCIP30.key != nil)
    }

    @Test("signData always attaches the COSE key")
    func signDataAlwaysAttachesKey() throws {
        let signed = try Signer.CIP30.signData(
            payload: Data("a".utf8),
            signingKey: .signingKey(TestFixtures.paymentSK)
        )
        #expect(signed.key != nil)
    }

    @Test("verify accepts a CIP-30-style attached-key message")
    func verifyAttachedKeyMessage() throws {
        let payload = Data("hello dApp".utf8)
        let signed = try Signer.CIP30.signData(
            payload: payload,
            signingKey: .signingKey(TestFixtures.paymentSK)
        )
        let result = try Signer.CIP30.verify(signed)
        #expect(result.verified)
    }

    @Test("Round-trip across mainnet and testnet network IDs")
    func networkRoundTrip() throws {
        let payload = Data("network".utf8)
        for network in [Network.mainnet, .preprod, .preview] {
            let signed = try Signer.CIP30.signData(
                payload: payload,
                signingKey: .signingKey(TestFixtures.paymentSK),
                network: network
            )
            let result = try Signer.CIP30.verify(signed)
            #expect(result.verified, "verify should accept message signed on \(network)")
        }
    }
}
