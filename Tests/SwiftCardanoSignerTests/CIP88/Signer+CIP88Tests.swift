import Foundation
import Testing
import SwiftCardanoCore
import SwiftCardanoCIPs
import SwiftNaCl
@testable import SwiftCardanoSigner

@Suite("Signer.CIP88 / Signer.CIP151 — Calidus pool-key facade")
struct SignerCIP88Tests {

    // Pool cold key — non-extended Ed25519 (cardano-cli's `node key-gen`
    // shape), reused across this suite.
    static let poolSK = try! StakePoolSigningKey(
        payload: Data(hex: "093be5cd3987d0c9fd8854ef908f7746b69e2d73320db6dc0f780d81585b84c2")
    )

    static let calidusKey = Data(repeating: 0xCA, count: 32)

    @Test("makeCalidusRegistration produces the {0:2, 1:payload, 2:[witness]} envelope under label 867")
    func envelopeShape() throws {
        let aux = try Signer.CIP88.makeCalidusRegistration(
            calidusPublicKey: Self.calidusKey,
            poolSigningKey: .signingKey(Self.poolSK),
            nonce: 1
        )
        guard case let .metadata(metadata) = aux.data,
              case let .map(envelope) = metadata.data[867] else {
            Issue.record("Expected map under label 867")
            return
        }
        guard case let .int(version) = envelope[.int(0)] else {
            Issue.record("Missing version")
            return
        }
        #expect(version == 2)
    }

    @Test("Witness signature verifies over blake2b_256(hex(CBOR(payload)))")
    func witnessVerifies() throws {
        let aux = try Signer.CIP88.makeCalidusRegistration(
            calidusPublicKey: Self.calidusKey,
            poolSigningKey: .signingKey(Self.poolSK),
            nonce: 42
        )
        guard case let .metadata(metadata) = aux.data,
              case let .map(envelope) = metadata.data[867],
              let payload = envelope[.int(1)],
              case let .list(witnesses) = envelope[.int(2)],
              case let .map(witness) = witnesses[0],
              case let .bytes(witnessKey) = witness[.int(1)],
              case let .bytes(signature) = witness[.int(2)] else {
            Issue.record("Could not extract verification inputs")
            return
        }
        #expect(witnessKey.count == 32)
        #expect(signature.count == 64)

        let payloadCBOR = try payload.toCBORData()
        let hexString = payloadCBOR.map { String(format: "%02x", $0) }.joined()
        let signingHash = try SwiftNaCl.Hash().blake2b(
            data: Data(hexString.utf8),
            digestSize: 32,
            encoder: RawEncoder.self
        )
        let verifyKey = try VerifyKey(key: witnessKey)
        _ = try verifyKey.verify(smessage: signingHash, signature: signature)
    }

    @Test("Signer.CIP151 is an alias for Signer.CIP88 — outputs match structurally")
    func cip151Alias() throws {
        let viaCIP88 = try Signer.CIP88.makeCalidusRegistration(
            calidusPublicKey: Self.calidusKey,
            poolSigningKey: .signingKey(Self.poolSK),
            nonce: 7
        )
        let viaCIP151 = try Signer.CIP151.makeCalidusRegistration(
            calidusPublicKey: Self.calidusKey,
            poolSigningKey: .signingKey(Self.poolSK),
            nonce: 7
        )
        guard case let .metadata(meta88) = viaCIP88.data,
              case let .metadata(meta151) = viaCIP151.data else {
            Issue.record("Unexpected MetadataType variant")
            return
        }
        // Ed25519 over the same input → identical signature, so the
        // 867 maps must be equal even though outer Metadata Dictionary
        // ordering varies between calls.
        #expect(meta88.data[867] == meta151.data[867])
    }
}
