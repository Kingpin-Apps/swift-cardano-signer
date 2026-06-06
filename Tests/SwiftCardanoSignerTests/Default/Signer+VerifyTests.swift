import Foundation
import Testing
import SwiftCardanoCore
@testable import SwiftCardanoSigner

@Suite("Signer.verify — default Ed25519")
struct DefaultSignerVerifyTests {

    @Test("Accepts a signature produced by sign (round-trip)")
    func roundTrip() throws {
        let signingKey = try SigningKey(payload: TestFixtures.RFC8032.seed)
        let payload = Data("the night is young".utf8)
        let result = try Signer.sign(payload: payload, signingKey: .signingKey(signingKey))

        let verificationKey = try VerificationKey(payload: result.publicKey)
        let ok = try Signer.verify(
            payload: payload,
            signature: result.signature,
            verificationKey: .verificationKey(verificationKey)
        )
        #expect(ok)
    }

    @Test("Returns false when the payload has been tampered with")
    func tamperedPayload() throws {
        let signingKey = try SigningKey(payload: TestFixtures.RFC8032.seed)
        let payload = Data("the night is young".utf8)
        let result = try Signer.sign(payload: payload, signingKey: .signingKey(signingKey))

        let verificationKey = try VerificationKey(payload: result.publicKey)
        let tamperedPayload = Data("the night is OLD!!".utf8)
        let ok = try Signer.verify(
            payload: tamperedPayload,
            signature: result.signature,
            verificationKey: .verificationKey(verificationKey)
        )
        #expect(!ok)
    }

    @Test("Returns false when the signature has been tampered with")
    func tamperedSignature() throws {
        let signingKey = try SigningKey(payload: TestFixtures.RFC8032.seed)
        let payload = Data("the night is young".utf8)
        let result = try Signer.sign(payload: payload, signingKey: .signingKey(signingKey))

        var tamperedSignature = result.signature
        tamperedSignature[0] ^= 0xFF

        let verificationKey = try VerificationKey(payload: result.publicKey)
        let ok = try Signer.verify(
            payload: payload,
            signature: tamperedSignature,
            verificationKey: .verificationKey(verificationKey)
        )
        #expect(!ok)
    }

    @Test("Rejects a malformed (wrong-length) signature with an error")
    func malformedSignatureThrows() throws {
        let signingKey = try SigningKey(payload: TestFixtures.RFC8032.seed)
        let vkeyType = try SigningKeyType.signingKey(signingKey).toVerificationKeyType()

        #expect(throws: SignerError.self) {
            _ = try Signer.verify(
                payload: Data(),
                signature: Data(repeating: 0, count: 63),
                verificationKey: vkeyType
            )
        }
    }

    @Test("Accepts an extended verification key — chain code stripped internally")
    func extendedVerificationKey() throws {
        let signingKey = try SigningKey(payload: TestFixtures.RFC8032.seed)
        let payload = Data("extended-key path".utf8)
        let result = try Signer.sign(payload: payload, signingKey: .signingKey(signingKey))

        // Synthesise a 64-byte extended verification key by appending an
        // arbitrary 32-byte chain code; Signer.verify should slice it
        // back to 32 bytes before passing to libsodium.
        let fakeChainCode = Data(repeating: 0xAB, count: 32)
        let extendedPayload = result.publicKey + fakeChainCode
        let extVKey = try ExtendedVerificationKey(payload: extendedPayload)

        let ok = try Signer.verify(
            payload: payload,
            signature: result.signature,
            verificationKey: .extendedVerificationKey(extVKey)
        )
        #expect(ok)
    }

    @Test("Returns false when verification key does not match the signing key")
    func wrongKey() throws {
        let signingKey = try SigningKey(payload: TestFixtures.RFC8032.seed)
        let payload = Data("hello".utf8)
        let result = try Signer.sign(payload: payload, signingKey: .signingKey(signingKey))

        // A different verification key (the test stake vkey) won't match.
        let wrongVKey = TestFixtures.stakeVK
        let ok = try Signer.verify(
            payload: payload,
            signature: result.signature,
            verificationKey: .verificationKey(wrongVKey)
        )
        #expect(!ok)
    }
}
