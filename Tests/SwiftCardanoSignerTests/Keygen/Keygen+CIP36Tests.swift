import Foundation
import Testing
import SwiftCardanoCore
@testable import SwiftCardanoSigner

@Suite("Signer.Keygen.cip36 — Catalyst voting key derivation")
struct KeygenCIP36Tests {

    @Test("CIP-36 vote key derivation produces a sign-verify-able key on its own path")
    func roundTrip() throws {
        let vote = try Signer.Keygen.cip36(mnemonic: TestFixtures.testMnemonic)
        #expect(vote.signingKey.type.contains("CIP36"))
        #expect(vote.signingKey.payload.count == 128)
        #expect(vote.verificationKey.payload.count == 64)

        let payload = Data("vote".utf8)
        let signature = try Signer.sign(
            payload: payload,
            signingKey: .extendedSigningKey(vote.signingKey)
        )
        let ok = try Signer.verify(
            payload: payload,
            signature: signature.signature,
            verificationKey: .extendedVerificationKey(vote.verificationKey)
        )
        #expect(ok)
    }

    @Test("CIP-36 vote key is on a distinct path from the standard payment key")
    func distinctFromPayment() throws {
        let vote = try Signer.Keygen.cip36(mnemonic: TestFixtures.testMnemonic)
        let payment = try Signer.Keygen.shelley(
            mnemonic: TestFixtures.testMnemonic, kind: .payment()
        )
        #expect(vote.signingKey.payload != payment.signingKey.payload)
    }

    @Test("Same mnemonic produces the same vote key (deterministic)")
    func deterministic() throws {
        let a = try Signer.Keygen.cip36(mnemonic: TestFixtures.testMnemonic)
        let b = try Signer.Keygen.cip36(mnemonic: TestFixtures.testMnemonic)
        #expect(a.signingKey.payload == b.signingKey.payload)
    }

    @Test("Account and address indices propagate into the derived key")
    func accountAddressIndices() throws {
        let base = try Signer.Keygen.cip36(mnemonic: TestFixtures.testMnemonic)
        let differentAccount = try Signer.Keygen.cip36(
            mnemonic: TestFixtures.testMnemonic, account: 1
        )
        let differentAddress = try Signer.Keygen.cip36(
            mnemonic: TestFixtures.testMnemonic, address: 1
        )
        #expect(base.signingKey.payload != differentAccount.signingKey.payload)
        #expect(base.signingKey.payload != differentAddress.signingKey.payload)
    }

    @Test("Envelope type is the canonical CIP-36 vote-extended marker")
    func envelopeTypeIsCanonical() throws {
        let vote = try Signer.Keygen.cip36(mnemonic: TestFixtures.testMnemonic)
        #expect(vote.signingKey.type == "CIP36VoteExtendedSigningKey_ed25519_bip32")
        #expect(vote.verificationKey.type == "CIP36VoteExtendedVerificationKey_ed25519_bip32")
    }
}
