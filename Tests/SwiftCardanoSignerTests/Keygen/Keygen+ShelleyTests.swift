import Foundation
import Testing
import SwiftCardanoCore
@testable import SwiftCardanoSigner

@Suite("Signer.Keygen.shelley — CIP-1852 Shelley path derivation")
struct KeygenShelleyTests {

    @Test("Payment key derivation produces a sign-verify-able extended key")
    func paymentRoundTrip() throws {
        let bundle = try Signer.Keygen.shelley(
            mnemonic: TestFixtures.testMnemonic,
            kind: .payment(account: 0, index: 0)
        )
        // Signing key payload shape: 64 (private) + 32 (public) + 32 (chain code).
        #expect(bundle.signingKey.payload.count == 128)
        #expect(bundle.verificationKey.payload.count == 64)
        #expect(bundle.signingKey.type.contains("Payment"))
        #expect(bundle.verificationKey.type.contains("Payment"))

        let payload = Data("the night is young".utf8)
        let signature = try Signer.sign(
            payload: payload,
            signingKey: .extendedSigningKey(bundle.signingKey)
        )
        let ok = try Signer.verify(
            payload: payload,
            signature: signature.signature,
            verificationKey: .extendedVerificationKey(bundle.verificationKey)
        )
        #expect(ok)
    }

    @Test("Different roles from the same mnemonic produce different keys")
    func differentRolesDiverge() throws {
        let payment = try Signer.Keygen.shelley(
            mnemonic: TestFixtures.testMnemonic, kind: .payment()
        )
        let stake = try Signer.Keygen.shelley(
            mnemonic: TestFixtures.testMnemonic, kind: .stake()
        )
        let drep = try Signer.Keygen.shelley(
            mnemonic: TestFixtures.testMnemonic, kind: .drep()
        )
        #expect(payment.signingKey.payload != stake.signingKey.payload)
        #expect(payment.signingKey.payload != drep.signingKey.payload)
        #expect(stake.signingKey.payload   != drep.signingKey.payload)
    }

    @Test("Same mnemonic + same role = deterministic derivation")
    func deterministic() throws {
        let a = try Signer.Keygen.shelley(
            mnemonic: TestFixtures.testMnemonic, kind: .payment(account: 0, index: 0)
        )
        let b = try Signer.Keygen.shelley(
            mnemonic: TestFixtures.testMnemonic, kind: .payment(account: 0, index: 0)
        )
        #expect(a.signingKey.payload == b.signingKey.payload)
        #expect(a.verificationKey.payload == b.verificationKey.payload)
    }

    @Test("Passphrase changes the derived key")
    func passphraseChangesDerivation() throws {
        let withoutPassphrase = try Signer.Keygen.shelley(
            mnemonic: TestFixtures.testMnemonic, kind: .payment()
        )
        let withPassphrase = try Signer.Keygen.shelley(
            mnemonic: TestFixtures.testMnemonic, passphrase: "the 25th word",
            kind: .payment()
        )
        #expect(withoutPassphrase.signingKey.payload != withPassphrase.signingKey.payload)
    }

    @Test("Account index changes the derived key")
    func accountChangesDerivation() throws {
        let account0 = try Signer.Keygen.shelley(
            mnemonic: TestFixtures.testMnemonic, kind: .payment(account: 0, index: 0)
        )
        let account1 = try Signer.Keygen.shelley(
            mnemonic: TestFixtures.testMnemonic, kind: .payment(account: 1, index: 0)
        )
        #expect(account0.signingKey.payload != account1.signingKey.payload)
    }

    @Test("Address index changes the derived key")
    func indexChangesDerivation() throws {
        let index0 = try Signer.Keygen.shelley(
            mnemonic: TestFixtures.testMnemonic, kind: .payment(account: 0, index: 0)
        )
        let index1 = try Signer.Keygen.shelley(
            mnemonic: TestFixtures.testMnemonic, kind: .payment(account: 0, index: 1)
        )
        #expect(index0.signingKey.payload != index1.signingKey.payload)
    }
}
