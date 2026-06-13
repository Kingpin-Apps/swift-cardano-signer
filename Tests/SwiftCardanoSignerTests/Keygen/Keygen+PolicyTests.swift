import Foundation
import Testing
import SwiftCardanoCore
@testable import SwiftCardanoSigner

@Suite("Signer.Keygen.policy — CIP-1855 minting-policy path derivation")
struct KeygenPolicyTests {

    @Test("Policy key derivation produces a sign-verify-able extended key")
    func policyRoundTrip() throws {
        let bundle = try Signer.Keygen.policy(
            mnemonic: TestFixtures.testMnemonic,
            policyIndex: 0
        )
        // Signing key payload shape: 64 (private) + 32 (public) + 32 (chain code).
        #expect(bundle.signingKey.payload.count == 128)
        #expect(bundle.verificationKey.payload.count == 64)
        // Policy keys are payment-class.
        #expect(bundle.signingKey.type.contains("Payment"))
        #expect(bundle.verificationKey.type.contains("Payment"))
        // HDWallet renders hardened indices in offset-numeric form
        // (n' == n + 2³¹), so 1855'/1815'/0' == 2147485503/2147485463/2147483648.
        #expect(bundle.path == "m/2147485503/2147485463/2147483648")

        let payload = Data("forge me a token".utf8)
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

    @Test("Same mnemonic + same index = deterministic derivation")
    func deterministic() throws {
        let a = try Signer.Keygen.policy(mnemonic: TestFixtures.testMnemonic, policyIndex: 0)
        let b = try Signer.Keygen.policy(mnemonic: TestFixtures.testMnemonic, policyIndex: 0)
        #expect(a.signingKey.payload == b.signingKey.payload)
        #expect(a.verificationKey.payload == b.verificationKey.payload)
    }

    @Test("Policy index changes the derived key")
    func indexChangesDerivation() throws {
        let index0 = try Signer.Keygen.policy(mnemonic: TestFixtures.testMnemonic, policyIndex: 0)
        let index1 = try Signer.Keygen.policy(mnemonic: TestFixtures.testMnemonic, policyIndex: 1)
        #expect(index0.signingKey.payload != index1.signingKey.payload)
        #expect(index1.path == "m/2147485503/2147485463/2147483649")   // 1855'/1815'/1'
    }

    @Test("Passphrase changes the derived key")
    func passphraseChangesDerivation() throws {
        let withoutPassphrase = try Signer.Keygen.policy(
            mnemonic: TestFixtures.testMnemonic, policyIndex: 0
        )
        let withPassphrase = try Signer.Keygen.policy(
            mnemonic: TestFixtures.testMnemonic, passphrase: "the 25th word", policyIndex: 0
        )
        #expect(withoutPassphrase.signingKey.payload != withPassphrase.signingKey.payload)
    }

    @Test("Policy keys differ from the CIP-1852 payment tree")
    func divergesFromPayment() throws {
        let policy = try Signer.Keygen.policy(mnemonic: TestFixtures.testMnemonic, policyIndex: 0)
        let payment = try Signer.Keygen.shelley(
            mnemonic: TestFixtures.testMnemonic, kind: .payment(account: 0, index: 0)
        )
        #expect(policy.signingKey.payload != payment.signingKey.payload)
    }

    @Test("Out-of-range policy index throws invalidDerivationPath")
    func rejectsOutOfRange() {
        #expect(throws: SignerError.self) {
            _ = try Signer.Keygen.policy(
                mnemonic: TestFixtures.testMnemonic,
                policyIndex: 0x8000_0000   // 2^31, one past the hardened max
            )
        }
    }
}
