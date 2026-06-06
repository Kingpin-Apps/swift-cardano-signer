import Foundation
import Testing
import SwiftCardanoCore
@testable import SwiftCardanoSigner

@Suite("Signer.Keygen.trezor — Trezor mnemonic derivation")
struct KeygenTrezorTests {

    @Test("Trezor matches ICARUS at the byte level for the same mnemonic + passphrase + kind")
    func trezorMatchesIcarus() throws {
        // cardano-signer.js does NOT differentiate Trezor from ICARUS at
        // the master-key level (the only differentiation lives in the
        // mnemonic→entropy step, which BIP-39 normalisation handles
        // transparently). Until a Trezor-specific firmware quirk shows
        // up, `trezor(...)` is a literal pass-through to `shelley(...)`.
        let trezor = try Signer.Keygen.trezor(
            mnemonic: TestFixtures.testMnemonic, kind: .payment()
        )
        let icarus = try Signer.Keygen.shelley(
            mnemonic: TestFixtures.testMnemonic, kind: .payment()
        )
        #expect(trezor.signingKey.payload == icarus.signingKey.payload)
        #expect(trezor.verificationKey.payload == icarus.verificationKey.payload)
    }

    @Test("Trezor matches ICARUS for every Shelley role kind",
          arguments: [
            ShelleyKeyKind.payment(),
            .stake(),
            .drep(),
            .ccCold(),
            .ccHot(),
            .pool(),
            .calidus(),
          ])
    func trezorMatchesIcarusAllRoles(kind: ShelleyKeyKind) throws {
        let trezor = try Signer.Keygen.trezor(
            mnemonic: TestFixtures.testMnemonic, kind: kind
        )
        let icarus = try Signer.Keygen.shelley(
            mnemonic: TestFixtures.testMnemonic, kind: kind
        )
        #expect(trezor.signingKey.payload == icarus.signingKey.payload)
        #expect(trezor.verificationKey.payload == icarus.verificationKey.payload)
    }

    @Test("Trezor passphrase changes the derived key")
    func passphraseChangesDerivation() throws {
        let withoutPassphrase = try Signer.Keygen.trezor(
            mnemonic: TestFixtures.testMnemonic, kind: .payment()
        )
        let withPassphrase = try Signer.Keygen.trezor(
            mnemonic: TestFixtures.testMnemonic, passphrase: "trezor 25",
            kind: .payment()
        )
        #expect(withoutPassphrase.signingKey.payload != withPassphrase.signingKey.payload)
    }
}
