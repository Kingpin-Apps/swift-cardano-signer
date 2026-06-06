import Foundation
import Testing
import SwiftCardanoCore
@testable import SwiftCardanoSigner

@Suite("Signer.Keygen.ledger — HW-wallet derivation")
struct KeygenLedgerTests {

    // MARK: - High-level shelley() path

    @Test("Ledger payment keygen produces a sign-verify-able extended key")
    func paymentRoundTrip() throws {
        let bundle = try Signer.Keygen.ledger(
            mnemonic: TestFixtures.testMnemonic,
            kind: .payment()
        )
        #expect(bundle.signingKey.payload.count == 128)
        #expect(bundle.verificationKey.payload.count == 64)

        let payload = Data("ledger test".utf8)
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

    @Test("Ledger derivation differs from ICARUS for the same mnemonic")
    func ledgerVsIcarus() throws {
        let ledger = try Signer.Keygen.ledger(
            mnemonic: TestFixtures.testMnemonic, kind: .payment()
        )
        let icarus = try Signer.Keygen.shelley(
            mnemonic: TestFixtures.testMnemonic, kind: .payment()
        )
        #expect(ledger.signingKey.payload != icarus.signingKey.payload)
    }

    @Test("Ledger passphrase changes the derived key")
    func passphraseChanges() throws {
        let withoutPassphrase = try Signer.Keygen.ledger(
            mnemonic: TestFixtures.testMnemonic, kind: .payment()
        )
        let withPassphrase = try Signer.Keygen.ledger(
            mnemonic: TestFixtures.testMnemonic, passphrase: "25th word!",
            kind: .payment()
        )
        #expect(withoutPassphrase.signingKey.payload != withPassphrase.signingKey.payload)
    }

    // MARK: - Master key (low-level helper)

    @Test("ledgerMasterKey is deterministic for the same mnemonic + passphrase")
    func masterKeyDeterministic() throws {
        let a = try Signer.Keygen.ledgerMasterKey(mnemonic: TestFixtures.testMnemonicJoined)
        let b = try Signer.Keygen.ledgerMasterKey(mnemonic: TestFixtures.testMnemonicJoined)
        #expect(a == b)
        #expect(a.count == 96, "Ledger master key is 64 (tweaked private) + 32 (chain code) = 96 bytes")
    }

    @Test("ledgerMasterKey applies the Ed25519 scalar clamp")
    func masterKeyHasClamp() throws {
        let master = try Signer.Keygen.ledgerMasterKey(mnemonic: TestFixtures.testMnemonicJoined)
        // Standard Ed25519 scalar clamp:
        //   byte 0  — low 3 bits clear
        //   byte 31 — top bit clear, bit 6 set
        // Plus the Ledger-specific recursion invariant:
        //   byte 31 — bit 5 clear (this is the terminating condition for
        //   the iterative HMAC-SHA512 loop)
        #expect(master[0]  & 0b0000_0111 == 0)
        #expect(master[31] & 0b1000_0000 == 0)
        #expect(master[31] & 0b0100_0000 != 0)
        #expect(master[31] & 0b0010_0000 == 0)
    }

    @Test("ledgerMasterKey is sensitive to the passphrase")
    func masterKeyPassphraseSensitive() throws {
        let a = try Signer.Keygen.ledgerMasterKey(mnemonic: TestFixtures.testMnemonicJoined)
        let b = try Signer.Keygen.ledgerMasterKey(
            mnemonic: TestFixtures.testMnemonicJoined,
            passphrase: "different"
        )
        #expect(a != b)
    }
}
