import Foundation
import Testing
import SwiftCardanoCore
@testable import SwiftCardanoSigner

@Suite("Signer.Keygen.trezor — Trezor mnemonic derivation")
struct KeygenTrezorTests {

    /// Account keys `m/1852'/1815'/0'` (public key ‖ chain code) read from
    /// the Trezor firmware emulator (trezor-user-env, 2026-11-08) with
    /// CardanoGetPublicKey and derivation types ICARUS (1) and
    /// ICARUS_TREZOR (2).
    static let emulator24Icarus = "b3f8aad750c8f498d2882d1ecd74bf550e81870e89acaed82e8e10ef5871887091286d601ecfe0aafc2121154db787bf489ccf35c6b5db5d60096052c8b34c2f"
    static let emulator24IcarusTrezor = "5e7708a4da16890d03445f8beb02d37c1a00967d5670522e54dbf255f10b9a77aaaf203d157fbf17f39dc5cd2baebcfb4f67735928a64a15b766562bc486c606"
    static let emulator12 = "d507c8f866691bd96e131334c355188b1a1d0b2fa0ab11545075aab332d77d9eb19657ad13ee581b56b0f8d744d66ca356b93d42fe176b3de007d53e9c4c4e7a"

    static func accountKey(_ wallet: HDWallet) throws -> String {
        let account = try wallet.derive(fromPath: "m/1852'/1815'/0'")
        return (account.publicKey + account.chainCode).map { String(format: "%02x", $0) }.joined()
    }

    @Test("24 words: Trezor matches the firmware's ICARUS_TREZOR key, not plain ICARUS")
    func trezor24MatchesFirmware() throws {
        let trezor = try Signer.Keygen.trezorRoot(mnemonic: TestFixtures.testMnemonic, passphrase: "")
        #expect(try Self.accountKey(trezor) == Self.emulator24IcarusTrezor)
        let icarus = try HDWallet.fromMnemonic(mnemonic: TestFixtures.testMnemonicJoined)
        #expect(try Self.accountKey(icarus) == Self.emulator24Icarus)
    }

    @Test("12 words: Trezor and ICARUS agree with the firmware")
    func trezor12MatchesFirmware() throws {
        let words = Array(repeating: "all", count: 12)
        #expect(try Self.accountKey(Signer.Keygen.trezorRoot(mnemonic: words, passphrase: "")) == Self.emulator12)
        let icarus = try HDWallet.fromMnemonic(mnemonic: words.joined(separator: " "))
        #expect(try Self.accountKey(icarus) == Self.emulator12)
        let trezor = try Signer.Keygen.trezor(mnemonic: words, kind: .stake())
        let shelley = try Signer.Keygen.shelley(mnemonic: words, kind: .stake())
        #expect(trezor.signingKey.payload == shelley.signingKey.payload)
    }

    @Test("Trezor rejects an invalid mnemonic")
    func trezorRejectsInvalidMnemonic() {
        #expect(throws: SignerError.self) {
            _ = try Signer.Keygen.trezor(mnemonic: Array(repeating: "abandon", count: 12), kind: .payment())
        }
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
