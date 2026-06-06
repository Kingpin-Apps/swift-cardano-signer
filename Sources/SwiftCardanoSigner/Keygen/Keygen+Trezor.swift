import Foundation
import CryptoSwift
import SwiftCardanoCore
import SwiftMnemonic

public extension Signer.Keygen {
    /// Derive a Trezor-Cardano–flavoured extended key from a BIP-39
    /// mnemonic, then derive along the requested role's CIP-1852 /
    /// CIP-1853 / CIP-1854 path.
    ///
    /// Equivalent to cardano-signer's `keygen --trezor`.
    ///
    /// Trezor's Cardano implementation uses the **same** master-key
    /// derivation as ICARUS (PBKDF2-HMAC-SHA512 with the passphrase as
    /// password and the BIP-39 entropy as salt, 4096 rounds, 96-byte
    /// output, then standard Ed25519 scalar clamping). The Trezor /
    /// Yoroi differentiation lives upstream in the **mnemonic →
    /// entropy** step (Trezor's firmware historically padded short
    /// mnemonics differently); BIP-39's canonical normalisation makes
    /// this transparent here.
    ///
    /// In practice this means `trezor(...)` and the ICARUS path inside
    /// ``Signer/Keygen/shelley(mnemonic:passphrase:kind:)`` produce
    /// identical keys for the same mnemonic. The separate entry point
    /// exists so cardano-signer.js–compatible callers can pass through
    /// the `--trezor` flag without code branching, and so a future
    /// Trezor-specific tweak (firmware quirk, BIP-39 padding rule)
    /// can land here without breaking the Shelley path.
    ///
    /// - Parameters:
    ///   - mnemonic: BIP-39 mnemonic words.
    ///   - passphrase: Optional BIP-39 passphrase.
    ///   - kind: Which role's path to derive.
    /// - Returns: The derived ``KeyPairBundle``.
    static func trezor(
        mnemonic: [String],
        passphrase: String = "",
        kind: ShelleyKeyKind
    ) throws -> KeyPairBundle {
        // Trezor master key derivation = ICARUS:
        //   PBKDF2-HMAC-SHA512(password = passphrase,
        //                      salt     = BIP-39 entropy bytes,
        //                      rounds   = 4096,
        //                      length   = 96)
        // followed by the standard Ed25519 scalar clamp on bytes 0 / 31.
        //
        // We can reach this exact pipeline through `HDWallet.fromMnemonic`,
        // which is the ICARUS implementation used by
        // ``Signer/Keygen/shelley(mnemonic:passphrase:kind:)``.
        return try Signer.Keygen.shelley(
            mnemonic: mnemonic,
            passphrase: passphrase,
            kind: kind
        )
    }
}
