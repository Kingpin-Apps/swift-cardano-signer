import Foundation
import CryptoSwift
import SwiftCardanoCore
import SwiftMnemonic

public extension Signer.Keygen {
    /// Derive a Trezor-Cardano–flavoured extended key from a BIP-39
    /// mnemonic, then derive along the requested role's CIP-1852 /
    /// CIP-1853 / CIP-1854 path.
    ///
    /// Equivalent to cardano-signer's `keygen --trezor`, and to the
    /// Trezor firmware's default `ICARUS_TREZOR` derivation type.
    ///
    /// The master key is the Icarus one — PBKDF2-HMAC-SHA512 with the
    /// passphrase as password, 4096 rounds, 96 bytes, then the Ed25519
    /// clamp — with one Trezor quirk: for a 24-word phrase the salt is
    /// the entropy **with its checksum byte appended** (33 bytes), where
    /// Icarus uses the 32-byte entropy alone. For 12, 15, 18 and 21
    /// words the two derivations agree.
    ///
    /// Checked against the Trezor firmware emulator: for the 24-word
    /// `abandon … art` phrase the account key `m/1852'/1815'/0'` matches
    /// the device's `ICARUS_TREZOR` result, which differs from `ICARUS`.
    ///
    /// - Parameters:
    ///   - mnemonic: BIP-39 mnemonic words; the checksum is validated.
    ///   - passphrase: Optional BIP-39 passphrase.
    ///   - kind: Which role's path to derive.
    /// - Returns: The derived ``KeyPairBundle``.
    static func trezor(
        mnemonic: [String],
        passphrase: String = "",
        kind: ShelleyKeyKind
    ) throws -> KeyPairBundle {
        try kind.validate()
        let root = try trezorRoot(mnemonic: mnemonic, passphrase: passphrase)
        let derived: HDWallet
        do {
            derived = try root.derive(fromPath: kind.path)
        } catch {
            throw SignerError.invalidDerivationPath("Failed to derive \(kind.path): \(error)")
        }
        let signingKey = try ExtendedSigningKey(
            payload: derived.xPrivateKey + derived.publicKey + derived.chainCode,
            type: kind.envelopeTypeSigning,
            description: kind.envelopeDescriptionSigning
        )
        let verificationKey = ExtendedVerificationKey(
            payload: derived.publicKey + derived.chainCode,
            type: kind.envelopeTypeSigning.replacingOccurrences(of: "Signing", with: "Verification"),
            description: kind.envelopeDescriptionSigning.replacingOccurrences(of: "Signing", with: "Verification")
        )
        return KeyPairBundle(signingKey: signingKey, verificationKey: verificationKey, path: derived.path)
    }

    /// The `ICARUS_TREZOR` root wallet node for a mnemonic.
    internal static func trezorRoot(mnemonic: [String], passphrase: String) throws -> HDWallet {
        let words = mnemonic.joined(separator: " ")
            .decomposedStringWithCompatibilityMapping
            .split(whereSeparator: { $0.isWhitespace })
            .map(String.init)
        let parsed: Mnemonic
        do {
            parsed = try Mnemonic(from: words)
        } catch {
            throw SignerError.invalidMnemonic(String(describing: error))
        }
        var salt = Data(parsed.entropy)
        if words.count == 24 {
            // 24 words carry 256 bits of entropy and an 8-bit checksum;
            // Trezor salts PBKDF2 with all 264 bits.
            salt.append(Data(SHA2(variant: .sha256).calculate(for: Array(parsed.entropy)))[0])
        }
        let seed = HDWallet.generateSeed(passphrase: passphrase, entropy: salt)
        return try HDWallet.fromSeed(seedData: seed)
    }
}
