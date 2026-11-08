import Foundation
import SwiftCardanoCore

public extension Signer.Keygen {
    /// Derive a Shelley-era extended key for one of the seven canonical
    /// Cardano roles, starting from a BIP-39 mnemonic.
    ///
    /// Equivalent to cardano-signer's `keygen --path payment|stake|drep|cc-cold|cc-hot|pool|calidus`.
    /// Uses the standard ICARUS master-key derivation
    /// (PBKDF2-HMAC-SHA512, 4096 rounds) via ``SwiftCardanoCore/HDWallet``.
    /// For Ledger / Trezor variant derivations, see Phase 8.
    ///
    /// - Parameters:
    ///   - mnemonic: BIP-39 mnemonic words. Language is auto-detected by
    ///     the wordlist (English, Japanese, Spanish, …) and the checksum
    ///     is validated; an invalid phrase throws.
    ///   - passphrase: Optional BIP-39 passphrase (the "25th word"). Empty
    ///     by default. Different passphrases produce wholly different key
    ///     trees from the same mnemonic — this is part of the standard
    ///     BIP-39 design, not a side channel.
    ///   - kind: Which role's path to derive. See ``ShelleyKeyKind``.
    /// - Returns: The derived ``KeyPairBundle``.
    /// - Throws: ``SignerError/invalidDerivationPath(_:)`` on path parse
    ///   failures, or the underlying ``SwiftCardanoCore/BIP32Error`` /
    ///   ``SwiftCardanoCore/CardanoCoreError`` cases on mnemonic / derivation
    ///   failures.
    static func shelley(
        mnemonic: [String],
        passphrase: String = "",
        kind: ShelleyKeyKind
    ) throws -> KeyPairBundle {
        try kind.validate()
        let root = try HDWallet.fromMnemonic(
            mnemonic: mnemonic.joined(separator: " "),
            passphrase: passphrase
        )

        let derived: HDWallet
        do {
            derived = try root.derive(fromPath: kind.path)
        } catch {
            throw SignerError.invalidDerivationPath(
                "Failed to derive \(kind.path): \(error)"
            )
        }

        let signingPayload = derived.xPrivateKey + derived.publicKey + derived.chainCode
        let signingKey = try ExtendedSigningKey(
            payload: signingPayload,
            type: kind.envelopeTypeSigning,
            description: kind.envelopeDescriptionSigning
        )

        // Extended verification keys are 64 bytes: 32-byte public key + 32-byte
        // chain code. The chain code is what enables further (public) child
        // derivation without the private key.
        let verificationKey = ExtendedVerificationKey(
            payload: derived.publicKey + derived.chainCode,
            type: kind.envelopeTypeSigning
                .replacingOccurrences(of: "Signing", with: "Verification"),
            description: kind.envelopeDescriptionSigning
                .replacingOccurrences(of: "Signing", with: "Verification")
        )

        return KeyPairBundle(
            signingKey: signingKey,
            verificationKey: verificationKey,
            path: derived.path
        )
    }
}
