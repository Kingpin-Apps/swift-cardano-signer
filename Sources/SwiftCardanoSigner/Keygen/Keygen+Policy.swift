import Foundation
import SwiftCardanoCore
import SwiftCardanoCIPs

public extension Signer.Keygen {
    /// Derive a CIP-1855 native-script minting-policy key from a BIP-39
    /// mnemonic.
    ///
    /// Minting-policy keys live on their own three-level, fully-hardened
    /// branch (`m/1855'/1815'/policy_ix'`) per
    /// [CIP-1855](https://cips.cardano.org/cip/CIP-1855) — separate from the
    /// CIP-1852 payment / stake trees. Each policy index yields a single
    /// Ed25519 key used to sign a `sig` native script (optionally
    /// time-locked).
    ///
    /// Equivalent to cardano-signer's `keygen --path 1855H/1815H/<ix>H`. The
    /// derivation path and the index range are owned by
    /// ``SwiftCardanoCIPs/CIP1855``; this function adds the BIP32-ED25519
    /// derivation via ``SwiftCardanoCore/HDWallet``.
    ///
    /// The derived keys reuse the *payment* extended-key envelope `type`
    /// strings, matching cardano-cli and cardano-signer (which treat policy
    /// keys as payment-class keys).
    ///
    /// - Parameters:
    ///   - mnemonic: BIP-39 mnemonic words. Language is auto-detected and the
    ///     checksum validated; an invalid phrase throws.
    ///   - passphrase: Optional BIP-39 passphrase (the "25th word"). Empty by
    ///     default.
    ///   - policyIndex: The CIP-1855 `policy_ix` (`0 ... 2³¹ − 1`).
    /// - Returns: The derived ``KeyPairBundle``.
    /// - Throws: ``SignerError/invalidDerivationPath(_:)`` if the index is out
    ///   of range or derivation fails, or the underlying
    ///   ``SwiftCardanoCore`` errors on mnemonic failures.
    static func policy(
        mnemonic: [String],
        passphrase: String = "",
        policyIndex: UInt32 = 0
    ) throws -> KeyPairBundle {
        let path: String
        do {
            path = try CIP1855.policyKeyPath(policyIndex: policyIndex)
        } catch {
            throw SignerError.invalidDerivationPath(
                "Invalid CIP-1855 policy index \(policyIndex): \(error)"
            )
        }

        let root = try HDWallet.fromMnemonic(
            mnemonic: mnemonic.joined(separator: " "),
            passphrase: passphrase
        )

        let derived: HDWallet
        do {
            derived = try root.derive(fromPath: path)
        } catch {
            throw SignerError.invalidDerivationPath(
                "Failed to derive \(path): \(error)"
            )
        }
        
        let signingPayload = derived.xPrivateKey + derived.publicKey + derived.chainCode
        let signingKey = ExtendedSigningKey(
            payload: signingPayload,
            type: PaymentExtendedSigningKey.TYPE,
            description: PaymentExtendedSigningKey.DESCRIPTION
        )

        let verificationKey = ExtendedVerificationKey(
            payload: derived.publicKey + derived.chainCode,
            type: PaymentExtendedVerificationKey.TYPE,
            description: PaymentExtendedVerificationKey.DESCRIPTION
        )

        return KeyPairBundle(
            signingKey: signingKey,
            verificationKey: verificationKey,
            path: derived.path
        )
    }
}
