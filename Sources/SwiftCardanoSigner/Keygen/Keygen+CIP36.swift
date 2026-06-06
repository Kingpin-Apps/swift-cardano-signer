import Foundation
import SwiftCardanoCore

public extension Signer.Keygen {
    /// Derive a CIP-36 vote-key pair from a BIP-39 mnemonic.
    ///
    /// CIP-36 voting keys are *separate* from payment and stake credentials —
    /// they live on a dedicated derivation tree
    /// (`m/1694'/1815'/account'/0/address`) per
    /// [CIP-0036 §6](https://cips.cardano.org/cip/CIP-0036). Voting power is
    /// delegated *to* these keys; the keys themselves never spend funds.
    ///
    /// Equivalent to cardano-signer's `keygen --cip36`.
    ///
    /// - Parameters:
    ///   - mnemonic: BIP-39 mnemonic words.
    ///   - passphrase: Optional BIP-39 passphrase.
    ///   - account: Hardened account index (default `0`).
    ///   - address: Unhardened address index (default `0`).
    /// - Returns: A ``CIP36VoteKeyPair``.
    static func cip36(
        mnemonic: [String],
        passphrase: String = "",
        account: UInt32 = 0,
        address: UInt32 = 0
    ) throws -> CIP36VoteKeyPair {
        let root = try HDWallet.fromMnemonic(
            mnemonic: mnemonic.joined(separator: " "),
            passphrase: passphrase
        )

        let path = CardanoPaths.cip36(account: account, address: address)
        let derived: HDWallet
        do {
            derived = try root.derive(fromPath: path)
        } catch {
            throw SignerError.invalidDerivationPath(
                "Failed to derive CIP-36 path \(path): \(error)"
            )
        }

        let signingPayload = derived.xPrivateKey + derived.publicKey + derived.chainCode
        let signingKey = ExtendedSigningKey(
            payload: signingPayload,
            type: "CIP36VoteExtendedSigningKey_ed25519_bip32",
            description: "Catalyst Vote Signing Key"
        )

        let verificationKey = ExtendedVerificationKey(
            payload: derived.publicKey + derived.chainCode,
            type: "CIP36VoteExtendedVerificationKey_ed25519_bip32",
            description: "Catalyst Vote Verification Key"
        )

        return CIP36VoteKeyPair(
            signingKey: signingKey,
            verificationKey: verificationKey,
            path: derived.path
        )
    }
}
