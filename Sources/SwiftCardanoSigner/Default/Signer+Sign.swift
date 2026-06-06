import Foundation
import SwiftCardanoCore

public extension Signer {
    /// Sign an arbitrary payload with an Ed25519 signing key.
    ///
    /// Accepts both 32-byte seed (`SigningKeyType.signingKey`) and 128-byte
    /// extended (`SigningKeyType.extendedSigningKey`, BIP32-ED25519) keys.
    /// The returned `SignatureResult` includes the 32-byte verification key
    /// derived from the signing key — for extended keys this is the
    /// chain-code-stripped non-extended verification key, matching how
    /// signatures are advertised on Cardano.
    ///
    /// This is the equivalent of cardano-signer's default `sign` operation
    /// (no `--cip*` flag). For CIP-8 / CIP-30 wrapped signing, see
    /// ``Signer/signCIP8(payload:signingKey:address:hashPayload:attachCoseKey:network:)``.
    ///
    /// - Parameters:
    ///   - payload: The raw bytes to sign. Hashing, if any, is the caller's
    ///     responsibility — this method signs the bytes as-is.
    ///   - signingKey: A `SigningKeyType` union value, accepting either a
    ///     32-byte seed key or a 128-byte extended (BIP32-ED25519) key.
    /// - Returns: The 64-byte Ed25519 signature plus the 32-byte derived
    ///   verification key.
    /// - Throws: ``SignerError/invalidSigningKey(_:)`` if the underlying
    ///   crypto rejects the key payload.
    static func sign(
        payload: Data,
        signingKey: SigningKeyType
    ) throws -> SignatureResult {
        let signature: Data
        do {
            signature = try signingKey.sign(data: payload)
        } catch {
            throw SignerError.invalidSigningKey(String(describing: error))
        }

        let vkeyType: VerificationKeyType
        do {
            vkeyType = try signingKey.toVerificationKeyType()
        } catch {
            throw SignerError.invalidSigningKey(String(describing: error))
        }

        // For extended verification keys (64 bytes), strip the trailing
        // chain code so callers always get the 32-byte form that matches a
        // Cardano vkey witness.
        let publicKey: Data
        switch vkeyType {
        case .verificationKey(let key):
            publicKey = key.payload
        case .extendedVerificationKey(let key):
            publicKey = key.payload.prefix(32)
        }

        return SignatureResult(signature: signature, publicKey: publicKey)
    }
}
