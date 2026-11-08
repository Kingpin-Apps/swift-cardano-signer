import Foundation
import SwiftCardanoCore
import SwiftNaCl

public extension Signer {
    /// Verify an Ed25519 signature against a payload and verification key.
    ///
    /// Mirrors cardano-signer's default `verify` operation — pure
    /// Ed25519 detached-signature verification, no CIP envelope.
    ///
    /// For extended verification keys (64 bytes: 32-byte key + 32-byte chain
    /// code), only the first 32 bytes are used for verification — the chain
    /// code is irrelevant once the key has been derived.
    ///
    /// - Parameters:
    ///   - payload: The original bytes that were signed.
    ///   - signature: The 64-byte Ed25519 detached signature.
    ///   - verificationKey: A `VerificationKeyType` union, accepting either
    ///     32-byte verification keys or 64-byte extended verification keys.
    /// - Returns: `true` if the signature is valid, `false` if libsodium
    ///   rejects it for any reason (bad signature, key/payload mismatch).
    /// - Throws: ``SignerError/malformedSignature(_:)`` if the signature is
    ///   not 64 bytes, or ``SignerError/invalidVerificationKey(_:)`` if the
    ///   verification key cannot be loaded by libsodium.
    static func verify(
        payload: Data,
        signature: Data,
        verificationKey: VerificationKeyType
    ) throws -> Bool {
        guard signature.count == 64 else {
            throw SignerError.malformedSignature(
                "Ed25519 signature must be 64 bytes, got \(signature.count)"
            )
        }

        let publicKey: Data
        switch verificationKey {
        case .verificationKey(let key):
            publicKey = key.payload
        case .extendedVerificationKey(let key):
            guard key.payload.count == 64 else {
                throw SignerError.invalidVerificationKey(
                    "Extended verification key must be 64 bytes, got \(key.payload.count)"
                )
            }
            publicKey = key.payload.prefix(32)
        }

        let verifyKey: VerifyKey
        do {
            verifyKey = try VerifyKey(key: publicKey)
        } catch {
            throw SignerError.invalidVerificationKey(String(describing: error))
        }

        // libsodium's verify(smessage:signature:) throws on bad-signature; the
        // returned `Data` is the original message. For a pure boolean answer
        // we treat any throw as a verification failure rather than an error.
        do {
            _ = try verifyKey.verify(smessage: payload, signature: signature)
            return true
        } catch {
            return false
        }
    }
}
