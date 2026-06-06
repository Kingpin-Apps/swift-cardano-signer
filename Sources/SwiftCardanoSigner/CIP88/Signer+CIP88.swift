import Foundation
import SwiftCardanoCore
import SwiftCardanoCIPs

public extension Signer {
    /// CIP-88 v2 / CIP-151 Calidus pool-key registration.
    ///
    /// Mirrors cardano-signer's `sign --cip88` (and the synonym
    /// `--cip151`). Delegates to ``SwiftCardanoCIPs/CIP88`` for the
    /// actual byte layout — the facade exists to anchor the operation
    /// under the `Signer.CIP88` namespace that cardano-signer.js callers
    /// expect.
    ///
    /// See [CIP-0088](https://cips.cardano.org/cip/CIP-0088) and
    /// [CIP-0151](https://cips.cardano.org/cip/CIP-0151) for the wire
    /// format.
    enum CIP88 {

        /// Build a CIP-151 Calidus pool-key registration `AuxiliaryData`.
        ///
        /// - Parameters:
        ///   - calidusPublicKey: 32-byte Ed25519 public key to register
        ///     as the pool's Calidus operational key.
        ///   - poolSigningKey: The pool cold signing key. Must produce a
        ///     32-byte (non-extended) verification key.
        ///   - nonce: Per-pool monotonic nonce. Typically the current
        ///     mainnet slot height — see ``SlotNonce``.
        public static func makeCalidusRegistration(
            calidusPublicKey: Data,
            poolSigningKey: SigningKeyType,
            nonce: UInt64
        ) throws -> AuxiliaryData {
            return try SwiftCardanoCIPs.CIP88.makeCalidusRegistration(
                calidusPublicKey: calidusPublicKey,
                poolSigningKey: poolSigningKey,
                nonce: nonce
            )
        }
    }
}

public extension Signer {
    /// Re-export under the `Signer.CIP151` alias.
    ///
    /// cardano-signer's CLI accepts both `--cip88` and `--cip151` for
    /// Calidus registration. Both routes here resolve to the same
    /// underlying builder.
    enum CIP151 {
        /// Equivalent to ``Signer/CIP88/makeCalidusRegistration(calidusPublicKey:poolSigningKey:nonce:)``.
        public static func makeCalidusRegistration(
            calidusPublicKey: Data,
            poolSigningKey: SigningKeyType,
            nonce: UInt64
        ) throws -> AuxiliaryData {
            return try Signer.CIP88.makeCalidusRegistration(
                calidusPublicKey: calidusPublicKey,
                poolSigningKey: poolSigningKey,
                nonce: nonce
            )
        }
    }
}
