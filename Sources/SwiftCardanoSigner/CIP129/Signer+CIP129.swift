import Foundation
import SwiftCardanoCIPs

public extension Signer {
    /// CIP-129 / CIP-151 bech32-prefixed governance identifiers.
    ///
    /// Mirrors cardano-signer's `--id` / `--id-output` shorthand for
    /// encoding dRep, Constitutional Committee (cold/hot), and Calidus
    /// pool-operator key hashes. Delegates to
    /// ``SwiftCardanoCIPs/CIP129`` for the actual byte layout — see that
    /// type for the spec-level header-byte table.
    enum CIP129 {

        /// Re-export of ``SwiftCardanoCIPs/CIP129/Prefix`` so callers can
        /// reach it under the `Signer.CIP129` namespace without a separate
        /// import.
        public typealias Prefix = SwiftCardanoCIPs.CIP129.Prefix

        /// Encode a 28-byte Blake2b-224 key hash as a CIP-129 bech32 ID.
        ///
        /// - Parameters:
        ///   - keyHash: 28 bytes — the Blake2b-224 hash of the
        ///     verification key or script.
        ///   - prefix: One of `.drep / .ccCold / .ccHot / .calidus`.
        ///   - isScript: Whether the hash represents a script (encodes the
        ///     script-form header byte). Calidus has no script form.
        public static func encode(
            keyHash: Data,
            as prefix: Prefix,
            isScript: Bool = false
        ) throws -> String {
            return try SwiftCardanoCIPs.CIP129.encode(
                keyHash: keyHash,
                as: prefix,
                isScript: isScript
            )
        }

        /// Decode a CIP-129 / CIP-151 bech32 ID into its prefix, key hash,
        /// and script flag.
        public static func decode(
            _ bech32: String
        ) throws -> (prefix: Prefix, keyHash: Data, isScript: Bool) {
            return try SwiftCardanoCIPs.CIP129.decode(bech32)
        }
    }
}
