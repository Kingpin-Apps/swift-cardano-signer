import Foundation
import SwiftCardanoCore
import SwiftCardanoCIPs

public extension Signer {
    /// CIP-0008 message signing — COSE_Sign1 wrapping of an arbitrary payload,
    /// with the signing address bound into the protected header.
    ///
    /// Mirrors cardano-signer's `sign --cip8` operation. Delegates to
    /// [`SwiftCardanoCIPs.CIP8`](https://github.com/Kingpin-Apps/swift-cardano-cips)
    /// — this enum exists purely to anchor the operation under the
    /// `Signer.CIP8` namespace so the public API matches cardano-signer's
    /// mental model. New behaviour should be added to `SwiftCardanoCIPs.CIP8`,
    /// not here.
    enum CIP8 {
        /// Sign an arbitrary byte payload following CIP-0008.
        ///
        /// The address bound into the COSE protected header is derived from
        /// the signing key — payment keys produce an `addr` enterprise
        /// address, stake keys produce a `stake` reward address. To bind a
        /// specific address, use the lower-level `SwiftCardanoCIPs.CIP8`
        /// directly.
        ///
        /// - Parameters:
        ///   - payload: Raw bytes to sign. cardano-signer's `hashed: false`
        ///     default applies — the payload is signed as-is, not hashed.
        ///   - signingKey: A payment or stake key (regular or extended).
        ///   - attachCoseKey: When `true`, the verification key is emitted as
        ///     a separate COSE_Key alongside the signed message; when `false`
        ///     (default), the verification key is embedded in the COSE
        ///     protected header via `KID`. CIP-30 wallet bridges typically
        ///     set this to `true`.
        ///   - network: Network ID used when deriving the protected-header
        ///     address from the signing key.
        /// - Returns: A `SignedMessage` carrying the hex-encoded COSE_Sign1
        ///   and (optionally) hex-encoded COSE_Key.
        /// - Throws: `SwiftCardanoCIPs.CIP8Error` on key / encoding failures,
        ///   propagated unchanged.
        public static func sign(
            payload: Data,
            signingKey: SigningKeyType,
            attachCoseKey: Bool = false,
            network: Network = .mainnet
        ) throws -> SignedMessage {
            return try SwiftCardanoCIPs.CIP8.sign(
                payload: payload,
                signingKey: signingKey,
                attachCoseKey: attachCoseKey,
                network: network
            )
        }

        /// Sign a UTF-8 string payload following CIP-0008.
        ///
        /// Convenience overload — the string is encoded as UTF-8 and then
        /// signed by ``sign(payload:signingKey:attachCoseKey:network:)``.
        public static func sign(
            message: String,
            signingKey: SigningKeyType,
            attachCoseKey: Bool = false,
            network: Network = .mainnet
        ) throws -> SignedMessage {
            return try SwiftCardanoCIPs.CIP8.sign(
                message: message,
                signingKey: signingKey,
                attachCoseKey: attachCoseKey,
                network: network
            )
        }

        /// Verify a CIP-0008 signed message.
        ///
        /// Decodes the COSE_Sign1, recovers the verification key (either from
        /// the attached COSE_Key or from the protected header's `KID`),
        /// verifies the signature, and confirms the protected-header address
        /// matches the verification key's hash.
        public static func verify(
            _ signedMessage: SignedMessage
        ) throws -> VerificationResult {
            return try SwiftCardanoCIPs.CIP8.verify(signedMessage: signedMessage)
        }
    }
}
