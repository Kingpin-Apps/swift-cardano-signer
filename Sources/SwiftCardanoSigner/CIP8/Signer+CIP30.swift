import Foundation
import SwiftCardanoCore
import SwiftCardanoCIPs

public extension Signer {
    /// CIP-0030 dApp-wallet signing operations.
    ///
    /// CIP-0030 `signData` is, in practice, CIP-0008 with the COSE key
    /// attached. cardano-signer treats `sign --cip30` as an alias of
    /// `sign --cip8 --include-maps`; this facade does the same.
    ///
    /// For full dApp-bridge integration (granted-extension policy, key store,
    /// per-operation approval), use
    /// `SwiftCardanoCIPs.KeyStoreCIP30Provider` directly — `Signer.CIP30` only
    /// covers the off-line signing primitive.
    enum CIP30 {
        /// Sign an arbitrary byte payload as a CIP-0030 `signData` response.
        ///
        /// Equivalent to ``Signer/CIP8/sign(payload:signingKey:attachCoseKey:network:)``
        /// with `attachCoseKey: true` — the verification key is returned as
        /// a separate `COSE_Key` so the dApp can verify without prior
        /// knowledge of the wallet's key set.
        public static func signData(
            payload: Data,
            signingKey: SigningKeyType,
            network: Network = .mainnet
        ) throws -> SignedMessage {
            return try SwiftCardanoCIPs.CIP8.sign(
                payload: payload,
                signingKey: signingKey,
                attachCoseKey: true,
                network: network
            )
        }

        /// Verify a CIP-0030 `signData` response.
        ///
        /// Same wire format as CIP-0008, so this delegates to
        /// ``Signer/CIP8/verify(_:)`` without modification.
        public static func verify(
            _ signedMessage: SignedMessage
        ) throws -> VerificationResult {
            return try SwiftCardanoCIPs.CIP8.verify(signedMessage: signedMessage)
        }
    }
}
