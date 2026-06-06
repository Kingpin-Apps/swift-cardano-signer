import Foundation
import SwiftCardanoCore
import SwiftCardanoCIPs

public extension Signer {
    /// CIP-36 Catalyst voting registration / deregistration metadata builder.
    ///
    /// Mirrors cardano-signer's `sign --cip36` (with and without the
    /// `--deregister` flag). Delegates to ``SwiftCardanoCIPs/CIP36``;
    /// this namespace exists to anchor the operations under the
    /// `Signer.CIP36` shape that cardano-signer.js callers expect.
    ///
    /// See [CIP-0036](https://cips.cardano.org/cip/CIP-0036) for the wire
    /// format.
    enum CIP36 {

        /// Re-export of the cips delegation type so callers can reach it
        /// from a single import.
        public typealias Delegation = SwiftCardanoCIPs.CIP36.Delegation

        /// Build a CIP-36 registration metadata blob, signed by the
        /// voter's stake signing key.
        ///
        /// - Parameters:
        ///   - delegations: At least one ``Delegation`` (voting key +
        ///     weight share).
        ///   - stakeSigningKey: The voter's stake key (regular or
        ///     extended). Used both to derive the stake credential
        ///     (field `2`) and to sign the hashed `61284` map.
        ///   - rewardsAddress: Address that receives Catalyst rewards.
        ///   - nonce: Per-stake-credential monotonic nonce. Typically the
        ///     current mainnet slot height — see ``SlotNonce`` for the
        ///     time-based helper.
        ///   - votingPurpose: `0` = Catalyst (default). Reserved for
        ///     future non-Catalyst voting purposes.
        /// - Returns: An ``SwiftCardanoCore/AuxiliaryData`` carrying both
        ///   the registration map (label `61284`) and the witness map
        ///   (label `61285`).
        public static func makeRegistration(
            delegations: [Delegation],
            stakeSigningKey: SigningKeyType,
            rewardsAddress: Address,
            nonce: UInt64,
            votingPurpose: UInt64 = 0
        ) throws -> AuxiliaryData {
            return try SwiftCardanoCIPs.CIP36.makeRegistration(
                delegations: delegations,
                stakeSigningKey: stakeSigningKey,
                rewardsAddress: rewardsAddress,
                nonce: nonce,
                votingPurpose: votingPurpose
            )
        }

        /// Build a CIP-36 deregistration metadata blob.
        ///
        /// Deregistering causes the voter's stake credential to stop
        /// counting in subsequent Catalyst snapshots until a new
        /// registration lands.
        public static func makeDeregistration(
            stakeSigningKey: SigningKeyType,
            nonce: UInt64,
            votingPurpose: UInt64 = 0
        ) throws -> AuxiliaryData {
            return try SwiftCardanoCIPs.CIP36.makeDeregistration(
                stakeSigningKey: stakeSigningKey,
                nonce: nonce,
                votingPurpose: votingPurpose
            )
        }
    }
}
