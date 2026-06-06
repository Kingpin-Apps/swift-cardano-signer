import Foundation

/// Helper for computing a Cardano mainnet slot-height nonce from a
/// real-world timestamp, used by ``Signer/CIP36`` and ``Signer/CIP88``
/// when the caller doesn't supply an explicit nonce.
///
/// CIP-36 / CIP-88 nonces must be monotonically increasing per stake
/// credential / pool key. The slot height is a natural choice — it's
/// strictly monotonic and freely derivable from any timestamp. This
/// helper implements the same mainnet time→slot mapping cardano-signer.js
/// uses.
public enum SlotNonce {

    /// Cardano mainnet's Shelley-era genesis Unix timestamp
    /// (2020-07-29 21:44:51 UTC). Slot 0 of the Shelley era lands here.
    public static let mainnetShelleyGenesisUnix: Int64 = 1_596_059_091

    /// Cardano mainnet's Byron-era slot number at the boundary into
    /// Shelley — required because the Byron era used 20 s slots and the
    /// Shelley era uses 1 s slots, and the on-chain slot counter is
    /// continuous across the boundary.
    public static let mainnetShelleyStartSlot: Int64 = 4_492_800

    /// Compute the mainnet slot height for a given Unix timestamp.
    ///
    /// - Parameter unixTime: Seconds since epoch. Pass a stable timestamp
    ///   captured at call sites; this helper does *not* read the wall
    ///   clock so that callers can keep their inputs deterministic
    ///   (`Date.now` is unavailable in some toolchains).
    /// - Returns: The mainnet slot number at that timestamp. The result
    ///   is clamped to zero for timestamps before Shelley genesis.
    public static func mainnetSlot(at unixTime: Int64) -> UInt64 {
        let deltaSeconds = unixTime - mainnetShelleyGenesisUnix
        guard deltaSeconds >= 0 else { return 0 }
        // Shelley-era slots are one second long. Add the Byron-era slot
        // offset so the result is continuous with on-chain slot numbers.
        return UInt64(mainnetShelleyStartSlot + deltaSeconds)
    }
}
