import Foundation
import Testing
@testable import SwiftCardanoSigner

@Suite("SlotNonce — Cardano mainnet time → slot height")
struct SlotNonceTests {

    @Test("Genesis constant matches the Cardano Foundation's published Shelley genesis (Unix 1596059091 = 2020-07-29 21:44:51 UTC)")
    func genesisConstant() {
        #expect(SlotNonce.mainnetShelleyGenesisUnix == 1_596_059_091)
    }

    @Test("Byron boundary slot constant is 4_492_800 (the slot at which Shelley-era 1s slots start)")
    func boundarySlotConstant() {
        #expect(SlotNonce.mainnetShelleyStartSlot == 4_492_800)
    }

    @Test("mainnetSlot at Shelley genesis Unix time returns the Byron→Shelley boundary slot")
    func slotAtGenesis() {
        let atGenesis = SlotNonce.mainnetSlot(at: SlotNonce.mainnetShelleyGenesisUnix)
        #expect(atGenesis == UInt64(SlotNonce.mainnetShelleyStartSlot))
    }

    @Test("mainnetSlot advances one slot per second after Shelley genesis")
    func slotAdvancesPerSecond() {
        let base = SlotNonce.mainnetSlot(at: SlotNonce.mainnetShelleyGenesisUnix)
        let plus10s = SlotNonce.mainnetSlot(at: SlotNonce.mainnetShelleyGenesisUnix + 10)
        let plusHour = SlotNonce.mainnetSlot(at: SlotNonce.mainnetShelleyGenesisUnix + 3600)
        #expect(plus10s == base + 10)
        #expect(plusHour == base + 3600)
    }

    @Test("mainnetSlot clamps to zero for timestamps before Shelley genesis")
    func clampsBeforeGenesis() {
        let preGenesis = SlotNonce.mainnetSlot(at: SlotNonce.mainnetShelleyGenesisUnix - 1)
        let waayBefore = SlotNonce.mainnetSlot(at: 0)
        #expect(preGenesis == 0)
        #expect(waayBefore == 0)
    }

    @Test("mainnetSlot is monotonic increasing past genesis", arguments: [
        SlotNonce.mainnetShelleyGenesisUnix + 0,
        SlotNonce.mainnetShelleyGenesisUnix + 1,
        SlotNonce.mainnetShelleyGenesisUnix + 1_000,
        SlotNonce.mainnetShelleyGenesisUnix + 86_400,
        SlotNonce.mainnetShelleyGenesisUnix + 31_536_000,
    ])
    func monotonicAfterGenesis(timestamp: Int64) {
        let earlier = SlotNonce.mainnetSlot(at: timestamp)
        let later = SlotNonce.mainnetSlot(at: timestamp + 1)
        #expect(later == earlier + 1)
    }
}
