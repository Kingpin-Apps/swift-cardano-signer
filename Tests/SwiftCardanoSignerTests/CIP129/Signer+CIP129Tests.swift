import Foundation
import Testing
import SwiftCardanoCIPs
@testable import SwiftCardanoSigner

@Suite("Signer.CIP129 — governance bech32 ID facade")
struct SignerCIP129Tests {

    static let testKeyHash = Data((0..<28).map { UInt8($0) })

    @Test("Facade encode/decode matches the cips implementation byte-for-byte",
          arguments: [
            (Signer.CIP129.Prefix.drep,    false),
            (.drep,    true),
            (.ccCold,  false),
            (.ccCold,  true),
            (.ccHot,   false),
            (.ccHot,   true),
            (.calidus, false),
          ])
    func facadeRoundTrip(prefix: Signer.CIP129.Prefix, isScript: Bool) throws {
        let viaFacade = try Signer.CIP129.encode(
            keyHash: Self.testKeyHash,
            as: prefix,
            isScript: isScript
        )
        let viaCIPs = try SwiftCardanoCIPs.CIP129.encode(
            keyHash: Self.testKeyHash,
            as: prefix,
            isScript: isScript
        )
        #expect(viaFacade == viaCIPs)

        let (decodedPrefix, decodedHash, decodedIsScript) =
            try Signer.CIP129.decode(viaFacade)
        #expect(decodedPrefix == prefix)
        #expect(decodedHash == Self.testKeyHash)
        #expect(decodedIsScript == isScript)
    }

    @Test("encode produces a bech32 string with the expected HRP")
    func bech32HRPs() throws {
        let drepID = try Signer.CIP129.encode(keyHash: Self.testKeyHash, as: .drep)
        #expect(drepID.hasPrefix("drep1"))

        let ccColdID = try Signer.CIP129.encode(keyHash: Self.testKeyHash, as: .ccCold)
        #expect(ccColdID.hasPrefix("cc_cold1"))

        let ccHotID = try Signer.CIP129.encode(keyHash: Self.testKeyHash, as: .ccHot)
        #expect(ccHotID.hasPrefix("cc_hot1"))

        let calidusID = try Signer.CIP129.encode(keyHash: Self.testKeyHash, as: .calidus)
        #expect(calidusID.hasPrefix("calidus1"))
    }

    @Test("Prefix is re-exported as a typealias from the cips implementation")
    func prefixTypeAlias() {
        let viaCIPs: SwiftCardanoCIPs.CIP129.Prefix = .drep
        let viaFacade: Signer.CIP129.Prefix = viaCIPs
        #expect(viaFacade == .drep)
    }
}
