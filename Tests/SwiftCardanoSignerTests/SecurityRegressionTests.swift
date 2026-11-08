import Foundation
import Testing
import SwiftCardanoCore
@testable import SwiftCardanoSigner

/// Regression tests for the 2026-11-08 security audit.
@Suite("Security regressions — keygen, sign and verify")
struct SecurityRegressionTests {

    // MARK: Daedalus derivation scheme 1

    /// cardano-crypto golden vectors (tests/goldens/cardano/crypto/wallet/BIP39-128),
    /// derivation-scheme1 with retry-old master keys, mnemonic
    /// "ring crime symptom enough erupt lady behave ramp apart settle citizen junk".
    /// Each xPriv is kL ‖ kR ‖ public key ‖ chain code.
    static let daedalusWords = "ring crime symptom enough erupt lady behave ramp apart settle citizen junk"
    static let daedalusVectors: [([UInt32], String)] = [
        ([], "6065a956b1b34145c4416fdc3ba3276801850e91a77a31a7be782463288aea5360ba6e25b1a02157fb69c5d1d7b96c4619736e545447069a6a6f0ba90844bc8e64b20fa082b3143d6b5eed42c6ef63f99599d0888afe060620abc1b319935fe1739f4b3caca4c9ad4fcd4bdc2ef42c8601af8d6946999ef85ef6ae84f66e72eb"),
        ([2147483648], "e7d27516538403a53a8b041656a3f570909df641a0ab811fe7d87c9ba02a830c794a2c54ad8b525b781773c87d38cbf4197636bc427a9d551368286fe4c294a495bb82ffd5707716bc65170ab4e8dafeed90fbe0ce9258713b7751e962d931df6755cb82e892d6614c007a5efbceb21d95a5244e269d0e206b48b9a495390b03"),
        ([2147483649], "9b5a3d9a4c60bcd49bb64b72c082b164314d0f61d842f2575fd1d4fb30a28a0cb093e376f41eb7bf80abcd0073a52455d25b5d21815bc758e5f6f81536aedebb79fc8154554b97e4c56ef2f9dbb4c1421ff19509688931a1e964bda5dec0f19f47a242713bd18608231147c066b6083bfc1e9066fec9f621844c84fed6228a34"),
        ([2147483648, 2147483649], "52e0c98aa600cfdcd1ff28fcda5227ed87063f4a98547a78b771052cf102b40c6c18d9f8075b1a6a1833540607479bd58b7beb8a83d2bb01ca7ae02452a25803dc907c7c06e6314eedd9e18c9f6c6f9cc4e205fb1c70da608234c319f1f7b0d6d6798491b9fa4612370ae5ef3c623a0b6872f3ad8f26970885fa67c83bdc425e"),
        ([2147483648, 2147483649, 2147483650], "11fd6462a3a92b35c22703f6f1c124ddcf36b7c2b09cc2784f320e1cfa12ec04c2785803c61c46aeca192a1bb1b7b20a8c4cc7fa01db57fc5d1d8a5473402352839775a41876e328986aa26168958bba1176e67819b357eea84afceab8b1db784169a2a32e3618a903e930bd1a713033a38f92389093408394e29ac37a1752ea"),
        ([2147483648, 2147483649, 2147483650, 2147483650], "5b1e5cad02274ba461f4708d8598d3497faf8fe3e894a379573aa6ac3a03e505ba179d2e3c67aabb486c48d16002b51ad32eab434c738a1550962313b07098cd75eb8d197ec8627c85af88e66aa1e49065dd8ac98ed8991db52ece01635dfb763ae9c99a5925cba2dcf121baf3a0254f3dea23c129f9eb70a8a7e8897c5199ba"),
        ([2147483648, 2147483649, 2147483650, 2147483650, 3147483648], "624b47150f58dfa44284fbc63c9f99b9b79f808c4955a461f0e2be44eb0be50d097aa006d694b165ef37cf23562e5967c96e49255d2f20faae478dee83aa5b020588589cd9b51dfc028cf225674069cbe52e0e70deb02dc45b79b26ee3548b0015c450b86dd7dd83b31951d9ee03eb1a7925161d817bd517c69cf09e3671f1ca"),
    ]

    static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

    @Test("Daedalus master and child keys match cardano-crypto's scheme-1 golden vectors")
    func daedalusGoldenVectors() throws {
        let master = try Signer.Keygen.daedalusMasterKey(mnemonic: Self.daedalusWords)
        for (path, xPriv) in Self.daedalusVectors {
            var node = DaedalusDerivation.Node(key: master.prefix(64), chainCode: master.suffix(32))
            for index in path { node = try DaedalusDerivation.derive(node, index: index) }
            #expect(Self.hex(node.key + (try node.publicKey) + node.chainCode) == xPriv, "path \(path)")
        }
    }

    @Test("Signer.Keygen.byron(.daedalus) returns the golden m/0' key")
    func daedalusPublicAPI() throws {
        let words = Self.daedalusWords.split(separator: " ").map(String.init)
        let bundle = try Signer.Keygen.byron(mnemonic: words, variant: .daedalus,
                                             path: try ByronPath(indices: [0], hardened: [true]))
        #expect(Self.hex(bundle.signingKey.payload) == Self.daedalusVectors[1].1)
        #expect(bundle.path == "m/0'")
    }

    @Test("Daedalus rejects a passphrase instead of ignoring it")
    func daedalusPassphrase() {
        #expect(throws: Signer.Keygen.ByronError.self) {
            _ = try Signer.Keygen.byron(mnemonic: TestFixtures.testMnemonic, passphrase: "secret", variant: .daedalus)
        }
    }

    // MARK: Index ranges

    @Test("Accounts and indices of 2^31 or more are rejected everywhere")
    func indexRanges() {
        let m = TestFixtures.testMnemonic
        #expect(throws: SignerError.self) { _ = try Signer.Keygen.shelley(mnemonic: m, kind: .payment(account: 0x8000_0000)) }
        #expect(throws: SignerError.self) { _ = try Signer.Keygen.shelley(mnemonic: m, kind: .payment(index: 0x8000_0000)) }
        #expect(throws: SignerError.self) { _ = try Signer.Keygen.shelley(mnemonic: m, kind: .pool(account: 0x8000_0001)) }
        #expect(throws: SignerError.self) { _ = try Signer.Keygen.ledger(mnemonic: m, kind: .stake(account: 0x8000_0000)) }
        #expect(throws: SignerError.self) { _ = try Signer.Keygen.trezor(mnemonic: m, kind: .drep(index: 0xFFFF_FFFF)) }
        #expect(throws: SignerError.self) { _ = try Signer.Keygen.cip36(mnemonic: m, account: 0x8000_0005) }
        #expect(throws: SignerError.self) { _ = try ByronPath(indices: [0x8000_0000], hardened: [false]) }
        #expect(throws: SignerError.self) { _ = try ByronPath(indices: [0, 1], hardened: [true]) }
    }

    @Test("The largest valid account still derives")
    func largestAccount() throws {
        _ = try Signer.Keygen.shelley(mnemonic: TestFixtures.testMnemonic, kind: .payment(account: 0x7FFF_FFFF))
    }

    // MARK: Ledger mnemonic validation

    @Test("Ledger keygen rejects phrases the Icarus path rejects")
    func ledgerMnemonic() throws {
        var typo = TestFixtures.testMnemonic
        typo[3] = "abandn"
        var capital = TestFixtures.testMnemonic
        capital[0] = "Abandon"
        for words in [Array(repeating: "abandon", count: 12), [], typo, capital] {
            #expect(throws: SignerError.self) { _ = try Signer.Keygen.ledger(mnemonic: words, kind: .payment()) }
        }
        _ = try Signer.Keygen.ledger(mnemonic: TestFixtures.testMnemonic, kind: .payment())
    }

    // MARK: Sign / verify / nonce

    @Test("Signing with an extended key whose stored public key is wrong throws")
    func signRejectsInconsistentKey() throws {
        let bundle = try Signer.Keygen.shelley(mnemonic: TestFixtures.testMnemonic, kind: .payment())
        var payload = bundle.signingKey.payload
        payload[70] ^= 0x01
        let broken = try ExtendedSigningKey(payload: payload, type: nil, description: nil)
        #expect(throws: SignerError.self) {
            _ = try Signer.sign(payload: Data("x".utf8), signingKey: .extendedSigningKey(broken))
        }
        _ = try Signer.sign(payload: Data("x".utf8), signingKey: .extendedSigningKey(bundle.signingKey))
    }

    @Test("Verify rejects an extended verification key that is not 64 bytes")
    func verifyExtendedLength() throws {
        let short = ExtendedVerificationKey(payload: Data(repeating: 1, count: 40), type: nil, description: nil)
        #expect(throws: SignerError.self) {
            _ = try Signer.verify(payload: Data(), signature: Data(count: 64), verificationKey: .extendedVerificationKey(short))
        }
    }

    @Test("SlotNonce never traps on extreme timestamps")
    func slotNonceExtremes() {
        #expect(SlotNonce.mainnetSlot(at: .min) == 0)
        #expect(SlotNonce.mainnetSlot(at: .max) > 0)
        #expect(SlotNonce.mainnetSlot(at: SlotNonce.mainnetShelleyGenesisUnix) == 4_492_800)
    }

    // MARK: CIP-100 facade

    @Test("CIP-100 verification is strict by default")
    func cip100Strict() async throws {
        let doc = Data(#"{"@context":{"t":"https://example.com/t"},"body":{"t":"x","unmapped":"y"}}"#.utf8)
        await #expect(throws: (any Error).self) { _ = try await Signer.CIP100.canonicalBodyHash(of: doc) }
        _ = try await Signer.CIP100.canonicalBodyHash(of: doc, strict: false)
    }

    // MARK: CIP-100 counterparty documents that were Apple-only crash leads

    /// Builds bytes with an NFC "é" (C3 A9) and an NFD "é" (65 CC 81) key,
    /// written as raw UTF-8 rather than JSON escapes.
    private static func equivalentKeys(_ template: String) -> Data {
        Data(template.replacingOccurrences(of: "NFC", with: "\u{00E9}")
            .replacingOccurrences(of: "NFD", with: "e\u{0301}").utf8)
    }

    @Test("Canonically equivalent keys throw or hash, never trap", arguments: [
        #"{"@context":{"@vocab":"https://example.com/cip-100#"},"body":{"NFC":"a","NFD":"b"}}"#,
        #"{"@context":{"@vocab":"https://example.com/cip-100#"},"body":{"x":"a"},"NFC":1,"NFD":2}"#,
    ])
    func equivalentKeysDoNotTrap(_ template: String) async {
        let doc = Self.equivalentKeys(template)
        _ = try? await Signer.CIP100.canonicalBodyHash(of: doc)
        _ = try? await Signer.CIP100.canonicalBodyHash(of: doc, strict: false)
    }

    @Test("Canonically equivalent keys inside an author entry never trap")
    func equivalentAuthorKeysDoNotTrap() async {
        let doc = Self.equivalentKeys(#"{"@context":{"@vocab":"https://example.com/cip-100#"},"body":{"x":"a"},"authors":[{"NFC":"a","NFD":"b","witness":{}}]}"#)
        _ = try? await Signer.CIP100.verifyMetadata(doc)
    }

    @Test("Deeply nested bodies throw instead of overflowing a cooperative-thread stack",
          arguments: [60, 100, 200, 300, 510])
    func deepNestingDoesNotCrash(_ depth: Int) async {
        let objects = String(repeating: #"{"a":"#, count: depth) + #""x""# + String(repeating: "}", count: depth)
        let arrays = String(repeating: "[", count: depth) + #""x""# + String(repeating: "]", count: depth)
        for body in [objects, arrays] {
            let doc = Data(#"{"@context":{"@vocab":"https://example.org/"},"body":\#(body)}"#.utf8)
            _ = try? await Signer.CIP100.verifyMetadata(doc)
            _ = try? await Signer.CIP100.canonicalBodyHash(of: doc, strict: false)
        }
    }
}
