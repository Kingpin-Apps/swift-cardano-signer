import Foundation
import SwiftCardanoCore

/// Shared test fixtures used across the signer test suite.
///
/// Centralising fixtures here keeps test files small and means a change
/// to a canonical reference vector (e.g. a new published Pycardano
/// signature, or a tweaked CIP-100 test document) only has to land in
/// one place. Each property is a static computed value that downstream
/// tests can lift via `TestFixtures.<name>`.
enum TestFixtures {

    // MARK: - BIP-39 mnemonics

    /// Canonical 24-word BIP-39 test mnemonic ("all twelves + art").
    /// Universally used across Cardano test fixtures so a regression in
    /// any HD-derivation path surfaces against a known oracle.
    static let testMnemonic: [String] = [
        "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "abandon", "abandon", "art",
    ]

    static let testMnemonicJoined: String = testMnemonic.joined(separator: " ")

    // MARK: - RFC 8032 Ed25519 reference vector

    /// RFC 8032 §7.1 Test 1 — the canonical Ed25519 reference vector.
    ///
    /// SECRET KEY:    `9d61b19d…7f60`
    /// PUBLIC KEY:    `d75a9801…711a`
    /// MESSAGE:       (empty)
    /// SIGNATURE:     `e5564300…100b`
    enum RFC8032 {
        static let seed = Data(hex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        static let publicKey = Data(hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        static let signature = Data(hex:
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
    }

    // MARK: - Cardano test keys

    /// Genesis Initial UTxO payment key — used across the Cardano
    /// ecosystem as a fixed, well-known test fixture (also referenced
    /// inside `swift-cardano-cips`'s CIP-8 tests).
    static let paymentSK = try! PaymentSigningKey.fromTextEnvelope(
        """
        {
            "type": "GenesisUTxOSigningKey_ed25519",
            "description": "Genesis Initial UTxO Signing Key",
            "cborHex": "5820093be5cd3987d0c9fd8854ef908f7746b69e2d73320db6dc0f780d81585b84c2"
        }
        """
    )

    /// Companion test stake key — referenced by CIP-8 and CIP-36 fixtures.
    static let stakeSK = try! StakeSigningKey.fromTextEnvelope(
        """
        {
            "type": "StakeSigningKeyShelley_ed25519",
            "description": "Stake Signing Key",
            "cborHex": "5820ff3a330df8859e4e5f42a97fcaee73f6a00d0cf864f4bca902bd106d423f02c0"
        }
        """
    )

    static let stakeVK = try! StakeVerificationKey.fromTextEnvelope(
        """
        {
            "type": "StakeVerificationKeyShelley_ed25519",
            "description": "Stake Verification Key",
            "cborHex": "58205edaa384c658c2bd8945ae389edac0a5bd452d0cfd5d1245e3ecd540030d1e3c"
        }
        """
    )

    // MARK: - CIP-8 / CIP-30 reference message

    /// Canonical Pycardano-signed CIP-0008 message ("Pycardano is cool.")
    /// — used across multiple Cardano implementations to verify wire
    /// interop on the verify side.
    static let pycardanoSignedMessage =
        "845869a3012704582060545b786d3a6f903158e35aae9b86548a99bc47d4b0a6f503ab5e78c1a9bbfc6761646472657373583900ddba3ad76313825f4f646f5aa6d323706653bda40ec1ae55582986a463e661768b92deba45b5ada4ab9e7ffd17ed3051b2e03500e0542e9aa166686173686564f452507963617264616e6f20697320636f6f6c2e58403b09cbae8d272ff94befd28cc04b152aea3c1633caffb4924a8a8c45be3ba6332a76d9f2aba833df53803286d32a5ee700990b79a0e86fab3cccdbfd37ce250f"
}

// MARK: - Test-only Data helpers

extension Data {
    /// Convenience hex initializer for embedding test vectors as
    /// literal hex strings. Whitespace ignored; odd length traps.
    init(hex: String) {
        let clean = hex.unicodeScalars.filter { !$0.properties.isWhitespace }
        precondition(clean.count.isMultiple(of: 2), "hex string must have even length")
        var bytes = [UInt8]()
        bytes.reserveCapacity(clean.count / 2)
        var iter = clean.makeIterator()
        while let hi = iter.next(), let lo = iter.next() {
            guard let h = UInt8(String(hi), radix: 16),
                  let l = UInt8(String(lo), radix: 16) else {
                preconditionFailure("invalid hex character in '\(hex)'")
            }
            bytes.append(h << 4 | l)
        }
        self.init(bytes)
    }
}
