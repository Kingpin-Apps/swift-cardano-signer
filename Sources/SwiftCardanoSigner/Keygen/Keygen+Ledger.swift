import Foundation
import CryptoSwift
import SwiftCardanoCore
import SwiftMnemonic
#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
import Crypto
#endif

public extension Signer.Keygen {
    /// Derive a Ledger-Cardano–flavoured extended key from a BIP-39
    /// mnemonic, then derive along the requested role's CIP-1852 /
    /// CIP-1853 / CIP-1854 path.
    ///
    /// Equivalent to cardano-signer's `keygen --ledger`.
    ///
    /// The Ledger master-key derivation differs from ICARUS:
    /// 1. Standard BIP-39 seed: `PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048, 64)`.
    /// 2. Chain code: `HMAC-SHA256(key="ed25519 seed", data=[0x01] + masterSeed)`.
    ///    The `0x01` prefix replicates a known Adrestia bug; cardano-cli
    ///    expects this exact byte sequence, so we must mirror it for
    ///    interop. Without the prefix, the derived keys won't match any
    ///    Ledger-managed Cardano wallet.
    /// 3. Tweaked hash: iterative `HMAC-SHA512(key="ed25519 seed", ...)`
    ///    starting with `masterSeed`, recursing on its own output until
    ///    bit 5 of byte 31 clears.
    /// 4. Bit tweaks: `tweakedHash[0] &= 0xF8; tweakedHash[31] &= 0x7F;
    ///    tweakedHash[31] |= 0x40`.
    /// 5. 96-byte master key: `tweakedHash || chainCode`.
    ///
    /// The 96-byte master key is then fed into ``SwiftCardanoCore/HDWallet``
    /// as a root seed, which performs the standard BIP-32-Ed25519
    /// child-key derivation.
    ///
    /// - Parameters:
    ///   - mnemonic: BIP-39 mnemonic words.
    ///   - passphrase: Optional BIP-39 passphrase (the "25th word").
    ///   - kind: Which role's CIP-1852 path to derive.
    /// - Returns: The derived ``KeyPairBundle``.
    static func ledger(
        mnemonic: [String],
        passphrase: String = "",
        kind: ShelleyKeyKind
    ) throws -> KeyPairBundle {
        let masterKey = try ledgerMasterKey(
            mnemonic: mnemonic.joined(separator: " "),
            passphrase: passphrase
        )
        return try deriveBundle(masterKey: masterKey, kind: kind)
    }

    /// Public-facing helper: compute the 96-byte Ledger master key from a
    /// mnemonic and optional passphrase without doing any further
    /// derivation. Useful for callers that want to plug into a
    /// non-standard derivation path or compare against a Ledger device.
    static func ledgerMasterKey(
        mnemonic: String,
        passphrase: String = ""
    ) throws -> Data {
        // 1. Validate the phrase as BIP-39 (known words, valid checksum,
        //    allowed length), as the Icarus path does, then take the
        //    standard 64-byte seed (PBKDF2-HMAC-SHA512, 2048 rounds,
        //    "mnemonic" + passphrase salt) of the canonical phrase.
        let words = mnemonic.decomposedStringWithCompatibilityMapping
            .split(whereSeparator: { $0.isWhitespace })
            .map(String.init)
        do {
            _ = try Mnemonic(from: words)
        } catch {
            throw SignerError.invalidMnemonic(String(describing: error))
        }
        let masterSeed = Data(try Mnemonic.toSeed(
            mnemonic: words.joined(separator: " "),
            passphrase: passphrase
        ))

        // 2. Chain code with the Adrestia-quirk [0x01] prefix.
        let messageWithPrefix = Data([0x01]) + masterSeed
        let chainCode = try Data(HMAC(
            key: Array("ed25519 seed".utf8),
            variant: .sha2(.sha256)
        ).authenticate(messageWithPrefix.byteArray))

        // 3. Iterative HMAC-SHA512 reducing until bit 5 of byte 31 clears.
        var tweakedHash = try Data(HMAC(
            key: Array("ed25519 seed".utf8),
            variant: .sha2(.sha512)
        ).authenticate(masterSeed.byteArray))
        while tweakedHash[31] & 0b0010_0000 != 0 {
            tweakedHash = try Data(HMAC(
                key: Array("ed25519 seed".utf8),
                variant: .sha2(.sha512)
            ).authenticate(tweakedHash.byteArray))
        }

        // 4. Bit tweaks per the Ed25519 scalar clamping convention.
        tweakedHash[0]  &= 0b1111_1000
        tweakedHash[31] &= 0b0111_1111
        tweakedHash[31] |= 0b0100_0000

        // 5. Master key = tweakedHash (64) || chainCode (32).
        return tweakedHash + chainCode
    }
}
