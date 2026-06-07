import Foundation
import CryptoSwift
import SwiftCardanoCore
import SwiftMnemonic
import SwiftNaCl

/// The Byron-era wallet variant. Determines the master-key derivation
/// algorithm; downstream child-key derivation uses BIP-32-Ed25519 once a
/// master key is in hand.
public enum ByronVariant: Sendable, Equatable {
    /// Daedalus — the original IOG wallet. Master key derivation:
    /// CBOR-wrap the BIP-39 entropy, Blake2b-256, CBOR-wrap again,
    /// then HMAC-SHA512 chain with `"Root Seed Chain N"` until the
    /// scalar clamp lands.
    case daedalus

    /// Yoroi paperwallet (21-word). Master key derivation requires
    /// unscrambling the paperwallet first, which delegates to an
    /// external `cardano-wallet` library (algorithm opaque in
    /// cardano-signer.js's source). Not yet implemented in this Swift
    /// port — throws ``Signer/Keygen/ByronError/unsupportedVariant(_:)``.
    case yoroi

    /// Exodus paperwallet. Uses a secp256k1-flavoured BIP-32 derivation
    /// (Bitcoin-style, not Cardano-native), and is the lowest-priority
    /// Byron variant in the original cardano-signer port plan. Not yet
    /// implemented — throws ``Signer/Keygen/ByronError/unsupportedVariant(_:)``.
    case exodus
}

/// A Byron-era derivation path. Stored as a parsed list of indices for
/// future-proofing (Byron addresses encrypt the path into the address
/// attributes); the canonical Daedalus paths are short — typically
/// `account` / `account/index`.
public struct ByronPath: Sendable, Equatable {
    public let indices: [UInt32]
    /// Whether each index is hardened (sets the high bit at derivation time).
    public let hardened: [Bool]

    /// Convenience constant for the canonical Daedalus root path
    /// `m/0'/0'` (first account, first address).
    public static let daedalusDefault = ByronPath(
        indices: [0, 0],
        hardened: [true, true]
    )

    public init(indices: [UInt32], hardened: [Bool]) {
        precondition(indices.count == hardened.count)
        self.indices = indices
        self.hardened = hardened
    }
}

public extension Signer.Keygen {

    /// Byron-era derivation errors.
    enum ByronError: Error, Equatable {
        /// The requested variant isn't implemented yet (Yoroi / Exodus
        /// paperwallets need external unscrambling logic that hasn't been
        /// ported into Swift).
        case unsupportedVariant(String)
        /// CBOR encoding of the input entropy failed.
        case encodingError(String)
    }

    /// Derive a Byron-era extended key from a BIP-39 mnemonic.
    ///
    /// Equivalent to cardano-signer's `keygen --byron` (with `--variant`
    /// selecting Daedalus / Yoroi / Exodus). Only `.daedalus` is
    /// currently supported in this Swift port — the paperwallet variants
    /// delegate to opaque external implementations in cardano-signer.js
    /// and need additional reverse-engineering before they can be
    /// ported.
    ///
    /// - Parameters:
    ///   - mnemonic: BIP-39 mnemonic words. For Daedalus this is the
    ///     standard 12 / 15 / 18 / 21 / 24-word phrase.
    ///   - passphrase: Optional BIP-39 passphrase. Daedalus master-key
    ///     derivation does not consume the passphrase (cardano-signer
    ///     ignores `--passphrase` in `--byron --variant daedalus`).
    ///   - variant: Which Byron wallet flavor to derive for.
    ///   - path: BIP-32 path to descend after the master key is in hand.
    /// - Returns: The derived ``KeyPairBundle``.
    static func byron(
        mnemonic: [String],
        passphrase: String = "",
        variant: ByronVariant,
        path: ByronPath = .daedalusDefault
    ) throws -> KeyPairBundle {
        switch variant {
        case .daedalus:
            let masterKey = try daedalusMasterKey(
                mnemonic: mnemonic.joined(separator: " ")
            )
            return try deriveBundle(masterKey: masterKey, path: path)
        case .yoroi:
            throw ByronError.unsupportedVariant(
                "Yoroi paperwallet unscrambling requires the `cardano-wallet` library's algorithm, which is not yet ported. Use a fully-restored Yoroi mnemonic via `Signer.Keygen.shelley(..., kind: .payment(...))` instead."
            )
        case .exodus:
            throw ByronError.unsupportedVariant(
                "Exodus paperwallet derivation uses a secp256k1-flavoured BIP-32 scheme distinct from Cardano's BIP-32-Ed25519. Not yet ported; deferred to a future release."
            )
        }
    }

    /// Compute the 96-byte Daedalus master key from a mnemonic, without
    /// performing any further derivation.
    static func daedalusMasterKey(mnemonic: String) throws -> Data {
        let words = mnemonic.components(separatedBy: " ").filter { !$0.isEmpty }
        let parsedMnemonic = try Mnemonic(from: words)
        let entropy = Data(parsedMnemonic.entropy)

        // Byron seed: CBOR(BLAKE2b-256(CBOR(entropy)))
        let cborEntropy = cborByteString(entropy)
        let entropyHash: Data
        do {
            entropyHash = try SwiftNaCl.Hash().blake2b(
                data: cborEntropy,
                digestSize: 32,
                encoder: RawEncoder.self
            )
        } catch {
            throw ByronError.encodingError("blake2b-256(CBOR(entropy)) failed: \(error)")
        }
        let seed = cborByteString(entropyHash)

        return try byronMasterKeyFromSeed(seed)
    }

    // MARK: - Implementation

    /// HMAC-SHA512 chain reducing until the scalar clamp lands cleanly.
    ///
    /// Each iteration uses a different message — `"Root Seed Chain N"`
    /// — so the chain terminates deterministically.
    private static func byronMasterKeyFromSeed(
        _ seed: Data,
        iteration: Int = 1
    ) throws -> Data {
        let message = "Root Seed Chain \(iteration)"
        let result = try Data(HMAC(
            key: seed.byteArray,
            variant: .sha2(.sha512)
        ).authenticate(Array(message.utf8)))

        let iL = result.prefix(32)
        let iR = result.suffix(from: 32)

        // SHA-512 of iL → 64-byte tweaked hash.
        var tweakedHash = Data(CryptoSwift.SHA2(variant: .sha512).calculate(for: iL.byteArray))
        tweakedHash[0]  &= 0b1111_1000
        tweakedHash[31] &= 0b0111_1111
        tweakedHash[31] |= 0b0100_0000

        if tweakedHash[31] & 0b0010_0000 != 0 {
            return try byronMasterKeyFromSeed(seed, iteration: iteration + 1)
        }

        return tweakedHash + iR
    }

    /// Encode a byte string as CBOR — just enough of the spec to support
    /// the Byron seed wrapping. Handles four length classes (≤ 23,
    /// ≤ 0xFF, ≤ 0xFFFF, ≤ 0xFFFFFFFF) which more than covers any
    /// realistic Cardano use.
    private static func cborByteString(_ bytes: Data) -> Data {
        var out = Data()
        let len = bytes.count
        switch len {
        case 0..<24:
            out.append(0x40 | UInt8(len))
        case 24..<256:
            out.append(0x58)
            out.append(UInt8(len))
        case 256..<65_536:
            out.append(0x59)
            out.append(UInt8((len >> 8) & 0xFF))
            out.append(UInt8(len & 0xFF))
        default:
            out.append(0x5A)
            out.append(UInt8((len >> 24) & 0xFF))
            out.append(UInt8((len >> 16) & 0xFF))
            out.append(UInt8((len >> 8) & 0xFF))
            out.append(UInt8(len & 0xFF))
        }
        out.append(bytes)
        return out
    }
}

// MARK: - Master-key → KeyPairBundle helpers

extension Signer.Keygen {
    /// Build an HDWallet from a 96-byte master key and derive along a
    /// Shelley-era role path. Used by Ledger and (in future) Trezor
    /// derivations.
    static func deriveBundle(
        masterKey: Data,
        kind: ShelleyKeyKind
    ) throws -> KeyPairBundle {
        // Use the `Data`-accepting overload added in swift-cardano-core
        // 0.4.6+. The older `seed: String` form hex-encoded the master
        // key into a Swift `String`, leaving the private scalar on the
        // heap as a non-zeroed string for the lifetime of that string.
        // The `seedData:` overload keeps the key as `Data` end-to-end.
        let root = try HDWallet.fromSeed(seedData: masterKey)
        let derived: HDWallet
        do {
            derived = try root.derive(fromPath: kind.path)
        } catch {
            throw SignerError.invalidDerivationPath(
                "Failed to derive \(kind.path): \(error)"
            )
        }
        let signingKey = ExtendedSigningKey(
            payload: derived.xPrivateKey + derived.publicKey + derived.chainCode,
            type: kind.envelopeTypeSigning,
            description: kind.envelopeDescriptionSigning
        )
        let verificationKey = ExtendedVerificationKey(
            payload: derived.publicKey + derived.chainCode,
            type: kind.envelopeTypeSigning
                .replacingOccurrences(of: "Signing", with: "Verification"),
            description: kind.envelopeDescriptionSigning
                .replacingOccurrences(of: "Signing", with: "Verification")
        )
        return KeyPairBundle(
            signingKey: signingKey,
            verificationKey: verificationKey,
            path: derived.path
        )
    }

    /// Build an HDWallet from a 96-byte master key and descend along a
    /// Byron-style path expressed as raw (index, hardened) pairs.
    static func deriveBundle(
        masterKey: Data,
        path: ByronPath
    ) throws -> KeyPairBundle {
        // Same `Data` overload — see the `deriveBundle(masterKey:kind:)`
        // helper above for the rationale (avoids hex-encoding the
        // master key into a heap-allocated `String`).
        var wallet = try HDWallet.fromSeed(seedData: masterKey)
        for (index, isHardened) in zip(path.indices, path.hardened) {
            wallet = try wallet.derive(
                index: index,
                isPrivate: true,
                hardened: isHardened
            )
        }
        let signingKey = ExtendedSigningKey(
            payload: wallet.xPrivateKey + wallet.publicKey + wallet.chainCode,
            type: "ByronExtendedSigningKey_ed25519_bip32",
            description: "Byron Signing Key"
        )
        let verificationKey = ExtendedVerificationKey(
            payload: wallet.publicKey + wallet.chainCode,
            type: "ByronExtendedVerificationKey_ed25519_bip32",
            description: "Byron Verification Key"
        )
        return KeyPairBundle(
            signingKey: signingKey,
            verificationKey: verificationKey,
            path: wallet.path
        )
    }
}
