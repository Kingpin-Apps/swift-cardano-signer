import Foundation
import SwiftCardanoCore

/// Top-level namespace for off-line / off-chain Cardano signing operations.
///
/// Mirrors the function-level surface of
/// [gitmachtl/cardano-signer](https://github.com/gitmachtl/cardano-signer),
/// but is library-only — no CLI argv parsing, no file I/O conveniences in the
/// public API. Callers pass `Data` payloads and typed key values; serialization
/// of `.skey` / `.vkey` envelopes is handled by `SwiftCardanoCore`.
///
/// The namespace is intentionally split into sub-namespaces matching
/// cardano-signer's mental model — `Signer.sign` / `Signer.verify` for default
/// Ed25519, then nested `Signer.CIP8`, `Signer.CIP36`, `Signer.CIP88`,
/// `Signer.CIP100`, `Signer.CIP129`, and `Signer.Keygen` for the CIP-specific
/// and key-derivation operations.
public enum Signer {}

/// Output of a default (non-CIP) sign operation.
///
/// Carries both the detached signature and the derived 32-byte verification
/// key so callers can attach a `signature + publicKey` pair without having to
/// re-derive the verification key themselves — matching the standard
/// cardano-signer JSON output shape.
public struct SignatureResult: Sendable, Equatable {
    /// The 64-byte Ed25519 detached signature.
    public let signature: Data

    /// The 32-byte Ed25519 verification key derived from the signing key.
    ///
    /// For extended (BIP32-ED25519) signing keys, this is the verification key
    /// with the chain code already stripped — i.e. always 32 bytes regardless
    /// of input key flavour.
    public let publicKey: Data

    public init(signature: Data, publicKey: Data) {
        self.signature = signature
        self.publicKey = publicKey
    }
}
