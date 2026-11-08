import Foundation

/// Errors thrown by `Signer` operations.
///
/// Wraps lower-level errors from the underlying crypto / CIP libraries with a
/// uniform surface so callers can pattern-match on the operation that failed
/// rather than the implementation that produced the failure.
public enum SignerError: Error, Sendable, Equatable {
    /// A signing key payload was the wrong length or otherwise malformed.
    case invalidSigningKey(String)

    /// A verification key payload was the wrong length or otherwise malformed.
    case invalidVerificationKey(String)

    /// An Ed25519 signature failed to verify against the supplied
    /// `(payload, verificationKey)` pair.
    ///
    /// Verification failure is *not* exceptional — callers should treat a
    /// `false` return from `Signer.verify` as the normal failure path. This
    /// case is reserved for situations where the signature payload itself is
    /// malformed (wrong length, etc.) and verification could not even attempt.
    case malformedSignature(String)

    /// The requested CIP operation failed for a reason described by the
    /// associated message — typically a delegate failure from
    /// `SwiftCardanoCIPs`.
    case cipError(String)

    /// The requested derivation path was not a valid CIP-1852 / CIP-1853 /
    /// CIP-1854 path, or the index was out of range.
    case invalidDerivationPath(String)

    /// The mnemonic is not a valid BIP-39 phrase (unknown word, bad
    /// checksum or unsupported length).
    case invalidMnemonic(String)
}
