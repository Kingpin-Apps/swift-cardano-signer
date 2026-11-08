import Foundation
import SwiftCardanoCore
import SwiftCardanoCIPs

public extension Signer {
    /// CIP-100 governance-metadata sign / verify (also covers CIP-108 +
    /// CIP-119, which reuse the same author-witness shape).
    ///
    /// Mirrors cardano-signer's `sign --cip100` and `verify --cip100`.
    /// Delegates to ``SwiftCardanoCIPs/CIP100`` — this facade exists to
    /// anchor the operations under the `Signer.CIP100` namespace that
    /// cardano-signer.js callers expect.
    ///
    /// The signing payload is `blake2b-256` of the URDNA2015-canonical
    /// N-Quads form of the document with its `authors` array stripped.
    /// See ``SwiftCardanoCIPs/CIP100`` for the full algorithm and
    /// [CIP-0100](https://cips.cardano.org/cip/CIP-0100) for the wire
    /// format.
    enum CIP100 {

        public typealias Witness = SwiftCardanoCIPs.CIP100.Witness
        public typealias Author = SwiftCardanoCIPs.CIP100.Author
        public typealias VerificationResult = SwiftCardanoCIPs.CIP100.VerificationResult

        /// Sign a CIP-100 governance-metadata document and append the
        /// signer's author entry to the `authors` array.
        ///
        /// - Parameters:
        ///   - document: JSON-LD document bytes (UTF-8 JSON).
        ///   - signingKey: The author's Ed25519 signing key (regular or
        ///     extended).
        ///   - authorName: Optional display name to attach to the author
        ///     entry.
        public static func signMetadata(
            document: Data,
            signingKey: SigningKeyType,
            authorName: String? = nil,
            strict: Bool = true
        ) async throws -> Data {
            return try await SwiftCardanoCIPs.CIP100.signMetadata(
                document: document,
                signingKey: signingKey,
                authorName: authorName,
                strict: strict
            )
        }

        /// Verify every author signature in a CIP-100 governance-metadata
        /// document.
        ///
        /// - Parameters:
        ///   - document: JSON-LD document bytes.
        ///   - strict: When `true` (the default), throw if JSON-LD
        ///     expansion would drop a body key, so every key a reader
        ///     sees is covered by the signatures. `false` hashes like
        ///     cardano-signer.js (jsonld.js `safe: false`).
        public static func verifyMetadata(
            _ document: Data,
            strict: Bool = true
        ) async throws -> VerificationResult {
            return try await SwiftCardanoCIPs.CIP100.verifyMetadata(document, strict: strict)
        }

        /// Compute the canonical body hash (the Ed25519 signing payload)
        /// for a CIP-100 document, without producing a signature.
        public static func canonicalBodyHash(of document: Data, strict: Bool = true) async throws -> Data {
            return try await SwiftCardanoCIPs.CIP100.canonicalBodyHash(of: document, strict: strict)
        }
    }
}
