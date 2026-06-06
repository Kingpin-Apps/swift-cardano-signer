import Foundation
import Testing
import SwiftCardanoCore
import SwiftCardanoCIPs
@testable import SwiftCardanoSigner

@Suite("Signer.CIP100 — governance JSON-LD facade")
struct SignerCIP100Tests {

    /// Minimal CIP-100 document with an inline @vocab context so the
    /// JSON-LD canonicaliser has property mappings to work with (without
    /// a context, JSON-LD drops every unknown key → empty canonical
    /// form → trivially-colliding hashes).
    static let exampleDocument: Data = """
    {
      "@context": { "@vocab": "https://example.com/cip-100#" },
      "hashAlgorithm": "blake2b-256",
      "body": {
        "comment": "Facade test document.",
        "references": []
      }
    }
    """.data(using: .utf8)!

    // MARK: - canonicalBodyHash

    @Test("canonicalBodyHash delegates byte-identically to the cips implementation")
    func canonicalBodyHashMatchesDelegate() async throws {
        let viaFacade = try await Signer.CIP100.canonicalBodyHash(of: Self.exampleDocument)
        let viaCIPs = try await SwiftCardanoCIPs.CIP100.canonicalBodyHash(of: Self.exampleDocument)
        #expect(viaFacade == viaCIPs)
        #expect(viaFacade.count == 32)
    }

    @Test("canonicalBodyHash is deterministic")
    func canonicalBodyHashIsDeterministic() async throws {
        let a = try await Signer.CIP100.canonicalBodyHash(of: Self.exampleDocument)
        let b = try await Signer.CIP100.canonicalBodyHash(of: Self.exampleDocument)
        #expect(a == b)
    }

    // MARK: - sign + verify

    @Test("signMetadata + verifyMetadata round-trips")
    func signVerifyRoundTrip() async throws {
        let signed = try await Signer.CIP100.signMetadata(
            document: Self.exampleDocument,
            signingKey: .signingKey(TestFixtures.stakeSK),
            authorName: "Test Author"
        )
        let result = try await Signer.CIP100.verifyMetadata(signed)
        #expect(result.allValid)
        #expect(result.authorResults.count == 1)
        #expect(result.authorResults[0].name == "Test Author")
        #expect(result.authorResults[0].valid)
    }

    @Test("Tampered body fails verify")
    func tamperedBodyFails() async throws {
        let signed = try await Signer.CIP100.signMetadata(
            document: Self.exampleDocument,
            signingKey: .signingKey(TestFixtures.stakeSK),
            authorName: "Test Author"
        )
        let tampered = String(data: signed, encoding: .utf8)!
            .replacingOccurrences(of: "Facade test document", with: "TAMPERED")
            .data(using: .utf8)!
        let result = try await Signer.CIP100.verifyMetadata(tampered)
        #expect(!result.allValid)
    }

    @Test("Anonymous author (no name) signs and verifies cleanly")
    func anonymousAuthor() async throws {
        let signed = try await Signer.CIP100.signMetadata(
            document: Self.exampleDocument,
            signingKey: .signingKey(TestFixtures.stakeSK),
            authorName: nil
        )
        let result = try await Signer.CIP100.verifyMetadata(signed)
        #expect(result.allValid)
        #expect(result.authorResults[0].name == nil)
    }

    // MARK: - Type re-exports

    @Test("Witness / Author / VerificationResult type aliases match the underlying cips types")
    func typeAliasesMatch() {
        let direct = SwiftCardanoCIPs.CIP100.Witness(
            witnessAlgorithm: "ed25519",
            publicKey: Data(repeating: 0, count: 32),
            signature: Data(repeating: 0, count: 64)
        )
        let viaFacade: Signer.CIP100.Witness = direct
        #expect(viaFacade.witnessAlgorithm == direct.witnessAlgorithm)
        #expect(viaFacade.publicKey == direct.publicKey)
        #expect(viaFacade.signature == direct.signature)
    }
}
