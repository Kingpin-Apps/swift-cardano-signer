import Foundation
import Testing
import SwiftCardanoCore
@testable import SwiftCardanoSigner

@Suite("Signer.Keygen umbrella — ShelleyKeyKind, KeyPairBundle, CIP36VoteKeyPair")
struct SignerKeygenTests {

    // MARK: - ShelleyKeyKind.path routing

    @Test("ShelleyKeyKind.path matches CardanoPaths for every role",
          arguments: [
            ShelleyKeyKind.payment(account: 0, index: 0),
            .stake(account: 1, index: 5),
            .drep(),
            .ccCold(),
            .ccHot(),
            .pool(account: 2),
            .calidus(account: 3),
          ])
    func kindPathRoutes(kind: ShelleyKeyKind) {
        switch kind {
        case let .payment(a, i): #expect(kind.path == CardanoPaths.payment(account: a, index: i))
        case let .stake(a, i):   #expect(kind.path == CardanoPaths.stake(account: a, index: i))
        case let .drep(a, i):    #expect(kind.path == CardanoPaths.drep(account: a, index: i))
        case let .ccCold(a, i):  #expect(kind.path == CardanoPaths.ccCold(account: a, index: i))
        case let .ccHot(a, i):   #expect(kind.path == CardanoPaths.ccHot(account: a, index: i))
        case let .pool(a):       #expect(kind.path == CardanoPaths.pool(account: a))
        case let .calidus(a):    #expect(kind.path == CardanoPaths.calidus(account: a))
        }
    }

    // MARK: - Envelope tags

    @Test("envelopeTypeSigning carries a role-specific prefix",
          arguments: [
            (ShelleyKeyKind.payment(), "Payment"),
            (.stake(),                 "Stake"),
            (.drep(),                  "DRep"),
            (.ccCold(),                "ConstitutionalCommitteeCold"),
            (.ccHot(),                 "ConstitutionalCommitteeHot"),
            (.pool(),                  "StakePool"),
            (.calidus(),               "Calidus"),
          ])
    func envelopeTypeStrings(kind: ShelleyKeyKind, expectedFragment: String) {
        #expect(kind.envelopeTypeSigning.contains(expectedFragment))
        // Every envelope tag ends with the BIP32-Ed25519 marker.
        #expect(kind.envelopeTypeSigning.contains("ed25519_bip32"))
    }

    @Test("envelopeDescriptionSigning is human-readable per role")
    func envelopeDescriptions() {
        #expect(ShelleyKeyKind.payment().envelopeDescriptionSigning  == "Payment Signing Key")
        #expect(ShelleyKeyKind.stake().envelopeDescriptionSigning    == "Stake Signing Key")
        #expect(ShelleyKeyKind.drep().envelopeDescriptionSigning     == "Delegate Representative Signing Key")
        #expect(ShelleyKeyKind.ccCold().envelopeDescriptionSigning   == "Constitutional Committee Cold Signing Key")
        #expect(ShelleyKeyKind.ccHot().envelopeDescriptionSigning    == "Constitutional Committee Hot Signing Key")
        #expect(ShelleyKeyKind.pool().envelopeDescriptionSigning     == "Stake Pool Signing Key")
        #expect(ShelleyKeyKind.calidus().envelopeDescriptionSigning  == "Calidus Signing Key")
    }

    @Test("ShelleyKeyKind cases are Equatable")
    func equatable() {
        #expect(ShelleyKeyKind.payment(account: 0, index: 0) == .payment(account: 0, index: 0))
        #expect(ShelleyKeyKind.payment(account: 0, index: 0) != .payment(account: 0, index: 1))
        #expect(ShelleyKeyKind.payment() != .stake())
    }

    // MARK: - KeyPairBundle

    @Test("KeyPairBundle stores signingKey + verificationKey + path verbatim")
    func bundleStoresFields() throws {
        let signing = try ExtendedSigningKey(
            payload: Data(repeating: 0xAB, count: 128),
            type: "Test",
            description: "Test"
        )
        let verification = try ExtendedVerificationKey(
            payload: Data(repeating: 0xCD, count: 64),
            type: "Test",
            description: "Test"
        )
        let bundle = KeyPairBundle(
            signingKey: signing,
            verificationKey: verification,
            path: "m/1852'/1815'/0'/0/0"
        )
        #expect(bundle.signingKey.payload == signing.payload)
        #expect(bundle.verificationKey.payload == verification.payload)
        #expect(bundle.path == "m/1852'/1815'/0'/0/0")
    }

    // MARK: - CIP36VoteKeyPair

    @Test("CIP36VoteKeyPair stores signingKey + verificationKey + path verbatim")
    func cip36BundleStoresFields() throws {
        let signing = try ExtendedSigningKey(
            payload: Data(repeating: 0x11, count: 128),
            type: "Test",
            description: "Test"
        )
        let verification = try ExtendedVerificationKey(
            payload: Data(repeating: 0x22, count: 64),
            type: "Test",
            description: "Test"
        )
        let bundle = CIP36VoteKeyPair(
            signingKey: signing,
            verificationKey: verification,
            path: "m/1694'/1815'/0'/0/0"
        )
        #expect(bundle.signingKey.payload == signing.payload)
        #expect(bundle.verificationKey.payload == verification.payload)
        #expect(bundle.path == "m/1694'/1815'/0'/0/0")
    }
}
