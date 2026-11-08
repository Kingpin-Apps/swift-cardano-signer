import Foundation
import Testing
import OrderedCollections
import SwiftCardanoCore
import SwiftCardanoCIPs
import SwiftNaCl
@testable import SwiftCardanoSigner

@Suite("Signer.CIP36 — Catalyst voting facade")
struct SignerCIP36Tests {

    static let votingKey = Data(repeating: 0xAA, count: 32)
    static let secondVotingKey = Data(repeating: 0xBB, count: 32)

    static func makeRewardsAddress() throws -> Address {
        try Address(
            paymentPart: nil,
            stakingPart: .verificationKeyHash(TestFixtures.stakeVK.hash()),
            network: .mainnet
        )
    }

    // MARK: - Delegation re-export

    @Test("Signer.CIP36.Delegation is a typealias to SwiftCardanoCIPs.CIP36.Delegation")
    func delegationIsAlias() {
        // Compile-time check — assigning a value of one type to the
        // other should type-check if they're the same.
        let direct = SwiftCardanoCIPs.CIP36.Delegation(votingKey: Self.votingKey, weight: 1)
        let viaFacade: Signer.CIP36.Delegation = direct
        #expect(viaFacade.votingKey == direct.votingKey)
        #expect(viaFacade.weight == direct.weight)
    }

    // MARK: - Registration

    @Test("makeRegistration produces auxiliary data with labels 61284 + 61285")
    func registrationLabels() throws {
        let aux = try Signer.CIP36.makeRegistration(
            delegations: [.init(votingKey: Self.votingKey, weight: 1)],
            stakeSigningKey: .signingKey(TestFixtures.stakeSK),
            rewardsAddress: try Self.makeRewardsAddress(),
            nonce: 12_345
        )
        guard case let .metadata(metadata) = aux.data else {
            Issue.record("Expected MetadataType.metadata")
            return
        }
        #expect(metadata.data[61_284] != nil)
        #expect(metadata.data[61_285] != nil)
    }

    @Test("Registration witness verifies against the stake vkey through libsodium")
    func registrationWitnessVerifies() throws {
        let aux = try Signer.CIP36.makeRegistration(
            delegations: [.init(votingKey: Self.votingKey, weight: 1)],
            stakeSigningKey: .signingKey(TestFixtures.stakeSK),
            rewardsAddress: try Self.makeRewardsAddress(),
            nonce: 100
        )
        guard case let .metadata(metadata) = aux.data,
              let registration = metadata.data[61_284],
              case let .map(witnessMap) = metadata.data[61_285],
              case let .bytes(signature) = witnessMap[.int(1)] else {
            Issue.record("Witness map shape did not match CIP-36")
            return
        }

        let registrationHash = try SwiftNaCl.Hash().blake2b(
            // CIP-36 sign_data: CBOR of the one-entry map {61284: registration}.
            data: Data([0xa1, 0x19, 0xef, 0x64]) + registration.toCBORData(),
            digestSize: 32,
            encoder: RawEncoder.self
        )
        let verifyKey = try VerifyKey(key: TestFixtures.stakeVK.payload)
        _ = try verifyKey.verify(smessage: registrationHash, signature: signature)
        // verify(...) throws on bad signature — reaching here = pass.
    }

    @Test("Multi-delegation encodes as an array of [vkey, weight] pairs")
    func multiDelegation() throws {
        let aux = try Signer.CIP36.makeRegistration(
            delegations: [
                .init(votingKey: Self.votingKey, weight: 3),
                .init(votingKey: Self.secondVotingKey, weight: 7),
            ],
            stakeSigningKey: .signingKey(TestFixtures.stakeSK),
            rewardsAddress: try Self.makeRewardsAddress(),
            nonce: 1
        )
        guard case let .metadata(metadata) = aux.data,
              case let .map(reg) = metadata.data[61_284],
              case let .list(delegations) = reg[.int(1)] else {
            Issue.record("Expected delegations list under field 1")
            return
        }
        #expect(delegations.count == 2)
    }

    @Test("Default voting purpose is 0 (Catalyst)")
    func defaultVotingPurpose() throws {
        let aux = try Signer.CIP36.makeRegistration(
            delegations: [.init(votingKey: Self.votingKey, weight: 1)],
            stakeSigningKey: .signingKey(TestFixtures.stakeSK),
            rewardsAddress: try Self.makeRewardsAddress(),
            nonce: 1
        )
        guard case let .metadata(metadata) = aux.data,
              case let .map(reg) = metadata.data[61_284],
              case let .int(purpose) = reg[.int(5)] else {
            Issue.record("Missing voting_purpose")
            return
        }
        #expect(purpose == 0)
    }

    // MARK: - Deregistration

    @Test("makeDeregistration produces labels 61286 + 61287 with verifiable witness")
    func deregistrationRoundTrip() throws {
        let aux = try Signer.CIP36.makeDeregistration(
            stakeSigningKey: .signingKey(TestFixtures.stakeSK),
            nonce: 99
        )
        guard case let .metadata(metadata) = aux.data else {
            Issue.record("Expected MetadataType.metadata")
            return
        }
        #expect(metadata.data[61_286] != nil)
        #expect(metadata.data[61_287] != nil)
        #expect(metadata.data[61_284] == nil)

        guard let dereg61286 = metadata.data[61_286],
              case let .map(witnessMap) = metadata.data[61_287],
              case let .bytes(signature) = witnessMap[.int(1)] else {
            Issue.record("Witness shape mismatch")
            return
        }
        let derHash = try SwiftNaCl.Hash().blake2b(
            // CIP-36 sign_data: CBOR of the one-entry map {61286: deregistration}.
            data: Data([0xa1, 0x19, 0xef, 0x66]) + dereg61286.toCBORData(),
            digestSize: 32,
            encoder: RawEncoder.self
        )
        let verifyKey = try VerifyKey(key: TestFixtures.stakeVK.payload)
        _ = try verifyKey.verify(smessage: derHash, signature: signature)
    }

    // MARK: - Facade structural equivalence

    @Test("Facade output is structurally equal to a direct cips delegate call")
    func facadeMatchesCIPs() throws {
        let viaFacade = try Signer.CIP36.makeRegistration(
            delegations: [.init(votingKey: Self.votingKey, weight: 1)],
            stakeSigningKey: .signingKey(TestFixtures.stakeSK),
            rewardsAddress: try Self.makeRewardsAddress(),
            nonce: 200
        )
        let viaCIPs = try SwiftCardanoCIPs.CIP36.makeRegistration(
            delegations: [.init(votingKey: Self.votingKey, weight: 1)],
            stakeSigningKey: .signingKey(TestFixtures.stakeSK),
            rewardsAddress: try Self.makeRewardsAddress(),
            nonce: 200
        )
        // Outer Metadata is hash-randomized Dictionary, so we compare
        // labels individually — the per-label values are deterministic.
        guard case let .metadata(facadeMeta) = viaFacade.data,
              case let .metadata(cipsMeta) = viaCIPs.data else {
            Issue.record("Unexpected MetadataType variant")
            return
        }
        #expect(facadeMeta.data[61_284] == cipsMeta.data[61_284])
        #expect(facadeMeta.data[61_285] == cipsMeta.data[61_285])
    }
}
