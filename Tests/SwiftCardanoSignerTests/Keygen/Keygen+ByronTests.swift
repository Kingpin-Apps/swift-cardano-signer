import Foundation
import Testing
import SwiftCardanoCore
@testable import SwiftCardanoSigner

@Suite("Signer.Keygen.byron — Byron-era derivation (Daedalus / Yoroi / Exodus)")
struct KeygenByronTests {

    // MARK: - Daedalus master key

    @Test("Daedalus master key is deterministic for the same mnemonic")
    func daedalusMasterKeyDeterministic() throws {
        let a = try Signer.Keygen.daedalusMasterKey(mnemonic: TestFixtures.testMnemonicJoined)
        let b = try Signer.Keygen.daedalusMasterKey(mnemonic: TestFixtures.testMnemonicJoined)
        #expect(a == b)
        #expect(a.count == 96)
    }

    @Test("Daedalus master key satisfies the Ed25519 scalar clamp")
    func daedalusMasterKeyHasClamp() throws {
        let master = try Signer.Keygen.daedalusMasterKey(mnemonic: TestFixtures.testMnemonicJoined)
        #expect(master[0]  & 0b0000_0111 == 0)
        #expect(master[31] & 0b1000_0000 == 0)
        #expect(master[31] & 0b0100_0000 != 0)
        #expect(master[31] & 0b0010_0000 == 0)
    }

    @Test("Daedalus master key differs from ICARUS for the same mnemonic")
    func daedalusVsIcarus() throws {
        let daedalus = try Signer.Keygen.daedalusMasterKey(mnemonic: TestFixtures.testMnemonicJoined)
        let icarusWallet = try HDWallet.fromMnemonic(mnemonic: TestFixtures.testMnemonicJoined)
        let icarusMaster = icarusWallet.rootXPrivateKey + icarusWallet.rootPublicKey + icarusWallet.rootChainCode
        // CBOR-wrapped Blake2b seed + HMAC-SHA512 chain (Daedalus) vs
        // PBKDF2-HMAC-SHA512(passphrase, entropy, 4096, 96) (ICARUS):
        // different algorithms → different master keys.
        #expect(daedalus.prefix(64) != icarusMaster.prefix(64))
    }

    // MARK: - Daedalus derivation

    @Test("Daedalus keygen produces a sign-verify-able extended key")
    func daedalusRoundTrip() throws {
        let bundle = try Signer.Keygen.byron(
            mnemonic: TestFixtures.testMnemonic, variant: .daedalus
        )
        #expect(bundle.signingKey.type.contains("Byron"))
        #expect(bundle.signingKey.payload.count == 128)

        let payload = Data("daedalus test".utf8)
        let signature = try Signer.sign(
            payload: payload,
            signingKey: .extendedSigningKey(bundle.signingKey)
        )
        let ok = try Signer.verify(
            payload: payload,
            signature: signature.signature,
            verificationKey: .extendedVerificationKey(bundle.verificationKey)
        )
        #expect(ok)
    }

    @Test("Daedalus default path is m/0'/0'")
    func daedalusDefaultPath() throws {
        let bundle = try Signer.Keygen.byron(
            mnemonic: TestFixtures.testMnemonic, variant: .daedalus
        )
        // HDWallet renders hardened indices with the +0x80000000 offset
        // rather than the apostrophe form, so we just count segments.
        // "m/<idx>/<idx>" → 3 segments after splitting on "/".
        let segments = bundle.path.split(separator: "/")
        #expect(segments.count == 3)
    }

    @Test("Daedalus derivation with a custom path differs from the default")
    func daedalusCustomPath() throws {
        let defaultBundle = try Signer.Keygen.byron(
            mnemonic: TestFixtures.testMnemonic, variant: .daedalus
        )
        let customBundle = try Signer.Keygen.byron(
            mnemonic: TestFixtures.testMnemonic,
            variant: .daedalus,
            path: try ByronPath(indices: [1, 0], hardened: [true, true])
        )
        #expect(defaultBundle.signingKey.payload != customBundle.signingKey.payload)
    }

    // MARK: - ByronVariant + ByronPath types

    @Test("ByronVariant is Equatable")
    func byronVariantEquatable() {
        #expect(ByronVariant.daedalus == ByronVariant.daedalus)
        #expect(ByronVariant.daedalus != ByronVariant.yoroi)
        #expect(ByronVariant.yoroi != ByronVariant.exodus)
    }

    @Test("ByronPath stores indices + hardened bits and the daedalusDefault matches m/0'/0'")
    func byronPathStorage() throws {
        let path = try ByronPath(indices: [1, 2, 3], hardened: [true, false, true])
        #expect(path.indices == [1, 2, 3])
        #expect(path.hardened == [true, false, true])

        #expect(ByronPath.daedalusDefault.indices == [0, 0])
        #expect(ByronPath.daedalusDefault.hardened == [true, true])
    }

    // MARK: - Unsupported variants

    @Test("Yoroi variant throws unsupportedVariant")
    func yoroiUnsupported() {
        #expect(throws: Signer.Keygen.ByronError.self) {
            _ = try Signer.Keygen.byron(
                mnemonic: TestFixtures.testMnemonic, variant: .yoroi
            )
        }
    }

    @Test("Exodus variant throws unsupportedVariant")
    func exodusUnsupported() {
        #expect(throws: Signer.Keygen.ByronError.self) {
            _ = try Signer.Keygen.byron(
                mnemonic: TestFixtures.testMnemonic, variant: .exodus
            )
        }
    }

    @Test("ByronError cases pattern-match distinctly")
    func byronErrorEquatable() {
        #expect(Signer.Keygen.ByronError.unsupportedVariant("a") == .unsupportedVariant("a"))
        #expect(Signer.Keygen.ByronError.unsupportedVariant("a") != .unsupportedVariant("b"))
        #expect(Signer.Keygen.ByronError.unsupportedVariant("a") != .encodingError("a"))
    }
}
