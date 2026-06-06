import Foundation
import SwiftCardanoCore

public extension Signer {
    /// Predefined-path key derivation, mirroring cardano-signer's `keygen`
    /// command family.
    ///
    /// Every operation here is built on
    /// ``SwiftCardanoCore/HDWallet`` — the Swift implementation of
    /// BIP32-ED25519 derivation that the rest of the stack already uses.
    /// `Signer.Keygen` adds:
    ///
    /// - **Named paths** for the seven canonical Cardano roles plus CIP-36
    ///   voting (see ``CardanoPaths``).
    /// - **Typed envelopes** — output bundles are tagged with the
    ///   role-specific TextEnvelope `type` string so callers can persist
    ///   them as `.skey` / `.vkey` files that cardano-cli reads back.
    /// - **Hardware-wallet variants** (Phase 8 — Ledger, Trezor) and
    ///   **Byron-era variants** (Phase 9 — Daedalus, Yoroi, Exodus)
    ///   that need different mnemonic-to-master-key derivations than the
    ///   standard ICARUS path.
    enum Keygen {}
}

/// The seven canonical Shelley-era key roles plus an explicit pool / calidus
/// case for the CIP-1853 / CIP-1854 hardened-leaf paths.
///
/// Used as the input to ``Signer/Keygen/shelley(mnemonic:passphrase:kind:)``.
public enum ShelleyKeyKind: Sendable, Equatable {
    case payment(account: UInt32 = 0, index: UInt32 = 0)
    case stake(account: UInt32 = 0, index: UInt32 = 0)
    case drep(account: UInt32 = 0, index: UInt32 = 0)
    case ccCold(account: UInt32 = 0, index: UInt32 = 0)
    case ccHot(account: UInt32 = 0, index: UInt32 = 0)
    case pool(account: UInt32 = 0)
    case calidus(account: UInt32 = 0)

    /// The BIP-32 derivation path for this role.
    public var path: String {
        switch self {
        case let .payment(account, index): return CardanoPaths.payment(account: account, index: index)
        case let .stake(account, index):   return CardanoPaths.stake(account: account, index: index)
        case let .drep(account, index):    return CardanoPaths.drep(account: account, index: index)
        case let .ccCold(account, index):  return CardanoPaths.ccCold(account: account, index: index)
        case let .ccHot(account, index):   return CardanoPaths.ccHot(account: account, index: index)
        case let .pool(account):           return CardanoPaths.pool(account: account)
        case let .calidus(account):        return CardanoPaths.calidus(account: account)
        }
    }

    /// The TextEnvelope `type` string this role uses when serialised as
    /// a `.skey` / `.vkey` file. These match the strings cardano-cli
    /// produces for the corresponding `cardano-cli ... key gen` flows.
    var envelopeTypeSigning: String {
        switch self {
        case .payment: return "PaymentExtendedSigningKeyShelley_ed25519_bip32"
        case .stake:   return "StakeExtendedSigningKeyShelley_ed25519_bip32"
        case .drep:    return "DRepExtendedSigningKey_ed25519_bip32"
        case .ccCold:  return "ConstitutionalCommitteeColdExtendedSigningKey_ed25519_bip32"
        case .ccHot:   return "ConstitutionalCommitteeHotExtendedSigningKey_ed25519_bip32"
        case .pool:    return "StakePoolExtendedSigningKey_ed25519_bip32"
        case .calidus: return "CalidusExtendedSigningKey_ed25519_bip32"
        }
    }

    /// Human-readable description suffix used in the TextEnvelope.
    var envelopeDescriptionSigning: String {
        switch self {
        case .payment: return "Payment Signing Key"
        case .stake:   return "Stake Signing Key"
        case .drep:    return "Delegate Representative Signing Key"
        case .ccCold:  return "Constitutional Committee Cold Signing Key"
        case .ccHot:   return "Constitutional Committee Hot Signing Key"
        case .pool:    return "Stake Pool Signing Key"
        case .calidus: return "Calidus Signing Key"
        }
    }
}

/// The result of a Shelley / CIP-36 keygen operation.
///
/// Carries both the extended signing key (with chain code, for further
/// child derivation) and the extended verification key, plus the
/// derivation path used. Callers can downcast `signingKey` to a
/// role-specific type (e.g. `PaymentExtendedSigningKey`) by reading the
/// envelope `type` string, or convert to non-extended forms via
/// ``SwiftCardanoCore/ExtendedSigningKey/toVerificationKey()``.
public struct KeyPairBundle: Sendable {
    public let signingKey: ExtendedSigningKey
    public let verificationKey: ExtendedVerificationKey
    public let path: String

    public init(
        signingKey: ExtendedSigningKey,
        verificationKey: ExtendedVerificationKey,
        path: String
    ) {
        self.signingKey = signingKey
        self.verificationKey = verificationKey
        self.path = path
    }
}

/// The result of a CIP-36 voting-key derivation.
///
/// Same shape as ``KeyPairBundle`` but with a distinct type to signal
/// "do not use this for transaction signing" at call sites — CIP-36 vote
/// keys are separate from payment / stake credentials.
public struct CIP36VoteKeyPair: Sendable {
    public let signingKey: ExtendedSigningKey
    public let verificationKey: ExtendedVerificationKey
    public let path: String

    public init(
        signingKey: ExtendedSigningKey,
        verificationKey: ExtendedVerificationKey,
        path: String
    ) {
        self.signingKey = signingKey
        self.verificationKey = verificationKey
        self.path = path
    }
}
