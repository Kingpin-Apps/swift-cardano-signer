import Foundation

/// Canonical BIP-32 / BIP-44 derivation paths used across the Cardano
/// ecosystem.
///
/// The seven Shelley-era roles plus the CIP-36 vote-key path, modelled after
/// the same constants cardano-signer.js exposes via its `--path` shorthand.
///
/// Path components:
///
/// - **purpose** — `1852'` for Shelley (CIP-1852), `1853'` for stake-pool
///   (CIP-1853), `1854'` for multisig/calidus (CIP-1854), `1694'` for CIP-36
///   voting.
/// - **coin type** — `1815'` for ADA (Cardano).
/// - **account** — caller-supplied hardened index (default `0'`).
/// - **role** — the leaf-role discriminator:
///   - `0` = payment, `2` = stake, `3` = drep, `4` = cc-cold, `5` = cc-hot
///     (per CIP-1852 / CIP-105).
/// - **index** — leaf address index, unhardened.
public enum CardanoPaths {

    // MARK: - CIP-1852 Shelley wallets

    /// `m/1852'/1815'/<account>'/0/<index>` — payment key.
    public static func payment(account: UInt32 = 0, index: UInt32 = 0) -> String {
        "m/1852'/1815'/\(account)'/0/\(index)"
    }

    /// `m/1852'/1815'/<account>'/2/<index>` — staking key.
    public static func stake(account: UInt32 = 0, index: UInt32 = 0) -> String {
        "m/1852'/1815'/\(account)'/2/\(index)"
    }

    /// `m/1852'/1815'/<account>'/3/<index>` — dRep (delegated representative)
    /// key, per CIP-105 / CIP-129.
    public static func drep(account: UInt32 = 0, index: UInt32 = 0) -> String {
        "m/1852'/1815'/\(account)'/3/\(index)"
    }

    /// `m/1852'/1815'/<account>'/4/<index>` — Constitutional Committee cold
    /// key, per CIP-105 / CIP-129.
    public static func ccCold(account: UInt32 = 0, index: UInt32 = 0) -> String {
        "m/1852'/1815'/\(account)'/4/\(index)"
    }

    /// `m/1852'/1815'/<account>'/5/<index>` — Constitutional Committee hot
    /// key, per CIP-105 / CIP-129.
    public static func ccHot(account: UInt32 = 0, index: UInt32 = 0) -> String {
        "m/1852'/1815'/\(account)'/5/\(index)"
    }

    // MARK: - CIP-1853 stake-pool cold key

    /// `m/1853'/1815'/<account>'/0'` — stake-pool cold key (CIP-1853).
    public static func pool(account: UInt32 = 0) -> String {
        "m/1853'/1815'/\(account)'/0'"
    }

    // MARK: - CIP-1854 / calidus pool operator key

    /// `m/1854'/1815'/<account>'/0'` — Calidus pool-operator key
    /// (CIP-1854-flavoured; same purpose number used by cardano-signer
    /// `keygen --path calidus`).
    public static func calidus(account: UInt32 = 0) -> String {
        "m/1854'/1815'/\(account)'/0'"
    }

    // MARK: - CIP-36 Catalyst voting

    /// `m/1694'/1815'/<account>'/0/<address>` — CIP-36 voting key.
    public static func cip36(account: UInt32 = 0, address: UInt32 = 0) -> String {
        "m/1694'/1815'/\(account)'/0/\(address)"
    }
}
