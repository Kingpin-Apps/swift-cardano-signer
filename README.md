# swift-cardano-signer

A pure-Swift port of [gitmachtl/cardano-signer](https://github.com/gitmachtl/cardano-signer) —
the de-facto reference for off-line / off-chain Ed25519 signing on
Cardano. Library-only; no CLI.

[![Swift 6](https://img.shields.io/badge/Swift-6.0%2B-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%20%7C%20macOS%20%7C%20watchOS%20%7C%20tvOS%20%7C%20visionOS%20%7C%20Linux-blue.svg)](Package.swift)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

- **Full feature parity** with cardano-signer.js for the CIPs that
  matter: default Ed25519, CIP-8 / CIP-30 message signing,
  CIP-36 Catalyst registration, CIP-88 v2 / CIP-151 Calidus pool keys,
  CIP-100 / 108 / 119 governance metadata, CIP-129 governance bech32
  IDs, and the full seven-role CIP-1852 / CIP-1853 / CIP-1854 keygen
  plus Ledger / Trezor / Byron Daedalus variants.
- **Deterministic Ed25519 throughout.** Routes signing through
  libsodium's RFC 8032 implementation, not CryptoKit's hedged variant —
  same inputs always produce the same bytes, as Ed25519 promises and as
  every downstream Cardano verifier expects.
- **Spec-compliant by construction.** CIP-151 v2's unusual
  `blake2b-256(hex-lowercase(CBOR(payload)))` signing payload is
  byte-equivalent to cardano-signer.js's output. CIP-100's signing
  payload is built on top of W3C RDFC-1.0 / URDNA2015 via
  [swift-jsonld](https://github.com/Kingpin-Apps/swift-jsonld) — the
  same canonicalisation `digitalbazaar/jsonld.js` uses.
- **Pure Swift.** [swift-cardano-core](https://github.com/Kingpin-Apps/swift-cardano-core),
  [swift-cardano-cips](https://github.com/Kingpin-Apps/swift-cardano-cips),
  [swift-mnemonic](https://github.com/Kingpin-Apps/swift-mnemonic),
  [swift-nacl](https://github.com/Kingpin-Apps/swift-nacl), and
  [krzyzanowskim/CryptoSwift](https://github.com/krzyzanowskim/CryptoSwift) —
  no FFI, no JavaScript runtime, no bridging headers. Same code on
  Apple platforms and Linux.
- **Strict concurrency clean.** Compiled at `swiftLanguageModes: [.v6]`,
  every public type that crosses an actor is `Sendable`.

## Quickstart

```swift
import SwiftCardanoSigner
import SwiftCardanoCore

let signingKey = try SigningKey(payload: seed)   // 32-byte Ed25519 seed

let result = try Signer.sign(
    payload: Data("hello cardano".utf8),
    signingKey: .signingKey(signingKey)
)
// result.signature  → 64-byte detached Ed25519 signature
// result.publicKey  → 32-byte derived verification key
```

The signing-key input is a `SwiftCardanoCore.SigningKeyType` —
union of regular Ed25519 (32-byte seed) and BIP32-Ed25519 extended
(128-byte) keys. The same `Signer.sign` / `Signer.verify` entry points
handle both.

### CIP-8 / CIP-30 message signing

```swift
let signed = try Signer.CIP8.sign(
    payload: Data("hello dApp".utf8),
    signingKey: .signingKey(paymentSK),
    attachCoseKey: false,
    network: .mainnet
)
// signed.signature  → hex COSE_Sign1
// signed.key        → nil (no attached COSE_Key)

let result = try Signer.CIP8.verify(signed)
// result.verified  → true
```

For dApp wallets, `Signer.CIP30.signData(payload:signingKey:network:)`
is identical to `Signer.CIP8.sign(attachCoseKey: true)`.

### CIP-36 Catalyst registration

```swift
let registration = try Signer.CIP36.makeRegistration(
    delegations: [.init(votingKey: voteVKey, weight: 1)],
    stakeSigningKey: .signingKey(stakeSK),
    rewardsAddress: addr,
    nonce: SlotNonce.mainnetSlot(at: nowUnix),
    votingPurpose: 0   // 0 = Catalyst
)
// AuxiliaryData with labels 61284 (registration) + 61285 (witness)
```

Multi-delegation with per-key weights is supported.
`Signer.CIP36.makeDeregistration(...)` produces the matching
`61286 / 61287` deregistration metadata.

### CIP-88 v2 / CIP-151 Calidus pool key

```swift
let registration = try Signer.CIP88.makeCalidusRegistration(
    calidusPublicKey: calidusVKey,
    poolSigningKey: .signingKey(poolColdSK),
    nonce: SlotNonce.mainnetSlot(at: nowUnix)
)
// AuxiliaryData under label 867 — {0:2, 1:payload, 2:[witness]}
```

`Signer.CIP151` is a literal alias of `Signer.CIP88`; both names work,
matching the cardano-signer CLI's `--cip88` and `--cip151` flags.

### CIP-100 governance metadata

```swift
let signed = try await Signer.CIP100.signMetadata(
    document: jsonLDBytes,
    signingKey: .signingKey(authorSK),
    authorName: "Alice"
)
let result = try await Signer.CIP100.verifyMetadata(signed)
// result.allValid                  → true
// result.authorResults[0].name     → "Alice"
// result.authorResults[0].valid    → true
// result.canonicalBodyHash         → 32-byte Blake2b-256 over the canonical N-Quads
```

The signing payload is `Blake2b-256` of the URDNA2015-canonical N-Quads
of the document with `authors` stripped (per
[CIP-0100](https://cips.cardano.org/cip/CIP-0100)). Multiple authors
sign independently; tampering with the `body` invalidates every
witness.

### CIP-129 governance IDs

```swift
let drepID = try Signer.CIP129.encode(
    keyHash: blake2b224(drepVKey),
    as: .drep,
    isScript: false
)
// drepID → "drep1..."

let (prefix, hash, isScript) = try Signer.CIP129.decode(drepID)
```

Supports `drep`, `ccCold`, `ccHot`, and `calidus` (CIP-151) plus the
script forms for the first three.

### Keygen

Derive any of the seven canonical Cardano roles from a BIP-39 mnemonic:

```swift
let payment = try Signer.Keygen.shelley(mnemonic: words, kind: .payment())
let stake   = try Signer.Keygen.shelley(mnemonic: words, kind: .stake())
let drep    = try Signer.Keygen.shelley(mnemonic: words, kind: .drep())
let ccCold  = try Signer.Keygen.shelley(mnemonic: words, kind: .ccCold())
let ccHot   = try Signer.Keygen.shelley(mnemonic: words, kind: .ccHot())
let pool    = try Signer.Keygen.shelley(mnemonic: words, kind: .pool())
let calidus = try Signer.Keygen.shelley(mnemonic: words, kind: .calidus())

// Catalyst voting key on the CIP-36 dedicated path:
let vote = try Signer.Keygen.cip36(mnemonic: words)

// HW-wallet variants — different master key, same downstream BIP-32-Ed25519:
let ledger = try Signer.Keygen.ledger(mnemonic: words, kind: .payment())
let trezor = try Signer.Keygen.trezor(mnemonic: words, kind: .payment())

// Byron Daedalus — original IOG wallet derivation:
let byron = try Signer.Keygen.byron(mnemonic: words, variant: .daedalus)
```

Ledger master-key derivation replicates the Adrestia `[0x01]`
chain-code-prefix quirk that `cardano-cli` expects for HW-wallet
interop. Yoroi / Exodus paperwallets throw
`Signer.Keygen.ByronError.unsupportedVariant(...)` — the unscrambling
algorithms aren't ported yet.

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/Kingpin-Apps/swift-cardano-signer.git", from: "0.1.0"),
],
```

Then add `SwiftCardanoSigner` to your target:

```swift
.target(name: "MyApp", dependencies: [
    .product(name: "SwiftCardanoSigner", package: "swift-cardano-signer"),
]),
```

## Platforms

iOS 16+, macOS 14+, watchOS 9+, tvOS 16+, visionOS 1+, and Linux on
Swift 6.0+. Strict-concurrency clean (compiled at
`swiftLanguageModes: [.v6]`).

The platform floor matches
[swift-cardano-cips](https://github.com/Kingpin-Apps/swift-cardano-cips)
to keep the dependency graph consistent across the Kingpin Apps Cardano
Swift stack.

## Test coverage

98 tests across 18 suites, with the test layout mirroring the source
tree — every `Sources/SwiftCardanoSigner/<Subdir>/<File>.swift` has a
paired `Tests/SwiftCardanoSignerTests/<Subdir>/<File>Tests.swift`.
Highlights:

- **RFC 8032 §7.1 Test 1** — canonical Ed25519 reference vector
- **Canonical Pycardano CIP-8 signed message** — cross-implementation
  interop fixture
- **End-to-end witness verification** through libsodium for CIP-36,
  CIP-88, CIP-100
- **HW-wallet derivation invariants** — Ed25519 scalar clamp (bytes
  0 / 31 bits), Ledger recursion termination (bit 5 of byte 31 clears),
  ICARUS divergence
- **Byron Daedalus algorithm parity** with cardano-signer.js
  (`CBOR(BLAKE2b-256(CBOR(entropy)))` seed + `HMAC-SHA512` chain with
  `"Root Seed Chain N"`)

Run the suite:

```bash
swift test
```

## Composing into the Cardano stack

The signer is the off-line / off-chain operations layer of the Kingpin
Apps Swift Cardano stack. Its place in the dependency graph:

```
swift-cardano-signer
  ↓
swift-cardano-cips    (CIP-8/30/36/88/100/129/119 implementations)
  ↓
swift-cardano-core    (Cardano types + BIP-32-Ed25519)
  ↓
swift-mnemonic        (BIP-39)
swift-nacl            (libsodium / RFC 8032 Ed25519)
swift-jsonld          (W3C JSON-LD 1.1 — for CIP-100 canonicalisation)
  ↓
swift-rdf-canonize    (W3C RDFC-1.0 / URDNA2015)
```

For transaction-level signing (building, balancing, witnessing transactions),
see [swift-cardano-txbuilder](https://github.com/Kingpin-Apps/swift-cardano-txbuilder)
and [swift-cardano-wallet](https://github.com/Kingpin-Apps/swift-cardano-wallet) —
they consume the same key types from `swift-cardano-core` that this
package operates on.

## Acknowledgements

- [gitmachtl/cardano-signer](https://github.com/gitmachtl/cardano-signer) —
  the reference JavaScript implementation. This Swift port mirrors its
  function-level surface byte-for-byte; the few intentional quirks
  (Ledger Adrestia `[0x01]` prefix, CIP-151 v2's hex-then-hash signing
  payload) are replicated for cross-implementation interop, not
  because they're elegant.
- [W3C RDF Canonicalization WG](https://www.w3.org/TR/rdf-canon/) for
  RDFC-1.0 / URDNA2015 — the foundation of CIP-100.
- Cardano Foundation's
  [CIPs repository](https://github.com/cardano-foundation/CIPs/) — the
  source of truth for every wire format we touch.

## License

[MIT](LICENSE).
