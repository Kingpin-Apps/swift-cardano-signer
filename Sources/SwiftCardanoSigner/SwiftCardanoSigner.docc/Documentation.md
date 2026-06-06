# ``SwiftCardanoSigner``

Pure-Swift port of [gitmachtl/cardano-signer](https://github.com/gitmachtl/cardano-signer) — off-line / off-chain Ed25519 signing for Cardano.

## Overview

`SwiftCardanoSigner` is the library-only Swift equivalent of the
de-facto reference CLI used by Cardano stake-pool operators, dRep
candidates, Catalyst voters, and dApp wallet bridges for off-line
signing. Everything cardano-signer.js exposes for programmatic use is
mirrored here through the single ``Signer`` namespace — no CLI argv
parsing, no shell-level conveniences in the public API.

The signer composes the rest of the Kingpin Apps Cardano Swift stack:
[swift-cardano-core](https://github.com/Kingpin-Apps/swift-cardano-core)
for key types and BIP-32-Ed25519, [swift-cardano-cips](https://github.com/Kingpin-Apps/swift-cardano-cips)
for the CIP implementations, [swift-mnemonic](https://github.com/Kingpin-Apps/swift-mnemonic)
for BIP-39, and libsodium (via [swift-nacl](https://github.com/Kingpin-Apps/swift-nacl))
for the RFC 8032 deterministic Ed25519 signing primitive. Each `Signer.<CIP>`
namespace is a thin facade that delegates to the corresponding `CIP*`
type in `swift-cardano-cips`; the value here is the cardano-signer-shaped
mental model in one place, not a re-implementation.

### Capabilities

- **Default Ed25519** — `Signer.sign(payload:signingKey:)` /
  `Signer.verify(payload:signature:verificationKey:)` for raw bytes.
  The RFC 8032 §7.1 Test 1 canonical vector is part of the test suite.
- **CIP-8 / CIP-30** — message signing for wallet flows. Deterministic
  COSE_Sign1 output (cips ≥ 0.3.6 routes signing through libsodium,
  not CryptoKit's hedged Ed25519, and emits the attached COSE_Key in
  canonical CBOR map order).
- **CIP-36** — Catalyst voting registration and deregistration metadata,
  including multi-delegation with per-key weights.
- **CIP-88 v2 / CIP-151** — Calidus pool-operator key registration. Signs
  the unusual `blake2b-256(hex-lowercase(CBOR(payload)))` payload the
  spec mandates, byte-equivalent to cardano-signer.js's `--cip88`
  output.
- **CIP-100 / 108 / 119** — governance metadata sign + verify, built on
  the RDFC-1.0 / URDNA2015 canonicalisation in
  [swift-jsonld](https://github.com/Kingpin-Apps/swift-jsonld).
- **CIP-129** — bech32 prefix helpers for `drep`, `cc_cold`, `cc_hot`,
  `calidus` (plus the four `*_script` forms) with the spec-mandated
  header byte.
- **Keygen** — seven CIP-1852 / CIP-1853 / CIP-1854 paths (payment,
  stake, dRep, CC-cold, CC-hot, pool, calidus), CIP-36 vote keys, Ledger
  and Trezor variant derivations (Adrestia `[0x01]` quirk replicated for
  HW-wallet interop), Byron Daedalus derivation, and a
  ``SlotNonce/mainnetSlot(at:)`` time → slot-height helper for
  registration nonces.

### Strict concurrency

Compiled at `swiftLanguageModes: [.v6]` — types are `Sendable` and
`Equatable` where the public API exposes them, and there are no
implicit-actor warnings on any supported platform.

## Quickstart

The most common path: default Ed25519 sign + verify on raw bytes.

```swift
import SwiftCardanoSigner
import SwiftCardanoCore

let signingKey = try SigningKey(payload: seed)      // 32-byte Ed25519 seed
let payload = Data("hello cardano".utf8)

let result = try Signer.sign(
    payload: payload,
    signingKey: .signingKey(signingKey)
)
// result.signature  → 64-byte detached Ed25519 signature
// result.publicKey  → 32-byte derived verification key

let verificationKey = try VerificationKey(payload: result.publicKey)
let ok = try Signer.verify(
    payload: payload,
    signature: result.signature,
    verificationKey: .verificationKey(verificationKey)
)
// ok → true
```

## CIP-8 message signing

CIP-0008 wraps a payload in COSE_Sign1 with the signer's address bound
into the protected header. This is the building block CIP-30 dApp
wallets use for `signData`.

```swift
let signed = try Signer.CIP8.sign(
    payload: Data("hello dApp".utf8),
    signingKey: .signingKey(paymentSK),
    attachCoseKey: false,
    network: .mainnet
)
// signed.signature  → hex-encoded COSE_Sign1
// signed.key        → nil (no attached COSE_Key)

let result = try Signer.CIP8.verify(signed)
// result.verified         → true
// result.message          → "hello dApp"
// result.signingAddress   → addr1...
```

For CIP-30 dApp bridge signatures, use `Signer.CIP30.signData(...)` —
identical wire format with the COSE_Key always attached.

## CIP-36 Catalyst registration

```swift
let registration = try Signer.CIP36.makeRegistration(
    delegations: [
        .init(votingKey: voteVKey, weight: 1)
    ],
    stakeSigningKey: .signingKey(stakeSK),
    rewardsAddress: try Address(stakingPart: ..., network: .mainnet),
    nonce: SlotNonce.mainnetSlot(at: nowUnix),
    votingPurpose: 0   // 0 = Catalyst
)
// registration is an AuxiliaryData carrying labels 61284 + 61285.
```

Pass that `AuxiliaryData` straight into a transaction body alongside the
rest of the registration tx.

## CIP-88 v2 / CIP-151 Calidus pool key

```swift
let registration = try Signer.CIP88.makeCalidusRegistration(
    calidusPublicKey: calidusVKey,
    poolSigningKey: .signingKey(poolColdSK),
    nonce: SlotNonce.mainnetSlot(at: nowUnix)
)
// AuxiliaryData under label 867 with the {0:2, 1:payload, 2:[witness]} envelope.
```

`Signer.CIP151` is a literal alias of `Signer.CIP88` — both names work,
matching the cardano-signer CLI's `--cip88` / `--cip151` flags.

## CIP-100 governance metadata signing

```swift
let document: Data = …  // JSON-LD bytes with @context, hashAlgorithm, body
let signed = try await Signer.CIP100.signMetadata(
    document: document,
    signingKey: .signingKey(authorSK),
    authorName: "Alice"
)
// `signed` carries the original body + a new `authors[]` entry with
// the witness `{witnessAlgorithm: "ed25519", publicKey, signature}`.

let result = try await Signer.CIP100.verifyMetadata(signed)
// result.allValid                → true
// result.authorResults[0].name   → "Alice"
// result.authorResults[0].valid  → true
// result.canonicalBodyHash       → 32-byte Blake2b-256 over the canonical N-Quads
```

The signing payload is `Blake2b-256` of the URDNA2015-canonical
N-Quads of the document with `authors` stripped (per
[CIP-0100](https://cips.cardano.org/cip/CIP-0100)). Multiple authors
sign independently; tampering with the body invalidates every witness.

## CIP-129 governance IDs

Bech32-encoded identifiers for Conway-era governance credentials with
the spec-mandated header byte.

```swift
let drepID = try Signer.CIP129.encode(
    keyHash: blake2b224(drepVKey),
    as: .drep,
    isScript: false
)
// drepID → "drep1..."

let (prefix, keyHash, isScript) = try Signer.CIP129.decode(drepID)
```

Supports `drep`, `ccCold`, `ccHot`, and `calidus` (CIP-151) plus the
script forms for the first three.

## Keygen

Derive an extended key for any of the seven canonical Cardano roles from
a BIP-39 mnemonic.

```swift
let bundle = try Signer.Keygen.shelley(
    mnemonic: ["abandon", "abandon", /* … */ "art"],
    kind: .payment(account: 0, index: 0)
)
// bundle.signingKey         → 128-byte extended (BIP32-Ed25519) private + chain code
// bundle.verificationKey    → 64-byte extended verification key
// bundle.path               → "m/1852'/1815'/0'/0/0"
```

Available roles via ``ShelleyKeyKind``:

| Role | Path |
|---|---|
| `.payment(account, index)` | `m/1852'/1815'/account'/0/index` |
| `.stake(account, index)`   | `m/1852'/1815'/account'/2/index` |
| `.drep(account, index)`    | `m/1852'/1815'/account'/3/index` |
| `.ccCold(account, index)`  | `m/1852'/1815'/account'/4/index` |
| `.ccHot(account, index)`   | `m/1852'/1815'/account'/5/index` |
| `.pool(account)`           | `m/1853'/1815'/account'/0'`     |
| `.calidus(account)`        | `m/1854'/1815'/account'/0'`     |

For Catalyst voting keys on the dedicated CIP-36 path:

```swift
let vote = try Signer.Keygen.cip36(
    mnemonic: words,
    account: 0,
    address: 0
)
```

For Ledger / Trezor / Byron Daedalus mnemonics — different master-key
derivations, identical downstream BIP-32-Ed25519:

```swift
let ledger = try Signer.Keygen.ledger(mnemonic: words, kind: .payment())
let trezor = try Signer.Keygen.trezor(mnemonic: words, kind: .payment())
let byron  = try Signer.Keygen.byron(mnemonic: words, variant: .daedalus)
```

Yoroi and Exodus paperwallet variants throw
``Signer/Keygen/ByronError/unsupportedVariant(_:)`` — the unscrambling
algorithms aren't ported yet.

## Topics

### Top-level namespace

- ``Signer``
- ``SignatureResult``
- ``SignerError``

### Default Ed25519

- ``Signer/sign(payload:signingKey:)``
- ``Signer/verify(payload:signature:verificationKey:)``

### CIP-8 / CIP-30 dApp signing

- ``Signer/CIP8``
- ``Signer/CIP30``

### CIP-36 Catalyst voting registration

- ``Signer/CIP36``

### CIP-88 v2 / CIP-151 Calidus pool-key registration

- ``Signer/CIP88``
- ``Signer/CIP151``

### CIP-100 governance metadata signing

- ``Signer/CIP100``

### CIP-129 governance bech32 IDs

- ``Signer/CIP129``

### Key derivation

- ``Signer/Keygen``
- ``ShelleyKeyKind``
- ``KeyPairBundle``
- ``CIP36VoteKeyPair``
- ``ByronVariant``
- ``ByronPath``
- ``CardanoPaths``

### Utilities

- ``SlotNonce``
