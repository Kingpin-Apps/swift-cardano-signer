import Foundation
import CryptoSwift
import SwiftNaCl

/// BIP32-Ed25519 child derivation, scheme 1 ("V1").
///
/// Legacy Daedalus (random) wallets derive child keys with this scheme,
/// not with the V2 scheme Icarus and Shelley wallets use. It is a direct
/// port of `wallet_encrypted_derive_private` with `DERIVATION_V1` in
/// IOHK's cardano-crypto (`cbits/encrypted_sign.c`), including its quirks:
///
/// - the index is serialized big-endian;
/// - `8·ZL` multiplies all 32 bytes of ZL, shifting each byte left by
///   three with no carry between bytes (`multiply8_v1`);
/// - the new `kL` is `(kL + 8·ZL) mod ℓ` (`cardano_crypto_ed25519_scalar_add`);
/// - the new `kR` adds `kR + ZR` byte by byte with no carry (`add_256bits_v1`).
///
/// Checked against cardano-crypto's golden vectors (derivation-scheme1,
/// retry-old master keys) in the tests.
enum DaedalusDerivation {
    /// One extended private key: 64-byte `kL‖kR` and its 32-byte chain code.
    struct Node {
        var key: Data
        var chainCode: Data

        var publicKey: Data {
            get throws { try Sodium().cryptoScalarmult.ed25519BaseNoclamp(n: key.prefix(32)) }
        }
    }

    /// The child of `node` at `index`. `index` carries the hardened bit
    /// itself (`0x8000_0000` and above are hardened).
    static func derive(_ node: Node, index: UInt32) throws -> Node {
        let indexBytes: [UInt8] = [
            UInt8(truncatingIfNeeded: index >> 24),
            UInt8(truncatingIfNeeded: index >> 16),
            UInt8(truncatingIfNeeded: index >> 8),
            UInt8(truncatingIfNeeded: index),
        ]
        let hardened = index & 0x8000_0000 != 0
        let material: [UInt8] = hardened ? Array(node.key) : Array(try node.publicKey)
        let zTag: UInt8 = hardened ? 0x00 : 0x02
        let ccTag: UInt8 = hardened ? 0x01 : 0x03

        let hmac = HMAC(key: Array(node.chainCode), variant: .sha2(.sha512))
        let z = try hmac.authenticate([zTag] + material + indexBytes)
        let i = try hmac.authenticate([ccTag] + material + indexBytes)

        let kL = Array(node.key.prefix(32))
        let kR = Array(node.key.suffix(32))
        let zl8 = z[0..<32].map { $0 << 3 }
        let newKL = scalarAddModL(kL, zl8)
        let newKR = zip(kR, z[32..<64]).map { $0 &+ $1 }

        return Node(key: Data(newKL + newKR), chainCode: Data(i[32..<64]))
    }

    /// The Ed25519 group order ℓ = 2^252 + 27742317777372353535851937790883648493,
    /// little-endian.
    private static let order: [UInt8] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ]

    /// `(a + b) mod ℓ` for two little-endian 256-bit numbers.
    static func scalarAddModL(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        // The sum is below 2^257 and ℓ is above 2^252, so at most 32
        // subtractions of ℓ bring it into range.
        var sum = [UInt8](repeating: 0, count: 33)
        var carry: UInt16 = 0
        for k in 0..<32 {
            let v = UInt16(a[k]) + UInt16(b[k]) + carry
            sum[k] = UInt8(truncatingIfNeeded: v)
            carry = v >> 8
        }
        sum[32] = UInt8(carry)
        let modulus = order + [0]
        while !isLess(sum, modulus) {
            var borrow: Int16 = 0
            for k in 0..<33 {
                var v = Int16(sum[k]) - Int16(modulus[k]) - borrow
                borrow = 0
                if v < 0 { v += 256; borrow = 1 }
                sum[k] = UInt8(v)
            }
        }
        return Array(sum.prefix(32))
    }

    private static func isLess(_ x: [UInt8], _ y: [UInt8]) -> Bool {
        for k in stride(from: x.count - 1, through: 0, by: -1) where x[k] != y[k] {
            return x[k] < y[k]
        }
        return false
    }
}
