// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! CANONICAL FILE — copied verbatim into each consumer's src/ for the
//! NON-fips path (alongside std_shim.zig). Pure comptime: no @cImport,
//! no OpenSSL, no `c.*`. std_shim.zig imports THIS file via
//! `@import("policy.zig")`. Keep byte-identical across fips + std_shim.
//!
//! Comptime FIPS-approved algorithm allow-list. Consumer libs gate
//! against `policy.isApproved` and the zlint rule references this table.
//! Every string is the exact OpenSSL 3.x fetch name (confirmed via
//! `openssl list` against 3.6.2).
const std = @import("std");

pub const Hash = enum { sha256, sha384, sha512, sha3_256, sha3_384, sha3_512 };
// `Mac`, `Kdf`, and `kdfName` (below) enumerate the FIPS-approved MAC/KDF
// taxonomy for spec completeness in this copy-verbatim canonical file. The
// seam wrappers (`Mac.hmac`, `Kdf.hkdf`/`pbkdf2`) select the digest via
// `policy.Hash`, so these decls are intentionally not referenced by the
// wrappers; they mirror the approved-algorithm table for consumers/tooling.
pub const Mac = enum { hmac_sha256, hmac_sha384, hmac_sha512 };
pub const Kdf = enum { hkdf, pbkdf2 };
pub const Aead = enum { aes_128_gcm, aes_256_gcm };
pub const SigAlg = enum {
    ecdsa_p256,
    ecdsa_p384,
    ecdsa_p521,
    rsa_pss,
    rsa_pkcs1,
    ed25519,
    ml_dsa_44,
    ml_dsa_65,
    ml_dsa_87,
    slh_dsa_sha2_128s,
    slh_dsa_sha2_128f,
    slh_dsa_sha2_192s,
    slh_dsa_sha2_192f,
    slh_dsa_sha2_256s,
    slh_dsa_sha2_256f,
    slh_dsa_shake_128s,
    slh_dsa_shake_128f,
    slh_dsa_shake_192s,
    slh_dsa_shake_192f,
    slh_dsa_shake_256s,
    slh_dsa_shake_256f,
};
/// RSA signature padding scheme, selected explicitly for verify paths
/// that route a classical RSA signature through the seam with a chosen
/// digest (rather than the digest pinned by `SigAlg`). `pkcs1` is
/// RSASSA-PKCS1-v1_5; `pss` is RSASSA-PSS (MGF1 with the same digest).
pub const RsaScheme = enum { pkcs1, pss };
pub const KemAlg = enum {
    ml_kem_512,
    ml_kem_768,
    ml_kem_1024,
    x25519_ml_kem_768,
    // Kept for source compatibility; the supported provider marks it fips=no.
    x448_ml_kem_1024,
    secp256r1_ml_kem_768,
    secp384r1_ml_kem_1024,
};

pub fn hashName(a: Hash) [:0]const u8 {
    return switch (a) {
        .sha256 => "SHA2-256",
        .sha384 => "SHA2-384",
        .sha512 => "SHA2-512",
        .sha3_256 => "SHA3-256",
        .sha3_384 => "SHA3-384",
        .sha3_512 => "SHA3-512",
    };
}
pub fn aeadName(a: Aead) [:0]const u8 {
    return switch (a) {
        .aes_128_gcm => "AES-128-GCM",
        .aes_256_gcm => "AES-256-GCM",
    };
}
pub fn kdfName(a: Kdf) [:0]const u8 {
    return switch (a) {
        .hkdf => "HKDF",
        .pbkdf2 => "PBKDF2",
    };
}
pub fn sigName(a: SigAlg) [:0]const u8 {
    return switch (a) {
        .ecdsa_p256, .ecdsa_p384, .ecdsa_p521 => "ECDSA",
        .rsa_pss, .rsa_pkcs1 => "RSA",
        .ed25519 => "ED25519",
        .ml_dsa_44 => "ML-DSA-44",
        .ml_dsa_65 => "ML-DSA-65",
        .ml_dsa_87 => "ML-DSA-87",
        .slh_dsa_sha2_128s => "SLH-DSA-SHA2-128s",
        .slh_dsa_sha2_128f => "SLH-DSA-SHA2-128f",
        .slh_dsa_sha2_192s => "SLH-DSA-SHA2-192s",
        .slh_dsa_sha2_192f => "SLH-DSA-SHA2-192f",
        .slh_dsa_sha2_256s => "SLH-DSA-SHA2-256s",
        .slh_dsa_sha2_256f => "SLH-DSA-SHA2-256f",
        .slh_dsa_shake_128s => "SLH-DSA-SHAKE-128s",
        .slh_dsa_shake_128f => "SLH-DSA-SHAKE-128f",
        .slh_dsa_shake_192s => "SLH-DSA-SHAKE-192s",
        .slh_dsa_shake_192f => "SLH-DSA-SHAKE-192f",
        .slh_dsa_shake_256s => "SLH-DSA-SHAKE-256s",
        .slh_dsa_shake_256f => "SLH-DSA-SHAKE-256f",
    };
}
pub fn kemName(a: KemAlg) [:0]const u8 {
    return switch (a) {
        .ml_kem_512 => "ML-KEM-512",
        .ml_kem_768 => "ML-KEM-768",
        .ml_kem_1024 => "ML-KEM-1024",
        .x25519_ml_kem_768 => "X25519MLKEM768",
        .x448_ml_kem_1024 => "X448MLKEM1024",
        .secp256r1_ml_kem_768 => "SecP256r1MLKEM768",
        .secp384r1_ml_kem_1024 => "SecP384r1MLKEM1024",
    };
}

// FIPS-approved fetch-name allow-list used by `isApproved` for comptime
// gating of consumer call sites and by the zlint ZL109 rule. This list is
// intentionally a SUPERSET of the algorithms that have dedicated typed
// wrappers in this seam. For example, `AES-256-CBC` is FIPS-approved for
// CBC+HMAC constructions that a consumer may build directly via EVP; however,
// this seam ships only AEAD GCM wrappers (`Aead`) and does NOT expose a CBC
// wrapper (resolving GAP-0028 by documentation rather than a spurious CBC
// AEAD type). Consumers that need CBC+HMAC must build that construction
// themselves using the raw OpenSSL EVP API after verifying the name with
// `policy.isApproved("AES-256-CBC")`.
const approved_names = [_][]const u8{
    "SHA2-256",           "SHA2-384",           "SHA2-512",           "SHA3-256",           "SHA3-384",           "SHA3-512",
    "HMAC",               "HKDF",               "PBKDF2",             "AES-128-GCM",        "AES-256-GCM",        "AES-256-CBC",
    "ECDSA",              "RSA",                "ED25519",            "ML-DSA-44",          "ML-DSA-65",          "ML-DSA-87",
    "ML-KEM-512",         "ML-KEM-768",         "ML-KEM-1024",        "X25519MLKEM768",     "SecP256r1MLKEM768",  "SecP384r1MLKEM1024",
    "SLH-DSA-SHA2-128s",  "SLH-DSA-SHA2-128f",  "SLH-DSA-SHA2-192s",  "SLH-DSA-SHA2-192f",  "SLH-DSA-SHA2-256s",  "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
    // SP 800-56A Rev. 3 KAS-ECC over P-256/P-384 (`Ecdh`, ENG-7617).
    "ECDH",
};

pub fn isApproved(comptime name: []const u8) bool {
    inline for (approved_names) |n| if (std.mem.eql(u8, n, name)) return true;
    return false;
}

/// Runtime KEM selection uses the same approval table as comptime callers.
pub fn isKemApproved(alg: KemAlg) bool {
    return switch (alg) {
        inline else => |value| isApproved(kemName(value)),
    };
}

/// FIPS 203 encapsulation-key length in bytes for `alg` (the raw `ek`
/// encoding, not SPKI). Hybrid groups use the provider's named-group wire
/// layout: X25519MLKEM768 = ML-KEM ek || X25519 public key; the SecP*
/// hybrids = SEC1 uncompressed point || ML-KEM ek.
pub fn kemEncapsulationKeyLen(alg: KemAlg) usize {
    return switch (alg) {
        .ml_kem_512 => 800,
        .ml_kem_768 => 1184,
        .ml_kem_1024 => 1568,
        .x25519_ml_kem_768 => 1184 + 32,
        .x448_ml_kem_1024 => 1568 + 56,
        .secp256r1_ml_kem_768 => 65 + 1184,
        .secp384r1_ml_kem_1024 => 97 + 1568,
    };
}

/// FIPS 203 ciphertext length in bytes (same hybrid layout as the key).
pub fn kemCiphertextLen(alg: KemAlg) usize {
    return switch (alg) {
        .ml_kem_512 => 768,
        .ml_kem_768 => 1088,
        .ml_kem_1024 => 1568,
        .x25519_ml_kem_768 => 1088 + 32,
        .x448_ml_kem_1024 => 1568 + 56,
        .secp256r1_ml_kem_768 => 1088 + 65,
        .secp384r1_ml_kem_1024 => 1568 + 97,
    };
}

/// Shared-secret length in bytes. Pure ML-KEM is 32; hybrids concatenate
/// the ML-KEM secret with the raw ECDH/X25519 secret.
pub fn kemSharedSecretLen(alg: KemAlg) usize {
    return switch (alg) {
        .ml_kem_512, .ml_kem_768, .ml_kem_1024 => 32,
        .x25519_ml_kem_768 => 32 + 32,
        .x448_ml_kem_1024 => 32 + 56,
        .secp256r1_ml_kem_768 => 32 + 32,
        .secp384r1_ml_kem_1024 => 32 + 48,
    };
}

/// Largest values of the three functions above over every `KemAlg`.
pub const kem_max_encapsulation_key_len = 1665;
pub const kem_max_ciphertext_len = 1665;
pub const kem_max_shared_secret_len = 88;

/// FIPS 203 §7.2 encapsulation-key input checks, applied before a peer key
/// is handed to any backend:
///   * type check: `ek` has exactly `kemEncapsulationKeyLen(alg)` bytes;
///   * modulus check: ByteEncode12(ByteDecode12(ek_PKE[0:384k])) == ek_PKE,
///     i.e. every packed 12-bit coefficient of t-hat is < q = 3329.
/// For hybrids the check covers the ML-KEM component at its wire offset;
/// the classical component is validated by the backend (on-curve /
/// X25519 decode). Pure, constant-time over the key bytes (public data).
pub fn kemEncapsulationKeyCheck(alg: KemAlg, ek: []const u8) bool {
    if (ek.len != kemEncapsulationKeyLen(alg)) return false;
    const off: usize, const k: usize = switch (alg) {
        .ml_kem_512 => .{ 0, 2 },
        .ml_kem_768 => .{ 0, 3 },
        .ml_kem_1024 => .{ 0, 4 },
        .x25519_ml_kem_768 => .{ 0, 3 },
        .x448_ml_kem_1024 => .{ 0, 4 },
        .secp256r1_ml_kem_768 => .{ 65, 3 },
        .secp384r1_ml_kem_1024 => .{ 97, 4 },
    };
    return mlKemModulusCheck(ek[off .. off + 384 * k]);
}

fn mlKemModulusCheck(t_hat: []const u8) bool {
    std.debug.assert(t_hat.len % 3 == 0);
    var bad: u32 = 0;
    var i: usize = 0;
    while (i < t_hat.len) : (i += 3) {
        const b0: u32 = t_hat[i];
        const b1: u32 = t_hat[i + 1];
        const b2: u32 = t_hat[i + 2];
        const c0 = b0 | ((b1 & 0x0f) << 8);
        const c1 = (b1 >> 4) | (b2 << 4);
        // (x - 3329) >> 31 is 1 iff x < 3329; accumulate the "not less" bits.
        bad |= ((c0 -% 3329) >> 31) ^ 1;
        bad |= ((c1 -% 3329) >> 31) ^ 1;
    }
    return bad == 0;
}

/// SP 800-56A Rev. 3 elliptic-curve Diffie-Hellman over the NIST prime
/// curves (KAS-ECC, C(2e,0s) / C(1e,1s) primitive). Both curves have
/// cofactor 1, so ECC CDH and plain ECDH coincide.
pub const EcdhCurve = enum { p256, p384 };

/// OpenSSL EC group name for `curve`.
pub fn ecdhGroupName(curve: EcdhCurve) [:0]const u8 {
    return switch (curve) {
        .p256 => "P-256",
        .p384 => "P-384",
    };
}

/// Runtime ECDH selection: approved when "ECDH" is in the approved table.
pub fn isEcdhApproved(curve: EcdhCurve) bool {
    return switch (curve) {
        .p256, .p384 => isApproved("ECDH"),
    };
}

/// SEC1 §2.3.3 uncompressed point length: 0x04 || X || Y.
pub fn ecdhPublicLen(curve: EcdhCurve) usize {
    return switch (curve) {
        .p256 => 65,
        .p384 => 97,
    };
}

/// Shared secret Z length: the x-coordinate, field-size octets (SP 800-56A
/// §5.7.1.2).
pub fn ecdhSecretLen(curve: EcdhCurve) usize {
    return switch (curve) {
        .p256 => 32,
        .p384 => 48,
    };
}

pub const ecdh_max_public_len = 97;
pub const ecdh_max_secret_len = 48;

test "approved table accepts AES-256-GCM, rejects ChaCha20-Poly1305" {
    try std.testing.expect(isApproved("AES-256-GCM"));
    try std.testing.expect(isApproved("ML-KEM-768"));
    try std.testing.expect(!isApproved("ChaCha20-Poly1305"));
    try std.testing.expect(!isApproved("Argon2id"));
    try std.testing.expect(!isApproved("BLAKE3"));
}
test "names match openssl fetch strings" {
    try std.testing.expectEqualStrings("AES-256-GCM", aeadName(.aes_256_gcm));
    try std.testing.expectEqualStrings("X25519MLKEM768", kemName(.x25519_ml_kem_768));
    try std.testing.expectEqualStrings("SLH-DSA-SHAKE-256f", sigName(.slh_dsa_shake_256f));
}

test "SONNY-4782 X448 hybrid is excluded from the approved fetch policy" {
    try std.testing.expect(!isApproved("X448MLKEM1024"));
    try std.testing.expect(!isKemApproved(.x448_ml_kem_1024));
    inline for (.{ "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024" }) |name| {
        try std.testing.expect(isApproved(name));
    }
    inline for (@typeInfo(KemAlg).@"enum".fields) |field| {
        const alg: KemAlg = @enumFromInt(field.value);
        try std.testing.expectEqual(isApproved(kemName(alg)), isKemApproved(alg));
    }
}

test "ENG-7617 KEM and ECDH size tables" {
    inline for (@typeInfo(KemAlg).@"enum".fields) |field| {
        const alg: KemAlg = @enumFromInt(field.value);
        try std.testing.expect(kemEncapsulationKeyLen(alg) <= kem_max_encapsulation_key_len);
        try std.testing.expect(kemCiphertextLen(alg) <= kem_max_ciphertext_len);
        try std.testing.expect(kemSharedSecretLen(alg) <= kem_max_shared_secret_len);
    }
    try std.testing.expectEqual(@as(usize, 1184), kemEncapsulationKeyLen(.ml_kem_768));
    try std.testing.expectEqual(@as(usize, 1568), kemCiphertextLen(.ml_kem_1024));
    try std.testing.expect(isApproved("ECDH"));
    try std.testing.expect(isEcdhApproved(.p256) and isEcdhApproved(.p384));
    try std.testing.expectEqual(@as(usize, 97), ecdhPublicLen(.p384));
    try std.testing.expectEqual(@as(usize, 32), ecdhSecretLen(.p256));
}

test "ENG-7617 FIPS 203 encapsulation-key type and modulus checks" {
    // All-zero coefficients are canonical.
    var ek = [_]u8{0} ** 1568;
    try std.testing.expect(kemEncapsulationKeyCheck(.ml_kem_768, ek[0..1184]));
    try std.testing.expect(kemEncapsulationKeyCheck(.ml_kem_1024, ek[0..1568]));
    // Type check: wrong length either way.
    try std.testing.expect(!kemEncapsulationKeyCheck(.ml_kem_768, ek[0..1183]));
    try std.testing.expect(!kemEncapsulationKeyCheck(.ml_kem_768, ek[0..1185]));
    try std.testing.expect(!kemEncapsulationKeyCheck(.ml_kem_768, ek[0..0]));
    // 3328 = q - 1 is the largest canonical coefficient (low then high nibble).
    ek[0] = 0x00;
    ek[1] = 0x0d;
    try std.testing.expect(kemEncapsulationKeyCheck(.ml_kem_768, ek[0..1184]));
    // 3329 = q in the first coefficient: rejected.
    ek[0] = 0x01;
    try std.testing.expect(!kemEncapsulationKeyCheck(.ml_kem_768, ek[0..1184]));
    // 3329 in the SECOND packed coefficient of the last triple of t-hat.
    @memset(&ek, 0);
    ek[384 * 3 - 2] = 0x10; // low nibble of c1 = 1 -> c1 = 0xd01 = 3329
    ek[384 * 3 - 1] = 0xd0;
    try std.testing.expect(!kemEncapsulationKeyCheck(.ml_kem_768, ek[0..1184]));
    // The 32-byte rho seed after t-hat is unconstrained.
    @memset(&ek, 0);
    @memset(ek[384 * 3 .. 1184], 0xff);
    try std.testing.expect(kemEncapsulationKeyCheck(.ml_kem_768, ek[0..1184]));
    // Hybrid offsets: the SEC1 point prefix is not part of the modulus check,
    // but an out-of-range coefficient right after it is.
    var hy = [_]u8{0} ** 1665;
    @memset(hy[0..97], 0xff);
    try std.testing.expect(kemEncapsulationKeyCheck(.secp384r1_ml_kem_1024, &hy));
    hy[97] = 0xff;
    hy[98] = 0x0f;
    try std.testing.expect(!kemEncapsulationKeyCheck(.secp384r1_ml_kem_1024, &hy));
}
