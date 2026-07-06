// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
const std = @import("std");
const ffi = @import("ffi.zig");
const c = ffi.c;
const policy = @import("policy.zig");
const provider = @import("provider.zig");

/// Key-import / signing-mode family for a signature algorithm.
const Family = enum { ed25519, der, pqc };

pub fn sigFamily(alg: policy.SigAlg) Family {
    return switch (alg) {
        .ed25519 => .ed25519,
        .ecdsa_p256, .ecdsa_p384, .ecdsa_p521, .rsa_pss, .rsa_pkcs1 => .der,
        else => .pqc,
    };
}

pub fn sigIsRsa(alg: policy.SigAlg) bool {
    return alg == .rsa_pss or alg == .rsa_pkcs1;
}

pub fn isPqc(alg: policy.SigAlg) bool {
    return sigFamily(alg) == .pqc;
}

// ---------------------------------------------------------------------------
// EC / PQC key import under FIPS.
//
// sigil hands the seam STRIPPED key material, not self-describing DER:
//   * EC private  -> bare SEC1 ECPrivateKey (PKCS#8 privateKey OCTET STRING
//                    contents) WITHOUT the [0] curve params.
//   * EC public   -> raw SEC1 point (0x04||X||Y), no SPKI wrapper.
//   * PQC private -> the PKCS#8 privateKey OCTET STRING contents.
//   * PQC public  -> the raw public key bytes.
// std.crypto (the non-fips shim) recovers the algorithm from the comptime Zig
// type, but OpenSSL's decoders need the algorithm/curve in an AlgorithmIdentifier
// — with only the stripped bytes every decode returns NULL under the fips+base
// provider config. So reconstruct a PKCS#8 (private) or SubjectPublicKeyInfo
// (public) carrying the AlgorithmIdentifier implied by `alg`, then decode through
// the FIPS libctx. (Root cause of the -Dfips CMS / ECDSA / CRL / PQC failures.)
// ---------------------------------------------------------------------------

// EC AlgorithmIdentifier ::= SEQUENCE { id-ecPublicKey, <namedCurve> } DER.
// id-ecPublicKey = 1.2.840.10045.2.1. PQC AlgIds are built dynamically from the
// algorithm name via OBJ_txt2obj (no fixed params), covering all ML-DSA/SLH-DSA.
const ec_algid_p256 = [_]u8{ // prime256v1 = 1.2.840.10045.3.1.7
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
};
const ec_algid_p384 = [_]u8{ // secp384r1 = 1.3.132.0.34
    0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
};
const ec_algid_p521 = [_]u8{ // secp521r1 = 1.3.132.0.35
    0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23,
};

// Return the DER AlgorithmIdentifier SEQUENCE for `alg`. EC returns a static
// constant; PQC builds SEQUENCE { OID(sigName) } into `buf` via OBJ_txt2obj.
// Returns null for algorithms that decode without a wrapper (RSA/Ed25519).
fn algIdFor(alg: policy.SigAlg, buf: []u8) ?[]const u8 {
    switch (alg) {
        .ecdsa_p256 => return &ec_algid_p256,
        .ecdsa_p384 => return &ec_algid_p384,
        .ecdsa_p521 => return &ec_algid_p521,
        else => {},
    }
    if (sigFamily(alg) != .pqc) return null;
    const obj = c.OBJ_txt2obj(policy.sigName(alg).ptr, 0) orelse return null;
    defer c.ASN1_OBJECT_free(obj);
    var oid: [64]u8 = undefined;
    var op: [*c]u8 = &oid;
    const oid_len = c.i2d_ASN1_OBJECT(obj, &op);
    if (oid_len <= 0) return null;
    const ol: usize = @intCast(oid_len);
    if (ol >= 0x80 or 2 + ol > buf.len) return null; // OID SEQ length is single-byte
    buf[0] = 0x30;
    buf[1] = @intCast(ol);
    @memcpy(buf[2..][0..ol], oid[0..ol]);
    return buf[0 .. 2 + ol];
}

// Write a minimal DER length for `n` into `out`, returning bytes written.
// Handles lengths up to 0xffff — ample for the largest ML-DSA PKCS#8.
fn writeDerLen(out: []u8, n: usize) usize {
    if (n < 0x80) {
        out[0] = @intCast(n);
        return 1;
    }
    if (n <= 0xff) {
        out[0] = 0x81;
        out[1] = @intCast(n);
        return 2;
    }
    out[0] = 0x82;
    out[1] = @intCast((n >> 8) & 0xff);
    out[2] = @intCast(n & 0xff);
    return 3;
}

// Build PKCS#8 PrivateKeyInfo { version 0, <algid>, OCTET STRING(inner) } into
// `buf`. Returns the encoded slice, or null on overflow.
fn buildPkcs8(buf: []u8, algid: []const u8, inner: []const u8) ?[]const u8 {
    const version = [_]u8{ 0x02, 0x01, 0x00 };
    var oct_len_buf: [3]u8 = undefined;
    const oct_len_n = writeDerLen(&oct_len_buf, inner.len);
    const octet_total = 1 + oct_len_n + inner.len; // 0x04 || len || inner
    const content_len = version.len + algid.len + octet_total;
    var seq_len_buf: [3]u8 = undefined;
    const seq_len_n = writeDerLen(&seq_len_buf, content_len);
    if (1 + seq_len_n + content_len > buf.len) return null;
    var i: usize = 0;
    buf[i] = 0x30;
    i += 1;
    @memcpy(buf[i..][0..seq_len_n], seq_len_buf[0..seq_len_n]);
    i += seq_len_n;
    @memcpy(buf[i..][0..version.len], &version);
    i += version.len;
    @memcpy(buf[i..][0..algid.len], algid);
    i += algid.len;
    buf[i] = 0x04;
    i += 1;
    @memcpy(buf[i..][0..oct_len_n], oct_len_buf[0..oct_len_n]);
    i += oct_len_n;
    @memcpy(buf[i..][0..inner.len], inner);
    i += inner.len;
    return buf[0..i];
}

// Build SubjectPublicKeyInfo { <algid>, BIT STRING(0x00 || pub_raw) } into
// `buf`. `pub_raw` is the raw key value (SEC1 point / PQC public bytes), no
// leading unused-bits byte. Returns the encoded slice, or null on overflow.
fn buildSpki(buf: []u8, algid: []const u8, pub_raw: []const u8) ?[]const u8 {
    const bitstr_val = 1 + pub_raw.len; // 0x00 unused-bits || pub_raw
    var bit_len_buf: [3]u8 = undefined;
    const bit_len_n = writeDerLen(&bit_len_buf, bitstr_val);
    const bitstr_total = 1 + bit_len_n + bitstr_val; // 0x03 || len || value
    const content_len = algid.len + bitstr_total;
    var seq_len_buf: [3]u8 = undefined;
    const seq_len_n = writeDerLen(&seq_len_buf, content_len);
    if (1 + seq_len_n + content_len > buf.len) return null;
    var i: usize = 0;
    buf[i] = 0x30;
    i += 1;
    @memcpy(buf[i..][0..seq_len_n], seq_len_buf[0..seq_len_n]);
    i += seq_len_n;
    @memcpy(buf[i..][0..algid.len], algid);
    i += algid.len;
    buf[i] = 0x03;
    i += 1;
    @memcpy(buf[i..][0..bit_len_n], bit_len_buf[0..bit_len_n]);
    i += bit_len_n;
    buf[i] = 0x00; // unused bits
    i += 1;
    @memcpy(buf[i..][0..pub_raw.len], pub_raw);
    i += pub_raw.len;
    return buf[0..i];
}

// Import an EC or PQC private key. Reconstruct the PKCS#8 from `raw` + the
// AlgorithmIdentifier for `alg`, then decode; fall back to decoding `raw` as-is
// if it's already self-describing (full SEC1-with-params or PKCS#8).
fn importPrivate(alg: policy.SigAlg, raw: []const u8) ?*c.EVP_PKEY {
    const raw_len = ffi.toCLong(raw.len) catch return null;
    var algid_buf: [80]u8 = undefined;
    if (algIdFor(alg, &algid_buf)) |algid| {
        var buf: [8192]u8 = undefined; // ML-DSA-87 PKCS#8 is ~5 KB
        if (buildPkcs8(&buf, algid, raw)) |pk8| {
            var pp: [*c]const u8 = pk8.ptr;
            const pk8_len = ffi.toCLong(pk8.len) catch return null;
            if (c.d2i_AutoPrivateKey_ex(null, &pp, pk8_len, provider.libCtx(), "fips=yes")) |k| return k;
            c.ERR_clear_error();
        }
    }
    var pp: [*c]const u8 = raw.ptr;
    return c.d2i_AutoPrivateKey_ex(null, &pp, raw_len, provider.libCtx(), "fips=yes");
}

// Import an EC or PQC public key. Decode `raw` directly first (it may already
// be a full SubjectPublicKeyInfo), else reconstruct the SPKI from `raw` + the
// AlgorithmIdentifier for `alg` and decode that.
fn importPublic(alg: policy.SigAlg, raw: []const u8) ?*c.EVP_PKEY {
    const raw_len = ffi.toCLong(raw.len) catch return null;
    {
        var pp: [*c]const u8 = raw.ptr;
        if (c.d2i_PUBKEY_ex(null, &pp, raw_len, provider.libCtx(), "fips=yes")) |k| return k;
        c.ERR_clear_error();
    }
    var algid_buf: [80]u8 = undefined;
    const algid = algIdFor(alg, &algid_buf) orelse return null;
    var buf: [4096]u8 = undefined; // ML-DSA-87 public is ~2.6 KB
    const spki = buildSpki(&buf, algid, raw) orelse return null;
    var pp: [*c]const u8 = spki.ptr;
    const spki_len = ffi.toCLong(spki.len) catch return null;
    return c.d2i_PUBKEY_ex(null, &pp, spki_len, provider.libCtx(), "fips=yes");
}

const min_rsa_bits = 2048;

fn assertRsaStrength(pkey: *c.EVP_PKEY) Sig.Error!void {
    if (c.EVP_PKEY_is_a(pkey, "RSA") != 1) return error.Unsupported;
    if (c.EVP_PKEY_get_bits(pkey) < min_rsa_bits) return error.Unsupported;
    // FIPS 186-5: e must be odd and >= 65537.
    var bn_e: ?*c.BIGNUM = null;
    defer if (bn_e) |b| c.BN_free(b);
    if (c.EVP_PKEY_get_bn_param(pkey, c.OSSL_PKEY_PARAM_RSA_E, &bn_e) != 1) return error.Unsupported;
    const e = bn_e orelse return error.Unsupported;
    if (c.BN_is_odd(e) != 1) return error.Unsupported;
    const bn_65537 = c.BN_new() orelse return error.Unsupported;
    defer c.BN_free(bn_65537);
    if (c.BN_set_word(bn_65537, 65537) != 1) return error.Unsupported;
    if (c.BN_cmp(e, bn_65537) < 0) return error.Unsupported;
}

/// Cheap RSA key binding for the per-op verify/sign hot path: confirms the
/// key is RSA and meets the 2048-bit floor WITHOUT the BIGNUM exponent
/// check. The exponent is validated once at import/construction by
/// `assertRsaStrength`, and an `EVP_PKEY` is immutable thereafter, so the
/// per-op path does not re-derive `e` (avoids two heap allocations per op).
fn assertRsaUsable(pkey: *c.EVP_PKEY) Sig.Error!void {
    if (c.EVP_PKEY_is_a(pkey, "RSA") != 1) return error.Unsupported;
    if (c.EVP_PKEY_get_bits(pkey) < min_rsa_bits) return error.Unsupported;
}

fn ecGroup(alg: policy.SigAlg) Sig.Error![:0]const u8 {
    return switch (alg) {
        .ecdsa_p256 => "P-256",
        .ecdsa_p384 => "P-384",
        .ecdsa_p521 => "P-521",
        else => error.Unsupported,
    };
}

/// OpenSSL normalises EC group names to OID short names when reading back
/// via EVP_PKEY_get_utf8_string_param. Return the canonical OID short name
/// for each NIST curve so the key-binding check in verifyEcdsa can compare
/// apples-to-apples with the stored key's group.
fn ecGroupOid(alg: policy.SigAlg) Sig.Error![:0]const u8 {
    return switch (alg) {
        .ecdsa_p256 => "prime256v1",
        .ecdsa_p384 => "secp384r1",
        .ecdsa_p521 => "secp521r1",
        else => error.Unsupported,
    };
}

/// OpenSSL group name for raw-EC `EVP_PKEY_fromdata` import. Restricted
/// to the two NIST curves geode stores raw keys for (P-256/P-384); P-521
/// (and any non-ECDSA alg) is `error.Unsupported` here because the raw
/// import path is scoped to those two curves. Uses the canonical OID
/// short names OpenSSL normalises to on read-back, so an imported key's
/// group compares equal in `verifyEcdsa`'s `ecGroupOid` binding check.
fn ecImportGroup(alg: policy.SigAlg) Sig.Error![:0]const u8 {
    return switch (alg) {
        .ecdsa_p256 => "prime256v1",
        .ecdsa_p384 => "secp384r1",
        else => error.Unsupported,
    };
}

/// Digest name used for classical (non-PQC) sign/verify. Ed25519 and the
/// PQC algorithms are one-shot pure modes (no pre-hash).
fn sigDigest(alg: policy.SigAlg) ?[:0]const u8 {
    return switch (alg) {
        .ed25519 => null,
        .ecdsa_p256, .rsa_pss, .rsa_pkcs1 => "SHA2-256",
        .ecdsa_p384 => "SHA2-384",
        .ecdsa_p521 => "SHA2-512",
        else => null, // PQC: one-shot, no digest
    };
}

/// EVP_MD fetch name for an explicitly-chosen digest. Only SHA-2 is
/// permitted for classical RSA/ECDSA verify (FIPS 186-5); SHA-3 is not a
/// FIPS-approved digest for these signature schemes, so callers passing a
/// SHA-3 variant get `error.Unsupported`.
fn explicitDigest(digest: policy.Hash) Sig.Error![:0]const u8 {
    return switch (digest) {
        .sha256 => "SHA2-256",
        .sha384 => "SHA2-384",
        .sha512 => "SHA2-512",
        .sha3_256, .sha3_384, .sha3_512 => error.Unsupported,
    };
}

pub const Sig = struct {
    pub const Error = error{ Unsupported, VerifyFailed, OpensslFailure };

    pub const KeyPair = struct {
        pkey: *c.EVP_PKEY,

        pub fn deinit(self: *KeyPair) void {
            c.EVP_PKEY_free(self.pkey);
        }

        /// Export the raw public key bytes (Ed25519 / PQC raw encodings).
        pub fn publicBytes(self: *KeyPair, out: []u8) Error!usize {
            var len: usize = out.len;
            if (c.EVP_PKEY_get_raw_public_key(self.pkey, out.ptr, &len) != 1) return error.OpensslFailure;
            return len;
        }

        pub fn fromPublicBytes(alg: policy.SigAlg, raw: []const u8) Error!KeyPair {
            provider.assertActive();
            const pkey = switch (sigFamily(alg)) {
                .ed25519 => c.EVP_PKEY_new_raw_public_key_ex(provider.libCtx(), "ED25519", "fips=yes", raw.ptr, raw.len),
                // PQC public key: `raw` is the raw public bytes; wrap in an SPKI
                // with the alg's AlgorithmIdentifier and decode (see importPublic).
                .pqc => importPublic(alg, raw),
                // ECDSA (raw SEC1 point) or RSA (full SPKI): importPublic decodes
                // a full SPKI directly, else wraps a raw EC point into one.
                .der => importPublic(alg, raw),
            } orelse return error.OpensslFailure;
            errdefer c.EVP_PKEY_free(pkey);
            if (sigIsRsa(alg)) try assertRsaStrength(pkey);
            return .{ .pkey = pkey };
        }

        pub fn fromPrivateBytes(alg: policy.SigAlg, raw: []const u8) Error!KeyPair {
            provider.assertActive();
            const pkey = switch (sigFamily(alg)) {
                .ed25519 => c.EVP_PKEY_new_raw_private_key_ex(provider.libCtx(), "ED25519", "fips=yes", raw.ptr, raw.len),
                // PQC private key: the PKCS#8 inner is a structured blob, not the
                // raw key EVP_PKEY_new_raw_private_key expects — reconstruct the
                // PKCS#8 and decode (see importPrivate).
                .pqc => importPrivate(alg, raw),
                .der => blk: {
                    if (sigIsRsa(alg)) {
                        // RSAPrivateKey (PKCS#1) is self-describing; _ex threads
                        // the FIPS libctx + "fips=yes" so the plain default-ctx
                        // d2i (which returns NULL under fips+base) is avoided.
                        var pp: [*c]const u8 = raw.ptr;
                        break :blk c.d2i_PrivateKey_ex(c.EVP_PKEY_RSA, null, &pp, try ffi.toCLong(raw.len), provider.libCtx(), "fips=yes");
                    }
                    // EC: `raw` is a bare SEC1 with no curve params — reconstruct
                    // a PKCS#8 with the curve from `alg` (see importPrivate).
                    break :blk importPrivate(alg, raw);
                },
            } orelse return error.OpensslFailure;
            errdefer c.EVP_PKEY_free(pkey);
            if (sigIsRsa(alg)) try assertRsaStrength(pkey);
            return .{ .pkey = pkey };
        }

        /// Import an RSA public key from a DER-encoded SubjectPublicKeyInfo
        /// (X.509 SPKI). Identical decode path to `fromPublicBytes` for the
        /// `.der` family, exposed under an RSA-specific name so RSA-only
        /// callers don't have to thread a `SigAlg`.
        pub fn fromRsaSpki(der: []const u8) Error!KeyPair {
            provider.assertActive();
            var pp: [*c]const u8 = der.ptr;
            // _ex threads the FIPS libctx + "fips=yes" (see fromPublicBytes).
            const k = c.d2i_PUBKEY_ex(null, &pp, try ffi.toCLong(der.len), provider.libCtx(), "fips=yes") orelse return error.OpensslFailure;
            errdefer c.EVP_PKEY_free(k);
            try assertRsaStrength(k);
            return .{ .pkey = k };
        }

        /// Import an RSA public key from raw big-endian modulus `n` and
        /// public exponent `e` components (the JWKS form: base64url-decoded
        /// `n`/`e`). Builds an `EVP_PKEY` via `EVP_PKEY_fromdata` under the
        /// fips lib context. The caller owns the returned KeyPair (deinit).
        pub fn fromRsaComponents(n: []const u8, e: []const u8) Error!KeyPair {
            provider.assertActive();

            // JWKS components are big-endian (network byte order). BN_bin2bn
            // parses big-endian into a BIGNUM; OSSL_PARAM_BLD_push_BN then
            // serializes it into the native param representation OpenSSL's
            // RSA keymgmt expects, so we never hand-roll endianness here.
            const bn_n = c.BN_bin2bn(n.ptr, try ffi.toCInt(n.len), null) orelse return error.OpensslFailure;
            defer c.BN_free(bn_n);
            const bn_e = c.BN_bin2bn(e.ptr, try ffi.toCInt(e.len), null) orelse return error.OpensslFailure;
            defer c.BN_free(bn_e);

            const bld = c.OSSL_PARAM_BLD_new() orelse return error.OpensslFailure;
            defer c.OSSL_PARAM_BLD_free(bld);
            if (c.OSSL_PARAM_BLD_push_BN(bld, c.OSSL_PKEY_PARAM_RSA_N, bn_n) != 1) return error.OpensslFailure;
            if (c.OSSL_PARAM_BLD_push_BN(bld, c.OSSL_PKEY_PARAM_RSA_E, bn_e) != 1) return error.OpensslFailure;
            const params = c.OSSL_PARAM_BLD_to_param(bld) orelse return error.OpensslFailure;
            defer c.OSSL_PARAM_free(params);

            const pctx = c.EVP_PKEY_CTX_new_from_name(provider.libCtx(), "RSA", "fips=yes") orelse return error.OpensslFailure;
            defer c.EVP_PKEY_CTX_free(pctx);
            if (c.EVP_PKEY_fromdata_init(pctx) != 1) return error.OpensslFailure;
            var pkey: ?*c.EVP_PKEY = null;
            if (c.EVP_PKEY_fromdata(pctx, &pkey, c.EVP_PKEY_PUBLIC_KEY, params) != 1) return error.OpensslFailure;
            const k = pkey orelse return error.OpensslFailure;
            errdefer c.EVP_PKEY_free(k);
            try assertRsaStrength(k);
            return .{ .pkey = k };
        }

        /// Import an EC public key from a raw SEC1 point — the on-the-wire
        /// elliptic-curve point, compressed (33B P-256 / 49B P-384) OR
        /// uncompressed (65B / 97B); OpenSSL's EC keymgmt decodes both via
        /// the `pub` octet-string param. Only `.ecdsa_p256`/`.ecdsa_p384`
        /// are valid (P-521/RSA/Ed25519/PQC → `error.Unsupported`). Builds
        /// an `EVP_PKEY` through `EVP_PKEY_fromdata` under the fips lib
        /// context (mirrors `fromRsaComponents`). The caller owns the
        /// returned KeyPair (deinit). The result plugs into the existing
        /// `Sig.verify` / `Sig.verifyEcdsa` paths unchanged.
        pub fn fromEcPublicPoint(alg: policy.SigAlg, point: []const u8) Error!KeyPair {
            provider.assertActive();
            const group = try ecImportGroup(alg);

            const bld = c.OSSL_PARAM_BLD_new() orelse return error.OpensslFailure;
            defer c.OSSL_PARAM_BLD_free(bld);
            // Group name as a UTF-8 string param; the point as an octet
            // string. OpenSSL's EC keymgmt parses both SEC1 encodings.
            if (c.OSSL_PARAM_BLD_push_utf8_string(bld, c.OSSL_PKEY_PARAM_GROUP_NAME, group.ptr, group.len) != 1) return error.OpensslFailure;
            if (c.OSSL_PARAM_BLD_push_octet_string(bld, c.OSSL_PKEY_PARAM_PUB_KEY, point.ptr, point.len) != 1) return error.OpensslFailure;
            const params = c.OSSL_PARAM_BLD_to_param(bld) orelse return error.OpensslFailure;
            defer c.OSSL_PARAM_free(params);

            const pctx = c.EVP_PKEY_CTX_new_from_name(provider.libCtx(), "EC", "fips=yes") orelse return error.OpensslFailure;
            defer c.EVP_PKEY_CTX_free(pctx);
            if (c.EVP_PKEY_fromdata_init(pctx) != 1) return error.OpensslFailure;
            var pkey: ?*c.EVP_PKEY = null;
            if (c.EVP_PKEY_fromdata(pctx, &pkey, c.EVP_PKEY_PUBLIC_KEY, params) != 1) return error.OpensslFailure;
            return .{ .pkey = pkey orelse return error.OpensslFailure };
        }

        /// Export the COMPRESSED SEC1 public point for an EC key pair.
        /// Only `.ecdsa_p256` (33 bytes, prefix 0x02/0x03) and
        /// `.ecdsa_p384` (49 bytes) are supported; any other algorithm
        /// returns `error.Unsupported`. A non-EC key type (RSA, Ed25519)
        /// also returns `error.Unsupported`. `out` must be at least the
        /// compressed size (33B / 49B); shorter buffers return
        /// `error.OpensslFailure`.
        ///
        /// NON-MUTATING: the compressed-format flag is set on a private
        /// duplicate of `self.pkey` created via `EVP_PKEY_dup`; `self.pkey`
        /// is NEVER modified, so a subsequent `publicBytes` / uncompressed
        /// read on the same `KeyPair` still returns the uncompressed form.
        pub fn ecPublicPoint(self: *KeyPair, alg: policy.SigAlg, out: []u8) Error!usize {
            const compressed_len: usize = switch (alg) {
                .ecdsa_p256 => 33,
                .ecdsa_p384 => 49,
                else => return error.Unsupported,
            };
            // Guard 1: key type must be EC (not RSA, Ed25519, PQC, …).
            if (c.EVP_PKEY_is_a(self.pkey, "EC") != 1) return error.Unsupported;
            // Guard 2: the key's stored curve must match the requested alg.
            // OpenSSL normalises curve names to OID short form on read-back
            // (e.g. "prime256v1" for P-256), so compare against ecGroupOid.
            var gname: [32]u8 = undefined;
            var glen: usize = 0;
            if (c.EVP_PKEY_get_utf8_string_param(self.pkey, c.OSSL_PKEY_PARAM_GROUP_NAME, &gname, gname.len, &glen) != 1) return error.Unsupported;
            if (!std.mem.eql(u8, gname[0..glen], try ecGroupOid(alg))) return error.Unsupported;
            // Buffer-size guard before any write.
            if (out.len < compressed_len) return error.OpensslFailure;
            // Create a private duplicate so self.pkey is never mutated.
            const dup = c.EVP_PKEY_dup(self.pkey) orelse return error.OpensslFailure;
            defer c.EVP_PKEY_free(dup);
            // Set compressed format on the duplicate only.
            var fmt = [_]c.OSSL_PARAM{
                c.OSSL_PARAM_construct_utf8_string(c.OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, @constCast(@as([:0]const u8, "compressed").ptr), 0),
                c.OSSL_PARAM_construct_end(),
            };
            if (c.EVP_PKEY_set_params(dup, &fmt) != 1) return error.OpensslFailure;
            var point_len: usize = 0;
            if (c.EVP_PKEY_get_octet_string_param(dup, c.OSSL_PKEY_PARAM_PUB_KEY, out.ptr, out.len, &point_len) != 1) return error.OpensslFailure;
            // Defensive: if the returned size is wrong (alg/curve mismatch
            // slipped through), zero the written bytes before returning an error.
            if (point_len != compressed_len) {
                @memset(out[0..compressed_len], 0);
                return error.OpensslFailure;
            }
            return point_len;
        }

        /// Export the raw big-endian EC private scalar for the generated
        /// key. Only `.ecdsa_p256` (32 bytes) and `.ecdsa_p384` (48 bytes)
        /// are supported; other algorithms return `error.Unsupported`.
        ///
        /// CONTRACT: `out` must be at least `coord_len` bytes (32 for
        /// P-256, 48 for P-384). The output is FIXED-WIDTH and
        /// left-zero-padded by `BN_bn2binpad`, so the caller always
        /// receives exactly `coord_len` bytes regardless of leading zeros
        /// in the scalar. This matches the `fromEcPrivateScalar` import
        /// contract and the cross-backend parity requirement.
        pub fn privateScalar(self: *KeyPair, alg: policy.SigAlg, out: []u8) Error!usize {
            const coord_len: usize = switch (alg) {
                .ecdsa_p256 => 32,
                .ecdsa_p384 => 48,
                else => return error.Unsupported,
            };
            if (out.len < coord_len) return error.OpensslFailure;
            var bn_d: ?*c.BIGNUM = null;
            defer if (bn_d) |b| c.BN_free(b);
            if (c.EVP_PKEY_get_bn_param(self.pkey, c.OSSL_PKEY_PARAM_PRIV_KEY, &bn_d) != 1) return error.OpensslFailure;
            const d = bn_d orelse return error.OpensslFailure;
            // BN_bn2binpad writes exactly coord_len bytes, left-zero-padding if needed.
            if (c.BN_bn2binpad(d, out.ptr, @intCast(coord_len)) < 0) return error.OpensslFailure;
            return coord_len;
        }

        /// Export the raw 32-byte Ed25519 seed (the private key material
        /// from which both the scalar and public key are derived). Only
        /// valid for `.ed25519` keypairs generated or imported via this
        /// seam; `out` must be at least 32 bytes. Returns 32 on success.
        pub fn privateSeed(self: *KeyPair, out: []u8) Error!usize {
            const seed_len: usize = 32;
            if (out.len < seed_len) return error.OpensslFailure;
            var len: usize = out.len;
            if (c.EVP_PKEY_get_raw_private_key(self.pkey, out.ptr, &len) != 1) return error.OpensslFailure;
            if (len != seed_len) return error.OpensslFailure;
            return seed_len;
        }

        /// Import an EC private key from the raw big-endian private scalar
        /// (32B P-256 / 48B P-384). Only `.ecdsa_p256`/`.ecdsa_p384`. The
        /// scalar is parsed big-endian via `BN_bin2bn`; `OSSL_PARAM_BLD`
        /// then serialises it into the native param form OpenSSL's EC
        /// keymgmt expects (no hand-rolled endianness). Builds a KEYPAIR
        /// `EVP_PKEY` through `EVP_PKEY_fromdata` under the fips lib context
        /// so the resulting key can both `Sig.sign` and `Sig.verify`.
        pub fn fromEcPrivateScalar(alg: policy.SigAlg, scalar: []const u8) Error!KeyPair {
            provider.assertActive();
            const group = try ecImportGroup(alg);

            const bn_d = c.BN_bin2bn(scalar.ptr, try ffi.toCInt(scalar.len), null) orelse return error.OpensslFailure;
            defer c.BN_free(bn_d);

            const bld = c.OSSL_PARAM_BLD_new() orelse return error.OpensslFailure;
            defer c.OSSL_PARAM_BLD_free(bld);
            if (c.OSSL_PARAM_BLD_push_utf8_string(bld, c.OSSL_PKEY_PARAM_GROUP_NAME, group.ptr, group.len) != 1) return error.OpensslFailure;
            if (c.OSSL_PARAM_BLD_push_BN(bld, c.OSSL_PKEY_PARAM_PRIV_KEY, bn_d) != 1) return error.OpensslFailure;
            const params = c.OSSL_PARAM_BLD_to_param(bld) orelse return error.OpensslFailure;
            defer c.OSSL_PARAM_free(params);

            const pctx = c.EVP_PKEY_CTX_new_from_name(provider.libCtx(), "EC", "fips=yes") orelse return error.OpensslFailure;
            defer c.EVP_PKEY_CTX_free(pctx);
            if (c.EVP_PKEY_fromdata_init(pctx) != 1) return error.OpensslFailure;
            var pkey: ?*c.EVP_PKEY = null;
            // KEYPAIR: from a private scalar OpenSSL's EC keymgmt derives the
            // matching public point, so the key is usable for sign AND verify.
            if (c.EVP_PKEY_fromdata(pctx, &pkey, c.EVP_PKEY_KEYPAIR, params) != 1) return error.OpensslFailure;
            return .{ .pkey = pkey orelse return error.OpensslFailure };
        }
    };

    /// Generate a fresh key pair for `alg`.
    pub fn generate(alg: policy.SigAlg) Error!KeyPair {
        provider.assertActive();
        const family = sigFamily(alg);
        const name: [:0]const u8 = switch (family) {
            .ed25519 => "ED25519",
            .pqc => policy.sigName(alg),
            .der => if (sigIsRsa(alg)) "RSA" else "EC",
        };
        const pctx = c.EVP_PKEY_CTX_new_from_name(provider.libCtx(), name.ptr, "fips=yes") orelse return error.OpensslFailure;
        defer c.EVP_PKEY_CTX_free(pctx);
        if (c.EVP_PKEY_keygen_init(pctx) != 1) return error.OpensslFailure;

        if (family == .der and !sigIsRsa(alg)) {
            // ECDSA: set the curve group.
            var params = [_]c.OSSL_PARAM{
                c.OSSL_PARAM_construct_utf8_string(c.OSSL_PKEY_PARAM_GROUP_NAME, @constCast((try ecGroup(alg)).ptr), 0),
                c.OSSL_PARAM_construct_end(),
            };
            if (c.EVP_PKEY_CTX_set_params(pctx, &params) != 1) return error.OpensslFailure;
        } else if (sigIsRsa(alg)) {
            var bits: c_int = 2048;
            var params = [_]c.OSSL_PARAM{
                c.OSSL_PARAM_construct_int(c.OSSL_PKEY_PARAM_RSA_BITS, &bits),
                c.OSSL_PARAM_construct_end(),
            };
            if (c.EVP_PKEY_CTX_set_params(pctx, &params) != 1) return error.OpensslFailure;
        }

        var pkey: ?*c.EVP_PKEY = null;
        if (c.EVP_PKEY_generate(pctx, &pkey) != 1) return error.OpensslFailure;
        return .{ .pkey = pkey orelse return error.OpensslFailure };
    }

    /// Sign `msg`, writing the signature into `sig_out`; returns the
    /// signature length. RSA key strength (type, >=2048 bits, FIPS 186-5
    /// exponent) is enforced once at construction — by `assertRsaStrength` in
    /// every `from*` import path, and by `generate` emitting a compliant key —
    /// and an `EVP_PKEY` is immutable thereafter, so the sign/verify hot paths
    /// do not re-derive it. INVARIANT: any future RSA `KeyPair` constructor
    /// MUST call `assertRsaStrength`, or the weak-exponent guard (SEC-2003) is
    /// silently bypassed for sign/verify.
    pub fn sign(alg: policy.SigAlg, kp: *KeyPair, msg: []const u8, sig_out: []u8) Error!usize {
        provider.assertActive();
        const ctx = c.EVP_MD_CTX_new() orelse return error.OpensslFailure;
        defer c.EVP_MD_CTX_free(ctx);

        try initSignDigest(alg, ctx, kp);

        var siglen: usize = sig_out.len;
        if (c.EVP_DigestSign(ctx, sig_out.ptr, &siglen, msg.ptr, msg.len) != 1) return error.OpensslFailure;
        return siglen;
    }

    /// Verify `sig` over `msg`. Returns `error.VerifyFailed` on a bad
    /// signature.
    pub fn verify(alg: policy.SigAlg, kp: *KeyPair, msg: []const u8, sig: []const u8) Error!void {
        provider.assertActive();
        if (sigIsRsa(alg)) try assertRsaUsable(kp.pkey);
        const ctx = c.EVP_MD_CTX_new() orelse return error.OpensslFailure;
        defer c.EVP_MD_CTX_free(ctx);

        try initVerifyDigest(alg, ctx, kp);

        const rc = c.EVP_DigestVerify(ctx, sig.ptr, sig.len, msg.ptr, msg.len);
        if (rc == 1) return;
        if (rc == 0) return error.VerifyFailed;
        return error.OpensslFailure;
    }

    /// Verify a classical RSA signature over `msg` with an EXPLICIT digest
    /// (SHA-256/384/512), routing through the FIPS module. `scheme` picks
    /// RSASSA-PKCS1-v1_5 (`.pkcs1`) or RSASSA-PSS (`.pss`); for PSS the
    /// MGF1 digest is the same as `digest` and the salt length defaults to
    /// the digest length (OpenSSL's default), matching JOSE PS256/384/512.
    /// `kp` must hold an RSA public key (e.g. from `fromRsaComponents` or
    /// `fromRsaSpki`). Returns `error.VerifyFailed` on a bad signature and
    /// `error.Unsupported` for a non-SHA-2 digest.
    pub fn verifyRsa(
        scheme: policy.RsaScheme,
        digest: policy.Hash,
        kp: *KeyPair,
        msg: []const u8,
        sig: []const u8,
    ) Error!void {
        provider.assertActive();
        try assertRsaUsable(kp.pkey);
        const mdname = try explicitDigest(digest);
        const ctx = c.EVP_MD_CTX_new() orelse return error.OpensslFailure;
        defer c.EVP_MD_CTX_free(ctx);

        var pctx: ?*c.EVP_PKEY_CTX = null;
        if (c.EVP_DigestVerifyInit_ex(ctx, &pctx, mdname.ptr, provider.libCtx(), "fips=yes", kp.pkey, null) != 1) {
            return error.OpensslFailure;
        }
        switch (scheme) {
            .pkcs1 => {}, // PKCS1-v1.5 is the EVP RSA default padding.
            .pss => try setPssPadDigest(pctx, mdname),
        }

        const rc = c.EVP_DigestVerify(ctx, sig.ptr, sig.len, msg.ptr, msg.len);
        if (rc == 1) return;
        if (rc == 0) return error.VerifyFailed;
        return error.OpensslFailure;
    }

    /// Verify an ECDSA signature over `msg` with an EXPLICIT (curve,
    /// digest) pair, so off-diagonal combinations (e.g. P-256 with
    /// SHA-384) route through the FIPS module rather than being pinned to
    /// the curve's "natural" digest. `alg` must be one of the `ecdsa_p*`
    /// curves; `digest` selects the EVP_MD. Returns `error.VerifyFailed`
    /// on a bad signature and `error.Unsupported` for a non-ECDSA `alg` or
    /// a non-SHA-2 digest.
    pub fn verifyEcdsa(
        alg: policy.SigAlg,
        digest: policy.Hash,
        kp: *KeyPair,
        msg: []const u8,
        sig: []const u8,
    ) Error!void {
        provider.assertActive();
        switch (alg) {
            .ecdsa_p256, .ecdsa_p384, .ecdsa_p521 => {},
            else => return error.Unsupported,
        }
        if (c.EVP_PKEY_is_a(kp.pkey, "EC") != 1) return error.Unsupported;
        // group name must match the requested curve; OpenSSL normalises the
        // stored name to OID short form (e.g. "prime256v1"), so compare
        // against ecGroupOid rather than the NIST input name.
        var gname: [32]u8 = undefined;
        var glen: usize = 0;
        if (c.EVP_PKEY_get_utf8_string_param(kp.pkey, c.OSSL_PKEY_PARAM_GROUP_NAME, &gname, gname.len, &glen) != 1) return error.Unsupported;
        if (!std.mem.eql(u8, gname[0..glen], try ecGroupOid(alg))) return error.Unsupported;
        const mdname = try explicitDigest(digest);
        const ctx = c.EVP_MD_CTX_new() orelse return error.OpensslFailure;
        defer c.EVP_MD_CTX_free(ctx);

        var pctx: ?*c.EVP_PKEY_CTX = null;
        if (c.EVP_DigestVerifyInit_ex(ctx, &pctx, mdname.ptr, provider.libCtx(), "fips=yes", kp.pkey, null) != 1) {
            return error.OpensslFailure;
        }

        const rc = c.EVP_DigestVerify(ctx, sig.ptr, sig.len, msg.ptr, msg.len);
        if (rc == 1) return;
        if (rc == 0) return error.VerifyFailed;
        return error.OpensslFailure;
    }

    fn initSignDigest(alg: policy.SigAlg, ctx: *c.EVP_MD_CTX, kp: *KeyPair) Error!void {
        var pctx: ?*c.EVP_PKEY_CTX = null;
        const mdname: [*c]const u8 = if (sigDigest(alg)) |d| d.ptr else null;
        if (c.EVP_DigestSignInit_ex(ctx, &pctx, mdname, provider.libCtx(), "fips=yes", kp.pkey, null) != 1) {
            return error.OpensslFailure;
        }
        if (alg == .rsa_pss) try setPssPad(pctx);
    }

    fn initVerifyDigest(alg: policy.SigAlg, ctx: *c.EVP_MD_CTX, kp: *KeyPair) Error!void {
        var pctx: ?*c.EVP_PKEY_CTX = null;
        const mdname: [*c]const u8 = if (sigDigest(alg)) |d| d.ptr else null;
        if (c.EVP_DigestVerifyInit_ex(ctx, &pctx, mdname, provider.libCtx(), "fips=yes", kp.pkey, null) != 1) {
            return error.OpensslFailure;
        }
        if (alg == .rsa_pss) try setPssPad(pctx);
    }

    fn setPssPad(pctx: ?*c.EVP_PKEY_CTX) Error!void {
        const p = pctx orelse return error.OpensslFailure;
        var params = [_]c.OSSL_PARAM{
            c.OSSL_PARAM_construct_utf8_string(c.OSSL_SIGNATURE_PARAM_PAD_MODE, @constCast(@as([:0]const u8, "pss").ptr), 0),
            c.OSSL_PARAM_construct_end(),
        };
        if (c.EVP_PKEY_CTX_set_params(p, &params) != 1) return error.OpensslFailure;
    }

    /// PSS padding with an explicit digest: sets pad-mode=pss and pins both
    /// the PSS hash and the MGF1 hash to `mdname`. The init digest already
    /// fixes the message digest; pinning MGF1 here makes the off-diagonal
    /// "digest chosen at call time" path unambiguous (PS256/384/512 use the
    /// same digest for the hash and the mask generation function).
    fn setPssPadDigest(pctx: ?*c.EVP_PKEY_CTX, mdname: [:0]const u8) Error!void {
        const p = pctx orelse return error.OpensslFailure;
        var params = [_]c.OSSL_PARAM{
            c.OSSL_PARAM_construct_utf8_string(c.OSSL_SIGNATURE_PARAM_PAD_MODE, @constCast(@as([:0]const u8, "pss").ptr), 0),
            c.OSSL_PARAM_construct_utf8_string(c.OSSL_SIGNATURE_PARAM_DIGEST, @constCast(mdname.ptr), 0),
            c.OSSL_PARAM_construct_utf8_string(c.OSSL_SIGNATURE_PARAM_MGF1_DIGEST, @constCast(mdname.ptr), 0),
            c.OSSL_PARAM_construct_end(),
        };
        if (c.EVP_PKEY_CTX_set_params(p, &params) != 1) return error.OpensslFailure;
    }
};

test "Ed25519 fromPublicBytes round-trips a wire public key" {
    var kp = try Sig.generate(.ed25519);
    defer kp.deinit();
    var sig: [64]u8 = undefined;
    const n = try Sig.sign(.ed25519, &kp, "wire msg", &sig);
    var pub_raw: [32]u8 = undefined;
    const pn = try kp.publicBytes(&pub_raw);
    try std.testing.expectEqual(@as(usize, 32), pn);
    var pub_kp = try Sig.KeyPair.fromPublicBytes(.ed25519, pub_raw[0..pn]);
    defer pub_kp.deinit();
    try Sig.verify(.ed25519, &pub_kp, "wire msg", sig[0..n]);
    try std.testing.expectError(error.VerifyFailed, Sig.verify(.ed25519, &pub_kp, "altered", sig[0..n]));
}

test "Ed25519 fromPrivateBytes reconstructs a signing key" {
    var kp = try Sig.generate(.ed25519);
    defer kp.deinit();
    var priv_raw: [32]u8 = undefined;
    var len: usize = priv_raw.len;
    try std.testing.expect(c.EVP_PKEY_get_raw_private_key(kp.pkey, &priv_raw, &len) == 1);
    var priv_kp = try Sig.KeyPair.fromPrivateBytes(.ed25519, priv_raw[0..len]);
    defer priv_kp.deinit();
    var sig: [64]u8 = undefined;
    const n = try Sig.sign(.ed25519, &priv_kp, "resigned", &sig);
    try Sig.verify(.ed25519, &kp, "resigned", sig[0..n]); // original verifies the reconstructed key's signature
}

test "ECDSA P-256 fromPrivateBytes (DER) round-trips" {
    var kp = try Sig.generate(.ecdsa_p256);
    defer kp.deinit();
    var der: [256]u8 = undefined;
    var p: [*c]u8 = &der;
    const der_len = c.i2d_PrivateKey(kp.pkey, &p);
    try std.testing.expect(der_len > 0);
    var imported = try Sig.KeyPair.fromPrivateBytes(.ecdsa_p256, der[0..@intCast(der_len)]);
    defer imported.deinit();
    var sig: [80]u8 = undefined;
    const n = try Sig.sign(.ecdsa_p256, &imported, "der msg", &sig);
    try Sig.verify(.ecdsa_p256, &imported, "der msg", sig[0..n]);
}

test "Ed25519 sign->verify round trip + tamper detect" {
    var kp = try Sig.generate(.ed25519);
    defer kp.deinit();
    var sig: [64]u8 = undefined;
    const n = try Sig.sign(.ed25519, &kp, "fips message", &sig);
    try std.testing.expectEqual(@as(usize, 64), n);
    try Sig.verify(.ed25519, &kp, "fips message", sig[0..n]);
    try std.testing.expectError(error.VerifyFailed, Sig.verify(.ed25519, &kp, "tampered", sig[0..n]));
}

test "ECDSA P-256 sign->verify round trip" {
    var kp = try Sig.generate(.ecdsa_p256);
    defer kp.deinit();
    var sig: [80]u8 = undefined;
    const n = try Sig.sign(.ecdsa_p256, &kp, "hello", &sig);
    try Sig.verify(.ecdsa_p256, &kp, "hello", sig[0..n]);
}

test "RSA-PSS 2048 sign->verify round trip + tamper detect" {
    var kp = try Sig.generate(.rsa_pss);
    defer kp.deinit();
    var sig: [512]u8 = undefined;
    const n = try Sig.sign(.rsa_pss, &kp, "rsa pss message", &sig);
    try Sig.verify(.rsa_pss, &kp, "rsa pss message", sig[0..n]);
    try std.testing.expectError(error.VerifyFailed, Sig.verify(.rsa_pss, &kp, "tampered", sig[0..n]));
}

test "ML-DSA-65 sign->verify round trip + tamper detect" {
    var kp = try Sig.generate(.ml_dsa_65);
    defer kp.deinit();
    var sig: [4096]u8 = undefined;
    const n = try Sig.sign(.ml_dsa_65, &kp, "pqc message", &sig);
    try Sig.verify(.ml_dsa_65, &kp, "pqc message", sig[0..n]);
    try std.testing.expectError(error.VerifyFailed, Sig.verify(.ml_dsa_65, &kp, "x", sig[0..n]));
}

test "SLH-DSA-SHA2-128s sign->verify round trip" {
    var kp = try Sig.generate(.slh_dsa_sha2_128s);
    defer kp.deinit();
    var sig: [8192]u8 = undefined;
    const n = try Sig.sign(.slh_dsa_sha2_128s, &kp, "pqc", &sig);
    try Sig.verify(.slh_dsa_sha2_128s, &kp, "pqc", sig[0..n]);
}

// --------------------------------------------------------------------
// Explicit-digest verify KATs (Task: route ALL classical VERIFY through
// the FIPS module). Each KAT signs with a chosen padding+digest via raw
// EVP and then verifies through the NEW seam API, proving the explicit
// digest selects the matching EVP_MD with "fips=yes".
// --------------------------------------------------------------------

/// Sign `msg` with RSA `scheme`+`digest` straight through EVP under the
/// fips lib context. Returns the signature length. Used only by KATs to
/// produce a known-answer the verify path must accept.
fn rsaSignExplicit(
    scheme: policy.RsaScheme,
    digest: policy.Hash,
    kp: *Sig.KeyPair,
    msg: []const u8,
    sig_out: []u8,
) !usize {
    const mdname: [:0]const u8 = switch (digest) {
        .sha256 => "SHA2-256",
        .sha384 => "SHA2-384",
        .sha512 => "SHA2-512",
        else => return error.Unsupported,
    };
    const ctx = c.EVP_MD_CTX_new() orelse return error.OpensslFailure;
    defer c.EVP_MD_CTX_free(ctx);
    var pctx: ?*c.EVP_PKEY_CTX = null;
    if (c.EVP_DigestSignInit_ex(ctx, &pctx, mdname.ptr, provider.libCtx(), "fips=yes", kp.pkey, null) != 1) return error.OpensslFailure;
    if (scheme == .pss) {
        const p = pctx.?;
        var params = [_]c.OSSL_PARAM{
            c.OSSL_PARAM_construct_utf8_string(c.OSSL_SIGNATURE_PARAM_PAD_MODE, @constCast(@as([:0]const u8, "pss").ptr), 0),
            c.OSSL_PARAM_construct_utf8_string(c.OSSL_SIGNATURE_PARAM_DIGEST, @constCast(mdname.ptr), 0),
            c.OSSL_PARAM_construct_utf8_string(c.OSSL_SIGNATURE_PARAM_MGF1_DIGEST, @constCast(mdname.ptr), 0),
            c.OSSL_PARAM_construct_end(),
        };
        if (c.EVP_PKEY_CTX_set_params(p, &params) != 1) return error.OpensslFailure;
    }
    var siglen: usize = sig_out.len;
    if (c.EVP_DigestSign(ctx, sig_out.ptr, &siglen, msg.ptr, msg.len) != 1) return error.OpensslFailure;
    return siglen;
}

/// Sign `msg` with ECDSA over `kp`'s curve using an explicit `digest`.
fn ecdsaSignExplicit(digest: policy.Hash, kp: *Sig.KeyPair, msg: []const u8, sig_out: []u8) !usize {
    const mdname: [:0]const u8 = switch (digest) {
        .sha256 => "SHA2-256",
        .sha384 => "SHA2-384",
        .sha512 => "SHA2-512",
        else => return error.Unsupported,
    };
    const ctx = c.EVP_MD_CTX_new() orelse return error.OpensslFailure;
    defer c.EVP_MD_CTX_free(ctx);
    var pctx: ?*c.EVP_PKEY_CTX = null;
    if (c.EVP_DigestSignInit_ex(ctx, &pctx, mdname.ptr, provider.libCtx(), "fips=yes", kp.pkey, null) != 1) return error.OpensslFailure;
    var siglen: usize = sig_out.len;
    if (c.EVP_DigestSign(ctx, sig_out.ptr, &siglen, msg.ptr, msg.len) != 1) return error.OpensslFailure;
    return siglen;
}

test "RSA-PKCS1 verifyRsa KAT: SHA-256/384/512 each route via explicit digest" {
    var kp = try Sig.generate(.rsa_pkcs1);
    defer kp.deinit();
    const msg = "fips rsa pkcs1 known-answer";
    inline for (.{ policy.Hash.sha256, policy.Hash.sha384, policy.Hash.sha512 }) |dg| {
        var sig: [512]u8 = undefined;
        const n = try rsaSignExplicit(.pkcs1, dg, &kp, msg, &sig);
        try Sig.verifyRsa(.pkcs1, dg, &kp, msg, sig[0..n]);
        try std.testing.expectError(error.VerifyFailed, Sig.verifyRsa(.pkcs1, dg, &kp, "tampered", sig[0..n]));
    }
    // A signature made with SHA-256 must NOT verify as SHA-512 (digest is
    // genuinely selected by the param, not ignored).
    var sig256: [512]u8 = undefined;
    const n256 = try rsaSignExplicit(.pkcs1, .sha256, &kp, msg, &sig256);
    try std.testing.expectError(error.VerifyFailed, Sig.verifyRsa(.pkcs1, .sha512, &kp, msg, sig256[0..n256]));
}

test "RSA-PSS verifyRsa KAT: SHA-256/384/512 each route via explicit digest" {
    var kp = try Sig.generate(.rsa_pss);
    defer kp.deinit();
    const msg = "fips rsa pss known-answer";
    inline for (.{ policy.Hash.sha256, policy.Hash.sha384, policy.Hash.sha512 }) |dg| {
        var sig: [512]u8 = undefined;
        const n = try rsaSignExplicit(.pss, dg, &kp, msg, &sig);
        try Sig.verifyRsa(.pss, dg, &kp, msg, sig[0..n]);
        try std.testing.expectError(error.VerifyFailed, Sig.verifyRsa(.pss, dg, &kp, "tampered", sig[0..n]));
    }
}

test "RSA verifyRsa rejects non-SHA-2 digest as Unsupported" {
    var kp = try Sig.generate(.rsa_pkcs1);
    defer kp.deinit();
    try std.testing.expectError(error.Unsupported, Sig.verifyRsa(.pkcs1, .sha3_256, &kp, "x", "y"));
}

test "RSA fromRsaComponents (n,e) import round-trips a PKCS1 verify" {
    // Generate a key, extract its (n, e) as big-endian (JWKS form), import
    // via fromRsaComponents, and verify a signature made by the original.
    var kp = try Sig.generate(.rsa_pkcs1);
    defer kp.deinit();

    var bn_n: ?*c.BIGNUM = null;
    var bn_e: ?*c.BIGNUM = null;
    try std.testing.expect(c.EVP_PKEY_get_bn_param(kp.pkey, c.OSSL_PKEY_PARAM_RSA_N, &bn_n) == 1);
    try std.testing.expect(c.EVP_PKEY_get_bn_param(kp.pkey, c.OSSL_PKEY_PARAM_RSA_E, &bn_e) == 1);
    defer c.BN_free(bn_n);
    defer c.BN_free(bn_e);

    var n_buf: [512]u8 = undefined;
    var e_buf: [16]u8 = undefined;
    const n_len = c.BN_bn2bin(bn_n, &n_buf);
    const e_len = c.BN_bn2bin(bn_e, &e_buf);
    try std.testing.expect(n_len > 0 and e_len > 0);

    var imported = try Sig.KeyPair.fromRsaComponents(n_buf[0..@intCast(n_len)], e_buf[0..@intCast(e_len)]);
    defer imported.deinit();

    const msg = "jwks (n,e) import round-trip";
    var sig: [512]u8 = undefined;
    const slen = try rsaSignExplicit(.pkcs1, .sha256, &kp, msg, &sig);
    try Sig.verifyRsa(.pkcs1, .sha256, &imported, msg, sig[0..slen]);
    try std.testing.expectError(error.VerifyFailed, Sig.verifyRsa(.pkcs1, .sha256, &imported, "altered", sig[0..slen]));
}

test "RSA fromRsaSpki (DER SPKI) import round-trips a PSS verify" {
    var kp = try Sig.generate(.rsa_pss);
    defer kp.deinit();
    var der: [1024]u8 = undefined;
    var p: [*c]u8 = &der;
    const der_len = c.i2d_PUBKEY(kp.pkey, &p);
    try std.testing.expect(der_len > 0);
    var imported = try Sig.KeyPair.fromRsaSpki(der[0..@intCast(der_len)]);
    defer imported.deinit();

    const msg = "spki der import round-trip";
    var sig: [512]u8 = undefined;
    const slen = try rsaSignExplicit(.pss, .sha384, &kp, msg, &sig);
    try Sig.verifyRsa(.pss, .sha384, &imported, msg, sig[0..slen]);
}

test "ECDSA P-256 with SHA-384 off-diagonal verify routes" {
    var kp = try Sig.generate(.ecdsa_p256);
    defer kp.deinit();
    const msg = "off-diagonal p256/sha384";
    var sig: [128]u8 = undefined;
    const n = try ecdsaSignExplicit(.sha384, &kp, msg, &sig);
    try Sig.verifyEcdsa(.ecdsa_p256, .sha384, &kp, msg, sig[0..n]);
    try std.testing.expectError(error.VerifyFailed, Sig.verifyEcdsa(.ecdsa_p256, .sha384, &kp, "tampered", sig[0..n]));
}

test "ECDSA P-384 with SHA-256 off-diagonal verify routes" {
    var kp = try Sig.generate(.ecdsa_p384);
    defer kp.deinit();
    const msg = "off-diagonal p384/sha256";
    var sig: [128]u8 = undefined;
    const n = try ecdsaSignExplicit(.sha256, &kp, msg, &sig);
    try Sig.verifyEcdsa(.ecdsa_p384, .sha256, &kp, msg, sig[0..n]);
}

test "fromEcPublicPoint + fromEcPrivateScalar round-trip P-256 and P-384" {
    // For each curve: generate a key, export its raw public point and raw
    // private scalar, re-import each independently, sign with the
    // scalar-imported key, and verify with the point-imported key. Proves
    // the FIPS provider both ACCEPTS raw-EC fromdata and USES the keys.
    inline for (.{
        // tuple: (alg, compressed-point-size hint, scalar byte width). NB: this
        // round-trip exports the UNCOMPRESSED point via publicBytes; the
        // compressed SEC1 form has its own dedicated test below.
        .{ policy.SigAlg.ecdsa_p256, @as(usize, 33), @as(usize, 32) },
        .{ policy.SigAlg.ecdsa_p384, @as(usize, 49), @as(usize, 48) },
    }) |t| {
        const alg = t[0];
        var kp = try Sig.generate(alg);
        defer kp.deinit();

        // Export the uncompressed public point (OSSL_PKEY_PARAM_PUB_KEY is
        // the uncompressed SEC1 octet string; OpenSSL decodes it back fine).
        var point_buf: [97]u8 = undefined;
        var point_len: usize = 0;
        try std.testing.expect(c.EVP_PKEY_get_octet_string_param(kp.pkey, c.OSSL_PKEY_PARAM_PUB_KEY, &point_buf, point_buf.len, &point_len) == 1);
        try std.testing.expect(point_len > 0);

        // Export the private scalar (big-endian) via the priv BIGNUM.
        var bn_d: ?*c.BIGNUM = null;
        try std.testing.expect(c.EVP_PKEY_get_bn_param(kp.pkey, c.OSSL_PKEY_PARAM_PRIV_KEY, &bn_d) == 1);
        defer c.BN_free(bn_d);
        var scalar_buf: [48]u8 = undefined;
        const scalar_len = c.BN_bn2bin(bn_d, &scalar_buf);
        try std.testing.expect(scalar_len > 0);

        var pub_kp = try Sig.KeyPair.fromEcPublicPoint(alg, point_buf[0..point_len]);
        defer pub_kp.deinit();
        var priv_kp = try Sig.KeyPair.fromEcPrivateScalar(alg, scalar_buf[0..@intCast(scalar_len)]);
        defer priv_kp.deinit();

        const msg = "raw-ec import round-trip";
        var sig: [128]u8 = undefined;
        const n = try Sig.sign(alg, &priv_kp, msg, &sig);
        // Verify with the point-imported (public-only) key.
        try Sig.verify(alg, &pub_kp, msg, sig[0..n]);
        try std.testing.expectError(error.VerifyFailed, Sig.verify(alg, &pub_kp, "tampered", sig[0..n]));

        // The point-imported key carries the correct group, so the explicit
        // verifyEcdsa binding check also accepts it on the natural digest.
        const dg: policy.Hash = if (alg == .ecdsa_p256) .sha256 else .sha384;
        try Sig.verifyEcdsa(alg, dg, &pub_kp, msg, sig[0..n]);
    }
}

test "fromEcPublicPoint accepts a compressed SEC1 point" {
    // Generate P-256, export the COMPRESSED point (33 bytes), and confirm
    // the import path decodes the compressed encoding (not just uncompressed).
    var kp = try Sig.generate(.ecdsa_p256);
    defer kp.deinit();

    // Ask OpenSSL to format the public key compressed, then read it back.
    var fmt = [_]c.OSSL_PARAM{
        c.OSSL_PARAM_construct_utf8_string(c.OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, @constCast(@as([:0]const u8, "compressed").ptr), 0),
        c.OSSL_PARAM_construct_end(),
    };
    try std.testing.expect(c.EVP_PKEY_set_params(kp.pkey, &fmt) == 1);
    var point_buf: [33]u8 = undefined;
    var point_len: usize = 0;
    try std.testing.expect(c.EVP_PKEY_get_octet_string_param(kp.pkey, c.OSSL_PKEY_PARAM_PUB_KEY, &point_buf, point_buf.len, &point_len) == 1);
    try std.testing.expectEqual(@as(usize, 33), point_len);
    try std.testing.expect(point_buf[0] == 0x02 or point_buf[0] == 0x03); // compressed prefix

    var pub_kp = try Sig.KeyPair.fromEcPublicPoint(.ecdsa_p256, point_buf[0..point_len]);
    defer pub_kp.deinit();
    // Sign with the original (full) key, verify with the compressed-imported key.
    var sig: [80]u8 = undefined;
    const n = try Sig.sign(.ecdsa_p256, &kp, "compressed point import", &sig);
    try Sig.verify(.ecdsa_p256, &pub_kp, "compressed point import", sig[0..n]);
}

test "ecPublicPoint exports compressed SEC1 point: P-256 (33B) and P-384 (49B)" {
    // For each curve: generate a key, call ecPublicPoint, verify the size
    // and 0x02/0x03 prefix, re-import via fromEcPublicPoint, sign with
    // the original key and verify with the re-imported public key.
    inline for (.{
        .{ policy.SigAlg.ecdsa_p256, @as(usize, 33), @as(usize, 32) },
        .{ policy.SigAlg.ecdsa_p384, @as(usize, 49), @as(usize, 48) },
    }) |t| {
        const alg = t[0];
        const expected_point_len = t[1];
        const scalar_len = t[2];

        var kp = try Sig.generate(alg);
        defer kp.deinit();

        // Export compressed public point.
        var point_buf: [49]u8 = undefined;
        const plen = try kp.ecPublicPoint(alg, &point_buf);
        try std.testing.expectEqual(expected_point_len, plen);
        try std.testing.expect(point_buf[0] == 0x02 or point_buf[0] == 0x03);

        // Re-import the compressed point.
        var pub_kp = try Sig.KeyPair.fromEcPublicPoint(alg, point_buf[0..plen]);
        defer pub_kp.deinit();

        // Export scalar and re-import to create a signing key.
        var scalar_buf: [48]u8 = undefined;
        const slen = try kp.privateScalar(alg, &scalar_buf);
        try std.testing.expectEqual(scalar_len, slen);
        var priv_kp = try Sig.KeyPair.fromEcPrivateScalar(alg, scalar_buf[0..slen]);
        defer priv_kp.deinit();

        // Sign with the scalar-imported key, verify with the
        // point-imported key (proves cross-import parity).
        const msg = "ecPublicPoint compressed SEC1 export";
        var sig_buf: [128]u8 = undefined;
        const n = try Sig.sign(alg, &priv_kp, msg, &sig_buf);
        try Sig.verify(alg, &pub_kp, msg, sig_buf[0..n]);
        try std.testing.expectError(error.VerifyFailed, Sig.verify(alg, &pub_kp, "tampered", sig_buf[0..n]));

        // fromEcPublicPoint (compressed) → verifyEcdsa explicit-digest path.
        const dg: policy.Hash = if (alg == .ecdsa_p256) .sha256 else .sha384;
        try Sig.verifyEcdsa(alg, dg, &pub_kp, msg, sig_buf[0..n]);
    }
}

test "ecPublicPoint rejects non-EC algs and short output buffers" {
    // Non-EC and unsupported algs return Unsupported.
    var ed_kp = try Sig.generate(.ed25519);
    defer ed_kp.deinit();
    var buf49: [49]u8 = undefined;
    try std.testing.expectError(error.Unsupported, ed_kp.ecPublicPoint(.ed25519, &buf49));

    var rsa_kp = try Sig.generate(.rsa_pss);
    defer rsa_kp.deinit();
    try std.testing.expectError(error.Unsupported, rsa_kp.ecPublicPoint(.rsa_pss, &buf49));

    // RSA key with an EC alg name (the real type-guard path): must return
    // error.Unsupported, NOT error.OpensslFailure, after the EC-type guard.
    try std.testing.expectError(error.Unsupported, rsa_kp.ecPublicPoint(.ecdsa_p256, &buf49));

    // Buffer too short returns OpensslFailure.
    var ec_kp = try Sig.generate(.ecdsa_p256);
    defer ec_kp.deinit();
    var buf16: [16]u8 = undefined;
    try std.testing.expectError(error.OpensslFailure, ec_kp.ecPublicPoint(.ecdsa_p256, &buf16));
}

test "ecPublicPoint is non-mutating: publicBytes after ecPublicPoint is unchanged" {
    // Prove that calling ecPublicPoint (which requests compressed format on a
    // dup) does NOT alter the original KeyPair's encoding. publicBytes on the
    // FIPS backend calls EVP_PKEY_get_raw_public_key (Ed25519/PQC) or reads
    // the uncompressed point; the compressed call must leave self.pkey intact.
    inline for (.{ policy.SigAlg.ecdsa_p256, policy.SigAlg.ecdsa_p384 }) |alg| {
        var kp = try Sig.generate(alg);
        defer kp.deinit();

        // Capture uncompressed public point BEFORE calling ecPublicPoint.
        var before: [97]u8 = undefined;
        var before_len: usize = 0;
        try std.testing.expect(c.EVP_PKEY_get_octet_string_param(kp.pkey, c.OSSL_PKEY_PARAM_PUB_KEY, &before, before.len, &before_len) == 1);
        try std.testing.expect(before_len > 0);
        try std.testing.expectEqual(@as(u8, 0x04), before[0]); // uncompressed prefix

        // Call ecPublicPoint (the operation under test).
        var compressed: [49]u8 = undefined;
        const clen = try kp.ecPublicPoint(alg, &compressed);
        try std.testing.expect(clen == 33 or clen == 49);
        try std.testing.expect(compressed[0] == 0x02 or compressed[0] == 0x03);

        // Read the public point AFTER ecPublicPoint — must still be uncompressed.
        var after: [97]u8 = undefined;
        var after_len: usize = 0;
        try std.testing.expect(c.EVP_PKEY_get_octet_string_param(kp.pkey, c.OSSL_PKEY_PARAM_PUB_KEY, &after, after.len, &after_len) == 1);
        try std.testing.expectEqual(before_len, after_len);
        try std.testing.expectEqualSlices(u8, before[0..before_len], after[0..after_len]);
        try std.testing.expectEqual(@as(u8, 0x04), after[0]); // still uncompressed
    }
}

test "ecPublicPoint: wrong-curve alg (P-256 alg on P-384 key) returns Unsupported" {
    // A P-384 key with .ecdsa_p256 alg must return error.Unsupported via the
    // curve-match guard (not error.OpensslFailure from a bad write).
    var kp = try Sig.generate(.ecdsa_p384);
    defer kp.deinit();
    var buf: [49]u8 = undefined;
    try std.testing.expectError(error.Unsupported, kp.ecPublicPoint(.ecdsa_p256, &buf));
}

test "ecPublicPoint: fromEcPublicPoint key (public-only) exports correctly" {
    // Import a compressed point, then re-export via ecPublicPoint — proves
    // public-only KeyPairs (no private scalar) work with ecPublicPoint.
    var kp = try Sig.generate(.ecdsa_p256);
    defer kp.deinit();
    var point: [33]u8 = undefined;
    const plen = try kp.ecPublicPoint(.ecdsa_p256, &point);
    try std.testing.expectEqual(@as(usize, 33), plen);

    var pub_kp = try Sig.KeyPair.fromEcPublicPoint(.ecdsa_p256, point[0..plen]);
    defer pub_kp.deinit();
    var reexport: [33]u8 = undefined;
    const rlen = try pub_kp.ecPublicPoint(.ecdsa_p256, &reexport);
    try std.testing.expectEqual(@as(usize, 33), rlen);
    try std.testing.expectEqualSlices(u8, point[0..plen], reexport[0..rlen]);
}

test "fromEcPublicPoint / fromEcPrivateScalar reject non-P256/384 algs" {
    const fake_point = [_]u8{0x04} ++ [_]u8{0} ** 64;
    const fake_scalar = [_]u8{1} ** 32;
    inline for (.{ policy.SigAlg.ecdsa_p521, policy.SigAlg.ed25519, policy.SigAlg.rsa_pss, policy.SigAlg.ml_dsa_65 }) |alg| {
        try std.testing.expectError(error.Unsupported, Sig.KeyPair.fromEcPublicPoint(alg, &fake_point));
        try std.testing.expectError(error.Unsupported, Sig.KeyPair.fromEcPrivateScalar(alg, &fake_scalar));
    }
}

test "verifyEcdsa rejects RSA alg and non-SHA-2 digest as Unsupported" {
    var kp = try Sig.generate(.ecdsa_p256);
    defer kp.deinit();
    try std.testing.expectError(error.Unsupported, Sig.verifyEcdsa(.rsa_pss, .sha256, &kp, "x", "y"));
    try std.testing.expectError(error.Unsupported, Sig.verifyEcdsa(.ecdsa_p256, .sha3_256, &kp, "x", "y"));
}

test "fromRsaComponents rejects n slice whose len exceeds c_int (BN_bin2bn guard)" {
    // Construct a slice with an impossible length without allocating it.
    // The toCInt guard in ffi.zig fires before BN_bin2bn is ever called,
    // so no memory is dereferenced at the huge address.
    const huge: usize = @as(usize, std.math.maxInt(c_int)) + 1;
    var one: [1]u8 = .{0};
    const n_huge: []const u8 = one[0..1].ptr[0..huge]; // len > c_int, never read
    const e_small = [_]u8{ 0x01, 0x00, 0x01 }; // normal 65537 exponent
    try std.testing.expectError(error.OpensslFailure, Sig.KeyPair.fromRsaComponents(n_huge, &e_small));
}

test "verifyRsa rejects a non-RSA key" {
    var ec = try Sig.generate(.ecdsa_p256);
    defer ec.deinit();
    try std.testing.expectError(error.Unsupported, Sig.verifyRsa(.pkcs1, .sha256, &ec, "x", "y"));
}

test "fromRsaComponents rejects an undersized (1024-bit) modulus" {
    // 1024-bit modulus (128 bytes) with exponent 65537 — must be rejected.
    const n = [_]u8{0xC0} ++ [_]u8{0xFF} ** 126 ++ [_]u8{0x01}; // 128 bytes, high bit set
    const e = [_]u8{ 0x01, 0x00, 0x01 };
    try std.testing.expectError(error.Unsupported, Sig.KeyPair.fromRsaComponents(&n, &e));
}

test "verifyEcdsa rejects a curve/alg mismatch" {
    var p256 = try Sig.generate(.ecdsa_p256);
    defer p256.deinit();
    try std.testing.expectError(error.Unsupported, Sig.verifyEcdsa(.ecdsa_p384, .sha384, &p256, "x", "y"));
}

test "ML-DSA-44 and ML-DSA-87 sign->verify + tamper" {
    inline for (.{ policy.SigAlg.ml_dsa_44, policy.SigAlg.ml_dsa_87 }) |alg| {
        var kp = try Sig.generate(alg);
        defer kp.deinit();
        var sig: [8192]u8 = undefined;
        const n = try Sig.sign(alg, &kp, "ml-dsa kat", &sig);
        try Sig.verify(alg, &kp, "ml-dsa kat", sig[0..n]);
        try std.testing.expectError(error.VerifyFailed, Sig.verify(alg, &kp, "x", sig[0..n]));
    }
}

test "ECDSA P-521 sign->verify + tamper" {
    var kp = try Sig.generate(.ecdsa_p521);
    defer kp.deinit();
    var sig: [180]u8 = undefined;
    const n = try Sig.sign(.ecdsa_p521, &kp, "p521 msg", &sig);
    try Sig.verify(.ecdsa_p521, &kp, "p521 msg", sig[0..n]);
    try std.testing.expectError(error.VerifyFailed, Sig.verify(.ecdsa_p521, &kp, "x", sig[0..n]));
}

test "SLH-DSA all 12 variants sign->verify + tamper" {
    const variants = [_]policy.SigAlg{
        .slh_dsa_sha2_128s,  .slh_dsa_sha2_128f,  .slh_dsa_sha2_192s,  .slh_dsa_sha2_192f,
        .slh_dsa_sha2_256s,  .slh_dsa_sha2_256f,  .slh_dsa_shake_128s, .slh_dsa_shake_128f,
        .slh_dsa_shake_192s, .slh_dsa_shake_192f, .slh_dsa_shake_256s, .slh_dsa_shake_256f,
    };
    const a = std.testing.allocator;
    const sig = try a.alloc(u8, 64 * 1024);
    defer a.free(sig);
    for (variants) |alg| {
        var kp = try Sig.generate(alg);
        defer kp.deinit();
        const n = try Sig.sign(alg, &kp, "slh-dsa kat", sig);
        try Sig.verify(alg, &kp, "slh-dsa kat", sig[0..n]);
        try std.testing.expectError(error.VerifyFailed, Sig.verify(alg, &kp, "tampered", sig[0..n]));
    }
}

test "privateScalar P-256 round-trip: export → fromEcPrivateScalar + fromEcPublicPoint → sign/verify" {
    var kp = try Sig.generate(.ecdsa_p256);
    defer kp.deinit();

    // Export private scalar (must be fixed-width 32 bytes).
    var scalar: [32]u8 = undefined;
    const slen = try kp.privateScalar(.ecdsa_p256, &scalar);
    try std.testing.expectEqual(@as(usize, 32), slen);

    // Export public point (uncompressed).
    var point: [97]u8 = undefined;
    var plen: usize = 0;
    try std.testing.expect(c.EVP_PKEY_get_octet_string_param(kp.pkey, c.OSSL_PKEY_PARAM_PUB_KEY, &point, point.len, &plen) == 1);

    // Re-import scalar and point independently.
    var priv_kp = try Sig.KeyPair.fromEcPrivateScalar(.ecdsa_p256, scalar[0..slen]);
    defer priv_kp.deinit();
    var pub_kp = try Sig.KeyPair.fromEcPublicPoint(.ecdsa_p256, point[0..plen]);
    defer pub_kp.deinit();

    // Sign with the imported scalar; verify with the imported public point.
    const msg = "privateScalar p256 round-trip";
    var sig: [128]u8 = undefined;
    const n = try Sig.sign(.ecdsa_p256, &priv_kp, msg, &sig);
    try Sig.verify(.ecdsa_p256, &pub_kp, msg, sig[0..n]);
    try std.testing.expectError(error.VerifyFailed, Sig.verify(.ecdsa_p256, &pub_kp, "tampered", sig[0..n]));
}

test "privateScalar P-384 round-trip: export → fromEcPrivateScalar + fromEcPublicPoint → sign/verify" {
    var kp = try Sig.generate(.ecdsa_p384);
    defer kp.deinit();

    // Export private scalar (must be fixed-width 48 bytes).
    var scalar: [48]u8 = undefined;
    const slen = try kp.privateScalar(.ecdsa_p384, &scalar);
    try std.testing.expectEqual(@as(usize, 48), slen);

    // Export public point (uncompressed).
    var point: [97]u8 = undefined;
    var plen: usize = 0;
    try std.testing.expect(c.EVP_PKEY_get_octet_string_param(kp.pkey, c.OSSL_PKEY_PARAM_PUB_KEY, &point, point.len, &plen) == 1);

    // Re-import scalar and point independently.
    var priv_kp = try Sig.KeyPair.fromEcPrivateScalar(.ecdsa_p384, scalar[0..slen]);
    defer priv_kp.deinit();
    var pub_kp = try Sig.KeyPair.fromEcPublicPoint(.ecdsa_p384, point[0..plen]);
    defer pub_kp.deinit();

    // Sign with the imported scalar; verify with the imported public point.
    const msg = "privateScalar p384 round-trip";
    var sig: [128]u8 = undefined;
    const n = try Sig.sign(.ecdsa_p384, &priv_kp, msg, &sig);
    try Sig.verify(.ecdsa_p384, &pub_kp, msg, sig[0..n]);
    try std.testing.expectError(error.VerifyFailed, Sig.verify(.ecdsa_p384, &pub_kp, "tampered", sig[0..n]));
}

test "privateSeed Ed25519 round-trip: export → fromPrivateBytes → sign/verify + pubkey match" {
    var kp = try Sig.generate(.ed25519);
    defer kp.deinit();

    // Export the seed (32 bytes).
    var seed: [32]u8 = undefined;
    const seed_len = try kp.privateSeed(&seed);
    try std.testing.expectEqual(@as(usize, 32), seed_len);

    // Export original public key.
    var pub_orig: [32]u8 = undefined;
    const pn = try kp.publicBytes(&pub_orig);
    try std.testing.expectEqual(@as(usize, 32), pn);

    // Re-import from seed; re-derive signing keypair.
    var reimported = try Sig.KeyPair.fromPrivateBytes(.ed25519, seed[0..seed_len]);
    defer reimported.deinit();

    // Sign with the re-imported keypair and verify with the original.
    const msg = "privateSeed ed25519 round-trip";
    var sig: [64]u8 = undefined;
    const n = try Sig.sign(.ed25519, &reimported, msg, &sig);
    try Sig.verify(.ed25519, &kp, msg, sig[0..n]);

    // The re-derived public key must match the original.
    var pub_reimported: [32]u8 = undefined;
    const pn2 = try reimported.publicBytes(&pub_reimported);
    try std.testing.expectEqual(@as(usize, 32), pn2);
    try std.testing.expectEqualSlices(u8, &pub_orig, &pub_reimported);
}

test "privateScalar rejects non-EC algs + privateSeed rejects EC key (insufficient buf)" {
    // privateScalar rejects Ed25519 and RSA.
    var ed_kp = try Sig.generate(.ed25519);
    defer ed_kp.deinit();
    var buf32 = [_]u8{0} ** 32;
    try std.testing.expectError(error.Unsupported, ed_kp.privateScalar(.ed25519, &buf32));

    var rsa_kp = try Sig.generate(.rsa_pss);
    defer rsa_kp.deinit();
    var buf512 = [_]u8{0} ** 512;
    try std.testing.expectError(error.Unsupported, rsa_kp.privateScalar(.rsa_pss, &buf512));

    // privateScalar rejects a buf that is too short.
    var ec_kp = try Sig.generate(.ecdsa_p256);
    defer ec_kp.deinit();
    var buf16 = [_]u8{0} ** 16;
    try std.testing.expectError(error.OpensslFailure, ec_kp.privateScalar(.ecdsa_p256, &buf16));

    // privateSeed rejects a buf that is too short.
    var buf16b = [_]u8{0} ** 16;
    try std.testing.expectError(error.OpensslFailure, ed_kp.privateSeed(&buf16b));
}

test "fromRsaComponents rejects degenerate RSA exponents (R1 regression guard)" {
    // FIPS 186-5: e must be odd and >= 65537.
    // OpenSSL FIPS keymgmt does NOT reject weak exponents at EVP_PKEY_fromdata;
    // assertRsaStrength now enforces this requirement.
    var kp = try Sig.generate(.rsa_pkcs1);
    defer kp.deinit();
    var bn_n: ?*c.BIGNUM = null;
    if (c.EVP_PKEY_get_bn_param(kp.pkey, c.OSSL_PKEY_PARAM_RSA_N, &bn_n) != 1) return error.SkipZigTest;
    defer c.BN_free(bn_n);
    var n_buf: [512]u8 = undefined;
    const n_len = c.BN_bn2bin(bn_n, &n_buf);
    if (n_len <= 0) return error.SkipZigTest;
    const n = n_buf[0..@intCast(n_len)];
    // e=1: below minimum, odd but < 65537 — must be rejected
    const e1 = [_]u8{0x01};
    try std.testing.expectError(error.Unsupported, Sig.KeyPair.fromRsaComponents(n, &e1));
    // e=2: even — must be rejected
    const e2 = [_]u8{0x02};
    try std.testing.expectError(error.Unsupported, Sig.KeyPair.fromRsaComponents(n, &e2));
}

test "fromPublicBytes rejects sub-2048-bit (1024-bit) RSA SPKI DER" {
    // Build a 1024-bit RSA public key via raw EVP_PKEY_fromdata over a
    // default-provider libCtx (no FIPS strength enforcement there).  This
    // lets us craft the weak DER blob without FIPS keygen, which refuses
    // 1024-bit RSA.  We then verify the FIPS seam rejects it on import.
    // Use a default-provider context (null) for the weak keygen only.
    const n = [_]u8{0xC0} ++ [_]u8{0xFF} ** 126 ++ [_]u8{0x01}; // 128-byte modulus, high bit set
    const e_bytes = [_]u8{ 0x01, 0x00, 0x01 }; // 65537

    const bn_n = c.BN_bin2bn(&n, n.len, null) orelse return error.SkipZigTest;
    defer c.BN_free(bn_n);
    const bn_e = c.BN_bin2bn(&e_bytes, e_bytes.len, null) orelse return error.SkipZigTest;
    defer c.BN_free(bn_e);

    const bld = c.OSSL_PARAM_BLD_new() orelse return error.SkipZigTest;
    defer c.OSSL_PARAM_BLD_free(bld);
    if (c.OSSL_PARAM_BLD_push_BN(bld, c.OSSL_PKEY_PARAM_RSA_N, bn_n) != 1) return error.SkipZigTest;
    if (c.OSSL_PARAM_BLD_push_BN(bld, c.OSSL_PKEY_PARAM_RSA_E, bn_e) != 1) return error.SkipZigTest;
    const params = c.OSSL_PARAM_BLD_to_param(bld) orelse return error.SkipZigTest;
    defer c.OSSL_PARAM_free(params);

    // Use the default (non-FIPS) lib context (null) so RSA 1024-bit keygen is allowed.
    const pctx = c.EVP_PKEY_CTX_new_from_name(null, "RSA", null) orelse return error.SkipZigTest;
    defer c.EVP_PKEY_CTX_free(pctx);
    if (c.EVP_PKEY_fromdata_init(pctx) != 1) return error.SkipZigTest;
    var weak_pkey: ?*c.EVP_PKEY = null;
    if (c.EVP_PKEY_fromdata(pctx, &weak_pkey, c.EVP_PKEY_PUBLIC_KEY, params) != 1) return error.SkipZigTest;
    const wk = weak_pkey orelse return error.SkipZigTest;
    defer c.EVP_PKEY_free(wk);

    // Export weak key to SPKI DER via i2d_PUBKEY.
    var der_buf: [512]u8 = undefined;
    var der_ptr: [*c]u8 = &der_buf;
    const der_len = c.i2d_PUBKEY(wk, &der_ptr);
    if (der_len <= 0) return error.SkipZigTest;

    // Positive case: a normal ≥2048-bit RSA key must still import fine.
    var strong = try Sig.generate(.rsa_pkcs1);
    defer strong.deinit();
    var spki: [1024]u8 = undefined;
    var sp: [*c]u8 = &spki;
    const spki_len = c.i2d_PUBKEY(strong.pkey, &sp);
    try std.testing.expect(spki_len > 0);
    var imported_strong = try Sig.KeyPair.fromPublicBytes(.rsa_pkcs1, spki[0..@intCast(spki_len)]);
    defer imported_strong.deinit();

    // Rejection: importing the 1024-bit SPKI must return error.Unsupported.
    try std.testing.expectError(
        error.Unsupported,
        Sig.KeyPair.fromPublicBytes(.rsa_pkcs1, der_buf[0..@intCast(der_len)]),
    );
}
