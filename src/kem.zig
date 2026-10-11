// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
const std = @import("std");
const ffi = @import("ffi.zig");
const c = ffi.c;
const policy = @import("policy.zig");
const provider = @import("provider.zig");

pub const Kem = struct {
    pub const Error = error{ Unsupported, DecapMismatch, OpensslFailure };

    /// Pinned named return type of `encapsulate` (NOT an anonymous
    /// struct). `ct_len` is bytes written into `ct_out`; `ss_len` is
    /// bytes written into `ss_out`. Referenced by name by std_shim and
    /// every consumer.
    pub const EncapResult = struct { ct_len: usize, ss_len: usize };

    pub const KeyPair = struct {
        pkey: *c.EVP_PKEY,
        pub fn deinit(self: *KeyPair) void {
            c.EVP_PKEY_free(self.pkey);
        }
    };

    /// Owned public-only peer key. It cannot be passed to decapsulate.
    pub const PublicKey = struct {
        pkey: *c.EVP_PKEY,
        pub fn deinit(self: *PublicKey) void {
            c.EVP_PKEY_free(self.pkey);
        }
    };

    fn checkKey(alg: policy.KemAlg, pkey: *c.EVP_PKEY) Error!void {
        if (!policy.isKemApproved(alg)) return error.Unsupported;
        if (!provider.ownsKey(pkey) or c.EVP_PKEY_is_a(pkey, policy.kemName(alg)) != 1)
            return error.Unsupported;
    }

    /// Export the provider's public-key wire encoding (not SPKI/PEM).
    /// Hybrid component ordering is defined by the provider's named group;
    /// callers must not reorder the public key, ciphertext, or shared secret.
    /// Size/policy/key rejection leaves out unchanged.
    pub fn exportPublic(alg: policy.KemAlg, kp: *KeyPair, out: []u8) Error!usize {
        try checkKey(alg, kp.pkey);
        var len: usize = 0;
        if (c.EVP_PKEY_get_octet_string_param(kp.pkey, c.OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, null, 0, &len) != 1)
            return error.OpensslFailure;
        if (len == 0 or len > out.len) return error.OpensslFailure;
        if (c.EVP_PKEY_get_octet_string_param(kp.pkey, c.OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, out.ptr, len, &len) != 1)
            return error.OpensslFailure;
        return len;
    }

    /// Import only public bytes using the approved provider. The provider
    /// validates the exact length and encoding for alg. Never imports secrets.
    pub fn importPublic(alg: policy.KemAlg, wire: []const u8) Error!PublicKey {
        if (!policy.isKemApproved(alg)) return error.Unsupported;
        provider.assertActive();
        const ctx = c.EVP_PKEY_CTX_new_from_name(provider.libCtx(), policy.kemName(alg), "fips=yes") orelse return error.Unsupported;
        defer c.EVP_PKEY_CTX_free(ctx);
        if (c.EVP_PKEY_fromdata_init(ctx) != 1) return error.OpensslFailure;
        // fromdata does not modify input; OSSL_PARAM uses a mutable pointer
        // because the same parameter representation also supports outputs.
        var params = [_]c.OSSL_PARAM{
            c.OSSL_PARAM_construct_octet_string(c.OSSL_PKEY_PARAM_PUB_KEY, @constCast(wire.ptr), wire.len),
            c.OSSL_PARAM_construct_end(),
        };
        var pkey: ?*c.EVP_PKEY = null;
        errdefer c.EVP_PKEY_free(pkey);
        if (c.EVP_PKEY_fromdata(ctx, &pkey, c.EVP_PKEY_PUBLIC_KEY, &params) != 1) return error.OpensslFailure;
        const key = pkey orelse return error.OpensslFailure;
        try checkKey(alg, key);
        return .{ .pkey = key };
    }

    /// Encapsulate to a peer's imported public key.
    pub fn encapsulatePublic(alg: policy.KemAlg, pk: *PublicKey, ct_out: []u8, ss_out: []u8) Error!EncapResult {
        return encapsulateKey(alg, pk.pkey, ct_out, ss_out);
    }

    /// Generate a fresh KEM key pair for `alg`.
    pub fn generate(alg: policy.KemAlg) Error!KeyPair {
        if (!policy.isKemApproved(alg)) return error.Unsupported;
        provider.assertActive();
        const pctx = c.EVP_PKEY_CTX_new_from_name(provider.libCtx(), policy.kemName(alg), "fips=yes") orelse return error.Unsupported;
        defer c.EVP_PKEY_CTX_free(pctx);
        if (c.EVP_PKEY_keygen_init(pctx) != 1) return error.OpensslFailure;
        var pkey: ?*c.EVP_PKEY = null;
        errdefer c.EVP_PKEY_free(pkey);
        if (c.EVP_PKEY_generate(pctx, &pkey) != 1) return error.OpensslFailure;
        const key = pkey orelse return error.OpensslFailure;
        try checkKey(alg, key);
        return .{ .pkey = key };
    }

    /// Encapsulate to `kp`'s public key. Writes the ciphertext into
    /// `ct_out` and the shared secret into `ss_out`; returns the lengths.
    pub fn encapsulate(alg: policy.KemAlg, kp: *KeyPair, ct_out: []u8, ss_out: []u8) Error!EncapResult {
        return encapsulateKey(alg, kp.pkey, ct_out, ss_out);
    }

    fn encapsulateKey(alg: policy.KemAlg, pkey: *c.EVP_PKEY, ct_out: []u8, ss_out: []u8) Error!EncapResult {
        try checkKey(alg, pkey);
        const ctx = c.EVP_PKEY_CTX_new_from_pkey(provider.libCtx(), pkey, "fips=yes") orelse return error.OpensslFailure;
        defer c.EVP_PKEY_CTX_free(ctx);
        if (c.EVP_PKEY_encapsulate_init(ctx, null) != 1) return error.OpensslFailure;
        var ct_len: usize = 0;
        var ss_len: usize = 0;
        // Size query (null outputs).
        if (c.EVP_PKEY_encapsulate(ctx, null, &ct_len, null, &ss_len) != 1) return error.OpensslFailure;
        if (ct_len > ct_out.len or ss_len > ss_out.len) return error.OpensslFailure;
        const secret = ss_out[0..ss_len];
        errdefer @import("util.zig").secureZero(secret);
        if (c.EVP_PKEY_encapsulate(ctx, ct_out.ptr, &ct_len, ss_out.ptr, &ss_len) != 1) return error.OpensslFailure;
        return .{ .ct_len = ct_len, .ss_len = ss_len };
    }

    /// Decapsulate `ct` with `kp`'s private key. Writes the shared
    /// secret into `ss_out`; returns its length.
    pub fn decapsulate(alg: policy.KemAlg, kp: *KeyPair, ct: []const u8, ss_out: []u8) Error!usize {
        try checkKey(alg, kp.pkey);
        const ctx = c.EVP_PKEY_CTX_new_from_pkey(provider.libCtx(), kp.pkey, "fips=yes") orelse return error.OpensslFailure;
        defer c.EVP_PKEY_CTX_free(ctx);
        if (c.EVP_PKEY_decapsulate_init(ctx, null) != 1) return error.OpensslFailure;
        var ss_len: usize = 0;
        if (c.EVP_PKEY_decapsulate(ctx, null, &ss_len, ct.ptr, ct.len) != 1) return error.OpensslFailure;
        if (ss_len > ss_out.len) return error.OpensslFailure;
        const secret = ss_out[0..ss_len];
        errdefer @import("util.zig").secureZero(secret);
        if (c.EVP_PKEY_decapsulate(ctx, ss_out.ptr, &ss_len, ct.ptr, ct.len) != 1) return error.OpensslFailure;
        return ss_len;
    }
};

test "Kem.encapsulate rejects undersized ct_out and ss_out buffers" {
    // The size-query path sets ct_len/ss_len; the guard
    // `if (ct_len > ct_out.len or ss_len > ss_out.len)` returns
    // error.OpensslFailure before any write occurs.
    var kp = try Kem.generate(.ml_kem_768);
    defer kp.deinit();
    var ct_ok: [2048]u8 = undefined;
    var ss_ok: [128]u8 = undefined;
    var ct_tiny: [1]u8 = undefined;
    var ss_tiny: [1]u8 = undefined;
    // Too-small ciphertext buffer.
    try std.testing.expectError(error.OpensslFailure, Kem.encapsulate(.ml_kem_768, &kp, &ct_tiny, &ss_ok));
    // Too-small shared-secret buffer.
    try std.testing.expectError(error.OpensslFailure, Kem.encapsulate(.ml_kem_768, &kp, &ct_ok, &ss_tiny));
}

test "ML-KEM-768 encap/decap shared secret agree" {
    const util = @import("util.zig");
    var kp = try Kem.generate(.ml_kem_768);
    defer kp.deinit();
    var ct: [2048]u8 = undefined;
    var ss_a: [64]u8 = undefined;
    const e = try Kem.encapsulate(.ml_kem_768, &kp, &ct, &ss_a);
    var ss_b: [64]u8 = undefined;
    const d = try Kem.decapsulate(.ml_kem_768, &kp, ct[0..e.ct_len], &ss_b);
    try std.testing.expect(util.timingSafeEql(ss_a[0..e.ss_len], ss_b[0..d]));
}
test "X25519MLKEM768 hybrid encap/decap agree" {
    const util = @import("util.zig");
    var kp = try Kem.generate(.x25519_ml_kem_768);
    defer kp.deinit();
    var ct: [2048]u8 = undefined;
    var ss_a: [64]u8 = undefined;
    const e = try Kem.encapsulate(.x25519_ml_kem_768, &kp, &ct, &ss_a);
    var ss_b: [64]u8 = undefined;
    const d = try Kem.decapsulate(.x25519_ml_kem_768, &kp, ct[0..e.ct_len], &ss_b);
    try std.testing.expect(util.timingSafeEql(ss_a[0..e.ss_len], ss_b[0..d]));
}
test "EncapResult is the pinned named type" {
    comptime {
        _ = Kem.EncapResult;
    }
}

test "all approved KEM variants encap/decap agree" {
    const util = @import("util.zig");
    const algs = [_]policy.KemAlg{
        .ml_kem_512,           .ml_kem_1024,
        .secp256r1_ml_kem_768, .secp384r1_ml_kem_1024,
    };
    for (algs) |alg| {
        var kp = try Kem.generate(alg);
        defer kp.deinit();
        var ct: [4096]u8 = undefined;
        // 128 bytes accommodates every approved hybrid combined secret.
        var ss_a: [128]u8 = undefined;
        var ss_b: [128]u8 = undefined;
        defer util.secureZero(&ss_a);
        defer util.secureZero(&ss_b);
        const e = try Kem.encapsulate(alg, &kp, &ct, &ss_a);
        const d = try Kem.decapsulate(alg, &kp, ct[0..e.ct_len], &ss_b);
        try std.testing.expect(util.timingSafeEql(ss_a[0..e.ss_len], ss_b[0..d]));
    }
}

test "SONNY-4782 provider rejects the X448 hybrid with fips=yes" {
    provider.assertActive();
    const ctx = c.EVP_PKEY_CTX_new_from_name(provider.libCtx(), policy.kemName(.x448_ml_kem_1024), "fips=yes");
    defer if (ctx) |p| c.EVP_PKEY_CTX_free(p);
    try std.testing.expect(ctx == null);
    try std.testing.expectError(error.Unsupported, Kem.generate(.x448_ml_kem_1024));
}

test "SONNY-4782 unapproved KEM operations reject even an approved key without writing outputs" {
    var kp = try Kem.generate(.ml_kem_768);
    defer kp.deinit();
    var ct = [_]u8{0xa5} ** 2048;
    var ss = [_]u8{0x5a} ** 128;
    try std.testing.expectError(error.Unsupported, Kem.encapsulate(.x448_ml_kem_1024, &kp, &ct, &ss));
    try std.testing.expect(std.mem.allEqual(u8, &ct, 0xa5));
    try std.testing.expect(std.mem.allEqual(u8, &ss, 0x5a));
    try std.testing.expectError(error.Unsupported, Kem.decapsulate(.x448_ml_kem_1024, &kp, &ct, &ss));
    try std.testing.expect(std.mem.allEqual(u8, &ss, 0x5a));
}

const wire_cases = .{
    .{ policy.KemAlg.ml_kem_512, 800, 768, 32 },
    .{ policy.KemAlg.ml_kem_768, 1184, 1088, 32 },
    .{ policy.KemAlg.ml_kem_1024, 1568, 1568, 32 },
    .{ policy.KemAlg.x25519_ml_kem_768, 1216, 1120, 64 },
    .{ policy.KemAlg.secp256r1_ml_kem_768, 1249, 1153, 64 },
    .{ policy.KemAlg.secp384r1_ml_kem_1024, 1665, 1665, 80 },
};

test "SONNY-4793 approved KEM wire keys round trip without private material" {
    const util = @import("util.zig");
    inline for (wire_cases) |case| {
        const alg = case[0];
        var kp = try Kem.generate(alg);
        defer kp.deinit();
        var wire = [_]u8{0xa5} ** 2048;
        try std.testing.expectError(error.OpensslFailure, Kem.exportPublic(alg, &kp, wire[0 .. case[1] - 1]));
        try std.testing.expect(std.mem.allEqual(u8, &wire, 0xa5));
        const n = try Kem.exportPublic(alg, &kp, &wire);
        try std.testing.expectEqual(case[1], n);
        try std.testing.expect(std.mem.allEqual(u8, wire[n..], 0xa5));
        var peer = try Kem.importPublic(alg, wire[0..n]);
        defer peer.deinit();
        try std.testing.expect(provider.ownsKey(peer.pkey));
        try std.testing.expectEqual(@as(c_int, 1), c.EVP_PKEY_eq(kp.pkey, peer.pkey));
        // Ask for all key material: the imported key must export public only.
        var params: [*c]c.OSSL_PARAM = null;
        try std.testing.expectEqual(@as(c_int, 1), c.EVP_PKEY_todata(peer.pkey, c.EVP_PKEY_KEYPAIR, &params));
        defer c.OSSL_PARAM_free(params);
        try std.testing.expect(c.OSSL_PARAM_locate_const(params, c.OSSL_PKEY_PARAM_PUB_KEY) != null);
        try std.testing.expect(c.OSSL_PARAM_locate_const(params, c.OSSL_PKEY_PARAM_PRIV_KEY) == null);
        try std.testing.expect(c.OSSL_PARAM_locate_const(params, c.OSSL_PKEY_PARAM_ML_KEM_SEED) == null);
        var ct: [2048]u8 = undefined;
        var a: [128]u8 = undefined;
        var b: [128]u8 = undefined;
        defer util.secureZero(&a);
        defer util.secureZero(&b);
        const enc = try Kem.encapsulatePublic(alg, &peer, &ct, &a);
        const dec = try Kem.decapsulate(alg, &kp, ct[0..enc.ct_len], &b);
        try std.testing.expectEqual(case[2], enc.ct_len);
        try std.testing.expectEqual(case[3], enc.ss_len);
        try std.testing.expectEqual(enc.ss_len, dec);
        try std.testing.expect(util.timingSafeEql(a[0..enc.ss_len], b[0..dec]));
    }
}

test "SONNY-4793 public import rejects malformed encodings and lengths" {
    inline for (wire_cases) |case| {
        const alg = case[0];
        var kp = try Kem.generate(alg);
        defer kp.deinit();
        var wire: [2048]u8 = undefined;
        const n = try Kem.exportPublic(alg, &kp, &wire);
        try std.testing.expectError(error.OpensslFailure, Kem.importPublic(alg, wire[0..0]));
        try std.testing.expectError(error.OpensslFailure, Kem.importPublic(alg, wire[0 .. n - 1]));
        wire[n] = 0;
        try std.testing.expectError(error.OpensslFailure, Kem.importPublic(alg, wire[0 .. n + 1]));
        // ML-KEM encodes coefficients modulo 3329 in 12 bits. A coefficient
        // of 4095 is non-canonical and must fail the provider's modulus check.
        const ml_offset = switch (alg) {
            .secp256r1_ml_kem_768 => 65,
            .secp384r1_ml_kem_1024 => 97,
            else => 0,
        };
        wire[ml_offset] = 0xff;
        wire[ml_offset + 1] |= 0x0f;
        try std.testing.expectError(error.OpensslFailure, Kem.importPublic(alg, wire[0..n]));
    }
    try std.testing.expectError(error.Unsupported, Kem.importPublic(.x448_ml_kem_1024, &.{}));
}

test "SONNY-4793 requested KEM algorithm must match the actual key" {
    var kp = try Kem.generate(.ml_kem_768);
    defer kp.deinit();
    var ct = [_]u8{0xa5} ** 2048;
    var ss = [_]u8{0x5a} ** 128;
    try std.testing.expectError(error.Unsupported, Kem.encapsulate(.ml_kem_512, &kp, &ct, &ss));
    try std.testing.expectError(error.Unsupported, Kem.decapsulate(.ml_kem_512, &kp, &ct, &ss));
    try std.testing.expect(std.mem.allEqual(u8, &ct, 0xa5));
    try std.testing.expect(std.mem.allEqual(u8, &ss, 0x5a));
}

test "SONNY-4793 imported keys enforce algorithm policy and output bounds" {
    var kp = try Kem.generate(.x25519_ml_kem_768);
    defer kp.deinit();
    var wire: [2048]u8 = undefined;
    const n = try Kem.exportPublic(.x25519_ml_kem_768, &kp, &wire);
    var peer = try Kem.importPublic(.x25519_ml_kem_768, wire[0..n]);
    defer peer.deinit();
    var ct = [_]u8{0xa5} ** 2048;
    var ss = [_]u8{0x5a} ** 128;
    try std.testing.expectError(error.Unsupported, Kem.exportPublic(.ml_kem_768, &kp, &ct));
    try std.testing.expectError(error.Unsupported, Kem.exportPublic(.x448_ml_kem_1024, &kp, &ct));
    try std.testing.expectError(error.Unsupported, Kem.encapsulatePublic(.ml_kem_768, &peer, &ct, &ss));
    try std.testing.expectError(error.Unsupported, Kem.encapsulatePublic(.x448_ml_kem_1024, &peer, &ct, &ss));
    try std.testing.expectError(error.OpensslFailure, Kem.encapsulatePublic(.x25519_ml_kem_768, &peer, ct[0..1119], &ss));
    try std.testing.expectError(error.OpensslFailure, Kem.encapsulatePublic(.x25519_ml_kem_768, &peer, &ct, ss[0..63]));
    try std.testing.expect(std.mem.allEqual(u8, &ct, 0xa5));
    try std.testing.expect(std.mem.allEqual(u8, &ss, 0x5a));
}

test "SONNY-4793 KEM operations reject keys from the default provider" {
    const foreign_ctx = c.OSSL_LIB_CTX_new() orelse return error.OutOfMemory;
    defer c.OSSL_LIB_CTX_free(foreign_ctx);
    const default_provider = c.OSSL_PROVIDER_load(foreign_ctx, "default") orelse return error.OpensslFailure;
    defer _ = c.OSSL_PROVIDER_unload(default_provider);
    const ctx = c.EVP_PKEY_CTX_new_from_name(foreign_ctx, "ML-KEM-768", "provider=default") orelse return error.OpensslFailure;
    defer c.EVP_PKEY_CTX_free(ctx);
    try std.testing.expectEqual(@as(c_int, 1), c.EVP_PKEY_keygen_init(ctx));
    var pkey: ?*c.EVP_PKEY = null;
    try std.testing.expectEqual(@as(c_int, 1), c.EVP_PKEY_generate(ctx, &pkey));
    var kp: Kem.KeyPair = .{ .pkey = pkey.? };
    defer kp.deinit();
    var ct = [_]u8{0xa5} ** 2048;
    var ss = [_]u8{0x5a} ** 128;
    try std.testing.expectError(error.Unsupported, Kem.exportPublic(.ml_kem_768, &kp, &ct));
    try std.testing.expectError(error.Unsupported, Kem.encapsulate(.ml_kem_768, &kp, &ct, &ss));
    try std.testing.expectError(error.Unsupported, Kem.decapsulate(.ml_kem_768, &kp, &ct, &ss));
    try std.testing.expect(std.mem.allEqual(u8, &ct, 0xa5));
    try std.testing.expect(std.mem.allEqual(u8, &ss, 0x5a));
}

test "SONNY-4793 X25519MLKEM768 wire interoperates with independent ML-KEM and ECDH" {
    // TLS's X25519MLKEM768 ordering is ML-KEM first for key, ciphertext,
    // and shared secret. Build the server response from separate component
    // algorithms so a symmetric but wrongly ordered composite wrapper cannot pass.
    const util = @import("util.zig");
    var kp = try Kem.generate(.x25519_ml_kem_768);
    defer kp.deinit();
    var wire: [1216]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1216), try Kem.exportPublic(.x25519_ml_kem_768, &kp, &wire));
    var ml_peer = try Kem.importPublic(.ml_kem_768, wire[0..1184]);
    defer ml_peer.deinit();
    // Independent remote-peer reference: standalone X25519 is not fetched
    // with fips=yes by this provider. The library's composite KEM remains
    // entirely FIPS-backed; only this test peer uses a separate default
    // context to construct its X25519 contribution.
    const peer_ctx = c.OSSL_LIB_CTX_new() orelse return error.OutOfMemory;
    defer c.OSSL_LIB_CTX_free(peer_ctx);
    const peer_provider = c.OSSL_PROVIDER_load(peer_ctx, "default") orelse return error.OpensslFailure;
    defer _ = c.OSSL_PROVIDER_unload(peer_provider);
    const x_peer = c.EVP_PKEY_new_raw_public_key_ex(peer_ctx, "X25519", "provider=default", wire[1184..].ptr, 32) orelse return error.OpensslFailure;
    defer c.EVP_PKEY_free(x_peer);
    const gen = c.EVP_PKEY_CTX_new_from_name(peer_ctx, "X25519", "provider=default") orelse return error.OpensslFailure;
    defer c.EVP_PKEY_CTX_free(gen);
    try std.testing.expectEqual(@as(c_int, 1), c.EVP_PKEY_keygen_init(gen));
    var ephemeral: ?*c.EVP_PKEY = null;
    defer c.EVP_PKEY_free(ephemeral);
    try std.testing.expectEqual(@as(c_int, 1), c.EVP_PKEY_generate(gen, &ephemeral));
    const x_ctx = c.EVP_PKEY_CTX_new_from_pkey(peer_ctx, ephemeral, "provider=default") orelse return error.OpensslFailure;
    defer c.EVP_PKEY_CTX_free(x_ctx);
    // TLS uses raw ECDH, not the HKDF-derived HPKE DHKEM exposed by
    // EVP_PKEY_encapsulate for a standalone X25519 key.
    try std.testing.expectEqual(@as(c_int, 1), c.EVP_PKEY_derive_init(x_ctx));
    try std.testing.expectEqual(@as(c_int, 1), c.EVP_PKEY_derive_set_peer(x_ctx, x_peer));
    var ct: [1120]u8 = undefined;
    var a: [64]u8 = undefined;
    var b: [64]u8 = undefined;
    defer util.secureZero(&a);
    defer util.secureZero(&b);
    const ml_enc = try Kem.encapsulatePublic(.ml_kem_768, &ml_peer, ct[0..1088], a[0..32]);
    try std.testing.expectEqual(@as(usize, 1088), ml_enc.ct_len);
    try std.testing.expectEqual(@as(usize, 32), ml_enc.ss_len);
    var x_ct_len: usize = 32;
    var x_ss_len: usize = 32;
    try std.testing.expectEqual(@as(c_int, 1), c.EVP_PKEY_get_raw_public_key(ephemeral, ct[1088..].ptr, &x_ct_len));
    try std.testing.expectEqual(@as(c_int, 1), c.EVP_PKEY_derive(x_ctx, a[32..].ptr, &x_ss_len));
    try std.testing.expectEqual(@as(usize, 32), x_ct_len);
    try std.testing.expectEqual(@as(usize, 32), x_ss_len);
    try std.testing.expectEqual(@as(usize, 64), try Kem.decapsulate(.x25519_ml_kem_768, &kp, &ct, &b));
    try std.testing.expect(util.timingSafeEql(&a, &b));
}

test "SONNY-4793 low-order X25519 peer fails closed and wipes partial secret" {
    var kp = try Kem.generate(.x25519_ml_kem_768);
    defer kp.deinit();
    var wire: [1216]u8 = undefined;
    _ = try Kem.exportPublic(.x25519_ml_kem_768, &kp, &wire);
    @memset(wire[1184..], 0);
    var peer = try Kem.importPublic(.x25519_ml_kem_768, &wire);
    defer peer.deinit();
    var ct: [1120]u8 = undefined;
    var ss = [_]u8{0xa5} ** 64;
    try std.testing.expectError(error.OpensslFailure, Kem.encapsulatePublic(.x25519_ml_kem_768, &peer, &ct, &ss));
    try std.testing.expect(std.mem.allEqual(u8, &ss, 0));

    const valid = try Kem.encapsulate(.x25519_ml_kem_768, &kp, &ct, &ss);
    @memset(ct[1088..], 0);
    try std.testing.expectError(error.OpensslFailure, Kem.decapsulate(.x25519_ml_kem_768, &kp, ct[0..valid.ct_len], &ss));
    try std.testing.expect(std.mem.allEqual(u8, &ss, 0));
}
