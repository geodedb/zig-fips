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

    /// Generate a fresh KEM key pair for `alg`.
    pub fn generate(alg: policy.KemAlg) Error!KeyPair {
        provider.assertActive();
        const pctx = c.EVP_PKEY_CTX_new_from_name(provider.libCtx(), policy.kemName(alg), "fips=yes") orelse return error.Unsupported;
        defer c.EVP_PKEY_CTX_free(pctx);
        if (c.EVP_PKEY_keygen_init(pctx) != 1) return error.OpensslFailure;
        var pkey: ?*c.EVP_PKEY = null;
        if (c.EVP_PKEY_generate(pctx, &pkey) != 1) return error.OpensslFailure;
        return .{ .pkey = pkey orelse return error.OpensslFailure };
    }

    /// Encapsulate to `kp`'s public key. Writes the ciphertext into
    /// `ct_out` and the shared secret into `ss_out`; returns the lengths.
    pub fn encapsulate(alg: policy.KemAlg, kp: *KeyPair, ct_out: []u8, ss_out: []u8) Error!EncapResult {
        _ = alg;
        provider.assertActive();
        const ctx = c.EVP_PKEY_CTX_new_from_pkey(provider.libCtx(), kp.pkey, "fips=yes") orelse return error.OpensslFailure;
        defer c.EVP_PKEY_CTX_free(ctx);
        if (c.EVP_PKEY_encapsulate_init(ctx, null) != 1) return error.OpensslFailure;
        var ct_len: usize = 0;
        var ss_len: usize = 0;
        // Size query (null outputs).
        if (c.EVP_PKEY_encapsulate(ctx, null, &ct_len, null, &ss_len) != 1) return error.OpensslFailure;
        if (ct_len > ct_out.len or ss_len > ss_out.len) return error.OpensslFailure;
        if (c.EVP_PKEY_encapsulate(ctx, ct_out.ptr, &ct_len, ss_out.ptr, &ss_len) != 1) return error.OpensslFailure;
        return .{ .ct_len = ct_len, .ss_len = ss_len };
    }

    /// Decapsulate `ct` with `kp`'s private key. Writes the shared
    /// secret into `ss_out`; returns its length.
    pub fn decapsulate(alg: policy.KemAlg, kp: *KeyPair, ct: []const u8, ss_out: []u8) Error!usize {
        _ = alg;
        provider.assertActive();
        const ctx = c.EVP_PKEY_CTX_new_from_pkey(provider.libCtx(), kp.pkey, "fips=yes") orelse return error.OpensslFailure;
        defer c.EVP_PKEY_CTX_free(ctx);
        if (c.EVP_PKEY_decapsulate_init(ctx, null) != 1) return error.OpensslFailure;
        var ss_len: usize = 0;
        if (c.EVP_PKEY_decapsulate(ctx, null, &ss_len, ct.ptr, ct.len) != 1) return error.OpensslFailure;
        if (ss_len > ss_out.len) return error.OpensslFailure;
        if (c.EVP_PKEY_decapsulate(ctx, ss_out.ptr, &ss_len, ct.ptr, ct.len) != 1) return error.OpensslFailure;
        return ss_len;
    }
};

test "ML-KEM-768 encap/decap shared secret agree" {
    var kp = try Kem.generate(.ml_kem_768);
    defer kp.deinit();
    var ct: [2048]u8 = undefined;
    var ss_a: [64]u8 = undefined;
    const e = try Kem.encapsulate(.ml_kem_768, &kp, &ct, &ss_a);
    var ss_b: [64]u8 = undefined;
    const d = try Kem.decapsulate(.ml_kem_768, &kp, ct[0..e.ct_len], &ss_b);
    try std.testing.expectEqualSlices(u8, ss_a[0..e.ss_len], ss_b[0..d]);
}
test "X25519MLKEM768 hybrid encap/decap agree" {
    var kp = try Kem.generate(.x25519_ml_kem_768);
    defer kp.deinit();
    var ct: [2048]u8 = undefined;
    var ss_a: [64]u8 = undefined;
    const e = try Kem.encapsulate(.x25519_ml_kem_768, &kp, &ct, &ss_a);
    var ss_b: [64]u8 = undefined;
    const d = try Kem.decapsulate(.x25519_ml_kem_768, &kp, ct[0..e.ct_len], &ss_b);
    try std.testing.expectEqualSlices(u8, ss_a[0..e.ss_len], ss_b[0..d]);
}
test "EncapResult is the pinned named type" {
    comptime {
        _ = Kem.EncapResult;
    }
}
