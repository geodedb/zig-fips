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

fn ecGroup(alg: policy.SigAlg) [:0]const u8 {
    return switch (alg) {
        .ecdsa_p256 => "P-256",
        .ecdsa_p384 => "P-384",
        .ecdsa_p521 => "P-521",
        else => unreachable,
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
                .pqc => c.EVP_PKEY_new_raw_public_key_ex(provider.libCtx(), policy.sigName(alg), "fips=yes", raw.ptr, raw.len),
                .der => blk: { // ECDSA / RSA: decode SubjectPublicKeyInfo DER.
                    var pp: [*c]const u8 = raw.ptr;
                    break :blk c.d2i_PUBKEY(null, &pp, @intCast(raw.len));
                },
            } orelse return error.OpensslFailure;
            return .{ .pkey = pkey };
        }

        pub fn fromPrivateBytes(alg: policy.SigAlg, raw: []const u8) Error!KeyPair {
            provider.assertActive();
            const pkey = switch (sigFamily(alg)) {
                .ed25519 => c.EVP_PKEY_new_raw_private_key_ex(provider.libCtx(), "ED25519", "fips=yes", raw.ptr, raw.len),
                .pqc => c.EVP_PKEY_new_raw_private_key_ex(provider.libCtx(), policy.sigName(alg), "fips=yes", raw.ptr, raw.len),
                .der => blk: { // ECDSA / RSA: decode type-specific DER.
                    var pp: [*c]const u8 = raw.ptr;
                    const t: c_int = if (sigIsRsa(alg)) c.EVP_PKEY_RSA else c.EVP_PKEY_EC;
                    break :blk c.d2i_PrivateKey(t, null, &pp, @intCast(raw.len));
                },
            } orelse return error.OpensslFailure;
            return .{ .pkey = pkey };
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
                c.OSSL_PARAM_construct_utf8_string(c.OSSL_PKEY_PARAM_GROUP_NAME, @constCast(ecGroup(alg).ptr), 0),
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
    /// signature length.
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
        const ctx = c.EVP_MD_CTX_new() orelse return error.OpensslFailure;
        defer c.EVP_MD_CTX_free(ctx);

        try initVerifyDigest(alg, ctx, kp);

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
