// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! SP 800-56A Rev. 3 elliptic-curve Diffie-Hellman (KAS-ECC primitive)
//! over P-256 / P-384, executed entirely inside the OpenSSL FIPS provider
//! (every fetch uses `fips=yes`, every key must be owned by the FIPS
//! provider, and the derive is refused unless the provider's approved-mode
//! indicator reports 1).
//!
//! Wire format: SEC1 §2.3.3 UNCOMPRESSED points only (0x04 || X || Y,
//! 65 / 97 bytes). Compressed, hybrid and infinity encodings are rejected.
//! Every imported peer key passes SP 800-56A §5.6.2.3.3 full public-key
//! validation (coordinates in [0, p-1], on the curve, not the identity,
//! n*Q = identity) before it can be used.

const std = @import("std");
const ffi = @import("ffi.zig");
const c = ffi.c;
const policy = @import("policy.zig");
const provider = @import("provider.zig");
const util = @import("util.zig");

pub const Ecdh = struct {
    /// `InvalidPublicKey`: a peer encoding failed the SEC1 type/length check
    /// or SP 800-56A public-key validation. `Unsupported`: curve not
    /// approved, or a key that is not a FIPS-provider key on the requested
    /// curve. `OpensslFailure`: output too small or a provider failure.
    pub const Error = error{ Unsupported, InvalidPublicKey, OpensslFailure };

    /// Ephemeral or static key pair held inside the FIPS provider. The
    /// private scalar never leaves the provider; there is no export.
    pub const KeyPair = struct {
        pkey: *c.EVP_PKEY,
        pub fn deinit(self: *KeyPair) void {
            c.EVP_PKEY_free(self.pkey);
        }
    };

    /// Validated public-only peer key.
    pub const PublicKey = struct {
        pkey: *c.EVP_PKEY,
        pub fn deinit(self: *PublicKey) void {
            c.EVP_PKEY_free(self.pkey);
        }
    };

    fn groupMatches(curve: policy.EcdhCurve, pkey: *c.EVP_PKEY) bool {
        var name: [32]u8 = undefined;
        var len: usize = 0;
        if (c.EVP_PKEY_get_group_name(pkey, &name, name.len, &len) != 1) return false;
        const got = name[0..len];
        const aliases: []const []const u8 = switch (curve) {
            .p256 => &.{ "P-256", "prime256v1", "secp256r1" },
            .p384 => &.{ "P-384", "secp384r1" },
        };
        for (aliases) |a| if (std.ascii.eqlIgnoreCase(a, got)) return true;
        return false;
    }

    fn checkKey(curve: policy.EcdhCurve, pkey: *c.EVP_PKEY) Error!void {
        if (!policy.isEcdhApproved(curve)) return error.Unsupported;
        if (!provider.ownsKey(pkey) or c.EVP_PKEY_is_a(pkey, "EC") != 1 or !groupMatches(curve, pkey))
            return error.Unsupported;
    }

    /// Generate a key pair on `curve` (the provider runs its pairwise
    /// consistency test on generation).
    pub fn generate(curve: policy.EcdhCurve) Error!KeyPair {
        if (!policy.isEcdhApproved(curve)) return error.Unsupported;
        provider.assertActive();
        const pctx = c.EVP_PKEY_CTX_new_from_name(provider.libCtx(), "EC", "fips=yes") orelse return error.Unsupported;
        defer c.EVP_PKEY_CTX_free(pctx);
        if (c.EVP_PKEY_keygen_init(pctx) != 1) return error.OpensslFailure;
        if (c.EVP_PKEY_CTX_set_group_name(pctx, policy.ecdhGroupName(curve)) != 1) return error.OpensslFailure;
        var pkey: ?*c.EVP_PKEY = null;
        errdefer c.EVP_PKEY_free(pkey);
        if (c.EVP_PKEY_generate(pctx, &pkey) != 1) return error.OpensslFailure;
        const key = pkey orelse return error.OpensslFailure;
        try checkKey(curve, key);
        return .{ .pkey = key };
    }

    /// Write `kp`'s public key as a SEC1 uncompressed point into `out`
    /// (needs `policy.ecdhPublicLen(curve)` bytes); returns the length.
    /// On any error `out` is left unchanged.
    pub fn exportPublic(curve: policy.EcdhCurve, kp: *KeyPair, out: []u8) Error!usize {
        try checkKey(curve, kp.pkey);
        const n = policy.ecdhPublicLen(curve);
        if (out.len < n) return error.OpensslFailure;
        var buf: [policy.ecdh_max_public_len]u8 = undefined;
        var len: usize = 0;
        if (c.EVP_PKEY_get_octet_string_param(kp.pkey, c.OSSL_PKEY_PARAM_PUB_KEY, &buf, buf.len, &len) != 1)
            return error.OpensslFailure;
        if (len != n or buf[0] != 0x04) return error.OpensslFailure;
        @memcpy(out[0..n], buf[0..n]);
        return n;
    }

    /// Import a peer's SEC1 uncompressed point on `curve`. Rejects any other
    /// length or encoding prefix, then runs the provider's SP 800-56A
    /// §5.6.2.3.3 full public-key validation. Never imports private material.
    pub fn importPublic(curve: policy.EcdhCurve, sec1: []const u8) Error!PublicKey {
        if (!policy.isEcdhApproved(curve)) return error.Unsupported;
        if (sec1.len != policy.ecdhPublicLen(curve) or sec1[0] != 0x04) return error.InvalidPublicKey;
        provider.assertActive();
        const ctx = c.EVP_PKEY_CTX_new_from_name(provider.libCtx(), "EC", "fips=yes") orelse return error.Unsupported;
        defer c.EVP_PKEY_CTX_free(ctx);
        if (c.EVP_PKEY_fromdata_init(ctx) != 1) return error.OpensslFailure;
        // fromdata does not modify its inputs; OSSL_PARAM takes mutable
        // pointers because the same representation also carries outputs.
        const group = policy.ecdhGroupName(curve);
        var params = [_]c.OSSL_PARAM{
            c.OSSL_PARAM_construct_utf8_string(c.OSSL_PKEY_PARAM_GROUP_NAME, @constCast(group.ptr), 0),
            c.OSSL_PARAM_construct_octet_string(c.OSSL_PKEY_PARAM_PUB_KEY, @constCast(sec1.ptr), sec1.len),
            c.OSSL_PARAM_construct_end(),
        };
        var pkey: ?*c.EVP_PKEY = null;
        if (c.EVP_PKEY_fromdata(ctx, &pkey, c.EVP_PKEY_PUBLIC_KEY, &params) != 1) {
            c.EVP_PKEY_free(pkey);
            c.ERR_clear_error();
            return error.InvalidPublicKey;
        }
        const key = pkey orelse return error.OpensslFailure;
        errdefer c.EVP_PKEY_free(key);
        try checkKey(curve, key);
        const vctx = c.EVP_PKEY_CTX_new_from_pkey(provider.libCtx(), key, "fips=yes") orelse return error.OpensslFailure;
        defer c.EVP_PKEY_CTX_free(vctx);
        if (c.EVP_PKEY_public_check(vctx) != 1) {
            c.ERR_clear_error();
            return error.InvalidPublicKey;
        }
        return .{ .pkey = key };
    }

    /// Compute the shared secret Z (the x-coordinate of d * Q_peer,
    /// `policy.ecdhSecretLen(curve)` bytes) into `out`; returns its length.
    /// Z is raw key material: feed it to an approved KDF (e.g. `Kdf.hkdf`),
    /// never use it directly as a key. Fails closed (out unchanged) unless
    /// the provider's approved-mode indicator for the exchange is 1.
    pub fn derive(curve: policy.EcdhCurve, kp: *KeyPair, peer: *PublicKey, out: []u8) Error!usize {
        try checkKey(curve, kp.pkey);
        try checkKey(curve, peer.pkey);
        const n = policy.ecdhSecretLen(curve);
        if (out.len < n) return error.OpensslFailure;
        const ctx = c.EVP_PKEY_CTX_new_from_pkey(provider.libCtx(), kp.pkey, "fips=yes") orelse return error.OpensslFailure;
        defer c.EVP_PKEY_CTX_free(ctx);
        if (c.EVP_PKEY_derive_init(ctx) != 1) return error.OpensslFailure;
        // validate_peer = 1: the provider re-validates the peer key too.
        if (c.EVP_PKEY_derive_set_peer_ex(ctx, peer.pkey, 1) != 1) return error.InvalidPublicKey;
        var len: usize = 0;
        if (c.EVP_PKEY_derive(ctx, null, &len) != 1 or len != n) return error.OpensslFailure;
        var z: [policy.ecdh_max_secret_len]u8 = undefined;
        defer util.secureZero(&z);
        if (c.EVP_PKEY_derive(ctx, &z, &len) != 1 or len != n) return error.OpensslFailure;
        if (!approvedIndicator(ctx)) return error.Unsupported;
        @memcpy(out[0..n], z[0..n]);
        return n;
    }

    fn approvedIndicator(ctx: *c.EVP_PKEY_CTX) bool {
        var approved: c_int = 0;
        var params = [_]c.OSSL_PARAM{
            c.OSSL_PARAM_construct_int(c.OSSL_EXCHANGE_PARAM_FIPS_APPROVED_INDICATOR, &approved),
            c.OSSL_PARAM_construct_end(),
        };
        if (c.EVP_PKEY_CTX_get_params(ctx, &params) != 1) return false;
        return c.OSSL_PARAM_modified(&params[0]) == 1 and approved == 1;
    }
};

// ---------------------------------------------------------------------------
// Tests (FIPS backend). Known-answer vectors: src/testdata_pubkey_kat.txt.
// ---------------------------------------------------------------------------

const kat = @import("kat.zig");

/// Test-only: rebuild a KAT key pair (private scalar d + public Q) inside
/// the FIPS provider. Production code has no private-key import.
fn katKeyPair(curve: policy.EcdhCurve, d: []const u8, q: []const u8) !Ecdh.KeyPair {
    provider.assertActive();
    const bld = c.OSSL_PARAM_BLD_new() orelse return error.OutOfMemory;
    defer c.OSSL_PARAM_BLD_free(bld);
    const bn = c.BN_bin2bn(d.ptr, @intCast(d.len), null) orelse return error.OutOfMemory;
    defer c.BN_clear_free(bn);
    try std.testing.expectEqual(@as(c_int, 1), c.OSSL_PARAM_BLD_push_utf8_string(bld, c.OSSL_PKEY_PARAM_GROUP_NAME, policy.ecdhGroupName(curve), 0));
    try std.testing.expectEqual(@as(c_int, 1), c.OSSL_PARAM_BLD_push_BN(bld, c.OSSL_PKEY_PARAM_PRIV_KEY, bn));
    try std.testing.expectEqual(@as(c_int, 1), c.OSSL_PARAM_BLD_push_octet_string(bld, c.OSSL_PKEY_PARAM_PUB_KEY, q.ptr, q.len));
    const params = c.OSSL_PARAM_BLD_to_param(bld) orelse return error.OutOfMemory;
    defer c.OSSL_PARAM_free(params);
    const ctx = c.EVP_PKEY_CTX_new_from_name(provider.libCtx(), "EC", "fips=yes") orelse return error.Unsupported;
    defer c.EVP_PKEY_CTX_free(ctx);
    try std.testing.expectEqual(@as(c_int, 1), c.EVP_PKEY_fromdata_init(ctx));
    var pkey: ?*c.EVP_PKEY = null;
    try std.testing.expectEqual(@as(c_int, 1), c.EVP_PKEY_fromdata(ctx, &pkey, c.EVP_PKEY_KEYPAIR, params));
    return .{ .pkey = pkey.? };
}

test "ENG-7617 ECDH KAT: NIST CAVP KAS_ECC_CDH P-256/P-384 via SEC1 import + derive" {
    var it = kat.records("ecdh_cdh");
    var count: usize = 0;
    var buf: [4][256]u8 = undefined;
    while (it.next()) |r| {
        const curve: policy.EcdhCurve = if (std.mem.eql(u8, r.param, "P-256")) .p256 else .p384;
        const d = try kat.hex(&buf[0], r.field(1));
        const q_own = try kat.hex(&buf[1], r.field(2));
        const q_peer = try kat.hex(&buf[2], r.field(3));
        const z_want = try kat.hex(&buf[3], r.field(4));
        var kp = try katKeyPair(curve, d, q_own);
        defer kp.deinit();
        // exportPublic reproduces the vector's own SEC1 point byte-for-byte.
        var pub_out: [policy.ecdh_max_public_len]u8 = undefined;
        const pn = try Ecdh.exportPublic(curve, &kp, &pub_out);
        try std.testing.expectEqualSlices(u8, q_own, pub_out[0..pn]);
        var peer = try Ecdh.importPublic(curve, q_peer);
        defer peer.deinit();
        var z: [policy.ecdh_max_secret_len]u8 = undefined;
        const zn = try Ecdh.derive(curve, &kp, &peer, &z);
        try std.testing.expectEqualSlices(u8, z_want, z[0..zn]);
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 10), count);
}

test "ENG-7617 ECDH two-party exchange agrees on both curves" {
    inline for (.{ policy.EcdhCurve.p256, policy.EcdhCurve.p384 }) |curve| {
        var a = try Ecdh.generate(curve);
        defer a.deinit();
        var b = try Ecdh.generate(curve);
        defer b.deinit();
        var wa: [policy.ecdh_max_public_len]u8 = undefined;
        var wb: [policy.ecdh_max_public_len]u8 = undefined;
        const na = try Ecdh.exportPublic(curve, &a, &wa);
        const nb = try Ecdh.exportPublic(curve, &b, &wb);
        try std.testing.expectEqual(policy.ecdhPublicLen(curve), na);
        try std.testing.expectEqual(@as(u8, 0x04), wa[0]);
        var pa = try Ecdh.importPublic(curve, wa[0..na]);
        defer pa.deinit();
        var pb = try Ecdh.importPublic(curve, wb[0..nb]);
        defer pb.deinit();
        try std.testing.expect(provider.ownsKey(pa.pkey));
        var za: [policy.ecdh_max_secret_len]u8 = undefined;
        var zb: [policy.ecdh_max_secret_len]u8 = undefined;
        defer util.secureZero(&za);
        defer util.secureZero(&zb);
        const la = try Ecdh.derive(curve, &a, &pb, &za);
        const lb = try Ecdh.derive(curve, &b, &pa, &zb);
        try std.testing.expectEqual(policy.ecdhSecretLen(curve), la);
        try std.testing.expect(util.timingSafeEql(za[0..la], zb[0..lb]));
        // The imported peer key carries no private material.
        var params: [*c]c.OSSL_PARAM = null;
        try std.testing.expectEqual(@as(c_int, 1), c.EVP_PKEY_todata(pa.pkey, c.EVP_PKEY_KEYPAIR, &params));
        defer c.OSSL_PARAM_free(params);
        try std.testing.expect(c.OSSL_PARAM_locate_const(params, c.OSSL_PKEY_PARAM_PRIV_KEY) == null);
    }
}

test "ENG-7617 ECDH import rejects malformed, off-curve and non-uncompressed points" {
    inline for (.{ policy.EcdhCurve.p256, policy.EcdhCurve.p384 }) |curve| {
        const n = comptime policy.ecdhPublicLen(curve);
        const fl = (n - 1) / 2;
        var kp = try Ecdh.generate(curve);
        defer kp.deinit();
        var good: [n]u8 = undefined;
        _ = try Ecdh.exportPublic(curve, &kp, &good);
        var w: [n + 1]u8 = undefined;
        // Length / type checks.
        try std.testing.expectError(error.InvalidPublicKey, Ecdh.importPublic(curve, good[0..0]));
        try std.testing.expectError(error.InvalidPublicKey, Ecdh.importPublic(curve, good[0 .. n - 1]));
        @memcpy(w[0..n], &good);
        w[n] = 0;
        try std.testing.expectError(error.InvalidPublicKey, Ecdh.importPublic(curve, w[0 .. n + 1]));
        // Compressed form of a valid point (0x02/0x03 || X) is refused.
        var comp: [fl + 1]u8 = undefined;
        comp[0] = 0x02 | (good[n - 1] & 1);
        @memcpy(comp[1..], good[1 .. 1 + fl]);
        try std.testing.expectError(error.InvalidPublicKey, Ecdh.importPublic(curve, &comp));
        // Hybrid prefix (0x06/0x07) with the full-length body is refused.
        @memcpy(w[0..n], &good);
        w[0] = 0x06 | (good[n - 1] & 1);
        try std.testing.expectError(error.InvalidPublicKey, Ecdh.importPublic(curve, w[0..n]));
        // Point at infinity: SEC1 single 0x00 octet, and an all-zero body.
        try std.testing.expectError(error.InvalidPublicKey, Ecdh.importPublic(curve, &[_]u8{0x00}));
        @memset(w[0..n], 0);
        w[0] = 0x04;
        try std.testing.expectError(error.InvalidPublicKey, Ecdh.importPublic(curve, w[0..n]));
        // Off-curve: flip one bit of Y.
        @memcpy(w[0..n], &good);
        w[n - 1] ^= 0x01;
        try std.testing.expectError(error.InvalidPublicKey, Ecdh.importPublic(curve, w[0..n]));
        // Coordinate >= p (all-ones X is above every NIST prime).
        @memcpy(w[0..n], &good);
        @memset(w[1 .. 1 + fl], 0xff);
        try std.testing.expectError(error.InvalidPublicKey, Ecdh.importPublic(curve, w[0..n]));
    }
    // A valid P-256 point is the wrong length for P-384 and vice versa.
    var k256 = try Ecdh.generate(.p256);
    defer k256.deinit();
    var p: [65]u8 = undefined;
    _ = try Ecdh.exportPublic(.p256, &k256, &p);
    try std.testing.expectError(error.InvalidPublicKey, Ecdh.importPublic(.p384, &p));
}

test "ENG-7617 ECDH enforces curve binding, provider ownership and output bounds" {
    var a = try Ecdh.generate(.p256);
    defer a.deinit();
    var b = try Ecdh.generate(.p384);
    defer b.deinit();
    var wb: [97]u8 = undefined;
    _ = try Ecdh.exportPublic(.p384, &b, &wb);
    var pb = try Ecdh.importPublic(.p384, &wb);
    defer pb.deinit();
    var out = [_]u8{0xa5} ** 97;
    // Wrong curve for the key pair.
    try std.testing.expectError(error.Unsupported, Ecdh.exportPublic(.p384, &a, &out));
    // Mixed-curve derive.
    try std.testing.expectError(error.Unsupported, Ecdh.derive(.p256, &a, &pb, &out));
    // Undersized outputs leave the buffer untouched.
    try std.testing.expectError(error.OpensslFailure, Ecdh.exportPublic(.p256, &a, out[0..64]));
    var a2 = try Ecdh.generate(.p256);
    defer a2.deinit();
    var w2: [65]u8 = undefined;
    _ = try Ecdh.exportPublic(.p256, &a2, &w2);
    var p2 = try Ecdh.importPublic(.p256, &w2);
    defer p2.deinit();
    try std.testing.expectError(error.OpensslFailure, Ecdh.derive(.p256, &a, &p2, out[0..31]));
    try std.testing.expect(std.mem.allEqual(u8, &out, 0xa5));

    // A key from a separate default-provider context is refused outright.
    const foreign_ctx = c.OSSL_LIB_CTX_new() orelse return error.OutOfMemory;
    defer c.OSSL_LIB_CTX_free(foreign_ctx);
    const default_provider = c.OSSL_PROVIDER_load(foreign_ctx, "default") orelse return error.OpensslFailure;
    defer _ = c.OSSL_PROVIDER_unload(default_provider);
    const gctx = c.EVP_PKEY_CTX_new_from_name(foreign_ctx, "EC", "provider=default") orelse return error.OpensslFailure;
    defer c.EVP_PKEY_CTX_free(gctx);
    try std.testing.expectEqual(@as(c_int, 1), c.EVP_PKEY_keygen_init(gctx));
    try std.testing.expectEqual(@as(c_int, 1), c.EVP_PKEY_CTX_set_group_name(gctx, "P-256"));
    var fkey: ?*c.EVP_PKEY = null;
    try std.testing.expectEqual(@as(c_int, 1), c.EVP_PKEY_generate(gctx, &fkey));
    var foreign: Ecdh.KeyPair = .{ .pkey = fkey.? };
    defer foreign.deinit();
    try std.testing.expectError(error.Unsupported, Ecdh.exportPublic(.p256, &foreign, &out));
    try std.testing.expectError(error.Unsupported, Ecdh.derive(.p256, &foreign, &p2, &out));
    try std.testing.expect(std.mem.allEqual(u8, &out, 0xa5));
}
