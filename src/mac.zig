// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
const std = @import("std");
const ffi = @import("ffi.zig");
const c = ffi.c;
const policy = @import("policy.zig");
const provider = @import("provider.zig");

pub const Mac = struct {
    pub const Error = error{OpensslFailure};

    /// HMAC over `msg` keyed by `key`, using the digest selected by
    /// `alg`. Returns bytes written into `out`.
    pub fn hmac(alg: policy.Hash, key: []const u8, msg: []const u8, out: []u8) Error!usize {
        provider.assertActive();
        const mac = provider.hmacMac() orelse return error.OpensslFailure;
        const ctx = c.EVP_MAC_CTX_new(mac) orelse return error.OpensslFailure;
        defer c.EVP_MAC_CTX_free(ctx);

        var params = [_]c.OSSL_PARAM{
            c.OSSL_PARAM_construct_utf8_string(
                c.OSSL_MAC_PARAM_DIGEST,
                @constCast(policy.hashName(alg).ptr),
                0,
            ),
            c.OSSL_PARAM_construct_end(),
        };
        if (c.EVP_MAC_init(ctx, key.ptr, key.len, &params) != 1) return error.OpensslFailure;
        if (c.EVP_MAC_update(ctx, msg.ptr, msg.len) != 1) return error.OpensslFailure;
        var n: usize = 0;
        if (c.EVP_MAC_final(ctx, out.ptr, &n, out.len) != 1) return error.OpensslFailure;
        return n;
    }

    /// HMAC-SHA1 for RFC 6238 TOTP / RFC 4226 HOTP consumers.
    ///
    /// SHA-1 is barred from the `policy.Hash` enum (bare SHA-1 is not an
    /// approved digest for new hashing or signing), but HMAC-SHA1 IS
    /// approved inside the OpenSSL FIPS module as a MAC (SP 800-131A Rev 2
    /// Table 7; FIPS 198-1). This dedicated function is the ONLY approved
    /// path to SHA-1 inside the seam — do NOT add `sha1` to policy.Hash.
    ///
    /// `out` must be ≥ 20 bytes. Writes exactly 20 bytes; returns 20.
    pub fn hmacSha1(key: []const u8, msg: []const u8, out: []u8) Error!usize {
        // EVP-fetch name for SHA-1 inside the OpenSSL FIPS provider.
        // Intentionally NOT exported from policy.zig / the Hash enum; it
        // lives here so only this approved MAC path can reach it.
        const sha1_evp_name: [:0]const u8 = "SHA-1";
        const hmac_out_len: usize = 20;

        if (out.len < hmac_out_len) return error.OpensslFailure;

        provider.assertActive();
        const mac = provider.hmacMac() orelse return error.OpensslFailure;
        const ctx = c.EVP_MAC_CTX_new(mac) orelse return error.OpensslFailure;
        defer c.EVP_MAC_CTX_free(ctx);

        var params = [_]c.OSSL_PARAM{
            c.OSSL_PARAM_construct_utf8_string(
                c.OSSL_MAC_PARAM_DIGEST,
                @constCast(sha1_evp_name.ptr),
                0,
            ),
            c.OSSL_PARAM_construct_end(),
        };
        if (c.EVP_MAC_init(ctx, key.ptr, key.len, &params) != 1) return error.OpensslFailure;
        if (c.EVP_MAC_update(ctx, msg.ptr, msg.len) != 1) return error.OpensslFailure;
        var n: usize = 0;
        if (c.EVP_MAC_final(ctx, out.ptr, &n, out.len) != 1) return error.OpensslFailure;
        return n;
    }
};

test "KAT HMAC-SHA1 RFC 2202 Test Case 2 (key=Jefe)" {
    var out: [20]u8 = undefined;
    const n = try Mac.hmacSha1("Jefe", "what do ya want for nothing?", &out);
    try std.testing.expectEqual(@as(usize, 20), n);
    const expect = [_]u8{
        0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74,
        0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79,
    };
    try std.testing.expectEqualSlices(u8, &expect, &out);
}

test "Mac.hmacSha1 rejects undersized output buffer" {
    var tiny: [19]u8 = undefined;
    try std.testing.expectError(error.OpensslFailure, Mac.hmacSha1("key", "msg", &tiny));
}

test "Mac.hmac rejects undersized output buffer" {
    // EVP_MAC_final takes out.len as capacity; if the buffer is smaller than
    // the HMAC length it returns 0 → error.OpensslFailure.
    var tiny: [16]u8 = undefined;
    try std.testing.expectError(error.OpensslFailure, Mac.hmac(.sha256, "key", "msg", &tiny));
}

test "KAT HMAC-SHA256 RFC 4231 Test Case 2 (key=Jefe)" {
    var out: [32]u8 = undefined;
    const n = try Mac.hmac(.sha256, "Jefe", "what do ya want for nothing?", &out);
    try std.testing.expectEqual(@as(usize, 32), n);
    const expect = [_]u8{
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };
    try std.testing.expectEqualSlices(u8, &expect, &out);
}
