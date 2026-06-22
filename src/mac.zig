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
        const mac = c.EVP_MAC_fetch(provider.libCtx(), "HMAC", "fips=yes") orelse return error.OpensslFailure;
        defer c.EVP_MAC_free(mac);
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
};

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
