// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
const std = @import("std");
const ffi = @import("ffi.zig");
const c = ffi.c;
const policy = @import("policy.zig");
const provider = @import("provider.zig");

pub const Hash = struct {
    pub const Error = error{ Unsupported, OpensslFailure };

    /// One-shot digest. Returns bytes written into `out`.
    pub fn digest(alg: policy.Hash, msg: []const u8, out: []u8) Error!usize {
        provider.assertActive();
        const md = c.EVP_MD_fetch(provider.libCtx(), policy.hashName(alg), "fips=yes") orelse return error.Unsupported;
        defer c.EVP_MD_free(md);
        const ctx = c.EVP_MD_CTX_new() orelse return error.OpensslFailure;
        defer c.EVP_MD_CTX_free(ctx);
        if (c.EVP_DigestInit_ex2(ctx, md, null) != 1) return error.OpensslFailure;
        if (c.EVP_DigestUpdate(ctx, msg.ptr, msg.len) != 1) return error.OpensslFailure;
        var n: c_uint = 0;
        if (c.EVP_DigestFinal_ex(ctx, out.ptr, &n) != 1) return error.OpensslFailure;
        return n;
    }
};

test "KAT SHA2-256(\"abc\") == ba7816bf..." {
    var out: [32]u8 = undefined;
    const n = try Hash.digest(.sha256, "abc", &out);
    try std.testing.expectEqual(@as(usize, 32), n);
    const expect = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    try std.testing.expectEqualSlices(u8, &expect, &out);
}
test "KAT SHA3-256(\"abc\")" {
    var out: [32]u8 = undefined;
    _ = try Hash.digest(.sha3_256, "abc", &out);
    const expect = [_]u8{
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
        0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
    };
    try std.testing.expectEqualSlices(u8, &expect, &out);
}
