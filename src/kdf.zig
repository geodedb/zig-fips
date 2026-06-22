// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
const std = @import("std");
const ffi = @import("ffi.zig");
const c = ffi.c;
const policy = @import("policy.zig");
const provider = @import("provider.zig");

pub const Kdf = struct {
    pub const Error = error{OpensslFailure};

    /// RFC 5869 extract-then-expand. `salt` may be empty.
    pub fn hkdf(hash: policy.Hash, ikm: []const u8, salt: []const u8, info: []const u8, out: []u8) Error!void {
        provider.assertActive();
        const kdf = provider.kdfHkdf() orelse return error.OpensslFailure;
        const ctx = c.EVP_KDF_CTX_new(kdf) orelse return error.OpensslFailure;
        defer c.EVP_KDF_CTX_free(ctx);
        var mode: c_int = c.EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
        var params = [_]c.OSSL_PARAM{
            c.OSSL_PARAM_construct_int(c.OSSL_KDF_PARAM_MODE, &mode),
            c.OSSL_PARAM_construct_utf8_string(c.OSSL_KDF_PARAM_DIGEST, @constCast(policy.hashName(hash).ptr), 0),
            c.OSSL_PARAM_construct_octet_string(c.OSSL_KDF_PARAM_KEY, @constCast(ikm.ptr), ikm.len),
            c.OSSL_PARAM_construct_octet_string(c.OSSL_KDF_PARAM_SALT, @constCast(salt.ptr), salt.len),
            c.OSSL_PARAM_construct_octet_string(c.OSSL_KDF_PARAM_INFO, @constCast(info.ptr), info.len),
            c.OSSL_PARAM_construct_end(),
        };
        if (c.EVP_KDF_derive(ctx, out.ptr, out.len, &params) != 1) return error.OpensslFailure;
    }

    /// RFC 5869 §2.3 expand-only. `prk` is a pseudorandom key already
    /// produced by Extract (or imported); `info` is optional context;
    /// `out.len` is the requested OKM length (<= 255*HashLen). Uses
    /// EVP_KDF "HKDF" with OSSL_KDF_PARAM_MODE = "EXPAND_ONLY".
    pub fn hkdfExpand(hash: policy.Hash, prk: []const u8, info: []const u8, out: []u8) Error!void {
        provider.assertActive();
        const kdf = provider.kdfHkdf() orelse return error.OpensslFailure;
        const ctx = c.EVP_KDF_CTX_new(kdf) orelse return error.OpensslFailure;
        defer c.EVP_KDF_CTX_free(ctx);
        var mode: c_int = c.EVP_KDF_HKDF_MODE_EXPAND_ONLY;
        var params = [_]c.OSSL_PARAM{
            c.OSSL_PARAM_construct_int(c.OSSL_KDF_PARAM_MODE, &mode),
            c.OSSL_PARAM_construct_utf8_string(c.OSSL_KDF_PARAM_DIGEST, @constCast(policy.hashName(hash).ptr), 0),
            c.OSSL_PARAM_construct_octet_string(c.OSSL_KDF_PARAM_KEY, @constCast(prk.ptr), prk.len),
            c.OSSL_PARAM_construct_octet_string(c.OSSL_KDF_PARAM_INFO, @constCast(info.ptr), info.len),
            c.OSSL_PARAM_construct_end(),
        };
        if (c.EVP_KDF_derive(ctx, out.ptr, out.len, &params) != 1) return error.OpensslFailure;
    }

    /// SP 800-132 PBKDF2. `iters` is the iteration count.
    /// Enforces SP 800-132 minimums: iters >= 1000, salt.len >= 16 (128 bits).
    /// Returns error.OpensslFailure if either minimum is not met.
    pub fn pbkdf2(hash: policy.Hash, password: []const u8, salt: []const u8, iters: u32, out: []u8) Error!void {
        // SP 800-132: >= 1000 iterations, >= 128-bit salt.
        if (iters < 1000 or salt.len < 16) return error.OpensslFailure;
        return pbkdf2Derive(hash, password, salt, iters, out, false);
    }

    /// PKCS5=1 (relax FIPS lower-bound checks) is used ONLY by the RFC 6070/7914
    /// known-answer tests, which use c=1 / short salts by design.
    fn pbkdf2Derive(hash: policy.Hash, password: []const u8, salt: []const u8, iters: u32, out: []u8, relax: bool) Error!void {
        provider.assertActive();
        const kdf = provider.kdfPbkdf2() orelse return error.OpensslFailure;
        const ctx = c.EVP_KDF_CTX_new(kdf) orelse return error.OpensslFailure;
        defer c.EVP_KDF_CTX_free(ctx);
        var iter: c_int = @intCast(iters);
        var pkcs5: c_int = if (relax) 1 else 0;
        var params = [_]c.OSSL_PARAM{
            c.OSSL_PARAM_construct_octet_string(c.OSSL_KDF_PARAM_PASSWORD, @constCast(password.ptr), password.len),
            c.OSSL_PARAM_construct_octet_string(c.OSSL_KDF_PARAM_SALT, @constCast(salt.ptr), salt.len),
            c.OSSL_PARAM_construct_int(c.OSSL_KDF_PARAM_ITER, &iter),
            c.OSSL_PARAM_construct_utf8_string(c.OSSL_KDF_PARAM_DIGEST, @constCast(policy.hashName(hash).ptr), 0),
            c.OSSL_PARAM_construct_int(c.OSSL_KDF_PARAM_PKCS5, &pkcs5),
            c.OSSL_PARAM_construct_end(),
        };
        if (c.EVP_KDF_derive(ctx, out.ptr, out.len, &params) != 1) return error.OpensslFailure;
    }
};

test "Kdf.hkdf rejects output longer than 255*HashLen" {
    // RFC 5869 §2.3: L <= 255 * HashLen. For SHA-256, max = 255*32 = 8160.
    // Requesting 8161 bytes must cause EVP_KDF_derive to return 0 → error.OpensslFailure.
    const a = std.testing.allocator;
    const too_long = try a.alloc(u8, 255 * 32 + 1);
    defer a.free(too_long);
    try std.testing.expectError(
        error.OpensslFailure,
        Kdf.hkdf(.sha256, "ikm", "salt1234567890ab", "info", too_long),
    );
}

test "KAT HKDF RFC 5869 Test Case 1 (extract+expand)" {
    const ikm = [_]u8{0x0b} ** 22;
    const salt = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
    const info = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };
    var okm: [42]u8 = undefined;
    try Kdf.hkdf(.sha256, &ikm, &salt, &info, &okm);
    const expect = [_]u8{
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    };
    try std.testing.expectEqualSlices(u8, &expect, &okm);
}

test "KAT HKDF-Expand RFC 5869 Test Case 1 (expand-only)" {
    // PRK from RFC 5869 §A.1 (extract output), info = 0xf0..0xf9, L=42.
    const prk = [_]u8{
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
        0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
    };
    const info = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };
    var okm: [42]u8 = undefined;
    try Kdf.hkdfExpand(.sha256, &prk, &info, &okm);
    const expect = [_]u8{
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    };
    try std.testing.expectEqualSlices(u8, &expect, &okm);
}

test "KAT PBKDF2-HMAC-SHA256 RFC 7914 vector (P=passwd, c=1)" {
    // RFC 7914 §11: PBKDF2-HMAC-SHA-256("passwd","salt",1,64).
    // Uses the internal relaxed path (c=1 and salt<16 are below SP 800-132 minimums).
    var out: [64]u8 = undefined;
    try Kdf.pbkdf2Derive(.sha256, "passwd", "salt", 1, &out, true);
    const expect = [_]u8{
        0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f, 0xec, 0x16, 0x91, 0xc2, 0x25, 0x44, 0xb6, 0x05,
        0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde, 0x04, 0x65, 0xe6, 0x8b, 0x9d, 0x57, 0xc2, 0x0d, 0xac, 0xbc,
        0x49, 0xca, 0x9c, 0xcc, 0xf1, 0x79, 0xb6, 0x45, 0x99, 0x16, 0x64, 0xb3, 0x9d, 0x77, 0xef, 0x31,
        0x7c, 0x71, 0xb8, 0x45, 0xb1, 0xe3, 0x0b, 0xd5, 0x09, 0x11, 0x20, 0x41, 0xd3, 0xa1, 0x97, 0x83,
    };
    try std.testing.expectEqualSlices(u8, &expect, &out);
}

test "pbkdf2 rejects sub-FIPS iteration count and short salt" {
    var out: [32]u8 = undefined;
    try std.testing.expectError(error.OpensslFailure, Kdf.pbkdf2(.sha256, "pw", "0123456789abcdef", 999, &out));
    try std.testing.expectError(error.OpensslFailure, Kdf.pbkdf2(.sha256, "pw", "shortsalt", 100_000, &out));
}
