// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Non-primitive seam utilities shared across the fips backend:
//! constant-time-cleanse and constant-time-compare of secret bytes.
//! Mirrored byte-for-byte (behaviorally) by std_shim.zig.
const std = @import("std");
const ffi = @import("ffi.zig");
const c = ffi.c;

/// Best-effort guaranteed memory wipe (OpenSSL OPENSSL_cleanse — not
/// elided by the optimizer). Use on private keys, shared secrets, and
/// derived key material before the buffer goes out of scope or is freed.
pub fn secureZero(buf: []u8) void {
    c.OPENSSL_cleanse(buf.ptr, buf.len);
}

/// Constant-time equality for secret byte slices (MAC/tag/secret
/// confirmation values). Returns false on length mismatch (length is
/// not secret); otherwise the byte comparison is constant-time.
pub fn timingSafeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    return c.CRYPTO_memcmp(a.ptr, b.ptr, a.len) == 0;
}

test "secureZero wipes a sentinel-filled buffer" {
    var buf = [_]u8{0xAB} ** 64;
    secureZero(&buf);
    try std.testing.expect(std.mem.allEqual(u8, &buf, 0));
}

test "timingSafeEql matches on equal, differs on any byte or length" {
    const a = [_]u8{ 1, 2, 3, 4 };
    try std.testing.expect(timingSafeEql(&a, &a));
    const b = [_]u8{ 1, 2, 3, 5 };
    try std.testing.expect(!timingSafeEql(&a, &b));
    try std.testing.expect(!timingSafeEql(&a, a[0..3]));
}
