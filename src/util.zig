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

test "secureZero wipes a sentinel-filled buffer" {
    var buf = [_]u8{0xAB} ** 64;
    secureZero(&buf);
    try std.testing.expect(std.mem.allEqual(u8, &buf, 0));
}
