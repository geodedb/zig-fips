// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
const std = @import("std");
const ffi = @import("ffi.zig");
const c = ffi.c;
const provider = @import("provider.zig");

pub const Csprng = struct {
    pub const Error = error{OpensslFailure};
    /// SP 800-90A DRBG via the FIPS provider's RAND.
    pub fn bytes(out: []u8) Error!void {
        provider.assertActive();
        if (c.RAND_bytes_ex(provider.libCtx(), out.ptr, out.len, 0) != 1) return error.OpensslFailure;
    }
};

test "csprng yields distinct non-zero draws" {
    var a: [64]u8 = undefined;
    var b: [64]u8 = undefined;
    try Csprng.bytes(&a);
    try Csprng.bytes(&b);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
    try std.testing.expect(!std.mem.allEqual(u8, &a, 0));
}
