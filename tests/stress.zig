// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Stress tests for fips.
//!
//! Runs via `zig build test-stress`. The crypto wrappers are exercised
//! for correctness by KATs in the unit suite; this file holds a light
//! module-surface stress placeholder so the stress step stays green
//! without requiring an OpenSSL link.

const std = @import("std");
const lib = @import("fips");

test "stress: 50k AES-256-GCM round-trips stay correct" {
    const key = [_]u8{0x5a} ** 32;
    const msg = "stress payload block";
    var i: usize = 0;
    while (i < 50_000) : (i += 1) {
        var iv = [_]u8{0} ** 12;
        std.mem.writeInt(u32, iv[0..4], @intCast(i), .little);
        var ct: [msg.len]u8 = undefined;
        var tag: [16]u8 = undefined;
        try lib.Aead.seal(.aes_256_gcm, &key, &iv, "", msg, &ct, &tag);
        var pt: [msg.len]u8 = undefined;
        try lib.Aead.open(.aes_256_gcm, &key, &iv, "", &ct, &tag, &pt);
        try std.testing.expectEqualSlices(u8, msg, &pt);
    }
}

test "stress: concurrent hashing across threads" {
    const builtin = @import("builtin");
    if (builtin.single_threaded) return error.SkipZigTest;
    const Worker = struct {
        fn run() void {
            var i: usize = 0;
            while (i < 5_000) : (i += 1) {
                var out: [32]u8 = undefined;
                _ = lib.Hash.digest(.sha256, "concurrent", &out) catch unreachable;
            }
        }
    };
    var threads: [8]std.Thread = undefined;
    for (&threads) |*t| t.* = std.Thread.spawn(.{}, Worker.run, .{}) catch unreachable;
    for (&threads) |*t| t.join();
}
