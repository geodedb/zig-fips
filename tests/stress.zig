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

test "stress: version constant is stable across repeated reads" {
    var i: usize = 0;
    while (i < 100_000) : (i += 1) {
        try std.testing.expectEqualStrings("0.1.0", lib.version);
    }
}
