// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Integration tests for fips.
//!
//! These tests run via `zig build test-integration`. PQC sign/KEM
//! interop test artifacts are wired as their own roots in build.zig
//! (tests/pqc_sig_interop.zig, tests/pqc_kem_interop.zig); this file
//! holds module-surface integration checks.

const std = @import("std");
const lib = @import("fips");

test "integration: version is defined" {
    try std.testing.expectEqualStrings("0.1.0", lib.version);
}
