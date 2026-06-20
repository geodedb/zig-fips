// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Meta-test for the canonical seam template
//! (templates/crypto_backend.zig). Wired in build.zig with a synthetic
//! `build_options` (fips=false) + the `std_shim` backend, proving the
//! seam selects std_shim and re-exports the full API when fips is off.
const std = @import("std");
const backend = @import("crypto_backend");

test "seam selects std_shim when fips=false and exposes the API" {
    try std.testing.expect(!backend.fips_enabled);
    var out: [32]u8 = undefined;
    _ = try backend.Hash.digest(.sha256, "abc", &out);
    backend.assertActive(); // no-op in the shim
    // Re-exports resolve as the pinned named types.
    comptime {
        _ = backend.Kem.EncapResult;
        _ = backend.Sig.KeyPair;
        _ = backend.policy.Hash;
    }
}
