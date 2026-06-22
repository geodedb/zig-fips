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

    // Streaming hash routes through the seam and equals one-shot.
    var s = try backend.HashStream.init(.sha256);
    defer s.deinit();
    s.update("a");
    s.update("bc");
    var streamed: [32]u8 = undefined;
    const n = try s.final(&streamed);
    try std.testing.expectEqualSlices(u8, out[0..n], streamed[0..n]);

    // Re-exports resolve as the pinned named types.
    comptime {
        _ = backend.Kem.EncapResult;
        _ = backend.Sig.KeyPair;
        _ = backend.policy.Hash;
        // HashStream alias and the nested type are the same type.
        std.debug.assert(backend.HashStream == backend.Hash.Stream);
    }
    // Parity: secureZero and timingSafeEql are exported from the seam template.
    comptime {
        _ = backend.secureZero;
        _ = backend.timingSafeEql;
    }
}
