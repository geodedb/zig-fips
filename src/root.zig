// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! fips — FIPS-140-3 / PQC backend over the OpenSSL 3.x FIPS provider.
//! Public surface is filled in by later tasks (policy, Hash, Mac, Kdf,
//! Aead, Sig, Kem, Csprng, assertActive).

pub const version = "0.1.1";

pub const policy = @import("policy.zig");

/// Raw OpenSSL FFI surface. Re-exported so consumers/tests that already
/// import `fips` can reach `c.*` without a SEPARATE `ffi` module root —
/// importing the same `ffi.zig` file under two module roots triggers the
/// Zig 0.16 module-dedup error (GAP-0020). Use `fips.ffi.c`.
pub const ffi = @import("ffi.zig");

const provider = @import("provider.zig");
pub const assertActive = provider.assertActive;
pub const ensureFips = provider.ensureFips;
pub const libCtx = provider.libCtx;

pub const Hash = @import("hash.zig").Hash;
pub const Mac = @import("mac.zig").Mac;
pub const Kdf = @import("kdf.zig").Kdf;
pub const Aead = @import("aead.zig").Aead;
pub const Csprng = @import("csprng.zig").Csprng;
pub const Sig = @import("sig.zig").Sig;
pub const Kem = @import("kem.zig").Kem;
pub const secureZero = @import("util.zig").secureZero;
pub const timingSafeEql = @import("util.zig").timingSafeEql;

test "package version is set" {
    const std = @import("std");
    try std.testing.expectEqualStrings("0.1.1", version);
}

test {
    // Pull in submodule tests (provider self-test, primitive KATs) so
    // they all run under `zig build test`.
    const std = @import("std");
    std.testing.refAllDecls(@This());
    _ = provider;
    _ = @import("policy.zig");
    _ = @import("hash.zig");
    _ = @import("mac.zig");
    _ = @import("kdf.zig");
    _ = @import("aead.zig");
    _ = @import("csprng.zig");
    _ = @import("sig.zig");
    _ = @import("kem.zig");
    _ = @import("util.zig");
}
