// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! fips — FIPS-140-3 / PQC backend over the OpenSSL 3.x FIPS provider.
//! Public surface is filled in by later tasks (policy, Hash, Mac, Kdf,
//! Aead, Sig, Kem, Csprng, assertActive).

pub const version = "0.1.0";

pub const policy = @import("policy.zig");

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

test "package version is set" {
    const std = @import("std");
    try std.testing.expectEqualStrings("0.1.0", version);
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
}
