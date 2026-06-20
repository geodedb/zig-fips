// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! fips — FIPS-140-3 / PQC backend over the OpenSSL 3.x FIPS provider.
//! Public surface is filled in by later tasks (policy, Hash, Mac, Kdf,
//! Aead, Sig, Kem, Csprng, assertActive).

pub const version = "0.1.0";

test "package version is set" {
    const std = @import("std");
    try std.testing.expectEqualStrings("0.1.0", version);
}
