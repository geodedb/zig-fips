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
    try s.update("a");
    try s.update("bc");
    var streamed: [32]u8 = undefined;
    const n = try s.final(&streamed);
    try std.testing.expectEqualSlices(u8, out[0..n], streamed[0..n]);

    // Re-exports resolve as the pinned named types.
    comptime {
        _ = backend.Kem.EncapResult;
        _ = backend.Sig.KeyPair;
        _ = backend.policy.Hash;
        // The whole-Sig re-export reaches the raw-EC import constructors
        // (geode routes ECDSA signing through these under -Dfips).
        std.debug.assert(@hasDecl(backend.Sig.KeyPair, "fromEcPublicPoint"));
        std.debug.assert(@hasDecl(backend.Sig.KeyPair, "fromEcPrivateScalar"));
        // HashStream alias and the nested type are the same type.
        std.debug.assert(backend.HashStream == backend.Hash.Stream);
    }

    // The raw-EC import constructors are callable THROUGH the seam: derive
    // a P-256 std keypair, import scalar + point via the seam, sign, verify.
    {
        const S = std.crypto.sign.ecdsa.EcdsaP256Sha256;
        var seed: [S.KeyPair.seed_length]u8 = undefined;
        try backend.Csprng.bytes(&seed);
        const ref = try S.KeyPair.generateDeterministic(seed);
        var priv_kp = try backend.Sig.KeyPair.fromEcPrivateScalar(.ecdsa_p256, &ref.secret_key.toBytes());
        defer priv_kp.deinit();
        var pub_kp = try backend.Sig.KeyPair.fromEcPublicPoint(.ecdsa_p256, &ref.public_key.toCompressedSec1());
        defer pub_kp.deinit();
        var sig: [80]u8 = undefined;
        const sn = try backend.Sig.sign(.ecdsa_p256, &priv_kp, "seam raw-ec", &sig);
        try backend.Sig.verify(.ecdsa_p256, &pub_kp, "seam raw-ec", sig[0..sn]);
    }
    // Parity: secureZero, timingSafeEql, ensureFips are exported from the seam template.
    comptime {
        _ = backend.secureZero;
        _ = backend.timingSafeEql;
        std.debug.assert(@hasDecl(backend, "ensureFips"));
    }
}
