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

test "integration: hash + hmac + hkdf + aead round-trip through the module surface" {
    var dg: [32]u8 = undefined;
    _ = try lib.Hash.digest(.sha256, "abc", &dg);
    var mac: [32]u8 = undefined;
    _ = try lib.Mac.hmac(.sha256, "key", "abc", &mac);
    var okm: [32]u8 = undefined;
    try lib.Kdf.hkdf(.sha256, "ikm-bytes-0123456789", "salt-bytes-0123456789", "info", &okm);
    const key = [_]u8{7} ** 32;
    const iv = [_]u8{9} ** 12;
    const msg = "integration message";
    var ct: [msg.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    try lib.Aead.seal(.aes_256_gcm, &key, &iv, "ad", msg, &ct, &tag);
    var pt: [msg.len]u8 = undefined;
    try lib.Aead.open(.aes_256_gcm, &key, &iv, "ad", &ct, &tag, &pt);
    try std.testing.expectEqualSlices(u8, msg, &pt);
}

test "integration: ed25519 + ml-kem-768 through the module surface" {
    var kp = try lib.Sig.generate(.ed25519);
    defer kp.deinit();
    var sig: [64]u8 = undefined;
    const n = try lib.Sig.sign(.ed25519, &kp, "m", &sig);
    try lib.Sig.verify(.ed25519, &kp, "m", sig[0..n]);
    var kem = try lib.Kem.generate(.ml_kem_768);
    defer kem.deinit();
    var c2: [2048]u8 = undefined;
    var ssa: [64]u8 = undefined;
    var ssb: [64]u8 = undefined;
    const e = try lib.Kem.encapsulate(.ml_kem_768, &kem, &c2, &ssa);
    const d = try lib.Kem.decapsulate(.ml_kem_768, &kem, c2[0..e.ct_len], &ssb);
    try std.testing.expect(lib.timingSafeEql(ssa[0..e.ss_len], ssb[0..d]));
}
