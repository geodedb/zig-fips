// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Default benchmark suite for fips.
//!
//! This file is invoked by `zig build bench`. Every scenario exercises the
//! real public library surface through the FIPS provider. The framework
//! handles iteration count, warmup, statistics, allocation tracking, and JSON
//! output.
//!
//! CLI:
//!   zig build bench -Dopenssl_path=/usr/local/ssl              # run default suite
//!   zig build bench -Dopenssl_path=/usr/local/ssl -- --output bench.json
//!   zig build bench -Dopenssl_path=/usr/local/ssl -- --filter sha256
//!   zig build bench -Dopenssl_path=/usr/local/ssl -- --list

const std = @import("std");
const Io = std.Io;
const lib = @import("fips");
const framework = @import("framework");

// ----------------------------------------------------------------------------
// Fixed inputs (compile-time constants — no heap needed for plaintexts/keys).
// These are declared at file scope so all scenario bodies can share them.
// ----------------------------------------------------------------------------

const aes_key = [_]u8{0x2b} ** 32; // 32-byte AES-256 key
const aes_nonce = [_]u8{0x9d} ** 12; // 12-byte GCM nonce
const msg_64: [64]u8 = [_]u8{0xab} ** 64;
const msg_8k: [8 * 1024]u8 = [_]u8{0xcd} ** (8 * 1024);
const msg_1350: [1350]u8 = [_]u8{0xef} ** 1350; // ≈ TLS record
const hmac_key = [_]u8{0x5a} ** 32;
const hkdf_ikm = [_]u8{0x11} ** 32;
const hkdf_salt = [_]u8{0x22} ** 32;

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(init.gpa);
    defer arena.deinit();
    const allocator = arena.allocator();

    var stderr_buf: [4096]u8 = undefined;
    var stderr_writer = Io.File.stderr().writer(init.io, &stderr_buf);
    const stderr = &stderr_writer.interface;

    const scenarios = [_]framework.Scenario{
        // ---- Hash -------------------------------------------------------
        .{
            .name = "sha256_64B",
            .ops_per_iteration = 1_000,
            .run = benchSha256_64B,
        },
        .{
            .name = "sha256_8KB",
            .ops_per_iteration = 500,
            .run = benchSha256_8KB,
        },
        // ---- MAC --------------------------------------------------------
        .{
            .name = "hmac_sha256_64B",
            .ops_per_iteration = 1_000,
            .run = benchHmacSha256_64B,
        },
        // ---- KDF --------------------------------------------------------
        .{
            .name = "hkdf_sha256_32B",
            .ops_per_iteration = 500,
            .run = benchHkdfSha256_32B,
        },
        // ---- AEAD -------------------------------------------------------
        .{
            .name = "aes256gcm_seal_64B",
            .ops_per_iteration = 1_000,
            .run = benchAesSeal64B,
        },
        .{
            .name = "aes256gcm_seal_1350B",
            .ops_per_iteration = 1_000,
            .run = benchAesSeal1350B,
        },
        .{
            .name = "aes256gcm_open_1350B",
            .ops_per_iteration = 1_000,
            .run = benchAesOpen1350B,
        },
        // ---- Sig --------------------------------------------------------
        .{
            .name = "ed25519_sign",
            .ops_per_iteration = 100,
            .run = benchEd25519Sign,
        },
        .{
            .name = "ed25519_verify",
            .ops_per_iteration = 100,
            .run = benchEd25519Verify,
        },
        .{
            .name = "ecdsa_p256_sign",
            .ops_per_iteration = 100,
            .run = benchEcdsaP256Sign,
        },
        // ---- KEM --------------------------------------------------------
        .{
            .name = "mlkem768_encap",
            .ops_per_iteration = 50,
            .run = benchMlkem768Encap,
        },
        .{
            .name = "mlkem768_decap",
            .ops_per_iteration = 50,
            .run = benchMlkem768Decap,
        },
        // ---- CSPRNG -----------------------------------------------------
        .{
            .name = "csprng_32B",
            .ops_per_iteration = 1_000,
            .run = benchCsprng32B,
        },
    };

    switch (try framework.parseArgs(allocator, init.minimal.args)) {
        .help_only => try framework.printHelp(stderr, "bench"),
        .list_only => try framework.printScenarios(stderr, &scenarios),
        .run => |opts| try framework.runScenarios(allocator, init.io, &scenarios, opts),
    }
}

// ----------------------------------------------------------------------------
// Scenario bodies
// ----------------------------------------------------------------------------

fn benchSha256_64B(ctx: *framework.Context) anyerror!void {
    var out: [32]u8 = undefined;
    var i: u64 = 0;
    while (i < ctx.scenario.ops_per_iteration) : (i += 1) {
        const n = try lib.Hash.digest(.sha256, &msg_64, &out);
        std.mem.doNotOptimizeAway(out[0..n]);
    }
}

fn benchSha256_8KB(ctx: *framework.Context) anyerror!void {
    var out: [32]u8 = undefined;
    var i: u64 = 0;
    while (i < ctx.scenario.ops_per_iteration) : (i += 1) {
        const n = try lib.Hash.digest(.sha256, &msg_8k, &out);
        std.mem.doNotOptimizeAway(out[0..n]);
    }
}

fn benchHmacSha256_64B(ctx: *framework.Context) anyerror!void {
    var out: [32]u8 = undefined;
    var i: u64 = 0;
    while (i < ctx.scenario.ops_per_iteration) : (i += 1) {
        const n = try lib.Mac.hmac(.sha256, &hmac_key, &msg_64, &out);
        std.mem.doNotOptimizeAway(out[0..n]);
    }
}

fn benchHkdfSha256_32B(ctx: *framework.Context) anyerror!void {
    var out: [32]u8 = undefined;
    var i: u64 = 0;
    while (i < ctx.scenario.ops_per_iteration) : (i += 1) {
        try lib.Kdf.hkdf(.sha256, &hkdf_ikm, &hkdf_salt, "bench-info", &out);
        std.mem.doNotOptimizeAway(&out);
    }
}

fn benchAesSeal64B(ctx: *framework.Context) anyerror!void {
    var ct: [64]u8 = undefined;
    var tag: [16]u8 = undefined;
    var i: u64 = 0;
    while (i < ctx.scenario.ops_per_iteration) : (i += 1) {
        try lib.Aead.seal(.aes_256_gcm, &aes_key, &aes_nonce, "", &msg_64, &ct, &tag);
        std.mem.doNotOptimizeAway(&ct);
        std.mem.doNotOptimizeAway(&tag);
    }
}

fn benchAesSeal1350B(ctx: *framework.Context) anyerror!void {
    var ct: [1350]u8 = undefined;
    var tag: [16]u8 = undefined;
    var i: u64 = 0;
    while (i < ctx.scenario.ops_per_iteration) : (i += 1) {
        try lib.Aead.seal(.aes_256_gcm, &aes_key, &aes_nonce, "", &msg_1350, &ct, &tag);
        std.mem.doNotOptimizeAway(&ct);
        std.mem.doNotOptimizeAway(&tag);
    }
}

fn benchAesOpen1350B(ctx: *framework.Context) anyerror!void {
    // Precompute the ciphertext and tag once per run (outside the timed loop).
    var ct: [1350]u8 = undefined;
    var tag: [16]u8 = undefined;
    try lib.Aead.seal(.aes_256_gcm, &aes_key, &aes_nonce, "", &msg_1350, &ct, &tag);

    var pt: [1350]u8 = undefined;
    var i: u64 = 0;
    while (i < ctx.scenario.ops_per_iteration) : (i += 1) {
        try lib.Aead.open(.aes_256_gcm, &aes_key, &aes_nonce, "", &ct, &tag, &pt);
        std.mem.doNotOptimizeAway(&pt);
    }
}

fn benchEd25519Sign(ctx: *framework.Context) anyerror!void {
    // Generate keypair once per run call; sign in the hot loop.
    var kp = try lib.Sig.generate(.ed25519);
    defer kp.deinit();
    var sig: [64]u8 = undefined;
    const msg = "bench-message-ed25519";
    var i: u64 = 0;
    while (i < ctx.scenario.ops_per_iteration) : (i += 1) {
        const n = try lib.Sig.sign(.ed25519, &kp, msg, &sig);
        std.mem.doNotOptimizeAway(sig[0..n]);
    }
}

fn benchEd25519Verify(ctx: *framework.Context) anyerror!void {
    // Precompute keypair and a valid signature outside the hot loop.
    var kp = try lib.Sig.generate(.ed25519);
    defer kp.deinit();
    const msg = "bench-message-ed25519";
    var sig: [64]u8 = undefined;
    const n = try lib.Sig.sign(.ed25519, &kp, msg, &sig);
    var i: u64 = 0;
    while (i < ctx.scenario.ops_per_iteration) : (i += 1) {
        try lib.Sig.verify(.ed25519, &kp, msg, sig[0..n]);
        std.mem.doNotOptimizeAway(&kp);
    }
}

fn benchEcdsaP256Sign(ctx: *framework.Context) anyerror!void {
    // Generate keypair once; sign in the hot loop.
    var kp = try lib.Sig.generate(.ecdsa_p256);
    defer kp.deinit();
    var sig: [72]u8 = undefined; // DER-encoded ECDSA sig: max ~72 bytes for P-256
    const msg = "bench-message-p256";
    var i: u64 = 0;
    while (i < ctx.scenario.ops_per_iteration) : (i += 1) {
        const n = try lib.Sig.sign(.ecdsa_p256, &kp, msg, &sig);
        std.mem.doNotOptimizeAway(sig[0..n]);
    }
}

fn benchMlkem768Encap(ctx: *framework.Context) anyerror!void {
    // Generate keypair once per run call; encapsulate in the hot loop.
    var kp = try lib.Kem.generate(.ml_kem_768);
    defer kp.deinit();
    // ML-KEM-768 ciphertext ≈ 1088 bytes, shared secret = 32 bytes.
    var ct: [2048]u8 = undefined;
    var ss: [64]u8 = undefined;
    defer lib.secureZero(&ss);
    var i: u64 = 0;
    while (i < ctx.scenario.ops_per_iteration) : (i += 1) {
        const e = try lib.Kem.encapsulate(.ml_kem_768, &kp, &ct, &ss);
        std.mem.doNotOptimizeAway(ct[0..e.ct_len]);
        std.mem.doNotOptimizeAway(ss[0..e.ss_len]);
    }
}

fn benchMlkem768Decap(ctx: *framework.Context) anyerror!void {
    // Precompute keypair and a ciphertext outside the hot loop.
    var kp = try lib.Kem.generate(.ml_kem_768);
    defer kp.deinit();
    var ct: [2048]u8 = undefined;
    var ss_enc: [64]u8 = undefined;
    defer lib.secureZero(&ss_enc);
    const e = try lib.Kem.encapsulate(.ml_kem_768, &kp, &ct, &ss_enc);

    var ss_dec: [64]u8 = undefined;
    defer lib.secureZero(&ss_dec);
    var i: u64 = 0;
    while (i < ctx.scenario.ops_per_iteration) : (i += 1) {
        const d = try lib.Kem.decapsulate(.ml_kem_768, &kp, ct[0..e.ct_len], &ss_dec);
        std.mem.doNotOptimizeAway(ss_dec[0..d]);
    }
}

fn benchCsprng32B(ctx: *framework.Context) anyerror!void {
    var out: [32]u8 = undefined;
    var i: u64 = 0;
    while (i < ctx.scenario.ops_per_iteration) : (i += 1) {
        try lib.Csprng.bytes(&out);
        std.mem.doNotOptimizeAway(&out);
    }
}
