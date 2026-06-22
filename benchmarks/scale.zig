// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Scale benchmark suite for fips.
//!
//! These scenarios run for longer than the default `bench` suite —
//! useful for ad-hoc grid sweeps or scheduled CI runs. Wired via
//! `zig build scale-bench` and gated to schedule/manual in the default
//! `.gitlab-ci.yml`.

const std = @import("std");
const Io = std.Io;
const lib = @import("fips");
const framework = @import("framework");

const aes_key = [_]u8{0x2b} ** 32;
const aes_nonce = [_]u8{0x9d} ** 12;
const msg_8k: [8 * 1024]u8 = [_]u8{0xcd} ** (8 * 1024);

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(init.gpa);
    defer arena.deinit();
    const allocator = arena.allocator();

    var stderr_buf: [4096]u8 = undefined;
    var stderr_writer = Io.File.stderr().writer(init.io, &stderr_buf);
    const stderr = &stderr_writer.interface;

    const scenarios = [_]framework.Scenario{
        .{
            .name = "sha256_8KB_x1m",
            .ops_per_iteration = 1_000_000,
            .warmup_iterations = 1,
            .sample_iterations = 5,
            .run = runSha256_8KB,
        },
        .{
            .name = "aes256gcm_seal_8KB_x500k",
            .ops_per_iteration = 500_000,
            .warmup_iterations = 1,
            .sample_iterations = 5,
            .run = runAesSeal8KB,
        },
    };

    switch (try framework.parseArgs(allocator, init.minimal.args)) {
        .help_only => try framework.printHelp(stderr, "scale-bench"),
        .list_only => try framework.printScenarios(stderr, &scenarios),
        .run => |opts| try framework.runScenarios(allocator, init.io, &scenarios, opts),
    }
}

fn runSha256_8KB(ctx: *framework.Context) anyerror!void {
    var out: [32]u8 = undefined;
    var i: u64 = 0;
    while (i < ctx.scenario.ops_per_iteration) : (i += 1) {
        const n = try lib.Hash.digest(.sha256, &msg_8k, &out);
        std.mem.doNotOptimizeAway(out[0..n]);
    }
}

fn runAesSeal8KB(ctx: *framework.Context) anyerror!void {
    var ct: [8 * 1024]u8 = undefined;
    var tag: [16]u8 = undefined;
    var i: u64 = 0;
    while (i < ctx.scenario.ops_per_iteration) : (i += 1) {
        try lib.Aead.seal(.aes_256_gcm, &aes_key, &aes_nonce, "", &msg_8k, &ct, &tag);
        std.mem.doNotOptimizeAway(&ct);
        std.mem.doNotOptimizeAway(&tag);
    }
}
