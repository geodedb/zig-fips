// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! PQC signature interop (standalone executable, run by
//! `zig build test-integration`): sign an ML-DSA-65 message in Zig (via
//! the fips backend), export the DER public key, and verify the
//! signature with the OpenSSL FIPS CLI (`pkeyutl -verify -rawin`).
//! Probes the CLI version first and SKIPs (exit 0) when OpenSSL < 3.5.
//!
//! Run as an executable (not a `zig test`) because std.process.run and
//! the Io.Dir filesystem API in Zig 0.16 need the `Io` that
//! std.process.Init provides to `main`.

const std = @import("std");
const fips = @import("fips");
const c = fips.ffi.c;
const Dir = std.Io.Dir;

const InteropError = error{ CliVerifyFailed, TamperNotRejected, MissingPubKey };

fn cliHasPqc(gpa: std.mem.Allocator, io: std.Io, ossl: []const u8) bool {
    const r = std.process.run(gpa, io, .{ .argv = &.{ ossl, "version" } }) catch return false;
    defer gpa.free(r.stdout);
    defer gpa.free(r.stderr);
    const v = r.stdout;
    return std.mem.indexOf(u8, v, "OpenSSL 3.5") != null or
        std.mem.indexOf(u8, v, "OpenSSL 3.6") != null or
        std.mem.indexOf(u8, v, "OpenSSL 3.7") != null or
        std.mem.indexOf(u8, v, "OpenSSL 3.8") != null or
        std.mem.indexOf(u8, v, "OpenSSL 3.9") != null or
        std.mem.indexOf(u8, v, "OpenSSL 3.1") != null;
}

fn termOk(term: std.process.Child.Term) bool {
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const env = init.environ_map;

    const prefix = env.get("OPENSSL_PREFIX") orelse "/usr/local/ssl";
    const ossl = try std.fmt.allocPrint(gpa, "{s}/bin/openssl", .{prefix});
    defer gpa.free(ossl);

    if (!cliHasPqc(gpa, io, ossl)) {
        std.debug.print("SKIP: OpenSSL >= 3.5 required for PQC sig interop\n", .{});
        return;
    }

    const conf = try std.fmt.allocPrint(gpa, "{s}/ssl/openssl.cnf", .{prefix});
    defer gpa.free(conf);
    try env.put("OPENSSL_CONF", conf);

    // Unique temp dir under /tmp.
    const tdir = try std.fmt.allocPrint(gpa, "/tmp/fips-pqc-sig-{d}", .{std.os.linux.getpid()});
    defer gpa.free(tdir);
    const cwd = Dir.cwd();
    cwd.deleteTree(io, tdir) catch {};
    try cwd.createDirPath(io, tdir);
    defer cwd.deleteTree(io, tdir) catch {};
    var d = try cwd.openDir(io, tdir, .{});
    defer d.close(io);

    // 1. Generate + sign in Zig.
    var kp = try fips.Sig.generate(.ml_dsa_65);
    defer kp.deinit();
    const msg = "interop ml-dsa-65 message";
    var sig: [8192]u8 = undefined;
    const n = try fips.Sig.sign(.ml_dsa_65, &kp, msg, &sig);

    // 2. Export DER public key.
    var der: [4096]u8 = undefined;
    var p: [*c]u8 = &der;
    const der_len = c.i2d_PUBKEY(kp.pkey, &p);
    if (der_len <= 0) return InteropError.MissingPubKey;

    // 3. Write artifacts.
    try d.writeFile(io, .{ .sub_path = "msg.bin", .data = msg });
    try d.writeFile(io, .{ .sub_path = "sig.bin", .data = sig[0..n] });
    try d.writeFile(io, .{ .sub_path = "pub.der", .data = der[0..@intCast(der_len)] });
    var bad = try gpa.dupe(u8, sig[0..n]);
    defer gpa.free(bad);
    bad[0] ^= 0x01;
    try d.writeFile(io, .{ .sub_path = "sig_bad.bin", .data = bad });

    const msg_p = try std.fmt.allocPrint(gpa, "{s}/msg.bin", .{tdir});
    defer gpa.free(msg_p);
    const sig_p = try std.fmt.allocPrint(gpa, "{s}/sig.bin", .{tdir});
    defer gpa.free(sig_p);
    const bad_p = try std.fmt.allocPrint(gpa, "{s}/sig_bad.bin", .{tdir});
    defer gpa.free(bad_p);
    const pub_p = try std.fmt.allocPrint(gpa, "{s}/pub.der", .{tdir});
    defer gpa.free(pub_p);

    // 4. CLI verify: exit 0 == valid.
    {
        const r = try std.process.run(gpa, io, .{
            .environ_map = env,
            .argv = &.{
                ossl,     "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
                "-inkey", pub_p,     "-rawin",  "-in",    msg_p,      "-sigfile",
                sig_p,
            },
        });
        defer gpa.free(r.stdout);
        defer gpa.free(r.stderr);
        if (!termOk(r.term)) {
            std.debug.print("verify FAILED stdout={s} stderr={s}\n", .{ r.stdout, r.stderr });
            return InteropError.CliVerifyFailed;
        }
    }

    // 5. Tamper: must reject (non-zero exit).
    {
        const r = try std.process.run(gpa, io, .{
            .environ_map = env,
            .argv = &.{
                ossl,     "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
                "-inkey", pub_p,     "-rawin",  "-in",    msg_p,      "-sigfile",
                bad_p,
            },
        });
        defer gpa.free(r.stdout);
        defer gpa.free(r.stderr);
        if (termOk(r.term)) return InteropError.TamperNotRejected;
    }

    std.debug.print("OK: ML-DSA-65 Zig-sign / OpenSSL-CLI-verify interop passed\n", .{});
}
