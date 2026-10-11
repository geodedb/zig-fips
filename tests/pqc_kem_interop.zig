// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! PQC KEM interop (standalone executable, run by
//! `zig build test-integration`): the OpenSSL FIPS CLI and the Zig fips
//! backend exchange ML-KEM-768 ciphertexts/secrets across the boundary
//! in BOTH directions and assert the shared secrets match. Probes the
//! CLI version first and SKIPs (exit 0) when OpenSSL < 3.5.

const std = @import("std");
const fips = @import("fips");
const c = fips.ffi.c;
const Dir = std.Io.Dir;

const InteropError = error{ CliFailed, SecretMismatch, ImportFailed };

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

fn runCli(gpa: std.mem.Allocator, io: std.Io, env: *std.process.Environ.Map, argv: []const []const u8) !void {
    const r = try std.process.run(gpa, io, .{ .environ_map = env, .argv = argv });
    defer gpa.free(r.stdout);
    defer gpa.free(r.stderr);
    if (!termOk(r.term)) {
        std.debug.print("CLI failed: {s}\nstderr={s}\n", .{ argv[1], r.stderr });
        return InteropError.CliFailed;
    }
}

/// Import a PEM key (public or private) into an EVP_PKEY via the FIPS
/// provider's OSSL_DECODER, selecting ML-KEM-768.
fn importPem(pem: []const u8, selection: c_int) !*c.EVP_PKEY {
    // libCtx() creates the context but does not initialize its provider.
    // Initialize before decoding so the key belongs to the active FIPS
    // provider rather than an implicitly loaded default provider.
    fips.assertActive();
    var pkey: ?*c.EVP_PKEY = null;
    const dctx = c.OSSL_DECODER_CTX_new_for_pkey(
        &pkey,
        "PEM",
        null,
        "ML-KEM-768",
        selection,
        fips.libCtx(),
        "fips=yes",
    ) orelse return InteropError.ImportFailed;
    defer c.OSSL_DECODER_CTX_free(dctx);
    var ptr: [*c]const u8 = pem.ptr;
    var len: usize = pem.len;
    if (c.OSSL_DECODER_from_data(dctx, &ptr, &len) != 1) return InteropError.ImportFailed;
    return pkey orelse InteropError.ImportFailed;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const env = init.environ_map;

    const prefix = env.get("OPENSSL_PREFIX") orelse "/usr/local/ssl";
    const ossl = try std.fmt.allocPrint(gpa, "{s}/bin/openssl", .{prefix});
    defer gpa.free(ossl);

    if (!cliHasPqc(gpa, io, ossl)) {
        std.debug.print("SKIP: OpenSSL >= 3.5 required for ML-KEM interop\n", .{});
        return;
    }

    const conf = try std.fmt.allocPrint(gpa, "{s}/ssl/openssl.cnf", .{prefix});
    defer gpa.free(conf);
    try env.put("OPENSSL_CONF", conf);

    const tdir = try std.fmt.allocPrint(gpa, "/tmp/fips-pqc-kem-{d}", .{std.os.linux.getpid()});
    defer gpa.free(tdir);
    const cwd = Dir.cwd();
    cwd.deleteTree(io, tdir) catch {};
    try cwd.createDirPath(io, tdir);
    defer cwd.deleteTree(io, tdir) catch {};
    var d = try cwd.openDir(io, tdir, .{});
    defer d.close(io);

    const priv_pem = try std.fmt.allocPrint(gpa, "{s}/kem_priv.pem", .{tdir});
    defer gpa.free(priv_pem);
    const pub_pem = try std.fmt.allocPrint(gpa, "{s}/kem_pub.pem", .{tdir});
    defer gpa.free(pub_pem);

    // 1. CLI generates an ML-KEM-768 keypair + extracts the public key.
    try runCli(gpa, io, env, &.{ ossl, "genpkey", "-algorithm", "ML-KEM-768", "-out", priv_pem });
    try runCli(gpa, io, env, &.{ ossl, "pkey", "-in", priv_pem, "-pubout", "-out", pub_pem });

    var pub_buf: [16384]u8 = undefined;
    var priv_buf: [32768]u8 = undefined;
    const pub_data = try d.readFile(io, "kem_pub.pem", &pub_buf);
    const priv_data = try d.readFile(io, "kem_priv.pem", &priv_buf);

    // ---- Direction A: CLI encapsulates -> Zig decapsulates ----
    const ct_a = try std.fmt.allocPrint(gpa, "{s}/ct_a.bin", .{tdir});
    defer gpa.free(ct_a);
    const ss_cli_a = try std.fmt.allocPrint(gpa, "{s}/ss_cli_a.bin", .{tdir});
    defer gpa.free(ss_cli_a);
    try runCli(gpa, io, env, &.{ ossl, "pkeyutl", "-encap", "-inkey", pub_pem, "-pubin", "-out", ct_a, "-secret", ss_cli_a });

    var ctbuf: [4096]u8 = undefined;
    var ssbuf: [256]u8 = undefined;
    const ct_a_data = try d.readFile(io, "ct_a.bin", &ctbuf);
    const ss_cli_a_data = try d.readFile(io, "ss_cli_a.bin", &ssbuf);

    const priv_pkey = try importPem(priv_data, c.EVP_PKEY_KEYPAIR);
    var priv_kp = fips.Kem.KeyPair{ .pkey = priv_pkey };
    defer priv_kp.deinit();
    var ss_zig_a: [64]u8 = undefined;
    const za = try fips.Kem.decapsulate(.ml_kem_768, &priv_kp, ct_a_data, &ss_zig_a);
    if (!std.mem.eql(u8, ss_cli_a_data, ss_zig_a[0..za])) return InteropError.SecretMismatch;

    // ---- Direction B: Zig encapsulates -> CLI decapsulates ----
    const pub_pkey = try importPem(pub_data, c.EVP_PKEY_PUBLIC_KEY);
    var pub_kp = fips.Kem.KeyPair{ .pkey = pub_pkey };
    defer pub_kp.deinit();
    var ct_zig: [4096]u8 = undefined;
    var ss_zig_b: [64]u8 = undefined;
    const eb = try fips.Kem.encapsulate(.ml_kem_768, &pub_kp, &ct_zig, &ss_zig_b);

    try d.writeFile(io, .{ .sub_path = "ct_zig.bin", .data = ct_zig[0..eb.ct_len] });
    const ct_zig_p = try std.fmt.allocPrint(gpa, "{s}/ct_zig.bin", .{tdir});
    defer gpa.free(ct_zig_p);
    const ss_cli_b = try std.fmt.allocPrint(gpa, "{s}/ss_cli_b.bin", .{tdir});
    defer gpa.free(ss_cli_b);
    try runCli(gpa, io, env, &.{ ossl, "pkeyutl", "-decap", "-inkey", priv_pem, "-in", ct_zig_p, "-secret", ss_cli_b });

    var ssbuf_b: [256]u8 = undefined;
    const ss_cli_b_data = try d.readFile(io, "ss_cli_b.bin", &ssbuf_b);
    if (!std.mem.eql(u8, ss_cli_b_data, ss_zig_b[0..eb.ss_len])) return InteropError.SecretMismatch;

    std.debug.print("OK: ML-KEM-768 bidirectional Zig<->OpenSSL-CLI KEM interop passed\n", .{});
}
