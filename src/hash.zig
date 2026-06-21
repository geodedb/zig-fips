// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
const std = @import("std");
const ffi = @import("ffi.zig");
const c = ffi.c;
const policy = @import("policy.zig");
const provider = @import("provider.zig");

pub const Hash = struct {
    pub const Error = error{ Unsupported, OpensslFailure };

    /// One-shot digest. Returns bytes written into `out`.
    pub fn digest(alg: policy.Hash, msg: []const u8, out: []u8) Error!usize {
        provider.assertActive();
        const md = c.EVP_MD_fetch(provider.libCtx(), policy.hashName(alg), "fips=yes") orelse return error.Unsupported;
        defer c.EVP_MD_free(md);
        const ctx = c.EVP_MD_CTX_new() orelse return error.OpensslFailure;
        defer c.EVP_MD_CTX_free(ctx);
        if (c.EVP_DigestInit_ex2(ctx, md, null) != 1) return error.OpensslFailure;
        if (c.EVP_DigestUpdate(ctx, msg.ptr, msg.len) != 1) return error.OpensslFailure;
        var n: c_uint = 0;
        if (c.EVP_DigestFinal_ex(ctx, out.ptr, &n) != 1) return error.OpensslFailure;
        return n;
    }

    /// Streaming / incremental digest over a live EVP_MD_CTX. Lets
    /// consumers route incremental hashing (TLS 1.3 transcript, DNSSEC
    /// canonical hashing) through the FIPS-validated module without
    /// buffering the whole message. Mirrors the std_shim backend's
    /// `Hash.Stream` byte-for-byte at the API level.
    ///
    /// Lifecycle: `init` -> any number of `update` -> `final` (which does
    /// NOT reset the context). `clone` snapshots the current state into a
    /// fully independent Stream; the two diverge under subsequent
    /// independent `update`s. Every Stream owns OpenSSL heap state and
    /// MUST be released with `deinit`.
    pub const Stream = struct {
        md: *c.EVP_MD,
        ctx: *c.EVP_MD_CTX,

        /// Begin an incremental digest for `alg`. Fetches the fips=yes
        /// EVP_MD and initialises a fresh context.
        pub fn init(alg: policy.Hash) Error!Stream {
            provider.assertActive();
            const md = c.EVP_MD_fetch(provider.libCtx(), policy.hashName(alg), "fips=yes") orelse return error.Unsupported;
            errdefer c.EVP_MD_free(md);
            const ctx = c.EVP_MD_CTX_new() orelse return error.OpensslFailure;
            errdefer c.EVP_MD_CTX_free(ctx);
            if (c.EVP_DigestInit_ex2(ctx, md, null) != 1) return error.OpensslFailure;
            return .{ .md = md, .ctx = ctx };
        }

        /// Absorb `bytes` into the running digest. Infallible at the API
        /// level (matches the shim): an OpenSSL update failure on a
        /// correctly-initialised context cannot happen for a software
        /// digest, so it panics rather than poisoning the type with an
        /// error on the hot path.
        pub fn update(self: *Stream, bytes: []const u8) void {
            if (c.EVP_DigestUpdate(self.ctx, bytes.ptr, bytes.len) != 1) @panic("EVP_DigestUpdate failed");
        }

        /// Finalise into `out` and return the digest length. Does not
        /// reset the context. `out` must be at least the digest size.
        pub fn final(self: *Stream, out: []u8) Error!usize {
            var n: c_uint = 0;
            if (c.EVP_DigestFinal_ex(self.ctx, out.ptr, &n) != 1) return error.OpensslFailure;
            return n;
        }

        /// Snapshot the current state into an independent Stream. The
        /// clone and the original share no mutable state: updating one
        /// does not affect the other.
        pub fn clone(self: *Stream) Error!Stream {
            // Keep an independent EVP_MD reference for the clone so each
            // Stream can EVP_MD_free on deinit without a use-after-free.
            const md = c.EVP_MD_fetch(provider.libCtx(), c.EVP_MD_get0_name(self.md), "fips=yes") orelse return error.Unsupported;
            errdefer c.EVP_MD_free(md);
            const ctx = c.EVP_MD_CTX_dup(self.ctx) orelse return error.OpensslFailure;
            return .{ .md = md, .ctx = ctx };
        }

        /// Release the OpenSSL context and digest reference.
        pub fn deinit(self: *Stream) void {
            c.EVP_MD_CTX_free(self.ctx);
            c.EVP_MD_free(self.md);
        }
    };
};

test "KAT SHA2-256(\"abc\") == ba7816bf..." {
    var out: [32]u8 = undefined;
    const n = try Hash.digest(.sha256, "abc", &out);
    try std.testing.expectEqual(@as(usize, 32), n);
    const expect = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    try std.testing.expectEqualSlices(u8, &expect, &out);
}
test "KAT SHA3-256(\"abc\")" {
    var out: [32]u8 = undefined;
    _ = try Hash.digest(.sha3_256, "abc", &out);
    const expect = [_]u8{
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
        0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
    };
    try std.testing.expectEqualSlices(u8, &expect, &out);
}

test "Stream chunked update equals one-shot SHA2-256" {
    // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    const msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    var oneshot: [32]u8 = undefined;
    const n1 = try Hash.digest(.sha256, msg, &oneshot);

    var s = try Hash.Stream.init(.sha256);
    defer s.deinit();
    // Feed in irregular chunks; the running digest must equal one-shot.
    s.update(msg[0..1]);
    s.update(msg[1..10]);
    s.update(msg[10..40]);
    s.update(msg[40..]);
    var streamed: [32]u8 = undefined;
    const n2 = try s.final(&streamed);

    try std.testing.expectEqual(n1, n2);
    try std.testing.expectEqualSlices(u8, oneshot[0..n1], streamed[0..n2]);
    // Known SHA2-256 vector for this 56-byte message.
    const expect = [_]u8{
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
    };
    try std.testing.expectEqualSlices(u8, &expect, &streamed);
}

test "Stream clone finalizes identically to its source (SHA2-384)" {
    var s = try Hash.Stream.init(.sha384);
    defer s.deinit();
    s.update("hello, ");
    s.update("world");

    var clone = try s.clone();
    defer clone.deinit();

    var a: [48]u8 = undefined;
    var b: [48]u8 = undefined;
    const na = try s.final(&a);
    const nb = try clone.final(&b);
    try std.testing.expectEqual(na, nb);
    try std.testing.expectEqualSlices(u8, a[0..na], b[0..nb]);
}

test "Stream clone diverges after independent updates (SHA2-512)" {
    var s = try Hash.Stream.init(.sha512);
    defer s.deinit();
    s.update("common-prefix");

    var clone = try s.clone();
    defer clone.deinit();

    // Independent suffixes => different digests.
    s.update("-A");
    clone.update("-B");

    var a: [64]u8 = undefined;
    var b: [64]u8 = undefined;
    _ = try s.final(&a);
    _ = try clone.final(&b);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));

    // And each must equal the corresponding one-shot digest.
    var ref_a: [64]u8 = undefined;
    var ref_b: [64]u8 = undefined;
    _ = try Hash.digest(.sha512, "common-prefix-A", &ref_a);
    _ = try Hash.digest(.sha512, "common-prefix-B", &ref_b);
    try std.testing.expectEqualSlices(u8, &ref_a, &a);
    try std.testing.expectEqualSlices(u8, &ref_b, &b);
}

test "Stream supports SHA-3 (incremental == one-shot SHA3-256)" {
    const msg = "the quick brown fox";
    var s = try Hash.Stream.init(.sha3_256);
    defer s.deinit();
    s.update(msg[0..4]);
    s.update(msg[4..]);
    var streamed: [32]u8 = undefined;
    const n = try s.final(&streamed);
    var oneshot: [32]u8 = undefined;
    _ = try Hash.digest(.sha3_256, msg, &oneshot);
    try std.testing.expectEqualSlices(u8, oneshot[0..n], streamed[0..n]);
}
