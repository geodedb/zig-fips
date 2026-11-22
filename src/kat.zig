// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Test-only reader for src/testdata_pubkey_kat.txt (trimmed NIST ACVP /
//! CAVP vectors, see the file header for provenance). One record per line:
//! `<kind> <param> <field0> <field1> ...`, space-separated, hex fields.
const std = @import("std");

const data = @embedFile("testdata_pubkey_kat.txt");

pub const Record = struct {
    param: []const u8,
    rest: []const u8,

    /// The i-th space-separated field after `<param>`.
    pub fn field(self: Record, i: usize) []const u8 {
        var it = std.mem.tokenizeScalar(u8, self.rest, ' ');
        var n: usize = 0;
        while (it.next()) |f| : (n += 1) if (n == i) return f;
        @panic("KAT record has too few fields");
    }
};

pub const Iterator = struct {
    lines: std.mem.TokenIterator(u8, .scalar),
    kind: []const u8,

    pub fn next(self: *Iterator) ?Record {
        while (self.lines.next()) |line| {
            if (line.len == 0 or line[0] == '#') continue;
            var it = std.mem.tokenizeScalar(u8, line, ' ');
            const kind = it.next() orelse continue;
            if (!std.mem.eql(u8, kind, self.kind)) continue;
            const param = it.next() orelse continue;
            return .{ .param = param, .rest = it.rest() };
        }
        return null;
    }
};

pub fn records(kind: []const u8) Iterator {
    return .{ .lines = std.mem.tokenizeScalar(u8, data, '\n'), .kind = kind };
}

/// Decode `s` (lower/upper hex) into `buf`; returns the decoded slice.
pub fn hex(buf: []u8, s: []const u8) ![]u8 {
    return std.fmt.hexToBytes(buf, s);
}

test "KAT file parses and every record kind is present" {
    inline for (.{ .{ "mlkem_keygen", 8 }, .{ "mlkem_encap", 8 }, .{ "mlkem_bad_ek", 12 }, .{ "ecdh_cdh", 10 } }) |want| {
        var it = records(want[0]);
        var n: usize = 0;
        while (it.next()) |_| n += 1;
        try std.testing.expectEqual(@as(usize, want[1]), n);
    }
}
