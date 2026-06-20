// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Basic usage example for fips.
//!
//! Run with `zig build example`. The non-fips (std-shim) path needs no
//! OpenSSL link; the fips backend requires `make deps` + `-Dfips=true`.

const std = @import("std");
const Io = std.Io;
const lib = @import("fips");

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buffer);
    const out = &stdout_writer.interface;

    try out.print("fips Example (v{s})\n", .{lib.version});
    try out.writeAll("========================\n\n");
    try out.writeAll(
        "fips is a library-only crypto backend; see docs/SEAM_CONTRACT.md\n" ++
            "for how consumers wire the -Dfips seam.\n",
    );
    try out.flush();
}
