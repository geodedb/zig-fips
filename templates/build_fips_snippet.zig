// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// CANONICAL -Dfips BUILD WIRING (reference snippet — NOT compiled).
//
// Paste this into a consumer's build.zig. The CARDINAL RULE (GAP-0020):
// materialize EXACTLY ONE `build_options` module via `b.addOptions()` +
// `.createModule()` and thread that SINGLE `*std.Build.Module` into
// every compile unit AND into the lazy `fips` dependency. Never call
// `.createModule()` on a second options instance reachable from the same
// file graph, or Zig 0.16 errors with
//   `error: file '...' exists in modules 'build_options' and 'build_options0'`.
//
// Steps:
//   1. const fips = b.option(bool, "fips", "Route crypto through the
//          FIPS-140-3 OpenSSL provider") orelse false;
//   2. const opts = b.addOptions();
//      opts.addOption(bool, "fips", fips);
//      // REQUIRED (GAP-0020 cross-package rule): make this lib's generated
//      // options.zig content UNIQUE so Zig 0.16 does not content-dedup it
//      // against another seam lib's identical build_options in a large
//      // consumer graph (which collapses crypto_backend.zig into multiple
//      // module roots). Use THIS lib's crate name:
//      opts.addOption([]const u8, "package_name", "<your-lib-name>");
//      const build_options_mod = opts.createModule();   // THE ONE INSTANCE
//   3. const openssl_path = b.option([]const u8, "openssl_path",
//          "OpenSSL prefix (e.g. /usr/local/ssl)");
//   4. The consumer's lib module imports the seam + std_shim + build_options:
//        module.addImport("build_options", build_options_mod);
//        module.addImport("std_shim", std_shim_mod); // rooted at src/std_shim.zig
//      and, ONLY when fips is on, the lazy fips dep + its OpenSSL link:
//        const fips_mod: ?*std.Build.Module = if (fips) blk: {
//            // REQUIRED (GAP-0020 fips-split rule): pass openssl_path here,
//            // and pass the SAME value in EVERY lib you propagate -Dfips to
//            // (quic/tls/etc.), else the fips backend splits into fips/fips0:
//            if (b.lazyDependency("fips", .{ .target = target, .optimize = optimize, .openssl_path = openssl_path orelse "/usr/local/ssl" })) |dep| {
//                const m = dep.module("fips");
//                module.addImport("fips", m);
//                break :blk m;
//            } else break :blk null;
//        } else null;
//        _ = fips_mod;
//   5. Thread build_options_mod (and, when present, the same fips_mod /
//      std_shim_mod) into EVERY test/check/lib compile unit — never a
//      second options.createModule().
//   6. When fips is on, link OpenSSL onto every unit that transitively
//      reaches `fips` via the canonical helper:
//        const link = @import("fips_link"); // or copy linkOpenssl
//        link.linkOpenssl(b, module, openssl_path);
//
// The seam file (src/crypto_backend.zig) selects @import("fips") vs
// @import("std_shim") at comptime from build_options.fips; only the fips
// branch pulls the lazy `fips` dependency, so a default build fetches
// nothing and links no OpenSSL.
