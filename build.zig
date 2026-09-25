// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

const std = @import("std");

fn importedModule(
    b: *std.Build,
    path: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    module: *std.Build.Module,
) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path(path),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "fips", .module = module },
        },
    });
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const tsan = b.option(bool, "tsan", "Enable ThreadSanitizer on test artifacts") orelse false;
    // `-Dfips=true|false` selects which backend a CONSUMER seam compiles
    // (templates/crypto_backend.zig keys off its own `build_options.fips`).
    // This package always builds + tests the OpenSSL FIPS backend AND the
    // std_shim backend, so the flag is accepted here for parity with the
    // documented consumer invocations (`zig build test -Dfips=false` runs
    // the shim parity + seam meta-test; `-Dfips=true` runs the FIPS KATs).
    // Both suites run regardless; the option keeps the commands valid.
    _ = b.option(bool, "fips", "Select FIPS (true) vs std_shim (false) backend for the consumer seam") orelse true;
    const repro_dedup = b.option(bool, "repro_dedup", "Wire the GAP-0020 module-dedup BAD shape (two build_options instances) to reproduce the bug") orelse false;

    const link = @import("src/link.zig");
    const openssl_path = b.option([]const u8, "openssl_path", "OpenSSL install prefix for non-standard installs (e.g. /usr/local/ssl)");

    // ------------------------------------------------------------------
    // Library module — primary public surface for downstream consumers.
    // The fips backend ALWAYS links libcrypto/libssl; CI sets
    // `-Dopenssl_path=/usr/local/ssl` to point at the FIPS build.
    // ------------------------------------------------------------------
    const module = b.addModule("fips", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    link.linkOpenssl(b, module, openssl_path);

    // Raw FFI surface as an importable module for standalone link tests.
    const ffi_module = b.addModule("ffi", .{
        .root_source_file = b.path("src/ffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    link.linkOpenssl(b, ffi_module, openssl_path);

    const static_lib = b.addLibrary(.{
        .name = "fips",
        .linkage = .static,
        .root_module = module,
    });
    b.installArtifact(static_lib);

    const build_step = b.step("build", "Build the standalone library (library-only; no CLI)");
    build_step.dependOn(&static_lib.step);

    // ------------------------------------------------------------------
    // Check step — fast IDE feedback. Compiles unit tests without
    // running them.
    // ------------------------------------------------------------------
    // The OpenSSL-free shim artifacts are always checked (wired below). The
    // fips backend links libcrypto/libssl, so a cross-OS `-Dtarget` without
    // `-Dopenssl_path` cannot resolve those libraries; skip only that
    // artifact then, so `zig build check -Dtarget=<other-os>` still proves
    // the canonical std_shim compiles for Windows/macOS.
    const check_step = b.step("check", "Compile the library and tests without running them");
    const cross_os = target.result.os.tag != b.graph.host.result.os.tag;
    if (!cross_os or openssl_path != null) {
        const check_tests = b.addTest(.{
            .root_module = module,
        });
        check_step.dependOn(&check_tests.step);
    }

    // ------------------------------------------------------------------
    // Test suites.
    // ------------------------------------------------------------------
    const unit_step = b.step("test", "Run unit tests");
    const unit_tests = b.addTest(.{
        .root_module = module,
    });
    if (tsan) unit_tests.root_module.sanitize_thread = true;
    unit_step.dependOn(&b.addRunArtifact(unit_tests).step);

    const integration_root = importedModule(b, "tests/integration.zig", target, optimize, module);
    link.linkOpenssl(b, integration_root, openssl_path);
    const integration_step = b.step("test-integration", "Run integration tests");
    const integration_tests = b.addTest(.{
        .root_module = integration_root,
    });
    if (tsan) integration_tests.root_module.sanitize_thread = true;
    integration_step.dependOn(&b.addRunArtifact(integration_tests).step);

    // PQC sign/KEM interop — standalone executables that shell the FIPS
    // OpenSSL CLI across the Zig<->CLI boundary. They are executables
    // (not `zig test`) because std.process.run needs the `Io` that
    // std.process.Init hands to `main`. They reach `c.*` via `fips.ffi.c`
    // (importing the standalone `ffi` module too would re-root ffi.zig
    // under two module graphs and trip the GAP-0020 dedup error).
    const interop_sources = [_][]const u8{
        "tests/pqc_sig_interop.zig",
        "tests/pqc_kem_interop.zig",
    };
    for (interop_sources) |src| {
        const interop_root = b.createModule(.{
            .root_source_file = b.path(src),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "fips", .module = module },
            },
        });
        link.linkOpenssl(b, interop_root, openssl_path);
        const interop_exe = b.addExecutable(.{
            .name = b.fmt("interop-{s}", .{std.fs.path.stem(src)}),
            .root_module = interop_root,
        });
        integration_step.dependOn(&b.addRunArtifact(interop_exe).step);
    }

    // Stress runs Debug under TSan so races aren't optimised away.
    const stress_optimize: std.builtin.OptimizeMode = if (tsan) .Debug else .ReleaseFast;
    const stress_root = importedModule(b, "tests/stress.zig", target, stress_optimize, module);
    link.linkOpenssl(b, stress_root, openssl_path);
    const stress_step = b.step("test-stress", "Run stress and load tests");
    const stress_tests = b.addTest(.{
        .root_module = stress_root,
    });
    if (tsan) stress_tests.root_module.sanitize_thread = true;
    stress_step.dependOn(&b.addRunArtifact(stress_tests).step);

    // ------------------------------------------------------------------
    // Link smoke test — proves libcrypto is LINKED (not just headers
    // present) by calling a real exported symbol at runtime. Rooted at
    // tests/link_smoke.zig importing the `ffi` module.
    // ------------------------------------------------------------------
    const link_smoke_root = b.createModule(.{
        .root_source_file = b.path("tests/link_smoke.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "ffi", .module = ffi_module },
        },
    });
    link.linkOpenssl(b, link_smoke_root, openssl_path);
    const link_smoke = b.addTest(.{
        .root_module = link_smoke_root,
    });
    unit_step.dependOn(&b.addRunArtifact(link_smoke).step);

    // ffi @cImport version/symbol-resolution test (its own root so the
    // header-only checks run under `zig build test`).
    const ffi_tests = b.addTest(.{
        .root_module = ffi_module,
    });
    unit_step.dependOn(&b.addRunArtifact(ffi_tests).step);

    // ------------------------------------------------------------------
    // std_shim — the canonical non-fips backend. Rooted at
    // src/std_shim.zig so its sibling `@import("policy.zig")` resolves.
    // NO OpenSSL link: the shim must build with zero OpenSSL coupling.
    // Exposed as a module so the shim parity test (and the seam template
    // meta-test in Task 11) can import it.
    // ------------------------------------------------------------------
    const std_shim_module = b.addModule("std_shim", .{
        .root_source_file = b.path("src/std_shim.zig"),
        .target = target,
        .optimize = optimize,
    });
    const shim_parity_root = b.createModule(.{
        .root_source_file = b.path("tests/shim_parity.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "std_shim", .module = std_shim_module },
        },
    });
    const shim_parity = b.addTest(.{ .root_module = shim_parity_root });
    unit_step.dependOn(&b.addRunArtifact(shim_parity).step);
    check_step.dependOn(&shim_parity.step);

    // The shim's own in-file tests (randomBytes entropy, key round-trips).
    const shim_tests = b.addTest(.{ .root_module = std_shim_module });
    unit_step.dependOn(&b.addRunArtifact(shim_tests).step);
    check_step.dependOn(&shim_tests.step);

    // ------------------------------------------------------------------
    // Seam template meta-test — wire templates/crypto_backend.zig with a
    // synthetic build_options (fips=false) + std_shim, proving the seam
    // selects the shim and re-exports the API. (Only the fips=false
    // branch is wired here; the fips=true branch is the consumer's own
    // build and is exercised by the rest of this package's tests.)
    // ------------------------------------------------------------------
    const seam_opts = b.addOptions();
    seam_opts.addOption(bool, "fips", false);
    const seam_opts_mod = seam_opts.createModule();
    const seam_root = b.createModule(.{
        .root_source_file = b.path("templates/crypto_backend.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "build_options", .module = seam_opts_mod },
            .{ .name = "std_shim", .module = std_shim_module },
        },
    });
    const seam_test_root = b.createModule(.{
        .root_source_file = b.path("tests/seam_template_test.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "crypto_backend", .module = seam_root },
        },
    });
    const seam_test = b.addTest(.{ .root_module = seam_test_root });
    unit_step.dependOn(&b.addRunArtifact(seam_test).step);
    check_step.dependOn(&seam_test.step);

    // ------------------------------------------------------------------
    // GAP-0020 module-dedup repro (gated behind -Drepro_dedup).
    //
    // Two helper graphs both reach the SAME policy.zig file. With
    // repro_dedup=true we (deliberately, the BAD shape) give each graph
    // its OWN build_options instance (.createModule() twice) — Zig 0.16
    // then errors `file 'src/policy.zig' exists in modules
    // 'build_options' and 'build_options0'`. With repro_dedup=false (the
    // default / canonical shape) BOTH graphs share the SINGLE
    // build_options instance and the build succeeds.
    // ------------------------------------------------------------------
    const policy_mod = b.addModule("policy", .{
        .root_source_file = b.path("src/policy.zig"),
        .target = target,
        .optimize = optimize,
    });
    const repro_opts_a = b.addOptions();
    repro_opts_a.addOption(bool, "repro", true);
    const repro_mod_a = repro_opts_a.createModule();
    // Canonical: reuse the SAME instance. BAD: a second instance.
    const repro_mod_b = if (repro_dedup) blk: {
        const repro_opts_b = b.addOptions();
        repro_opts_b.addOption(bool, "repro", true);
        break :blk repro_opts_b.createModule();
    } else repro_mod_a;
    const graph_a = b.createModule(.{
        .root_source_file = b.path("tests/dedup_graph_a.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "build_options", .module = repro_mod_a },
            .{ .name = "policy", .module = policy_mod },
        },
    });
    const graph_b = b.createModule(.{
        .root_source_file = b.path("tests/dedup_graph_b.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "build_options", .module = repro_mod_b },
            .{ .name = "policy", .module = policy_mod },
        },
    });
    const dedup_root = b.createModule(.{
        .root_source_file = b.path("tests/dedup_repro_test.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "graph_a", .module = graph_a },
            .{ .name = "graph_b", .module = graph_b },
        },
    });
    const dedup_test = b.addTest(.{ .root_module = dedup_root });
    unit_step.dependOn(&b.addRunArtifact(dedup_test).step);

    const all_tests_step = b.step("test-all", "Run unit, integration, and stress suites");
    all_tests_step.dependOn(&b.addRunArtifact(unit_tests).step);
    all_tests_step.dependOn(&b.addRunArtifact(link_smoke).step);
    all_tests_step.dependOn(&b.addRunArtifact(integration_tests).step);
    all_tests_step.dependOn(&b.addRunArtifact(stress_tests).step);

    // ------------------------------------------------------------------
    // Example — demonstrates library usage end-to-end.
    // ------------------------------------------------------------------
    const example_step = b.step("example", "Build and run the basic example");
    const example_exe = b.addExecutable(.{
        .name = "fips-basic",
        .root_module = importedModule(b, "examples/basic.zig", target, optimize, module),
    });
    example_step.dependOn(&b.addRunArtifact(example_exe).step);

    // ------------------------------------------------------------------
    // Benchmarks — see benchmarks/README.md.
    //
    // The benchmark framework (benchmarks/framework.zig) is library-
    // agnostic and depends only on the Zig stdlib. We expose it as its
    // own module so any bench source — including files in subdirectories
    // like benchmarks/micro/ — can `@import("framework")` it. Each suite
    // is then a standalone exe whose root module imports both the
    // framework and the project library. The framework module and each
    // bench exe's root module are built ReleaseFast; NOTE the imported `fips`
    // library module follows the top-level `-Doptimize` (Debug by default),
    // so for production-representative numbers run
    // `zig build bench -Doptimize=ReleaseFast`.
    // ------------------------------------------------------------------

    const framework_module = b.addModule("framework", .{
        .root_source_file = b.path("benchmarks/framework.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });

    const bench_exe = b.addExecutable(.{
        .name = "fips-bench",
        .root_module = benchModule(b, "benchmarks/bench.zig", target, module, framework_module),
    });
    b.installArtifact(bench_exe);
    const run_bench = b.addRunArtifact(bench_exe);
    if (b.args) |args| run_bench.addArgs(args);
    const bench_step = b.step("bench", "Run the default benchmark suite");
    bench_step.dependOn(&run_bench.step);

    const scale_bench_exe = b.addExecutable(.{
        .name = "fips-scale-bench",
        .root_module = benchModule(b, "benchmarks/scale.zig", target, module, framework_module),
    });
    b.installArtifact(scale_bench_exe);
    const run_scale_bench = b.addRunArtifact(scale_bench_exe);
    if (b.args) |args| run_scale_bench.addArgs(args);
    const scale_bench_step = b.step("scale-bench", "Run the larger / longer benchmark grid");
    scale_bench_step.dependOn(&run_scale_bench.step);

    const compare_bench_exe = b.addExecutable(.{
        .name = "fips-compare-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("benchmarks/compare.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "framework", .module = framework_module },
            },
        }),
    });
    b.installArtifact(compare_bench_exe);
    const run_compare = b.addRunArtifact(compare_bench_exe);
    if (b.args) |args| run_compare.addArgs(args);
    const compare_step = b.step("compare-bench", "Diff two benchmark result files and gate on regressions");
    compare_step.dependOn(&run_compare.step);

    const micro_example_exe = b.addExecutable(.{
        .name = "fips-micro-example",
        .root_module = benchModule(b, "benchmarks/micro/example.zig", target, module, framework_module),
    });
    const run_micro_example = b.addRunArtifact(micro_example_exe);
    if (b.args) |args| run_micro_example.addArgs(args);
    const micro_example_step = b.step("bench-micro-example", "Example micro-benchmark");
    micro_example_step.dependOn(&run_micro_example.step);

    const micro_all_step = b.step("bench-micro", "Run all micro-benchmarks");
    micro_all_step.dependOn(&run_micro_example.step);

    const tools_step = b.step("tools", "Build benchmark tooling artifacts");
    tools_step.dependOn(&bench_exe.step);
    tools_step.dependOn(&scale_bench_exe.step);
    tools_step.dependOn(&compare_bench_exe.step);
    tools_step.dependOn(&micro_example_exe.step);

    // ------------------------------------------------------------------
    // deps — provision the OpenSSL FIPS provider.
    //
    // `zig build deps` shells to the same script `make deps` runs, so CI
    // can provision the FIPS provider through either entrypoint. The run
    // has side effects (touches the system OpenSSL prefix) and must never
    // be cached.
    // ------------------------------------------------------------------
    const deps_run = b.addSystemCommand(&.{"./scripts/install-openssl-fips.sh"});
    deps_run.has_side_effects = true;
    const deps_step = b.step("deps", "Build+install latest OpenSSL + FIPS provider (always upgrades to latest)");
    deps_step.dependOn(&deps_run.step);
}

fn benchModule(
    b: *std.Build,
    path: []const u8,
    target: std.Build.ResolvedTarget,
    lib_module: *std.Build.Module,
    framework_module: *std.Build.Module,
) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path(path),
        .target = target,
        .optimize = .ReleaseFast,
        .imports = &.{
            .{ .name = "fips", .module = lib_module },
            .{ .name = "framework", .module = framework_module },
        },
    });
}
