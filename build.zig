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
    const check_step = b.step("check", "Compile the library and tests without running them");
    const check_tests = b.addTest(.{
        .root_module = module,
    });
    check_step.dependOn(&check_tests.step);

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
    // framework and the project library. ReleaseFast is forced for all
    // benchmark exes so casual `zig build bench` invocations still
    // produce comparable numbers regardless of the top-level optimize
    // option.
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
