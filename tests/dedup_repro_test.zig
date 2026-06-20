// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! GAP-0020 reproduction (gated behind -Drepro_dedup=true). When wired
//! with TWO separate build_options module instances that both reach the
//! same shared file graph, Zig 0.16 errors with
//! `file '...' exists in modules 'build_options' and 'build_options0'`.
//! With the canonical single-instance wiring (default), this builds and
//! the assertion below passes.
const std = @import("std");
const a = @import("graph_a");
const b = @import("graph_b");

test "single build_options graph resolves (no dedup error)" {
    // Both graphs reach the SAME policy.zig; under the canonical
    // single-instance wiring this compiles. Under the BAD two-instance
    // wiring (-Drepro_dedup=true) the BUILD fails before this runs.
    try std.testing.expect(a.approved or b.approved);
}
