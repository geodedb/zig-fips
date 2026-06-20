// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//! GAP-0020 repro graph A: imports build_options + the shared policy.zig.
const bo = @import("build_options");
const policy = @import("policy");
pub const approved = bo.repro and policy.isApproved("AES-256-GCM");
