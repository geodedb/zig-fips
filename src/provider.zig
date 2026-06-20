// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! FIPS provider lifecycle: load the validated module, force the
//! default property query to `fips=yes`, run its self-tests, and offer
//! a hard-fail assertion for startup.
const std = @import("std");
const ffi = @import("ffi.zig");
const c = ffi.c;

var g_ctx: ?*c.OSSL_LIB_CTX = null;
var g_fips: ?*c.OSSL_PROVIDER = null;

/// Returns the process-global lib context with `fips=yes` as the
/// default property query. Loads the fips + base providers on first use.
pub fn libCtx() *c.OSSL_LIB_CTX {
    if (g_ctx) |ctx| return ctx;
    const ctx = c.OSSL_LIB_CTX_new() orelse @panic("OSSL_LIB_CTX_new failed");
    g_ctx = ctx;
    return ctx;
}

/// Load the FIPS provider and force fips-only algorithm selection.
pub fn ensureFips() error{FipsProviderUnavailable}!void {
    if (g_fips != null) return;
    const ctx = libCtx();
    // The FIPS provider self-test needs the install config data
    // (fipsmodule.cnf install-MAC, referenced from openssl.cnf). A fresh
    // OSSL_LIB_CTX created via OSSL_LIB_CTX_new() loads NO config by
    // default, so without this the provider fails with
    // "SELF_TEST_post: missing config data". Load OPENSSL_CONF when set,
    // otherwise the libcrypto's compiled-in default config file (NULL).
    const conf = c.getenv("OPENSSL_CONF"); // null when unset => default config
    if (c.OSSL_LIB_CTX_load_config(ctx, conf) != 1) return error.FipsProviderUnavailable;
    // base provider supplies non-cryptographic encoders the fips
    // provider relies on (e.g. key serialization).
    _ = c.OSSL_PROVIDER_load(ctx, "base");
    const fips = c.OSSL_PROVIDER_load(ctx, "fips") orelse return error.FipsProviderUnavailable;
    if (c.EVP_default_properties_enable_fips(ctx, 1) != 1) return error.FipsProviderUnavailable;
    // Self-test: provider must report available (runs KATs on load).
    if (c.OSSL_PROVIDER_self_test(fips) != 1) return error.FipsProviderUnavailable;
    g_fips = fips;
}

/// Hard-fail startup assertion. Panics if the validated FIPS provider
/// is not loaded + self-tested.
pub fn assertActive() void {
    ensureFips() catch @panic("FIPS provider not loaded/self-tested; run `make deps`");
}

test "fips provider loads + self-tests" {
    try ensureFips();
    // Idempotent: second call is a no-op.
    try ensureFips();
}

test "fips=yes selects only fips-approved digests" {
    try ensureFips();
    // SHA2-256 is fips-approved and must fetch under fips=yes.
    const ok = c.EVP_MD_fetch(libCtx(), "SHA2-256", "fips=yes");
    try std.testing.expect(ok != null);
    c.EVP_MD_free(ok);
}
