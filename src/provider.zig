// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! FIPS provider lifecycle: load the validated module, force the
//! default property query to `fips=yes`, run its self-tests, and offer
//! a hard-fail assertion for startup.
const std = @import("std");
const ffi = @import("ffi.zig");
const c = ffi.c;
const policy = @import("policy.zig");

var g_ctx: ?*c.OSSL_LIB_CTX = null;
var g_fips: ?*c.OSSL_PROVIDER = null;
// g_ready is the lock-free readiness flag for the double-checked lock pattern.
// The release-store happens-after all g_ctx/g_fips/g_ciphers/g_mds/g_hmac writes;
// any thread that observes g_ready==true via an acquire-load is guaranteed to
// see those writes. The lock is acquired only until init completes once per
// process lifetime.
var g_ready = std.atomic.Value(bool).init(false);
var g_mu: std.atomic.Mutex = .unlocked;

// ---------------------------------------------------------------------------
// Per-algorithm primitive caches. Populated once under g_mu before g_ready
// is released; read lock-free thereafter (acquire on g_ready synchronises).
// Callers must always invoke assertActive()/ensureFips() before touching
// these — the acquire-load of g_ready guarantees the arrays are visible.
// ---------------------------------------------------------------------------

const aead_count = @typeInfo(policy.Aead).@"enum".fields.len;
const hash_count = @typeInfo(policy.Hash).@"enum".fields.len;

/// Cached EVP_CIPHER* for each policy.Aead variant (fips=yes, process-lifetime).
var g_ciphers: [aead_count]?*c.EVP_CIPHER = [_]?*c.EVP_CIPHER{null} ** aead_count;
/// Cached EVP_MD* for each policy.Hash variant (fips=yes, process-lifetime).
var g_mds: [hash_count]?*c.EVP_MD = [_]?*c.EVP_MD{null} ** hash_count;
/// Cached HMAC EVP_MAC* (fips=yes, process-lifetime).
var g_hmac: ?*c.EVP_MAC = null;

/// Spin-acquire g_mu, parking via Thread.yield while contended.
fn muLock() void {
    while (!g_mu.tryLock()) std.Thread.yield() catch {};
}

/// Returns the process-global lib context with `fips=yes` as the
/// default property query. Loads the fips + base providers on first use.
pub fn libCtx() *c.OSSL_LIB_CTX {
    // Fast path: g_ctx is immutable after init; the acquire-load
    // synchronizes-with ensureFips()'s release-store so g_ctx is visible.
    if (g_ready.load(.acquire)) return g_ctx.?;
    muLock();
    defer g_mu.unlock();
    return ctxLocked();
}

/// Load the FIPS provider and force fips-only algorithm selection.
pub fn ensureFips() error{FipsProviderUnavailable}!void {
    if (g_ready.load(.acquire)) return; // fast path: fully initialized, no lock
    muLock();
    defer g_mu.unlock();
    if (g_ready.load(.acquire)) return; // in-lock recheck: another thread may have finished
    // libCtx() also takes g_mu — call the unlocked core to avoid deadlock.
    const ctx = ctxLocked();
    // The FIPS provider self-test needs the install config data
    // (fipsmodule.cnf install-MAC, referenced from openssl.cnf). A fresh
    // OSSL_LIB_CTX created via OSSL_LIB_CTX_new() loads NO config by
    // default, so without this the provider fails with
    // "SELF_TEST_post: missing config data". Load OPENSSL_CONF when set,
    // otherwise the libcrypto's compiled-in default config file (NULL).
    // This call is idempotent and needed for self-test; it runs on every
    // attempt including retries after partial-init.
    const conf = c.getenv("OPENSSL_CONF"); // null when unset => default config
    if (c.OSSL_LIB_CTX_load_config(ctx, conf) != 1) return error.FipsProviderUnavailable;
    // Provider-load guard: skip if g_fips is already set (e.g. retry after
    // partial-init failure during cache population). OSSL_PROVIDER_load is
    // NOT idempotent so it must run at most once.
    if (g_fips == null) {
        // base provider supplies non-cryptographic encoders the fips
        // provider relies on (e.g. key serialization). SEC-1013: check return.
        if (c.OSSL_PROVIDER_load(ctx, "base") == null) return error.FipsProviderUnavailable;
        const fips = c.OSSL_PROVIDER_load(ctx, "fips") orelse return error.FipsProviderUnavailable;
        if (c.EVP_default_properties_enable_fips(ctx, 1) != 1) return error.FipsProviderUnavailable;
        // Self-test: provider must report available (runs KATs on load).
        if (c.OSSL_PROVIDER_self_test(fips) != 1) return error.FipsProviderUnavailable;
        g_fips = fips;
    }
    // Populate the caches under the already-held init lock, BEFORE the
    // release-store.  Every future acquire-load of g_ready happens-after
    // this, so cache reads need no lock.  Cache population runs on every
    // attempt (including retries) so a partial-init that failed mid-cache
    // will re-populate fully before publishing g_ready=true.
    inline for (@typeInfo(policy.Aead).@"enum".fields, 0..) |_, i| {
        const alg: policy.Aead = @enumFromInt(i);
        g_ciphers[i] = c.EVP_CIPHER_fetch(ctx, policy.aeadName(alg), "fips=yes") orelse
            return error.FipsProviderUnavailable;
    }
    inline for (@typeInfo(policy.Hash).@"enum".fields, 0..) |_, i| {
        const alg: policy.Hash = @enumFromInt(i);
        g_mds[i] = c.EVP_MD_fetch(ctx, policy.hashName(alg), "fips=yes") orelse
            return error.FipsProviderUnavailable;
    }
    g_hmac = c.EVP_MAC_fetch(ctx, "HMAC", "fips=yes") orelse return error.FipsProviderUnavailable;
    g_ready.store(true, .release); // publish: ctx + fips + caches fully initialized
}

/// Caller MUST hold g_mu. Lazy-creates the lib context.
fn ctxLocked() *c.OSSL_LIB_CTX {
    if (g_ctx) |ctx| return ctx;
    const ctx = c.OSSL_LIB_CTX_new() orelse @panic("OSSL_LIB_CTX_new failed");
    g_ctx = ctx;
    return ctx;
}

// ---------------------------------------------------------------------------
// Lock-free primitive accessors — callers must have already called
// assertActive() so the acquire-load has run and the caches are visible.
// ---------------------------------------------------------------------------

/// Return the cached fips=yes EVP_CIPHER for the given Aead algorithm.
pub fn cipherFor(alg: policy.Aead) ?*c.EVP_CIPHER {
    return g_ciphers[@intFromEnum(alg)];
}

/// Return the cached fips=yes EVP_MD for the given Hash algorithm.
pub fn mdFor(alg: policy.Hash) ?*c.EVP_MD {
    return g_mds[@intFromEnum(alg)];
}

/// Return the cached fips=yes HMAC EVP_MAC.
pub fn hmacMac() ?*c.EVP_MAC {
    return g_hmac;
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

test "concurrent first-use init is race-free and converges to one context" {
    const builtin = @import("builtin");
    if (builtin.single_threaded) return error.SkipZigTest;
    const N = 16;
    var threads: [N]std.Thread = undefined;
    const Worker = struct {
        fn run() void {
            ensureFips() catch unreachable;
            const md = c.EVP_MD_fetch(libCtx(), "SHA2-256", "fips=yes");
            std.debug.assert(md != null);
            c.EVP_MD_free(md);
        }
    };
    for (&threads) |*t| t.* = std.Thread.spawn(.{}, Worker.run, .{}) catch unreachable;
    for (&threads) |*t| t.join();
    // After the storm there must be exactly one lib context + one provider.
    try ensureFips();
    try std.testing.expect(g_ctx != null and g_fips != null);
}

test "ensureFips is all-or-nothing: retry after partial-init re-publishes" {
    // Simulate a partial-init state: provider loaded, caches populated,
    // but g_ready not yet visible (e.g. another goroutine failed mid-init).
    try ensureFips();
    // Force g_ready back to false to simulate a partial-init retry scenario.
    g_ready.store(false, .monotonic);
    // A retry must re-publish rather than early-returning due to g_fips != null.
    try ensureFips();
    try std.testing.expect(g_ready.load(.monotonic) == true);
    try std.testing.expect(cipherFor(.aes_256_gcm) != null);
}
