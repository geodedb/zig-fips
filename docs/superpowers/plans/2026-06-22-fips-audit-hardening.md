# FIPS Seam Audit Hardening — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every confirmed finding from the Round-1 appsec + codepros audits (security/correctness bugs, missing primitives, test-coverage holes, stale docs, placeholder benchmarks) in the `devnw/zig/fips` crypto seam, without regressing the green dual-mode baseline.

**Architecture:** A FIPS-140-3 crypto seam in Zig 0.16 with two comptime-selected backends — the OpenSSL FIPS provider backend (`src/*.zig`) and `src/std_shim.zig` (std.crypto). The seam `templates/crypto_backend.zig` re-exports a pinned public surface that BOTH backends implement identically. Fixes preserve this parity invariant: any new public symbol is added to the fips backend (via `src/root.zig`), to `src/std_shim.zig`, and to `templates/crypto_backend.zig`.

**Tech Stack:** Zig 0.16.0, OpenSSL 3.x FIPS provider (3.6.2 installed at `/usr/local/ssl`), `@cImport` FFI.

## Global Constraints

- **Parity invariant:** `src/*.zig` (fips backend), `src/std_shim.zig`, and `templates/crypto_backend.zig` MUST expose an identical public API. `std_shim.zig` + `src/policy.zig` + `templates/crypto_backend.zig` are copied verbatim into consumers — keep them self-contained (shim imports only `std` + sibling `policy.zig`).
- **Error-set stability:** To preserve parity by construction, REUSE existing error members. Length/buffer/oversized-input failures return `error.OpensslFailure` (matches the shim's existing choice at `std_shim.zig:208,214`). Weak/wrong-type-key failures return `error.Unsupported`. Do NOT add new error-set members unless a task says so explicitly.
- **Dual-mode gate:** every change must keep BOTH backends green: `make test-shim` (no OpenSSL link) AND `make test-fips` (`OPENSSL_CONF=/usr/local/ssl/ssl/openssl.cnf zig build test -Dopenssl_path=/usr/local/ssl`). `make test-dual` runs both.
- **Format gate:** run `zig fmt src tests examples benchmarks build.zig templates` before each commit; CI runs `zig fmt --check`.
- **Versions:** Zig 0.16.0; OpenSSL ≥ 3.5 (PQC). Copyright header `// SPDX-License-Identifier: Apache-2.0\n// Copyright (c) 2024-2026 CodePros` on new source files.
- **Design intent — do NOT reverse:** `make deps` always upgrades to latest OpenSSL 3.x (harden via signature verification, not pinning); exactly one `build_options` module instance (GAP-0020); publish-time `.path`→`git+https` swap is deferred.
- **Branch/commit:** all work on branch `audit/round-1-hardening`. Commit per task. Do NOT push. End commit messages with `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- **Std API note:** exact std symbol names (e.g. `std.crypto.secureZero`, `std.crypto.random.bytes`) may differ slightly in 0.16; if a symbol doesn't resolve, find the 0.16 equivalent via the compiler error and use it — the behavior specified is the contract, not the exact path.

---

## Phase A — Security & correctness (code)

### Task 1: AEAD output-buffer + nonce/tag/key length validation (fips backend)

Closes F3 / SEC-1002 / QUAL-0006 (heap over-write) and the length half of SEC-1011 (nonce length). The std_shim already validates (`std_shim.zig:208,214`); mirror it into the fips backend so `open` cannot write past `plaintext` and both backends reject the same malformed lengths with the same error.

**Files:**

- Modify: `src/aead.zig` (`seal` ~line 15-44, `open` ~line 48-79; add a private length helper)
- Test: `src/aead.zig` (in-file tests, append)

**Interfaces:**

- Produces: `seal`/`open` now return `error.OpensslFailure` when `key.len` ≠ the alg's key length (16 for `aes_128_gcm`, 32 for `aes_256_gcm`), `nonce.len != 12`, `tag.len != 16`, or the output buffer is too small (`ciphertext.len < plaintext.len` for seal; `plaintext.len < ciphertext.len` for open). Signatures unchanged.

- [ ] **Step 1 — Write failing tests.** Append to `src/aead.zig`:

```zig
test "Aead.open rejects undersized plaintext buffer (no overrun)" {
    const key = [_]u8{0x42} ** 32;
    const iv = [_]u8{0x24} ** 12;
    const msg = "the quick brown fox";
    var ct: [msg.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    try Aead.seal(.aes_256_gcm, &key, &iv, "", msg, &ct, &tag);
    var too_small: [msg.len - 1]u8 = undefined; // one byte short
    try std.testing.expectError(error.OpensslFailure, Aead.open(.aes_256_gcm, &key, &iv, "", &ct, &tag, &too_small));
}

test "Aead rejects wrong key/nonce/tag lengths" {
    const key32 = [_]u8{0} ** 32;
    const iv12 = [_]u8{0} ** 12;
    var ct: [4]u8 = undefined;
    var pt: [4]u8 = undefined;
    var tag16: [16]u8 = undefined;
    // wrong key length for aes_256_gcm
    try std.testing.expectError(error.OpensslFailure, Aead.seal(.aes_256_gcm, key32[0..16], &iv12, "", "msg!", &ct, &tag16));
    // wrong nonce length (must be 12 for GCM)
    try std.testing.expectError(error.OpensslFailure, Aead.seal(.aes_256_gcm, &key32, key32[0..11], "", "msg!", &ct, &tag16));
    // wrong tag length
    var tag15: [15]u8 = undefined;
    try std.testing.expectError(error.OpensslFailure, Aead.seal(.aes_256_gcm, &key32, &iv12, "", "msg!", &ct, &tag15));
    // seal: ciphertext buffer too small
    var ct_small: [3]u8 = undefined;
    try std.testing.expectError(error.OpensslFailure, Aead.seal(.aes_256_gcm, &key32, &iv12, "", "msg!", &ct_small, &tag16));
    _ = &pt;
}
```

- [ ] **Step 2 — Run, expect FAIL** (open writes past the buffer / no rejection): `make test-fips` (or just `OPENSSL_CONF=/usr/local/ssl/ssl/openssl.cnf zig build test -Dopenssl_path=/usr/local/ssl`). Expect the new tests to fail (no validation today).

- [ ] **Step 3 — Implement.** In `src/aead.zig`, add a helper and call it first in both `seal` and `open`:

```zig
/// AES-GCM fixed parameters (SP 800-38D): 96-bit IV, 128-bit tag.
const gcm_nonce_len = 12;
const gcm_tag_len = 16;

fn aeadKeyLen(alg: policy.Aead) usize {
    return switch (alg) {
        .aes_128_gcm => 16,
        .aes_256_gcm => 32,
    };
}
```

In `seal`, immediately after `provider.assertActive();`:

```zig
    if (key.len != aeadKeyLen(alg) or nonce.len != gcm_nonce_len or
        tag.len != gcm_tag_len or ciphertext.len < plaintext.len)
        return error.OpensslFailure;
```

In `open`, immediately after `provider.assertActive();`:

```zig
    if (key.len != aeadKeyLen(alg) or nonce.len != gcm_nonce_len or
        tag.len != gcm_tag_len or plaintext.len < ciphertext.len)
        return error.OpensslFailure;
```

- [ ] **Step 4 — Run, expect PASS:** `make test-fips`. New tests pass; all existing AEAD KATs (`aead.zig:82-123`) still pass. Then `make test-shim` (unaffected) and confirm `make test-dual` green.

- [ ] **Step 5 — Commit:** `zig fmt src && git add src/aead.zig && git commit` — message: `fix(aead): validate key/nonce/tag/output-buffer lengths in fips backend`.

---

### Task 2: Thread-safe provider initialization + base-provider check + concurrency test

Closes F4 / SEC-1006 / QUAL-0015 / PERF-0005 (init data race) and SEC-1013 (ignored `base` load return).

**Files:**

- Modify: `src/provider.zig` (globals ~11-12; `libCtx` 16-21; `ensureFips` 24-43)
- Test: `src/provider.zig` (append concurrency test)

**Interfaces:**

- Produces: `ensureFips()` and `libCtx()` are safe under concurrent first use; `OSSL_PROVIDER_load(ctx, "base")` failure now returns `error.FipsProviderUnavailable`. Signatures unchanged.

- [ ] **Step 1 — Write failing test.** Append to `src/provider.zig`:

```zig
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
```

- [ ] **Step 2 — Run under the thread sanitizer, expect FAIL/race:** `OPENSSL_CONF=/usr/local/ssl/ssl/openssl.cnf zig build test -Dopenssl_path=/usr/local/ssl -Dtsan --summary all`. Expect a TSan data-race report on `g_ctx`/`g_fips` (or a flaky failure). (Without `-Dtsan` it may pass by luck — the race is real; use `-Dtsan` to surface it.)

- [ ] **Step 3 — Implement.** In `src/provider.zig` add a mutex and guard both init paths:

```zig
var g_ctx: ?*c.OSSL_LIB_CTX = null;
var g_fips: ?*c.OSSL_PROVIDER = null;
var g_mu: std.Thread.Mutex = .{};

pub fn libCtx() *c.OSSL_LIB_CTX {
    g_mu.lock();
    defer g_mu.unlock();
    if (g_ctx) |ctx| return ctx;
    const ctx = c.OSSL_LIB_CTX_new() orelse @panic("OSSL_LIB_CTX_new failed");
    g_ctx = ctx;
    return ctx;
}

pub fn ensureFips() error{FipsProviderUnavailable}!void {
    g_mu.lock();
    defer g_mu.unlock();
    if (g_fips != null) return;
    // libCtx() also takes g_mu — call the unlocked core to avoid deadlock.
    const ctx = ctxLocked();
    const conf = c.getenv("OPENSSL_CONF");
    if (c.OSSL_LIB_CTX_load_config(ctx, conf) != 1) return error.FipsProviderUnavailable;
    if (c.OSSL_PROVIDER_load(ctx, "base") == null) return error.FipsProviderUnavailable; // SEC-1013
    const fips = c.OSSL_PROVIDER_load(ctx, "fips") orelse return error.FipsProviderUnavailable;
    if (c.EVP_default_properties_enable_fips(ctx, 1) != 1) return error.FipsProviderUnavailable;
    if (c.OSSL_PROVIDER_self_test(fips) != 1) return error.FipsProviderUnavailable;
    g_fips = fips;
}

/// Caller MUST hold g_mu. Lazy-creates the lib context.
fn ctxLocked() *c.OSSL_LIB_CTX {
    if (g_ctx) |ctx| return ctx;
    const ctx = c.OSSL_LIB_CTX_new() orelse @panic("OSSL_LIB_CTX_new failed");
    g_ctx = ctx;
    return ctx;
}
```

Keep `assertActive()` unchanged (it calls `ensureFips()`).

- [ ] **Step 4 — Run, expect PASS:** `... -Dtsan ...` race-free; then `make test-dual` green.

- [ ] **Step 5 — Commit:** `fix(provider): synchronize lazy FIPS init and check base-provider load`.

---

### Task 3: `secureZero` primitive — implement, export, and apply to secret buffers

Closes F1 / SEC-1004 / GAP-0021(a). Spec `FIPS_SPECIFICATION.md:256` already promises `secureZero`; make it real on both backends and wipe the secret buffers that exist today.

**Files:**

- Modify: `src/ffi.zig` (add `@cInclude("openssl/crypto.h")` for `OPENSSL_cleanse`/`CRYPTO_memcmp`)
- Create: `src/util.zig` (fips-backend `secureZero` + `timingSafeEql` — Task 4 adds the latter)
- Modify: `src/root.zig` (re-export `secureZero`)
- Modify: `src/std_shim.zig` (add `secureZero`)
- Modify: `templates/crypto_backend.zig` (re-export `secureZero`)
- Modify: `src/kem.zig` (`decapsulate`/`encapsulate` wipe shared secret on error), `src/std_shim.zig` (wipe `seed` at line ~300, `prk_arr` at ~176)
- Test: `src/util.zig`, `tests/shim_parity.zig` (assert symbol + behavior), `tests/seam_template_test.zig`

**Interfaces:**

- Produces: `pub fn secureZero(buf: []u8) void` available as `fips.secureZero`, `std_shim.secureZero`, and `crypto_backend.secureZero` (identical semantics: overwrite `buf` with zeros in a way the optimizer cannot elide).

- [ ] **Step 1 — Write failing test.** Create `src/util.zig`:

```zig
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Non-primitive seam utilities shared across the fips backend:
//! constant-time-cleanse and constant-time-compare of secret bytes.
//! Mirrored byte-for-byte (behaviorally) by std_shim.zig.
const std = @import("std");
const ffi = @import("ffi.zig");
const c = ffi.c;

/// Best-effort guaranteed memory wipe (OpenSSL OPENSSL_cleanse — not
/// elided by the optimizer). Use on private keys, shared secrets, and
/// derived key material before the buffer goes out of scope or is freed.
pub fn secureZero(buf: []u8) void {
    c.OPENSSL_cleanse(buf.ptr, buf.len);
}

test "secureZero wipes a sentinel-filled buffer" {
    var buf = [_]u8{0xAB} ** 64;
    secureZero(&buf);
    try std.testing.expect(std.mem.allEqual(u8, &buf, 0));
}
```

Add to `src/ffi.zig` cImport block: `@cInclude("openssl/crypto.h"); // OPENSSL_cleanse, CRYPTO_memcmp`.

- [ ] **Step 2 — Run, expect FAIL** (`util.zig` not wired into the build/test graph yet; `secureZero` not exported): add `_ = @import("util.zig");` to the `test {}` block in `src/root.zig` and `pub const secureZero = @import("util.zig").secureZero;` near the other re-exports. Re-run `make test-fips`; the in-file `util` test should now compile and pass — that proves the fips side.

- [ ] **Step 3 — Implement the shim + seam + applications.**
  - `src/std_shim.zig`: add (near the top-level `pub fn assertActive`):

    ```zig
    /// Best-effort guaranteed wipe (mirrors fips.secureZero). std's
    /// secureZero uses volatile writes the optimizer cannot elide.
    pub fn secureZero(buf: []u8) void {
        std.crypto.secureZero(u8, buf);
    }
    ```

  - `templates/crypto_backend.zig`: add `pub const secureZero = backend.secureZero;`.
  - `src/std_shim.zig` `generate` (~line 300): `var seed: [64]u8 = undefined; defer secureZero(&seed); randomBytes(&seed);`.
  - `src/std_shim.zig` `hke` (~line 176): `var prk_arr: [H.prk_length]u8 = undefined; defer secureZero(&prk_arr); @memcpy(...)`.
  - `src/kem.zig` `decapsulate`: on the `if (ss_len > ss_out.len) return error.OpensslFailure;` path the secret hasn't been written yet; after the second `EVP_PKEY_decapsulate`, no error path leaves a secret — but add `errdefer` protection: wrap the final write so any future early-return wipes `ss_out`. Minimal concrete change: after computing `ss_len` and before returning, nothing leaks; add a doc comment that callers MUST `secureZero(ss_out[0..ss_len])` when done, and demonstrate it in the KEM tests (Task 13). (No functional bug today; the deliverable is the wipe primitive + caller contract.)

- [ ] **Step 4 — Add parity tests.** In `tests/shim_parity.zig` add:

    ```zig
    test "shim secureZero wipes buffer" {
        var buf = [_]u8{0x7e} ** 32;
        std_shim.secureZero(&buf);
        try std.testing.expect(std.mem.allEqual(u8, &buf, 0));
    }
    ```

  In `tests/seam_template_test.zig` assert `@hasDecl(crypto_backend, "secureZero")`.

- [ ] **Step 5 — Run + commit:** `make test-dual` green; `zig fmt`; commit `feat(seam): add secureZero memory-wipe primitive to both backends and wipe shim key buffers`.

---

### Task 4: `timingSafeEql` constant-time comparison primitive

Closes F2 / SEC-1005 / GAP-0021(b). Same shape as Task 3.

**Files:**

- Modify: `src/util.zig`, `src/root.zig`, `src/std_shim.zig`, `templates/crypto_backend.zig`
- Modify: `src/csprng.zig` (test at line 22 uses `std.mem.eql` on random draws), `src/kem.zig` (tests at 77/87 compare secrets) — switch secret comparisons to the new primitive to model correct usage
- Test: `src/util.zig`, `tests/shim_parity.zig`, `tests/seam_template_test.zig`

**Interfaces:**

- Produces: `pub fn timingSafeEql(a: []const u8, b: []const u8) bool` as `fips.timingSafeEql`, `std_shim.timingSafeEql`, `crypto_backend.timingSafeEql`. Returns false on length mismatch; otherwise compares all bytes in constant time.

- [ ] **Step 1 — Write failing test** in `src/util.zig`:

```zig
test "timingSafeEql matches on equal, differs on any byte or length" {
    const a = [_]u8{ 1, 2, 3, 4 };
    try std.testing.expect(timingSafeEql(&a, &a));
    const b = [_]u8{ 1, 2, 3, 5 };
    try std.testing.expect(!timingSafeEql(&a, &b));
    try std.testing.expect(!timingSafeEql(&a, a[0..3]));
}
```

- [ ] **Step 2 — Run, expect FAIL** (`timingSafeEql` undefined): `make test-fips`.

- [ ] **Step 3 — Implement.**
  - `src/util.zig`:

    ```zig
    /// Constant-time equality for secret byte slices (MAC/tag/secret
    /// confirmation values). Returns false on length mismatch (length is
    /// not secret); otherwise the byte comparison is constant-time.
    pub fn timingSafeEql(a: []const u8, b: []const u8) bool {
        if (a.len != b.len) return false;
        return c.CRYPTO_memcmp(a.ptr, b.ptr, a.len) == 0;
    }
    ```

  - `src/std_shim.zig`:

    ```zig
    pub fn timingSafeEql(a: []const u8, b: []const u8) bool {
        if (a.len != b.len) return false;
        var diff: u8 = 0;
        for (a, b) |x, y| diff |= x ^ y;
        return diff == 0;
    }
    ```

  - `src/root.zig`: `pub const timingSafeEql = @import("util.zig").timingSafeEql;`
  - `templates/crypto_backend.zig`: `pub const timingSafeEql = backend.timingSafeEql;`
  - `src/csprng.zig` test: replace `!std.mem.eql(u8, &a, &b)` with `!@import("util.zig").timingSafeEql(&a, &b)`.
  - `src/kem.zig` tests: replace `expectEqualSlices` shared-secret comparisons with `try std.testing.expect(@import("util.zig").timingSafeEql(ss_a[0..e.ss_len], ss_b[0..d]))`.

- [ ] **Step 4 — Parity tests** in `tests/shim_parity.zig` (mirror the util test against `std_shim.timingSafeEql`) and `@hasDecl` check in `tests/seam_template_test.zig`.

- [ ] **Step 5 — Run + commit:** `make test-dual` green; `zig fmt`; commit `feat(seam): add constant-time timingSafeEql to both backends`.

---

### Task 5: RSA verify key-strength floor + key-type binding

Closes SEC-1003. Reject undersized RSA keys on import and bind verify to the expected key type/curve so an attacker-supplied weak/mismatched key cannot satisfy a verify.

**Files:**

- Modify: `src/sig.zig` (`fromRsaComponents` ~121-146, `fromRsaSpki` ~110-115, `fromPublicBytes`/`fromPrivateBytes` `.der` family ~84-101; `verifyRsa` ~220-245, `verifyEcdsa` ~254-279)
- Test: `src/sig.zig`

**Interfaces:**

- Produces: RSA imports reject keys with `EVP_PKEY_get_bits < 2048` (`error.Unsupported`). `verifyRsa` rejects a non-RSA key (`error.Unsupported`); `verifyEcdsa` rejects a non-EC key or a key whose group ≠ `alg`'s curve (`error.Unsupported`).

- [ ] **Step 1 — Write failing tests** in `src/sig.zig`:

```zig
test "verifyRsa rejects a non-RSA key" {
    var ec = try Sig.generate(.ecdsa_p256);
    defer ec.deinit();
    try std.testing.expectError(error.Unsupported, Sig.verifyRsa(.pkcs1, .sha256, &ec, "x", "y"));
}

test "fromRsaComponents rejects an undersized (1024-bit) modulus" {
    // 1024-bit modulus (128 bytes) with exponent 65537 — must be rejected.
    const n = [_]u8{0xC0} ++ [_]u8{0xFF} ** 126 ++ [_]u8{0x01}; // 128 bytes, high bit set
    const e = [_]u8{ 0x01, 0x00, 0x01 };
    try std.testing.expectError(error.Unsupported, Sig.KeyPair.fromRsaComponents(&n, &e));
}

test "verifyEcdsa rejects a curve/alg mismatch" {
    var p256 = try Sig.generate(.ecdsa_p256);
    defer p256.deinit();
    try std.testing.expectError(error.Unsupported, Sig.verifyEcdsa(.ecdsa_p384, .sha384, &p256, "x", "y"));
}
```

- [ ] **Step 2 — Run, expect FAIL:** `make test-fips`.

- [ ] **Step 3 — Implement.** Add a private helper and apply it:

```zig
const min_rsa_bits = 2048;

fn assertRsaStrength(pkey: *c.EVP_PKEY) Error!void {
    if (c.EVP_PKEY_is_a(pkey, "RSA") != 1) return error.Unsupported;
    if (c.EVP_PKEY_get_bits(pkey) < min_rsa_bits) return error.Unsupported;
}
```

- In `fromRsaComponents`, before `return .{ .pkey = ... }`: `const k = pkey orelse return error.OpensslFailure; try assertRsaStrength(k); return .{ .pkey = k };` (wipe/free `k` on the error path via `errdefer c.EVP_PKEY_free(k);`).
- In `fromRsaSpki` and the `.der` branch of `fromPublicBytes`/`fromPrivateBytes` when `sigIsRsa(alg)` is true (note: `d2i_PUBKEY` can yield RSA or EC): after building `pkey`, if it is RSA enforce strength. Concretely in `fromRsaSpki`: `const k = c.d2i_PUBKEY(...) orelse return error.OpensslFailure; errdefer c.EVP_PKEY_free(k); try assertRsaStrength(k); return .{ .pkey = k };`. For `fromPublicBytes`/`fromPrivateBytes` `.der` family, only enforce when `sigIsRsa(alg)`.
- In `verifyRsa`, first line after `provider.assertActive();`: `try assertRsaStrength(kp.pkey);`.
- In `verifyEcdsa`, after the existing `alg` switch validates `ecdsa_p*`, add a key-type/curve binding:

  ```zig
  if (c.EVP_PKEY_is_a(kp.pkey, "EC") != 1) return error.Unsupported;
  // group name must match the requested curve
  var gname: [32]u8 = undefined;
  var glen: usize = 0;
  if (c.EVP_PKEY_get_utf8_string_param(kp.pkey, c.OSSL_PKEY_PARAM_GROUP_NAME, &gname, gname.len, &glen) != 1) return error.Unsupported;
  if (!std.mem.eql(u8, gname[0..glen], ecGroup(alg))) return error.Unsupported;
  ```

  (`ecGroup` returns the OpenSSL group string `P-256`/`P-384`/`P-521`.)

- [ ] **Step 4 — Run, expect PASS:** `make test-fips` (all existing sig KATs still green — they use ≥2048-bit RSA and matching curves). `make test-shim` unaffected (shim RSA is Unsupported anyway).

- [ ] **Step 5 — Commit:** `fix(sig): enforce RSA-2048 floor and key-type/curve binding on verify`.

---

### Task 6: Reject oversized lengths before narrowing `usize`→`c_int` in FFI

Closes F5 / SEC-1007. Prevent silent truncation/UB in `ReleaseFast` when a length exceeds `c_int`.

**Files:**

- Modify: `src/aead.zig` (casts at ~31,36,39,42,43,64,69,72,75), `src/sig.zig` (`@intCast(raw.len)`/`@intCast(der.len)`/`@intCast(n.len)`/`@intCast(e.len)` at ~86,100,113,128,130), `src/kdf.zig` (`@intCast(iters)` is fine — `iters` is u32; the octet-string lengths pass `usize` directly so OK)
- Test: `src/aead.zig`

**Interfaces:**

- Produces: any AEAD/sig input slice whose `.len > maxInt(c_int)` returns `error.OpensslFailure` rather than truncating.

- [ ] **Step 1 — Write failing test** (length-only, no 2 GiB allocation — use a fake-wide slice via `@as`): in `src/aead.zig`:

```zig
test "Aead rejects an associated-data slice longer than c_int" {
    // Construct a slice with an impossible length without allocating it,
    // to exercise the guard (never dereferenced — the guard returns first).
    const huge: usize = @as(usize, std.math.maxInt(c_int)) + 1;
    var one: [1]u8 = .{0};
    const ad: []const u8 = one[0..1].ptr[0..huge]; // len > c_int, never read
    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 12;
    var ct: [0]u8 = undefined;
    var tag: [16]u8 = undefined;
    try std.testing.expectError(error.OpensslFailure, Aead.seal(.aes_256_gcm, &key, &iv, ad, "", &ct, &tag));
}
```

- [ ] **Step 2 — Run, expect FAIL** (or panic in safe mode): `make test-fips`.

- [ ] **Step 3 — Implement.** Add a helper in `src/aead.zig` and a sibling in `src/sig.zig`:

```zig
fn toCInt(len: usize) Aead.Error!c_int { // sig.zig: Sig.Error
    if (len > std.math.maxInt(c_int)) return error.OpensslFailure;
    return @intCast(len);
}
```

Replace each `@intCast(x.len)` feeding an OpenSSL `int` length parameter with `try toCInt(x.len)`. (Leave `@intCast(outl)` offsets — those are bounded by the just-validated input — and `tag.len`/`nonce.len`, already length-checked in Task 1, but routing them through `toCInt` is harmless and uniform.)

- [ ] **Step 4 — Run, expect PASS:** `make test-dual` green.

- [ ] **Step 5 — Commit:** `fix(ffi): reject input lengths exceeding c_int before narrowing`.

---

### Task 7: `Hash.Stream.update` returns an error (no panic) + `clone` up-refs the digest

Closes F6 / QUAL-0011 / QUAL-0018 (panic→error) and PERF-0004 (clone re-fetch→up_ref).

**Files:**

- Modify: `src/hash.zig` (`Stream.update` ~58-60, `Stream.clone` ~73-80, doc comment ~53-57), `src/std_shim.zig` (`Stream.update` ~89-93), `src/hash.zig` tests + `tests/shim_parity.zig` call sites (add `try`)
- Test: `src/hash.zig`

**Interfaces:**

- Produces: `pub fn update(self: *Stream, bytes: []const u8) Error!void` in BOTH backends (was `void`). `clone` no longer calls `EVP_MD_fetch`.

- [ ] **Step 1 — Update doc + signature (fips), expect existing tests to FAIL to compile** until call sites add `try`:
  - `src/hash.zig` `update`:

    ```zig
    /// Absorb `bytes` into the running digest. Returns error.OpensslFailure
    /// if the provider update fails (e.g. provider error under memory
    /// pressure) — a network-facing transcript must fail the connection,
    /// not the process.
    pub fn update(self: *Stream, bytes: []const u8) Error!void {
        if (c.EVP_DigestUpdate(self.ctx, bytes.ptr, bytes.len) != 1) return error.OpensslFailure;
    }
    ```

  - `src/hash.zig` `clone` — replace the `EVP_MD_fetch(...)` line with an up-ref:

    ```zig
    pub fn clone(self: *Stream) Error!Stream {
        if (c.EVP_MD_up_ref(self.md) != 1) return error.OpensslFailure;
        errdefer c.EVP_MD_free(self.md);
        const ctx = c.EVP_MD_CTX_dup(self.ctx) orelse return error.OpensslFailure;
        return .{ .md = self.md, .ctx = ctx };
    }
    ```

  - `src/std_shim.zig` `update`:

    ```zig
    pub fn update(self: *Stream, bytes: []const u8) Error!void {
        switch (self.state) {
            inline else => |*h| h.update(bytes),
        }
    }
    ```

- [ ] **Step 2 — Fix call sites:** add `try` to every `s.update(...)` / `clone.update(...)` in `src/hash.zig` tests (lines ~119-122,139-140,156,162-163,182-183) and any in `tests/shim_parity.zig`. Run `make test-dual`, expect FAIL first if any site missed (compile error), then green once all have `try`.

- [ ] **Step 3 — Add a clone-correctness assertion** (guards the up_ref change) — the existing `src/hash.zig:136` "clone finalizes identically" test already covers it; confirm it passes.

- [ ] **Step 4 — Run, expect PASS:** `make test-dual` green.

- [ ] **Step 5 — Commit:** `fix(hash): make Stream.update fallible and up-ref MD on clone`.

---

### Task 8: PBKDF2 enforces SP 800-132 minimums in production

Closes F7 / SEC-1009. The public `pbkdf2` enforces `iters >= 1000` and `salt.len >= 16`; the RFC short-vector KAT moves to an internal relaxed path.

**Files:**

- Modify: `src/kdf.zig` (`pbkdf2` ~52-73; add internal `pbkdf2Derive`), `src/std_shim.zig` (`pbkdf2` ~181-190)
- Test: `src/kdf.zig` (adjust the c=1 KAT to call the internal path; add a rejection test); check `tests/shim_parity.zig` for a pbkdf2 c<1000 KAT and relax it if present.

**Interfaces:**

- Produces: public `pbkdf2(hash, password, salt, iters, out)` returns `error.OpensslFailure` if `iters < 1000` or `salt.len < 16` (both backends).

- [ ] **Step 1 — Read `tests/shim_parity.zig`** to learn whether it has a pbkdf2 vector with `iters < 1000` / `salt.len < 16`. If yes, that assertion must move to the relaxed internal path / a compliant vector (note it in the commit).

- [ ] **Step 2 — Write failing test** in `src/kdf.zig`:

```zig
test "pbkdf2 rejects sub-FIPS iteration count and short salt" {
    var out: [32]u8 = undefined;
    try std.testing.expectError(error.OpensslFailure, Kdf.pbkdf2(.sha256, "pw", "0123456789abcdef", 999, &out));
    try std.testing.expectError(error.OpensslFailure, Kdf.pbkdf2(.sha256, "pw", "shortsalt", 100_000, &out));
}
```

- [ ] **Step 3 — Run, expect FAIL:** `make test-fips`.

- [ ] **Step 4 — Implement.** In `src/kdf.zig` split the derive core out and add the guard:

```zig
pub fn pbkdf2(hash: policy.Hash, password: []const u8, salt: []const u8, iters: u32, out: []u8) Error!void {
    // SP 800-132: >= 1000 iterations, >= 128-bit salt.
    if (iters < 1000 or salt.len < 16) return error.OpensslFailure;
    return pbkdf2Derive(hash, password, salt, iters, out, false);
}

/// PKCS5=1 (relax FIPS lower-bound checks) is used ONLY by the RFC 6070/7914
/// known-answer tests, which use c=1 / short salts by design.
fn pbkdf2Derive(hash: policy.Hash, password: []const u8, salt: []const u8, iters: u32, out: []u8, relax: bool) Error!void {
    provider.assertActive();
    const kdf = c.EVP_KDF_fetch(provider.libCtx(), "PBKDF2", "fips=yes") orelse return error.OpensslFailure;
    defer c.EVP_KDF_free(kdf);
    const ctx = c.EVP_KDF_CTX_new(kdf) orelse return error.OpensslFailure;
    defer c.EVP_KDF_CTX_free(ctx);
    var iter: c_int = @intCast(iters);
    var pkcs5: c_int = if (relax) 1 else 0;
    var params = [_]c.OSSL_PARAM{
        c.OSSL_PARAM_construct_octet_string(c.OSSL_KDF_PARAM_PASSWORD, @constCast(password.ptr), password.len),
        c.OSSL_PARAM_construct_octet_string(c.OSSL_KDF_PARAM_SALT, @constCast(salt.ptr), salt.len),
        c.OSSL_PARAM_construct_int(c.OSSL_KDF_PARAM_ITER, &iter),
        c.OSSL_PARAM_construct_utf8_string(c.OSSL_KDF_PARAM_DIGEST, @constCast(policy.hashName(hash).ptr), 0),
        c.OSSL_PARAM_construct_int(c.OSSL_KDF_PARAM_PKCS5, &pkcs5),
        c.OSSL_PARAM_construct_end(),
    };
    if (c.EVP_KDF_derive(ctx, out.ptr, out.len, &params) != 1) return error.OpensslFailure;
}
```

Change the existing RFC 7914 c=1 KAT (`kdf.zig:107-118`) to call `pbkdf2Derive(.sha256, "passwd", "salt", 1, &out, true)`.

In `src/std_shim.zig` `pbkdf2`, add the same guard as the first line: `if (iters < 1000 or salt.len < 16) return error.OpensslFailure;`. If `tests/shim_parity.zig` has a c=1 PBKDF2 KAT, change it to assert the rejection (or to a compliant vector).

- [ ] **Step 5 — Run + commit:** `make test-dual` green; commit `fix(kdf): enforce SP 800-132 PBKDF2 minimums in production path`.

---

### Task 9: Cross-platform, errno-correct CSPRNG in the shim

Closes SEC-1015 / GAP-0027. Replace the Linux-only `getrandom` busy-loop with the portable std CSPRNG.

**Files:**

- Modify: `src/std_shim.zig` (`randomBytes` ~17-29)

**Interfaces:**

- Produces: `randomBytes(out)` fills `out` from a cryptographically secure, OS-seeded PRNG on Linux/macOS/Windows; no busy-loop, no `std.os.linux` dependency.

- [ ] **Step 1 — Implement** (this path is exercised by the existing `shim Csprng yields distinct draws` parity test, so it is the regression guard):

```zig
fn randomBytes(out: []u8) void {
    // Non-fips shim CSPRNG: Zig's std.crypto CSPRNG (OS-seeded, ChaCha-based),
    // portable across Linux/macOS/Windows. The FIPS backend uses the
    // validated DRBG instead (src/csprng.zig).
    std.crypto.random.bytes(out);
}
```

- [ ] **Step 2 — Run, expect PASS:** `make test-shim` (the distinct-draws + keygen tests still pass) and confirm the shim still compiles with no `std.os.linux` reference: `grep -n "std.os.linux" src/std_shim.zig` returns nothing.

- [ ] **Step 3 — Commit:** `fix(shim): use portable std.crypto CSPRNG instead of Linux-only getrandom`.

---

### Task 10: Make `ecGroup` total (no `unreachable` UB)

Closes QUAL-0016. `ecGroup` currently has `else => unreachable` over a 21-variant enum.

**Files:**

- Modify: `src/sig.zig` (`ecGroup` ~28-35; callers `generate` ~162, `verifyEcdsa` Task 5 addition)

- [ ] **Step 1 — Implement.** Make `ecGroup` return an error for non-EC algs and thread it:

```zig
fn ecGroup(alg: policy.SigAlg) Sig.Error![:0]const u8 {
    return switch (alg) {
        .ecdsa_p256 => "P-256",
        .ecdsa_p384 => "P-384",
        .ecdsa_p521 => "P-521",
        else => error.Unsupported,
    };
}
```

Update callers: `generate` uses `@constCast((try ecGroup(alg)).ptr)`; the Task-5 `verifyEcdsa` group check uses `try ecGroup(alg)`. (Both are only reached for `ecdsa_p*` so behavior is unchanged; the `unreachable` UB is removed.)

- [ ] **Step 2 — Run + commit:** `make test-fips` green; commit `refactor(sig): make ecGroup total to remove unreachable UB`.

---

## Phase B — Test coverage

### Task 11: SLH-DSA — KATs for all 12 approved variants

Closes GAP-0023. Today only `slh_dsa_sha2_128s` is tested (`sig.zig:402`).

**Files:** Test: `src/sig.zig` (append)

- [ ] **Step 1 — Add a table-driven test** (SLH-DSA signatures are large — up to ~50 KB for 256f — so allocate on the heap; SLH-DSA `s` variants are slow to sign, which is expected):

```zig
test "SLH-DSA all 12 variants sign->verify + tamper" {
    const variants = [_]policy.SigAlg{
        .slh_dsa_sha2_128s, .slh_dsa_sha2_128f, .slh_dsa_sha2_192s, .slh_dsa_sha2_192f,
        .slh_dsa_sha2_256s, .slh_dsa_sha2_256f, .slh_dsa_shake_128s, .slh_dsa_shake_128f,
        .slh_dsa_shake_192s, .slh_dsa_shake_192f, .slh_dsa_shake_256s, .slh_dsa_shake_256f,
    };
    const a = std.testing.allocator;
    const sig = try a.alloc(u8, 64 * 1024);
    defer a.free(sig);
    for (variants) |alg| {
        var kp = try Sig.generate(alg);
        defer kp.deinit();
        const n = try Sig.sign(alg, &kp, "slh-dsa kat", sig);
        try Sig.verify(alg, &kp, "slh-dsa kat", sig[0..n]);
        try std.testing.expectError(error.VerifyFailed, Sig.verify(alg, &kp, "tampered", sig[0..n]));
    }
}
```

- [ ] **Step 2 — Run + commit:** `make test-fips` green (may take longer due to `s` variants); commit `test(sig): cover all 12 SLH-DSA variants`.

---

### Task 12: ML-DSA — KATs for 44 and 87

Closes GAP-0024. Today only `ml_dsa_65` is tested.

**Files:** Test: `src/sig.zig` (append)

- [ ] **Step 1 — Add:**

```zig
test "ML-DSA-44 and ML-DSA-87 sign->verify + tamper" {
    inline for (.{ policy.SigAlg.ml_dsa_44, policy.SigAlg.ml_dsa_87 }) |alg| {
        var kp = try Sig.generate(alg);
        defer kp.deinit();
        var sig: [8192]u8 = undefined;
        const n = try Sig.sign(alg, &kp, "ml-dsa kat", &sig);
        try Sig.verify(alg, &kp, "ml-dsa kat", sig[0..n]);
        try std.testing.expectError(error.VerifyFailed, Sig.verify(alg, &kp, "x", sig[0..n]));
    }
}
```

- [ ] **Step 2 — Run + commit:** `make test-fips` green; commit `test(sig): cover ML-DSA-44 and ML-DSA-87`.

---

### Task 13: ECDSA P-521 + remaining KEM variants (hybrids, ML-KEM-512/1024)

Closes GAP-0025. P-521 and three hybrids + ML-KEM-512/1024 are unexercised in the fips backend.

**Files:** Test: `src/sig.zig`, `src/kem.zig` (append)

- [ ] **Step 1 — ECDSA P-521** (`src/sig.zig`):

```zig
test "ECDSA P-521 sign->verify + tamper" {
    var kp = try Sig.generate(.ecdsa_p521);
    defer kp.deinit();
    var sig: [180]u8 = undefined;
    const n = try Sig.sign(.ecdsa_p521, &kp, "p521 msg", &sig);
    try Sig.verify(.ecdsa_p521, &kp, "p521 msg", sig[0..n]);
    try std.testing.expectError(error.VerifyFailed, Sig.verify(.ecdsa_p521, &kp, "x", sig[0..n]));
}
```

- [ ] **Step 2 — KEM variants** (`src/kem.zig`) — table-driven over the remaining algs, demonstrating the `secureZero` shared-secret wipe contract from Task 3:

```zig
test "all KEM variants encap/decap agree" {
    const util = @import("util.zig");
    const algs = [_]policy.KemAlg{
        .ml_kem_512, .ml_kem_1024, .x448_ml_kem_1024,
        .secp256r1_ml_kem_768, .secp384r1_ml_kem_1024,
    };
    for (algs) |alg| {
        var kp = try Kem.generate(alg);
        defer kp.deinit();
        var ct: [4096]u8 = undefined;
        var ss_a: [64]u8 = undefined;
        var ss_b: [64]u8 = undefined;
        defer util.secureZero(&ss_a);
        defer util.secureZero(&ss_b);
        const e = try Kem.encapsulate(alg, &kp, &ct, &ss_a);
        const d = try Kem.decapsulate(alg, &kp, ct[0..e.ct_len], &ss_b);
        try std.testing.expect(util.timingSafeEql(ss_a[0..e.ss_len], ss_b[0..d]));
    }
}
```

- [ ] **Step 3 — Run + commit:** `make test-fips` green; commit `test(sig,kem): cover P-521, hybrid KEMs, and ML-KEM-512/1024`.

---

### Task 14: FIPS-backend error-path tests

Closes QUAL-0013. Each `Error` member should have a negative test.

**Files:** Test: `src/hash.zig`, `src/mac.zig`, `src/kdf.zig`, `src/kem.zig`, `src/csprng.zig` (append a small negative test each)

- [ ] **Step 1 — Add buffer-too-small / Unsupported tests**, e.g.:
  - `src/hash.zig`: `try std.testing.expectError(error.OpensslFailure, Hash.digest(.sha256, "abc", buf[0..16]));` (16 < 32).
  - `src/mac.zig`: HMAC into a 16-byte `out` for SHA-256 → `error.OpensslFailure`.
  - `src/kdf.zig`: `hkdf` with `out` longer than `255*HashLen` → expect error from the EVP path (`error.OpensslFailure`).
  - `src/kem.zig`: `encapsulate` with a `ct_out`/`ss_out` too small → `error.OpensslFailure`.
  - `src/csprng.zig`: covered by existing draw test; add a zero-length `bytes(&.{})` succeeds.

- [ ] **Step 2 — Run + commit:** `make test-fips` green; commit `test: add fips-backend error-path coverage`.

---

### Task 15: Real integration + stress tests

Closes QUAL-0014. Replace the version-string placeholders.

**Files:** Modify: `tests/integration.zig`, `tests/stress.zig`

- [ ] **Step 1 — Integration** (`tests/integration.zig`) — exercise each family end-to-end through the `fips` module surface:

```zig
test "integration: hash + hmac + hkdf + aead round-trip through the module surface" {
    var dg: [32]u8 = undefined;
    _ = try lib.Hash.digest(.sha256, "abc", &dg);
    var mac: [32]u8 = undefined;
    _ = try lib.Mac.hmac(.sha256, "key", "abc", &mac);
    var okm: [32]u8 = undefined;
    try lib.Kdf.hkdf(.sha256, "ikm-bytes-0123456789", "salt-bytes-0123456789", "info", &okm);
    const key = [_]u8{7} ** 32;
    const iv = [_]u8{9} ** 12;
    const msg = "integration message";
    var ct: [msg.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    try lib.Aead.seal(.aes_256_gcm, &key, &iv, "ad", msg, &ct, &tag);
    var pt: [msg.len]u8 = undefined;
    try lib.Aead.open(.aes_256_gcm, &key, &iv, "ad", &ct, &tag, &pt);
    try std.testing.expectEqualSlices(u8, msg, &pt);
}

test "integration: ed25519 + ml-kem-768 through the module surface" {
    var kp = try lib.Sig.generate(.ed25519);
    defer kp.deinit();
    var sig: [64]u8 = undefined;
    const n = try lib.Sig.sign(.ed25519, &kp, "m", &sig);
    try lib.Sig.verify(.ed25519, &kp, "m", sig[0..n]);
    var kem = try lib.Kem.generate(.ml_kem_768);
    defer kem.deinit();
    var c2: [2048]u8 = undefined;
    var ssa: [64]u8 = undefined;
    var ssb: [64]u8 = undefined;
    const e = try lib.Kem.encapsulate(.ml_kem_768, &kem, &c2, &ssa);
    const d = try lib.Kem.decapsulate(.ml_kem_768, &kem, c2[0..e.ct_len], &ssb);
    try std.testing.expect(lib.timingSafeEql(ssa[0..e.ss_len], ssb[0..d]));
}
```

- [ ] **Step 2 — Stress** (`tests/stress.zig`) — many AEAD round-trips + a multi-threaded crypto loop (complements the Task-2 init race test; surfaces steady-state races under `-Dtsan`):

```zig
test "stress: 50k AES-256-GCM round-trips stay correct" {
    const key = [_]u8{0x5a} ** 32;
    const msg = "stress payload block";
    var i: usize = 0;
    while (i < 50_000) : (i += 1) {
        var iv = [_]u8{0} ** 12;
        std.mem.writeInt(u32, iv[0..4], @intCast(i), .little);
        var ct: [msg.len]u8 = undefined;
        var tag: [16]u8 = undefined;
        try lib.Aead.seal(.aes_256_gcm, &key, &iv, "", msg, &ct, &tag);
        var pt: [msg.len]u8 = undefined;
        try lib.Aead.open(.aes_256_gcm, &key, &iv, "", &ct, &tag, &pt);
        try std.testing.expectEqualSlices(u8, msg, &pt);
    }
}

test "stress: concurrent hashing across threads" {
    const builtin = @import("builtin");
    if (builtin.single_threaded) return error.SkipZigTest;
    const Worker = struct {
        fn run() void {
            var i: usize = 0;
            while (i < 5_000) : (i += 1) {
                var out: [32]u8 = undefined;
                _ = lib.Hash.digest(.sha256, "concurrent", &out) catch unreachable;
            }
        }
    };
    var threads: [8]std.Thread = undefined;
    for (&threads) |*t| t.* = std.Thread.spawn(.{}, Worker.run, .{}) catch unreachable;
    for (&threads) |*t| t.join();
}
```

Note: `tests/stress.zig` is wired with an OpenSSL link in `build.zig:128-135`, so `lib.*` crypto calls work. Keep the `lib` import.

- [ ] **Step 3 — Run + commit:** `make test-fips` (runs integration) and `zig build test-stress -Dopenssl_path=/usr/local/ssl` green; also `-Dtsan` clean. Commit `test: real integration + stress crypto coverage`.

---

## Phase C — Documentation reconciliation

### Task 16: Rewrite README to match reality

Closes QUAL-0001 / GAP-0026. Remove `fips.init`, the CLI, "zero dependencies", `-Dno-cli`, `make run`.

**Files:** Modify: `README.md`

- [ ] **Step 1 — Replace** the Features, Quick Start, Building, and any CLI/`-Dno-cli`/`make run` content with accurate text: it is a **library** crypto seam (no CLI); it links **OpenSSL 3.x FIPS provider** under `-Dfips=true` (not zero-dependency — the non-fips shim is std-only, the fips backend needs OpenSSL); the real API is `Hash`/`Mac`/`Kdf`/`Aead`/`Sig`/`Kem`/`Csprng`/`secureZero`/`timingSafeEql`/`assertActive` via `@import("fips")` or the `crypto_backend` seam. Use a real quick-start (e.g. an AES-256-GCM round-trip or `Hash.digest`). Document `make test-dual`, `-Dfips`, `-Dopenssl_path`, `make deps`, `-Dtsan`. Remove the `## Requirements: Zig only` line; state Zig 0.16 + OpenSSL 3.x (≥3.5) for fips mode. Keep badges/license/security sections.

- [ ] **Step 2 — Verify** every command/snippet in the README is real: `grep -nE "fips\.init|no-cli|build run|Zero dependencies" README.md` returns nothing; each `make`/`zig build` target named exists in `Makefile`/`build.zig`.

- [ ] **Step 3 — Commit:** `docs(readme): rewrite to match the real library/seam/OpenSSL surface`.

---

### Task 17: Fill in the CHANGELOG

Closes QUAL-0017 / GAP-0029.

**Files:** Modify: `CHANGELOG.md`

- [ ] **Step 1 — Replace** the `[0.1.0] - YYYY-MM-DD` placeholder with a dated `0.1.0` entry enumerating the delivered features from `git log` (FIPS provider self-test, comptime approved-algorithm policy, Hash/Mac/Kdf incl. hkdfExpand, AEAD AES-GCM, CSPRNG SP800-90A, ECDSA/RSA-PSS/Ed25519 + KATs, ML-DSA/SLH-DSA + interop, ML-KEM + hybrids, streaming Hash.Stream, classical VERIFY routed through the FIPS seam, dual-mode CI gate, GAP-0020 dedup rule) plus this round's hardening (secureZero, timingSafeEql, AEAD length validation, thread-safe init, RSA verify floor). Use the date from the environment (`2026-06-22`). No `YYYY-MM-DD` placeholder remains.

- [ ] **Step 2 — Commit:** `docs(changelog): populate 0.1.0 from delivered features`.

---

### Task 18: Reconcile SEAM_CONTRACT + FIPS_SPECIFICATION + policy with reality

Closes QUAL-0019 (encoding/`alg` caveats), GAP-0022 (ZL109 over-claim), GAP-0028 (AES-256-CBC), and the doc half of SEC-1011 (nonce-reuse guidance) + SEC-1016 (Unsupported-must-not-fall-back note).

**Files:** Modify: `docs/SEAM_CONTRACT.md`, `docs/FIPS_SPECIFICATION.md`, `src/policy.zig` (comment), `SECURITY.md`

- [ ] **Step 1 — SEAM_CONTRACT.md §2:** add the new pinned symbols `secureZero`, `timingSafeEql`. Add a "Cross-backend caveats" subsection documenting: (a) public-key encodings differ by backend for ECDSA (fips: SPKI-DER via `d2i_PUBKEY`; shim: compressed SEC1) — keys are NOT byte-portable across `-Dfips`; consumers must re-import per backend; (b) the shim's `Sig.sign`/`verify` derive the algorithm from the stored key (the `alg` arg is advisory) while the fips backend uses `alg`; (c) `Aead` requires a 12-byte nonce and 16-byte tag in both backends; (d) `error.Unsupported`/`error.OpensslFailure` from a fips fetch MUST NOT be treated by a consumer as license to fall back to a non-FIPS algorithm (SEC-1016).

- [ ] **Step 2 — FIPS_SPECIFICATION.md:** the `secureZero`/`timing_safe` claim at `:256` is now TRUE (Tasks 3-4) — leave it but ensure the names match (`secureZero`, `timingSafeEql`). For the ZL109 / `zig-fips-lint` claims (`:26,109,229-247`): add a clarifying note that ZL109 is a workspace-level `ci-catalog` component applied across consumer repos and is NOT yet wired into THIS foundational repo's `.gitlab-ci.yml` (tracked as a deferred follow-up); the in-repo enforcement of record is the dual-mode (`make test-dual`) gate plus the comptime `policy.isApproved` allow-list. Do not claim "Verified" for an in-repo ZL109 job that does not exist.

- [ ] **Step 3 — policy.zig:** add a comment above `approved_names` clarifying it is the FIPS-approved *fetch-name allow-list* used by `isApproved` for comptime gating, and is intentionally a SUPERSET of the algorithms with dedicated wrappers in this seam (e.g. `AES-256-CBC` is approved for CBC+HMAC constructions a consumer may build, but this seam ships only AEAD GCM wrappers) — resolving GAP-0028 by documentation rather than a spurious CBC AEAD wrapper.

- [ ] **Step 4 — SECURITY.md:** add an "AES-GCM nonce handling" subsection: callers MUST supply a unique 12-byte nonce per (key, message); nonce reuse under a fixed key is catastrophic for GCM; recommend a counter or random 96-bit nonce with rekeying limits (SEC-1011 guidance).

- [ ] **Step 5 — Commit:** `docs: reconcile seam contract, FIPS spec, and policy with implementation`.

---

## Phase D — Performance

### Task 19: Real benchmark scenarios

Closes PERF-0006 / QUAL-0002. The bench suite currently spins on `lib.version.len`.

**Files:** Modify: `benchmarks/bench.zig` (and, if trivial, `benchmarks/scale.zig` / `benchmarks/micro/example.zig`)

- [ ] **Step 1 — Replace** the two placeholder scenarios with real ones calling `lib.*`: `sha256_64B`, `sha256_8KB`, `hmac_sha256_64B`, `hkdf_sha256_32B`, `aes256gcm_seal_64B`, `aes256gcm_seal_1350B` (TLS record size), `aes256gcm_open_1350B`, `ed25519_sign`, `ed25519_verify`, `ecdsa_p256_sign`, `mlkem768_encap`, `mlkem768_decap`, `csprng_32B`. Each scenario body performs the op `ops_per_iteration` times with fixed inputs (generate keys once outside the timed loop via `framework.Context` setup if the framework supports it; otherwise reuse a key created at scenario entry — keep keygen out of the hot loop). Use `std.mem.doNotOptimizeAway` on outputs. Honor the framework's `Scenario`/`Context` API already used in the file.

- [ ] **Step 2 — Verify it runs:** `OPENSSL_CONF=/usr/local/ssl/ssl/openssl.cnf zig build bench -Dopenssl_path=/usr/local/ssl -- --list` shows the new scenarios; `... -- --output /tmp/b.json` produces JSON.

- [ ] **Step 3 — Commit:** `perf(bench): replace placeholder scenarios with real crypto workloads`.

---

### Task 20: Thread-safe EVP fetch cache (one-shot hot-path cost)

Closes PERF-0001 (and reduces PERF-0002/0003 pressure). Cache `EVP_CIPHER`/`EVP_MD`/`EVP_MAC` fetched under `fips=yes` over the FIPS lib context so per-call ops skip the provider lookup. The cache stores the RESULT of a `fips=yes` fetch over the FIPS lib context (which has `EVP_default_properties_enable_fips` set), preserving the FIPS guarantee; it must NEVER fetch from the default lib context.

**Files:** Modify: `src/provider.zig` (add cache + accessors), `src/aead.zig` (use `provider.fetchCipher`), `src/hash.zig` (`provider.fetchMd`), `src/mac.zig` (`provider.fetchMac`)
**Depends on:** Task 2 (mutex) and Task 19 (to measure).

- [ ] **Step 1 — Measure baseline:** record `aes256gcm_seal_64B` + `sha256_64B` numbers from Task 19 (`zig build bench ... --output /tmp/before.json`).

- [ ] **Step 2 — Implement a small, mutex-guarded, name-keyed cache** in `src/provider.zig`. Because the approved algorithm set is small and fixed, a simple append-only list keyed by the (kind, name) string is sufficient; entries live for process lifetime (never freed — they are shared immutable provider objects):

```zig
const CacheEntry = struct { name: []const u8, ptr: ?*anyopaque };
var g_cipher_cache: std.BoundedArray(CacheEntry, 8) = .{};
var g_md_cache: std.BoundedArray(CacheEntry, 8) = .{};

pub fn fetchCipher(name: [:0]const u8) ?*c.EVP_CIPHER {
    g_mu.lock();
    defer g_mu.unlock();
    for (g_cipher_cache.slice()) |e| if (std.mem.eql(u8, e.name, std.mem.span(name.ptr))) return @ptrCast(e.ptr);
    const ci = c.EVP_CIPHER_fetch(ctxLocked(), name, "fips=yes") orelse return null;
    g_cipher_cache.append(.{ .name = std.mem.span(name.ptr), .ptr = ci }) catch {};
    return ci;
}
// fetchMd / fetchMac follow the same shape with EVP_MD_fetch / EVP_MAC_fetch.
```

(Use the actual 0.16 `std.BoundedArray` API; if absent, a fixed array + count. `name` strings come from `policy.*Name`, which are static `[:0]const u8`, so storing the span is safe.)

- [ ] **Step 3 — Switch call sites** in `aead.zig`/`hash.zig`/`mac.zig` from `c.EVP_*_fetch(...) orelse return error.* ; defer c.EVP_*_free(...)` to `provider.fetchCipher(...) orelse return error.*` (NO `defer free` — cached). Keep `Hash.Stream` using its own owned `md` (it dups/up-refs; do not cache there) OR have `Stream.init` use the cached md with `up_ref`; simplest: leave `Stream` as-is (Task 7 already up-refs on clone). The `digest` one-shot path uses `fetchMd`.

- [ ] **Step 4 — Run, expect PASS + measure:** `make test-dual` green (all KATs unaffected — same algorithm objects); `-Dtsan` clean (cache is mutex-guarded); `zig build bench ... --output /tmp/after.json` and confirm the per-call cost drops for `sha256_64B`/`aes256gcm_seal_64B`. Record the before/after in `docs/PERF_GAP_ANALYSIS.md`.

- [ ] **Step 5 — Commit:** `perf(provider): cache fips=yes EVP fetches to remove per-call provider lookup`.

---

## Phase E — Supply chain

### Task 21: Verify the OpenSSL release signature in the deps script

Closes SEC-1001 (and the integrity half of SEC-1014). Keep "always latest" — add cryptographic verification of whatever 3.x release is downloaded.

**Files:** Modify: `scripts/install-openssl-fips.sh`

- [ ] **Step 1 — Implement** download-then-verify before `tar xzf`: fetch the matching `.tar.gz.asc` (and/or the `.sha256`) from the same GitHub release, import the OpenSSL release signing keys (the OpenSSL Foundation OMC keys, or pin their fingerprints in the script), and `gpg --verify` the signature against the tarball; abort on failure. If `gpg` is unavailable, fall back to verifying a pinned SHA-256 obtained over TLS from the release `*.sha256` and FAIL CLOSED if neither verification can run. Mirror the structure already used in `scripts/install-zig.sh` (which the security review noted DOES verify). Add a `log` line stating which verification succeeded.

- [ ] **Step 2 — Smoke-test** the script's verification path on this host without reinstalling: run the resolve + download + verify steps against the current `${VER}` in a temp dir (do NOT `sudo make install`); confirm `gpg --verify` (or sha256) passes for a known-good tarball and fails for a corrupted one (flip a byte). Document the manual check in the commit message (the full `make deps` is environment-mutating and already validated by the running FIPS provider).

- [ ] **Step 3 — Commit:** `fix(deps): verify OpenSSL release signature/checksum before build (fail closed)`.

---

## Post-implementation: update tracking docs

### Task 22: Mark closed findings in the GAP_ANALYSIS docs

**Files:** Modify: `docs/GAP_ANALYSIS.md`, `docs/QUALITY_GAP_ANALYSIS.md`, `docs/PERF_GAP_ANALYSIS.md`, `docs/SECURITY_GAP_ANALYSIS.md`; Create: `docs/GAP_ANALYSIS_RESOLVED.md`

- [ ] **Step 1 — Move** each closed finding to a "Resolved" section / `GAP_ANALYSIS_RESOLVED.md` with the commit SHA and the test that now verifies it. Mark intentional deferrals (GAP-0030 publish swap; cross-OS FIPS runtime testing; SEC-1012 OPENSSL_CONF env — partially mitigated by the post-load self-test) as **Deferred** with rationale, NOT open. Leave genuinely-open items open.
- [ ] **Step 2 — Commit:** `docs: update gap-analysis tracking after round-1 closure`.

---

## Self-Review (completed during authoring)

- **Spec coverage:** every Round-1 finding maps to a task — F1→T3, F2→T4, F3/SEC-1002/QUAL-0006→T1, F4/SEC-1006/QUAL-0015/PERF-0005→T2, F5/SEC-1007→T6, F6/QUAL-0011/0018→T7, F7→T8, F8→T18(docs)+T2, SEC-1001→T21, SEC-1003→T5, SEC-1011→T1(len)+T18(docs), SEC-1013→T2, SEC-1015/GAP-0027→T9, SEC-1016→T18, GAP-0021→T3/T4, GAP-0022→T18, GAP-0023→T11, GAP-0024→T12, GAP-0025→T13, GAP-0026/QUAL-0001→T16, GAP-0028→T18, GAP-0029/QUAL-0017→T17, QUAL-0002/PERF-0006→T19, QUAL-0013→T14, QUAL-0014→T15, QUAL-0016→T10, QUAL-0019→T18, PERF-0001/0002/0003→T20, PERF-0004→T7. GAP-0030/SEC-1012/SEC-1014(deploy)/cross-OS → Deferred in T22 with rationale.
- **Type consistency:** `secureZero(buf: []u8) void` and `timingSafeEql(a,b) bool` used identically in T3/T4/T13/T15/T18; `fetchCipher/fetchMd/fetchMac` names consistent T20; `ecGroup` returns `Sig.Error![:0]const u8` after T10 and is consumed with `try` in T5/T10.
- **Error-set stability:** no task adds error-set members; all reuse `OpensslFailure`/`Unsupported`/`VerifyFailed`/`AuthFailed`, preserving backend parity by construction.
