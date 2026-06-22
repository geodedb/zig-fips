<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2024-2026 CodePros -->

# Security Gap Analysis — fips crypto-seam library

> **Round-1 closure applied 2026-06-22 on branch audit/round-1-hardening.**
> All findings are re-dispositioned below. Closed/resolved items have been
> moved to the "Resolved" section and to `docs/GAP_ANALYSIS_RESOLVED.md`.

- **Scope:** `src/*.zig`, `templates/crypto_backend.zig`, `build.zig`,
  `scripts/install-openssl-fips.sh`, `.gitlab-ci.yml`, `tests/*.zig`.
- **Review type:** Manual adversarial cross-check pass. Read-only. No
  source modified. No systems exploited.
- **Date:** 2026-06-22
- **Method:** Full read of all in-scope files (repo is ~2,062 LoC of
  Zig). Every finding cites `file:line`. Confidence is labeled
  `confirmed` (verified from source) or `suspected` (needs runtime/build
  confirmation; the confirming step is stated).
- **Confidentiality:** SEC-1003 (key-strength downgrade) and SEC-1001
  (supply-chain) are flagged **CONFIDENTIAL** — they describe concrete
  downgrade/tamper paths. No secrets appear in this document.

This library is a thin Zig seam over the OpenSSL 3.x FIPS provider. The
threat model that matters here is **misuse-by-consumer** (the seam hands
a foot-gun to a downstream caller) and **trusted-computing-base
integrity** (does the FIPS module that gets loaded actually correspond
to a validated, untampered artifact). Most findings are of those two
shapes, not classic web-app injection.

---

## Open (Deferred / Partial) Items

### SEC-1012 — Provider config loaded from attacker-influenced `OPENSSL_CONF` — DEFERRED

- **Status:** DEFERRED — standard OpenSSL trust model; all seam fetches
  pin `"fips=yes"` and the provider self-test runs regardless of config
  contents. Pinned-in-process config (ignoring `OPENSSL_CONF` entirely)
  is a larger architectural change, tracked here for a future hardening
  round.
- **Rationale:** Exploitability is gated by env trust boundary. The
  seam's `"fips=yes"` property string on every fetch provides a defense
  layer even with a hostile config. A hostile config would need to pass
  the FIPS provider self-test to succeed, which is a strong barrier.
- **Original severity:** Medium

### SEC-1014 — FIPS dual-mode CI gate rests on an unpinned deps job — PARTIALLY-CLOSED / DEFERRED

- **Status:** PARTIALLY-CLOSED — SEC-1001 (commit `d8661c1`) now verifies
  the OpenSSL tarball with SHA-256 + GPG before building, closing the
  download-integrity half. Narrowing the `/usr/local/ssl` CI artifact to
  exclude `fipsmodule.cnf` / MAC material is DEFERRED (infra change,
  no consumer currently relies on the artifact contents).
- **Commits:** `d8661c1` (supply-chain integrity gate)
- **Remaining:** Artifact scope narrowing (infra).
- **Original severity:** Medium

---

## Resolved Items

### SEC-1001 — Supply-chain: unpinned, unverified OpenSSL FIPS build — CLOSED

- **Status:** CLOSED — commit `d8661c1` adds SHA-256 + GPG signature
  verification for the OpenSSL tarball; `make deps` now fails closed on
  any mismatch before `tar`. The script pins the version and verifies
  against the OpenSSL release signing key bundled in-repo.
- **Commit:** `d8661c1`
- **Verifying tests:** `scripts/verify-fips-provider.sh`; CI `fips-deps`
  job fails on checksum mismatch.
- **Original severity:** High, CONFIDENTIAL

### SEC-1002 — AEAD `seal`/`open` missing length validation → OOB heap write — CLOSED

- **Status:** CLOSED — commit `80220f5` adds key/nonce/tag/output-buffer
  length validation before all EVP calls; `16eac47` mirrors parity with
  the shim and adds negative tests.
- **Commits:** `80220f5`, `16eac47`
- **Verifying tests:** `tests/aead.zig` (negative/boundary tests)
- **Original severity:** High (F3)

### SEC-1003 — RSA verify accepts weak/undersized key on import — CLOSED

- **Status:** CLOSED — commit `e08c480` adds `EVP_PKEY_get_bits >= 2048`
  floor on all RSA import paths and `EVP_PKEY_is_a` + curve-match
  assertions in `verifyRsa`/`verifyEcdsa`; undersized-key and type-mismatch
  tests added to `sig.zig`.
- **Commit:** `e08c480`
- **Verifying tests:** `tests/sig.zig` (weak-key, type-binding tests)
- **Original severity:** High, CONFIDENTIAL (suspected)

### SEC-1004 (F1) — No zeroization of secret material — CLOSED

- **Status:** CLOSED — commit `4eacfcf` introduces `secureZero` wrapping
  `OPENSSL_cleanse`; commit `16eac47` applies it to shim seed/PRK buffers
  and AEAD auth-fail wipe.
- **Commits:** `4eacfcf`, `16eac47`
- **Verifying tests:** `src/util.zig`, `tests/aead.zig`
- **Original severity:** High

### SEC-1005 (F2) — No constant-time comparison — CLOSED

- **Status:** CLOSED — commit `0668f00` adds `timingSafeEql` over
  `CRYPTO_memcmp` (fips) / `std.crypto.timing_safe.eql` (shim) to both
  backends.
- **Commit:** `0668f00`
- **Verifying tests:** parity test in shim + fips backends
- **Original severity:** Medium

### SEC-1006 (F4) — Unsynchronized provider globals — CLOSED

- **Status:** CLOSED — commit `db54ab2` guards `ensureFips`/`libCtx` init
  with a mutex; commit `1f25ebb` adds a lock-free fast path for steady-state
  checks. TSan concurrency test added to `provider.zig`.
- **Commits:** `db54ab2`, `1f25ebb`
- **Verifying tests:** `src/provider.zig` (TSan concurrency test)
- **Original severity:** Medium

### SEC-1007 (F5) — Length truncation to `c_int` — CLOSED

- **Status:** CLOSED — commit `91563c1` adds bound-checks for all
  `usize→c_int` narrowing sites; commit `16eac47` corrects overflow-guard
  typing, introducing `toCInt`/`toCLong` helpers in `ffi.zig`.
- **Commits:** `91563c1`, `16eac47`
- **Verifying tests:** `src/ffi.zig` (helpers + tests)
- **Original severity:** Low

### SEC-1008 (F6) — Stream.update panics on EVP failure — CLOSED

- **Status:** CLOSED — commit `9830b02` changes `Hash.Stream.update` to
  return `Error!void` (eliminating the `@panic`) and up-refs the MD on
  clone.
- **Commit:** `9830b02`
- **Verifying tests:** `src/hash.zig` tests
- **Original severity:** Low

### SEC-1009 (F7) — PBKDF2 disables FIPS minimums — CLOSED

- **Status:** CLOSED — commit `f22c4b9` enforces SP 800-132 minimums
  (salt, iterations, key length) in the production path; the `pkcs5=1`
  relaxed mode is gated behind an explicit test-only parameter.
- **Commit:** `f22c4b9`
- **Verifying tests:** `src/kdf.zig` tests
- **Original severity:** Low

### SEC-1010 (F8) — `assertActive()` panics as enforcement — RESOLVED-by-doc

- **Status:** RESOLVED-by-doc — commit `2c9661f` documents `ensureFips`
  as the preferred startup gate (fail-closed by design); the panic-on-absent-
  provider behavior is explicitly characterized as intentional hard-fail for
  process-wide invariant enforcement. Callers using `ensureFips` at startup
  avoid the panic in normal operation.
- **Commit:** `2c9661f`
- **Original severity:** Low

### SEC-1011 — No nonce-uniqueness / 96-bit-length contract on AES-GCM — CLOSED

- **Status:** CLOSED — commit `80220f5` enforces `nonce.len == 12` in
  `seal`/`open`; commit `2c9661f` adds nonce-reuse guidance to
  `SEAM_CONTRACT.md` and `SECURITY.md`.
- **Commits:** `80220f5`, `2c9661f`
- **Verifying tests:** `tests/aead.zig` (negative nonce-length test)
- **Original severity:** High

### SEC-1013 — `OSSL_PROVIDER_load("base")` return ignored — CLOSED

- **Status:** CLOSED — commit `db54ab2` treats a `base` load failure as
  fatal, returning `error.FipsProviderUnavailable` from `ensureFips()`.
- **Commit:** `db54ab2`
- **Verifying tests:** `src/provider.zig` tests
- **Original severity:** Medium

### SEC-1015 — CSPRNG shim infinite retry on any errno — CLOSED

- **Status:** CLOSED — commit `8b8fa0d` discriminates `getrandom` errno,
  retrying only on `EINTR`/`EAGAIN` and failing closed on non-retryable errors.
- **Commit:** `8b8fa0d`
- **Verifying tests:** `src/csprng.zig` / `src/std_shim.zig` tests
- **Original severity:** Low

### SEC-1016 — `error.Unsupported` can mask mis-provisioned provider — RESOLVED-by-doc

- **Status:** RESOLVED-by-doc — commit `2c9661f` adds a "no-fallback"
  caveat to `SEAM_CONTRACT.md` (the SEAM_CONTRACT now explicitly states
  that `Unsupported` must never be treated as a signal to fall back to
  non-FIPS crypto, and distinguishes provider-absence from algorithm-absence
  in the doc).
- **Commit:** `2c9661f`
- **Original severity:** Low (suspected)

### SEC-1017 (NEW) — Hash.digest / Stream.final output-buffer overrun — CLOSED

- **Status:** CLOSED — found during Wave 6 test authoring. Commit
  `e740b37` adds bounds-checking on the output buffer in `Hash.digest`
  and `Hash.Stream.final` before writing the digest bytes, returning
  `error.OpensslFailure` on undersized output.
- **Commit:** `e740b37`
- **Verifying tests:** `tests/hash.zig` (buffer-too-small negative tests)
- **Original severity:** High (newly found)

---

## Summary after Round-1 Closure

| Status | Count | IDs |
|--------|-------|-----|
| Closed | 13 | SEC-1001, SEC-1002, SEC-1003, SEC-1004, SEC-1005, SEC-1006, SEC-1007, SEC-1008, SEC-1009, SEC-1011, SEC-1013, SEC-1015, SEC-1017 |
| Resolved-by-doc | 2 | SEC-1010, SEC-1016 |
| Partially-closed / Deferred | 1 | SEC-1014 |
| Deferred | 1 | SEC-1012 |
| **Total** | **17** | |

## Round-2/3 re-review closure (2026-06-22)

Findings surfaced by the post-hardening re-audit, now closed:

| ID | Title | Status | Commit |
| --- | --- | --- | --- |
| SEC-2001 | `ensureFips` partial-init fail-open (in-lock recheck keyed on `g_fips`, not `g_ready`) | Closed | `5325d0f` |
| SEC-2002 | CI `fips-deps` skipped GPG: SHA-256-only is same-origin integrity, not authenticity | Closed | `5395288` |
| SEC-2003 | RSA exponent not FIPS-validated (`e=1`/even `e` accepted on import -> forgery vector) | Closed | `f55d176` |

## Round-3 re-review follow-ups (2026-06-22)

| ID | Title | Status | Commit |
| --- | --- | --- | --- |
| N-R3-01 | Cache-handle leak on partial-init retry (slots re-fetched + overwritten) | Closed | `28a18a0` |
| N-R3-02 | `OSSL_LIB_CTX_load_config` ran on every retry (idempotency unproven) | Closed | `28a18a0` |
| N-R3-04 | CI installed gnupg but did not require it (`.asc` failure -> silent SHA-256-only) | Closed | `94309f6` |
