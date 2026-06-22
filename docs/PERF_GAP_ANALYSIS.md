<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2024-2026 CodePros -->

# PERF_GAP_ANALYSIS — fips crypto seam

> **Round-1 closure applied 2026-06-22 on branch audit/round-1-hardening.**
> All findings are re-dispositioned below. Closed and resolved items have been
> moved to the "Resolved" section and to `docs/GAP_ANALYSIS_RESOLVED.md`.
> Only genuinely still-open (deferred) items remain in the open section.

Performance review of the Zig FIPS crypto-seam library
(`/home/benji/src/devnw/zig/fips`), a library-only OpenSSL 3.x FIPS-provider
backend consumed by high-throughput servers (TLS, QUIC, WireGuard).

- **Scope**: `src/*.zig`, `templates/crypto_backend.zig`, `benchmarks/*.zig`,
  `build.zig`.
- **Toolchain**: Zig 0.16.0; FFI to OpenSSL 3.x (host has **OpenSSL 3.6.2**,
  confirmed via `openssl version`).
- **Method**: full inline read of all in-scope files; static evidence only.
- **Guiding principle**: correctness/security trump perf. The FIPS
  property-query guarantee (`"fips=yes"` on every fetch) and fail-closed
  behavior MUST be preserved by any remediation.

## PerfSeverity rubric

| Sev | Meaning |
|-----|---------|
| **P0** | Throughput/latency cliff on the dominant production hot path; fix warranted before high-throughput GA. |
| **P1** | Material per-op overhead on a real hot path; worth fixing, bounded blast radius. |
| **P2** | Measurable waste but small absolute cost, or off the hottest path. |
| **P3** | Minor / hygiene / latent (shows up only under specific conditions). |

---

## Open Items (Deferred)

### PERF-0002 / PERF-0003 — Cached-primitive reuse API — SUBSTANTIALLY-ADDRESSED / DEFERRED

- **Status:** SUBSTANTIALLY-ADDRESSED — the one-shot fetch cache introduced
  by PERF-0001 (commit `9a01666`) eliminates the per-call provider lookup for
  one-shot operations, which was the dominant cost. An explicit
  `Aead.Cipher`/`Mac.Key`/`Hash.Md` cached-handle API (allowing callers to
  hoist both the fetch *and* the `CTX_new`/`CTX_free` out of a per-record
  loop) is DEFERRED as unnecessary for one-shot callers and a larger surface
  change that needs its own design round.
- **P1** items; P2 post-cache.

### PERF-0007 — KEM two-call size query — DEFERRED

- **Status:** DEFERRED — P3, <2% of encap/decap cost (ML-KEM math dominates).
  The fix (compile-time size table from `policy.KemAlg`) is well-understood but
  not worth the churn this round.
- **Original severity:** P3

### PERF-0008 — RSA keygen bit-size hard-pinned — DEFERRED

- **Status:** DEFERRED — P3, keygen is not a per-request hot path. The
  `min_rsa_bits` constant is introduced by QUAL-0003 partial (commit `e08c480`);
  a configurable keygen bit-size is a follow-on feature tracked in QUAL-0003.
- **Original severity:** P3

### PERF-0009 — `git rev-parse` per bench process — NOT-A-DEFECT

- **Status:** NOT-A-DEFECT — one-time, untimed env metadata capture. No action needed.
- **Original severity:** P3

---

## Resolved Items (Round-1)

### PERF-0001 — `EVP_*_fetch` on every AEAD/MAC/hash/KDF call — CLOSED

- **Status:** CLOSED — commit `9a01666` introduces a fetch cache in
  `provider.zig` keyed by `(kind, alg-name)` over the FIPS `OSSL_LIB_CTX`.
  One-shot ops now fetch from the cache (no per-call provider lookup).
  Measured improvements: ~44% throughput lift for AES-256-GCM-64B, ~40% for
  SHA-256-64B, ~32% for HMAC.
- **Commit:** `9a01666`
- **Verifying tests:** `benchmarks/bench.zig` (real crypto workloads, committed in PERF-0006)
- **Original severity:** P0

### PERF-0004 — `Hash.Stream.clone()` re-fetches `EVP_MD` instead of up-reffing — CLOSED

- **Status:** CLOSED — commit `9830b02` replaces the `EVP_MD_fetch` in
  `clone()` with `EVP_MD_up_ref` (O(1) atomic refcount bump), eliminating
  the per-clone provider lookup on the TLS-1.3 transcript path.
- **Commit:** `9830b02`
- **Verifying tests:** `src/hash.zig` (clone tests)
- **Original severity:** P2

### PERF-0005 — Unsynchronized lazy global init of `g_ctx`/`g_fips` — CLOSED

- **Status:** CLOSED — commits `db54ab2` and `1f25ebb` guard init with a
  mutex + lock-free fast path for steady-state reads. Cold-start race and
  double provider load eliminated; TSan-clean.
- **Commits:** `db54ab2`, `1f25ebb`
- **Verifying tests:** `src/provider.zig` (TSan concurrency test)
- **Original severity:** P2

### PERF-0006 — Benchmark suite measures no crypto — CLOSED

- **Status:** CLOSED — commit `90ba16d` replaces all placeholder scenarios
  with real hot-path benchmarks: AES-256-GCM at multiple payload sizes,
  SHA-256, HMAC-SHA256, HKDF, Ed25519 sign/verify, ECDSA P-256,
  ML-KEM-768 encap/decap, CSPRNG. The `benchmark-regression` job now gates
  on `fips-deps`.
- **Commit:** `90ba16d`
- **Verifying tests:** `benchmarks/bench.zig`, `benchmarks/scale.zig`,
  `benchmarks/micro/`
- **Original severity:** P0 (coverage)

---

## Summary table (post-Round-1)

| ID | PerfSeverity | Title | Status |
|----|--------------|-------|--------|
| PERF-0001 | P0 | `EVP_*_fetch` per call | Closed (`9a01666`) |
| PERF-0002 | P1 | No cached-cipher/MD reuse API for one-shot ops | Substantially-addressed / Deferred |
| PERF-0003 | P1 | Sign/KEM re-resolve per op | Substantially-addressed / Deferred |
| PERF-0004 | P2 | `Hash.Stream.clone()` re-fetches EVP_MD | Closed (`9830b02`) |
| PERF-0005 | P2 | Unsynchronized lazy global init | Closed (`db54ab2`, `1f25ebb`) |
| PERF-0006 | P0 (coverage) | Benchmark suite measures no crypto | Closed (`90ba16d`) |
| PERF-0007 | P3 | KEM two-call size query | Deferred |
| PERF-0008 | P3 | RSA keygen bit-size hard-pinned | Deferred |
| PERF-0009 | P3 | `git rev-parse` per bench process | Not-a-defect |

**Round-1 counts:** Closed 4 · Substantially-addressed/Deferred 2 ·
Deferred 2 · Not-a-defect 1.

## Round-2/3 re-review closure (2026-06-22)

| ID | Title | Status | Commit |
| --- | --- | --- | --- |
| PERF-0010 | KDF hot path (`EVP_KDF_fetch` per call) was not covered by the fetch cache | Closed | `8b859a1` |
| PERF-0011 | `Hash.Stream.init` re-fetched the MD instead of up-reffing the cached one | Closed | `b8410f9` |
| PERF-0012 | Bench-imported `fips` lib follows top-level optimize (Debug) under bare `zig build bench` | Resolved-by-doc | `07ccfa1` |

PERF-0001 update: the fetch cache now also covers HKDF + PBKDF2 (`g_kdf_hkdf`/`g_kdf_pbkdf2`, commit `8b859a1`), so all AEAD/Hash/HMAC/KDF one-shot ops skip the per-call provider lookup.
