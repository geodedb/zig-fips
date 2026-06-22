<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2024-2026 CodePros -->

# PERF_GAP_ANALYSIS — fips crypto seam

Performance review of the Zig FIPS crypto-seam library
(`/home/benji/src/devnw/zig/fips`), a library-only OpenSSL 3.x FIPS-provider
backend consumed by high-throughput servers (TLS, QUIC, WireGuard).

- **Scope**: `src/*.zig`, `templates/crypto_backend.zig`, `benchmarks/*.zig`,
  `build.zig`.
- **Toolchain**: Zig 0.16.0; FFI to OpenSSL 3.x (host has **OpenSSL 3.6.2**,
  confirmed via `openssl version`).
- **Method**: full inline read of all in-scope files; static evidence only. No
  benchmarks were run (the existing suite measures no crypto — see PERF-0006),
  so every quantitative claim below is labeled with its confidence and a
  validation plan. Read-only: no source was modified.
- **Guiding principle (from the brief)**: correctness/security trump perf. The
  FIPS property-query guarantee (`"fips=yes"` on every fetch) and fail-closed
  behavior MUST be preserved by any remediation. Severities are rated
  realistically.

## PerfSeverity rubric

| Sev | Meaning |
|-----|---------|
| **P0** | Throughput/latency cliff on the dominant production hot path; fix warranted before high-throughput GA. |
| **P1** | Material per-op overhead on a real hot path; worth fixing, bounded blast radius. |
| **P2** | Measurable waste but small absolute cost, or off the hottest path. |
| **P3** | Minor / hygiene / latent (shows up only under specific conditions). |

## Confidence

- `confidence::confirmed` — the code path and the mechanism are verified from
  source + OpenSSL's documented behavior; only the *magnitude* may need a bench.
- `confidence::suspected` — mechanism is sound but the production impact depends
  on call mix / deployment and needs measurement to size.

---

## Summary table

| ID | PerfSeverity | Title | Location | Confidence |
|----|--------------|-------|----------|------------|
| PERF-0001 | P0 | `EVP_*_fetch` on every AEAD/MAC/hash/KDF call (provider lookup per record) | `src/aead.zig:25,58`, `src/mac.zig:16`, `src/hash.zig:15`, `src/kdf.zig:15,37,55` | confirmed |
| PERF-0002 | P1 | No cached-cipher / cached-MD reuse API for one-shot AEAD/MAC/hash | `src/aead.zig`, `src/mac.zig`, `src/hash.zig` (whole files) | confirmed |
| PERF-0003 | P1 | Signature/KEM init re-resolves algorithm + rebuilds `EVP_PKEY_CTX` per op | `src/sig.zig:185,199,284,293`, `src/kem.zig:41,58` | confirmed |
| PERF-0004 | P2 | `Hash.Stream.clone()` re-fetches the `EVP_MD` instead of up-reffing | `src/hash.zig:73-80` | confirmed |
| PERF-0005 | P2 | `provider.ensureFips()` fast-path read is an unsynchronized global (race + redundant first-call work) | `src/provider.zig:16-21,24-43,47-49` | confirmed |
| PERF-0006 | P0 (coverage) | Benchmark suite measures zero crypto — no fetch cost, AEAD throughput, or sign/KEM latency | `benchmarks/bench.zig:55-67`, `benchmarks/scale.zig:49-61`, `benchmarks/micro/example.zig:42-47` | confirmed |
| PERF-0007 | P3 | KEM two-call size query per encapsulate/decapsulate (could use fixed-size table) | `src/kem.zig:44-49,61-64` | confirmed |
| PERF-0008 | P3 | RSA keygen hard-pinned to 2048 bits; no path to reuse a generated key context | `src/sig.zig:169-176` | suspected |
| PERF-0009 | P3 | Benchmark exes shell out to `git rev-parse` once per process (env capture); fine, but documents the only real cost the harness measures | `benchmarks/framework.zig:558-575` | confirmed |

---

## Algorithms & Data Structures

| Finding | File:Line | Root Cause | Impact | How to Verify | Confidence |
|---------|-----------|------------|--------|---------------|------------|
| No quadratic/regex/algorithmic hot-loop issues in seam code; compute is inside OpenSSL. `policy.isApproved` is a comptime linear scan over ~37 names but is `comptime`-only (compile-time, never on the hot path). | `src/policy.zig:123-126` | N/A | None (comptime-only) | `isApproved` takes `comptime name` — confirm no runtime caller. | confirmed |
| KEM two-call size query (PERF-0007) is the only "redundant work" pattern; see I/O section. | `src/kem.zig:44-49` | — | — | — | — |

There are **no genuine algorithmic defects** in the Zig layer. The library is a
thin FFI seam; per-operation arithmetic cost lives in libcrypto. The
performance story here is entirely **per-call object construction / provider
lookup churn** (below), not Big-O.

---

## Memory & GC

| Finding | File:Line | Root Cause | Impact | How to Verify | Confidence |
|---------|-----------|------------|--------|---------------|------------|
| **PERF-0001 (allocation/churn facet)** Each `seal`/`open`/`hmac`/`digest`/`hkdf`/`derive` allocates **and frees** an `EVP_*_CTX` (heap) *and* an `EVP_*` method object (fetch allocates + refcounts) per call. For per-record AEAD in TLS/QUIC this is 2 heap objects created+destroyed per packet, plus the provider's internal fetch allocations. | `src/aead.zig:25-28,58-61`; `src/mac.zig:16-19`; `src/hash.zig:15-18`; `src/kdf.zig:15-18,37-40,55-58` | One-shot API owns the full fetch→ctx→init→free lifecycle inside the call. | malloc churn proportional to packet rate; allocator pressure + cache misses on the hot path. | `valgrind --tool=callgrind` or `ltrace -c` on a tight `Aead.seal` loop; count `malloc`/`free` per op. Expect ≥2 ctx alloc/free + fetch-internal allocs per call. | confirmed |
| No unbounded caches/maps/queues exist in the seam (there is *no* cache at all — see PERF-0002). No leak risk in the one-shot paths: every `fetch`/`CTX_new` has a matching `defer *_free`. `Hash.Stream` and `Sig/Kem.KeyPair` correctly pair `init`/`generate` with `deinit`. | `src/aead.zig:26,28`; `src/hash.zig:83-86`; `src/sig.zig:68-70`; `src/kem.zig:20-22` | Correct RAII via `defer`/`errdefer`. | None (this is good). | `zig build test` under a leak-checking allocator already covers KAT paths. | confirmed |
| Transient buffers are caller-provided slices (`out: []u8`, `ciphertext: []u8`); no entire-file reads, no over-allocated internal buffers. Streaming hash (`Hash.Stream`) exists for large inputs. | `src/hash.zig:37-87` | Good API design (caller owns buffers). | None. | — | confirmed |

---

## I/O & Network

| Finding | File:Line | Root Cause | Impact | How to Verify | Confidence |
|---------|-----------|------------|--------|---------------|------------|
| **PERF-0007** KEM `encapsulate`/`decapsulate` call `EVP_PKEY_encapsulate`/`decapsulate` twice — once with NULL outputs to query sizes, once to produce. The size query for ML-KEM is a cheap field read inside OpenSSL (not a network/disk I/O), but it is a second FFI round-trip per op. ML-KEM ciphertext/shared-secret sizes are **fixed per algorithm** and known at compile time, so the query is avoidable. | `src/kem.zig:44-49` (encap), `src/kem.zig:61-64` (decap) | Defensive "ask OpenSSL for the size" pattern. | One extra FFI call + bounds re-check per KEM op. Minor for TLS handshakes (KEM is per-connection, not per-record), hence P3. | Bench `Kem.encapsulate` with vs. without the size query (hardcode sizes from `policy.KemAlg`); measure delta. Likely <2% of encap cost (the ML-KEM math dominates). | confirmed |
| No HTTP/compression/pagination surface — this is a crypto FFI library, not a service. Out of scope. | — | — | — | — | — |

---

## Concurrency

| Finding | File:Line | Root Cause | Impact | How to Verify | Confidence |
|---------|-----------|------------|--------|---------------|------------|
| **PERF-0005** `provider.libCtx()` and `ensureFips()` lazily initialize process-global `g_ctx`/`g_fips` with **no synchronization**. The fast path (`if (g_fips != null) return;`) is a single non-atomic pointer read — cheap (sub-nanosecond, well-predicted), so the *steady-state* assertion cost is negligible. BUT first-call initialization from multiple server worker threads is a **data race**: two threads can both observe `g_fips == null`, both run `OSSL_LIB_CTX_new` / `OSSL_PROVIDER_load` / `OSSL_PROVIDER_self_test`, leaking a context+provider and double-running the self-test (the FIPS KAT battery — not free). | `src/provider.zig:16-21` (`libCtx`), `:24-43` (`ensureFips`), `:47-49` (`assertActive`) | Lazy globals without `std.once`/atomics; assumes single-threaded warmup. | Steady-state: ~0 (good). Cold-start under concurrency: duplicated provider load + self-test, possible context leak, and a benign-but-real race that ThreadSanitizer will flag. | `zig build test-stress -Dtsan=true` with a test that calls `assertActive()` from N threads simultaneously on first use. TSan reports the race on `g_ctx`/`g_fips`. (Current stress test does not exercise this — see PERF-0006.) | confirmed |
| Steady-state hot-path assertion (`provider.assertActive()` at the top of every op) is correctly cheap: it short-circuits on `g_fips != null` after warmup. Quantified: 1 load + 1 compare + predicted-not-taken branch. **Not** a material cost once warmed. | `src/provider.zig:47-49`, `src/aead.zig:24`, etc. | Intended fast-path. | Negligible per-op. | `perf stat` / callgrind on a warmed loop; the `assertActive` frame should be ~nil vs. the fetch+ctx cost. | confirmed |
| No lock contention, no event-loop blocking, no backpressure surface in the seam itself (it is synchronous FFI invoked by the caller's threads). The library does not spawn threads. Concurrency correctness of OpenSSL itself (locking inside libcrypto) is OpenSSL's contract. | whole `src/` | Synchronous design. | None at the seam layer. | — | confirmed |

> **Note on PERF-0005 severity**: rated **P2**, not higher, because (a) the
> steady-state cost is ~zero and (b) the typical deployment calls a warmup
> (`assertActive`/`ensureFips`) once at startup before forking workers, which
> sidesteps the race. It becomes P1 if workers can race the very first crypto
> call. The fix is cheap and removes a latent TSan failure, so it is worth
> doing regardless.

---

## Pipelining & Streaming

| Finding | File:Line | Root Cause | Impact | How to Verify | Confidence |
|---------|-----------|------------|--------|---------------|------------|
| **PERF-0004** `Hash.Stream.clone()` calls `EVP_MD_fetch(...)` again to obtain an independent `EVP_MD*` for the clone, when `EVP_MD_up_ref(self.md)` would take a reference to the already-fetched method in O(1) (an atomic increment) and avoid a second provider lookup. `EVP_MD_CTX_dup` already copies the context state; only the method handle needs a fresh owned reference. | `src/hash.zig:73-80` (esp. line 76) | Re-fetch chosen over up-ref for the cloned method handle. | A full provider lookup per `clone()`. TLS 1.3 transcript hashing clones the running hash at each handshake message that needs an interim digest — so clones are on the handshake path. | Bench `Hash.Stream.clone()` as written vs. an `EVP_MD_up_ref`-based variant. Expect the up-ref variant to cut clone cost to ~the `EVP_MD_CTX_dup` cost alone (eliminates the fetch). | confirmed |
| The streaming `Hash.Stream` API is the **correct** pipelining primitive and is the model the one-shot APIs should follow (fetch once at `init`, many `update`s, `final` without reset). Its existence is a strength; it just needs the `clone` fix and a sibling pattern for AEAD/MAC (PERF-0002). | `src/hash.zig:37-87` | Good design. | Positive. | — | confirmed |
| No SIMD/vectorization opportunities in the Zig layer (numerical work is in OpenSSL, which already uses AES-NI / AVX). N/A. | — | — | — | — | confirmed |

---

## Per-call EVP object churn — the central finding (PERF-0001 / PERF-0002 / PERF-0003)

### Evidence

Every one-shot operation follows the same fetch→ctx→init→do→free shape **on each
call**. Representative (AEAD seal):

```zig
// src/aead.zig:24-28
provider.assertActive();
const cipher = c.EVP_CIPHER_fetch(provider.libCtx(), policy.aeadName(alg), "fips=yes") orelse return error.Unsupported;
defer c.EVP_CIPHER_free(cipher);
const ctx = c.EVP_CIPHER_CTX_new() orelse return error.OpensslFailure;
defer c.EVP_CIPHER_CTX_free(ctx);
```

The same per-call fetch appears at:

- `src/aead.zig:25` (seal) and `:58` (open) — `EVP_CIPHER_fetch`
- `src/mac.zig:16` — `EVP_MAC_fetch("HMAC")`
- `src/hash.zig:15` (one-shot `digest`) — `EVP_MD_fetch`
- `src/kdf.zig:15` (hkdf), `:37` (hkdfExpand), `:55` (pbkdf2) — `EVP_KDF_fetch`
- `src/sig.zig` — sign/verify build a fresh `EVP_MD_CTX` and call
  `EVP_DigestSignInit_ex` / `EVP_DigestVerifyInit_ex` with `provider.libCtx()` +
  `"fips=yes"` per call (`:184-195`, `:199-210`, `:281-297`), which re-resolves
  the signature implementation each time.
- `src/kem.zig:41` / `:58` — `EVP_PKEY_CTX_new_from_pkey(..., "fips=yes")` per
  encapsulate / decapsulate.

Static call-site census (per public op, from the source):

| File | `assertActive()` | `libCtx()` | `*_fetch` / `new_from_*` | `*_CTX_new` |
|------|------|------|------|------|
| aead.zig | 2 | 2 | 2 | 2 |
| hash.zig | 2 | 3 | 3 | 2 |
| mac.zig  | 1 | 1 | 1 | 1 |
| kdf.zig  | 3 | 3 | 3 | 3 |
| sig.zig  | 9 | 12 | 2 | 8 |
| kem.zig  | 3 | 3 | 3 | 3 |

### Why this matters (OpenSSL 3.x semantics)

OpenSSL 3.x replaced the legacy static `EVP_aes_256_gcm()` accessors with
**explicit fetching** (`EVP_CIPHER_fetch` / `EVP_MD_fetch` / `EVP_MAC_fetch` /
`EVP_KDF_fetch`). A fetch performs a **provider + property-query resolution**:
it walks loaded providers, evaluates the property query string
(here `"fips=yes"`), constructs/【caches internally】 a method object, and returns
a reference-counted handle. OpenSSL's own documentation
(crypto(7) "Performance", EVP_CIPHER_fetch(3), "Implicit vs explicit fetching")
states explicit fetching is **comparatively expensive** and that applications on
a hot path **should fetch once and reuse** the returned object (it is safe to
share a fetched `EVP_CIPHER`/`EVP_MD` across many `*_CTX` inits). The per-call
property-query parse + provider walk is precisely the cost incurred here on
every TLS/QUIC record.

This is the **most likely material production cost** in the library: in a
per-message AEAD workload (TLS record, QUIC packet, WireGuard datagram), the
provider lookup + property-string parse can rival or exceed the AES-GCM
transform for small records, because AES-GCM with AES-NI is only tens of
nanoseconds for a short payload while a fetch is a multi-step lookup.

### Can it be cached without breaking the FIPS property guarantee? — Yes

The `"fips=yes"` guarantee is a property of **what gets fetched**, not **when**.
Caching the *result* of a `fips=yes` fetch preserves the guarantee exactly: the
cached `EVP_CIPHER*`/`EVP_MD*`/`EVP_MAC*` is the FIPS-provider implementation
that the property query already selected. Two safe, FIPS-preserving designs:

1. **Per-`OSSL_LIB_CTX` fetch cache keyed by `(kind, algorithm)`** living next to
   `g_fips` in `provider.zig`, populated lazily under the same one-time init as
   the provider load (so it inherits PERF-0005's fix). Each entry is the handle
   returned by a `fips=yes` fetch; ops then do `CTX_new` + init against the
   cached handle (no re-fetch). Because OpenSSL already enables
   `EVP_default_properties_enable_fips(ctx, 1)` on `g_ctx`
   (`src/provider.zig:39`), the cached handles are unambiguously FIPS handles.

2. **Caller-held cached-primitive objects** mirroring `Hash.Stream`: a
   `Aead.Cipher` / `Mac.Key` / `Hash.Md` opaque that fetches once at construction
   (`fips=yes`) and exposes `seal`/`open`/`update` that only build/reset a
   `*_CTX`. This matches the already-shipped `Hash.Stream` pattern
   (`src/hash.zig:37`) and is the most surgical for hot loops (the caller hoists
   the fetch out of its per-record loop). Even better for AEAD: a long-lived
   `EVP_CIPHER_CTX` can be re-used across records by re-initializing key/IV via
   `EVP_EncryptInit_ex2(ctx, NULL, key, iv, NULL)` (the cipher is already bound),
   eliminating both the fetch **and** the per-record `CTX_new`/`CTX_free`.

Either design keeps the public one-shot functions intact (back-compat) and adds
a **reuse** surface for hot callers. The seam contract (identical API across the
`fips` and `std_shim` backends, `templates/crypto_backend.zig`) means any new
cached-primitive type must be added to **both** backends to preserve parity; the
shim version is trivial (the std primitives are comptime types with no fetch
cost, so its "cached cipher" is a thin wrapper).

> **Important non-negotiable**: the cache must be keyed/owned per
> `OSSL_LIB_CTX` and must NOT fall back to the default (non-FIPS) library
> context, or it would silently defeat fail-closed. Today the seam always passes
> `provider.libCtx()` + `"fips=yes"`; the cache must do the same.

### Detailed remediation table

| ID | PerfSeverity | Finding | File:Line | Remediation | Expected impact |
|----|------|---------|-----------|-------------|-----------------|
| **PERF-0001** | **P0** | `EVP_*_fetch` (provider+property-query lookup) executed on every AEAD/MAC/hash/KDF call. | `src/aead.zig:25,58`; `src/mac.zig:16`; `src/hash.zig:15`; `src/kdf.zig:15,37,55` | Introduce a fetch cache in `provider.zig` keyed by `(kind, alg-name)` over the FIPS `OSSL_LIB_CTX`, populated under one-time init; have one-shot ops fetch-from-cache. Preserves `fips=yes`. | Removes the per-call provider lookup. For small-record AEAD the fetch is plausibly a large fraction of per-op cost; eliminating it should materially raise records/sec. **Size with a bench (PERF-0006 must land first).** |
| **PERF-0002** | **P1** | No reuse API: even a caller that does millions of identical `Aead.seal`s cannot avoid the per-call fetch (+ ctx new/free). | `src/aead.zig`, `src/mac.zig`, `src/hash.zig` | Add cached-primitive types (`Aead.Cipher`/`Mac.Key`/`Hash.Md`) mirroring `Hash.Stream`: fetch once at construct, reuse a `*_CTX` across calls (re-init key/IV for AEAD). Add to `std_shim` too (trivial wrappers) for seam parity. | Hot callers hoist fetch + ctx allocation out of the per-record loop → near-zero per-record OpenSSL setup overhead; lets TLS/QUIC reach AES-NI-bound throughput. |
| **PERF-0003** | **P1** | Sign/verify and KEM re-resolve the algorithm implementation + rebuild `EVP_PKEY_CTX`/`EVP_MD_CTX` per op via `*Init_ex(..., "fips=yes")` / `new_from_pkey(..., "fips=yes")`. | `src/sig.zig:185,199,284,293`; `src/kem.zig:41,58` | Allow a cached signing/verifying context bound to a `KeyPair` (the `KeyPair` already owns the `EVP_PKEY`); reuse `EVP_PKEY_CTX` for repeated encapsulate/verify against the same key. | Sign/verify and KEM are per-connection (handshake), not per-record, so this is P1 not P0 — but high-QPS TLS termination does thousands of handshakes/sec; cutting the per-op `EVP_PKEY_CTX` rebuild + re-resolution helps handshake throughput. |

---

## Infrastructure & CI / Benchmark coverage

| Finding | File:Line | Root Cause | Impact | How to Verify | Confidence |
|---------|-----------|------------|--------|---------------|------------|
| **PERF-0006** — The entire benchmark suite measures **no crypto**. `bench.zig`, `scale.zig`, and `micro/example.zig` all spin a loop over `std.mem.doNotOptimizeAway(lib.version.len)` / `&lib.version`. None calls `Aead.seal`, `Hash.digest`, `Mac.hmac`, `Sig.sign`, `Kem.encapsulate`, `Csprng.bytes`, or even `provider.assertActive()`. So the harness reports "263 billion ops/sec" for reading a string-literal length — it cannot detect any regression in the actual library, and specifically **cannot observe the PERF-0001 fetch cost** it most needs to track. | `benchmarks/bench.zig:55-67`, `benchmarks/scale.zig:49-61`, `benchmarks/micro/example.zig:42-47` | Placeholder scenarios were never replaced (the files say "replace these"). | **Zero** performance regression coverage on the real hot paths; the CI `benchmark-regression` gate (`.gitlab-ci.yml:252`) is vacuous (and `allow_failure: true`). | Read the scenario bodies; run `zig build bench --list` — every scenario is an `init_*` placeholder. | confirmed |
| The framework itself (`framework.zig`) is solid: warmup/sample split, sorted percentiles (p50/p95/p99), throughput, stddev, alloc tracking via `TrackingAllocator`, RSS from `/proc/self/status`, JSON schema, and a regression comparer (`compare.zig`) with a noise-gated diff. The *infrastructure* is good; only the *scenarios* are empty. | `benchmarks/framework.zig:193-323`, `compare.zig` | — | Positive — the harness is ready to host real benchmarks. | — | confirmed |
| **PERF-0009** Benchmarks shell `git rev-parse HEAD` once per process for env capture. This is a one-time process cost (not per-iteration) and is correctly outside the timed region. Noted only because it is currently the only real syscall the harness performs. | `benchmarks/framework.zig:558-575` | Env metadata capture. | Negligible (once per run). | — | confirmed |
| CI benchmark job builds Zig on stock `ubuntu:24.04` and runs `zig build bench`. Note: the bench exes are forced `ReleaseFast` (`build.zig:304,386`) — correct for stable numbers. But the bench job does **not** build/link the FIPS provider (no `make deps`), and the placeholder scenarios don't need it; once real crypto benches land, the `benchmark-regression` job must depend on `fips-deps` (like `test-fips` does, `.gitlab-ci.yml:320-328`) or it will measure the std_shim, not the FIPS backend. | `.gitlab-ci.yml:252-270`, `build.zig:301-360` | Bench job predates real crypto scenarios. | Future: bench would silently measure the wrong backend. | Inspect `benchmark-regression` `needs:` — it has none on `fips-deps`. | confirmed |

### PERF-0006 remediation (highest-leverage action)

| ID | PerfSeverity | Remediation | Expected impact |
|----|------|-------------|-----------------|
| **PERF-0006** | **P0 (coverage)** | Replace placeholder scenarios with real hot-path benchmarks, and **add the diagnostic that isolates PERF-0001**: (a) `aead_seal_1350B` (TLS-record-sized) and `aead_seal_64B` (QUIC ack-sized) measuring records/sec; (b) `aead_seal_cached_cipher` vs `aead_seal_fetch_per_call` — the A/B that *directly prices the fetch*; (c) `hash_sha256_64B` one-shot vs `hash_stream_64B` (already-fetched `Hash.Stream`); (d) `hmac_sha256_short`; (e) `hkdf_expand_tls13_label`; (f) `sign_ed25519` / `verify_ed25519`, `sign_ecdsa_p256`; (g) `kem_mlkem768_encap`/`decap`; (h) `csprng_32B`. Wire these under `bench.zig` and gate `benchmark-regression` on `fips-deps`. | Establishes the baseline the brief asks for; the cached-vs-uncached AEAD pair quantifies PERF-0001/0002 directly (this is the number that justifies the cache work). Until this lands, the cache ROI is unmeasured. |

---

## Lower-severity items

| ID | PerfSeverity | Finding | File:Line | Remediation | Expected impact |
|----|------|---------|-----------|-------------|-----------------|
| **PERF-0004** | **P2** | `Hash.Stream.clone()` re-fetches the `EVP_MD` (full provider lookup) for the clone's owned method handle. | `src/hash.zig:73-80` (line 76) | Replace the `EVP_MD_fetch(... EVP_MD_get0_name(self.md) ...)` with `EVP_MD_up_ref(self.md)` (O(1) atomic refcount bump) and assign the same handle; `deinit` already frees per-Stream so the refcount is balanced. Keeps FIPS handle. | Eliminates a provider lookup per clone on the TLS-1.3 transcript path; clone cost drops to the `EVP_MD_CTX_dup` alone. |
| **PERF-0005** | **P2** | Unsynchronized lazy global init of `g_ctx`/`g_fips`; cold-start race duplicates provider load + self-test under concurrent first call. | `src/provider.zig:16-21,24-43` | Guard init with `std.Thread.Once` (or an atomic CAS on a state enum). Steady-state read can remain a relaxed atomic load. Document "call `assertActive()` once at startup before forking workers." | Removes a latent TSan failure and double self-test on concurrent cold start; steady-state cost unchanged (already ~0). |
| **PERF-0007** | **P3** | KEM size query is a redundant second FFI call; ML-KEM sizes are fixed per alg. | `src/kem.zig:44-49,61-64` | Optionally short-circuit the NULL-output size query using a compile-time size table derived from `policy.KemAlg` (keep the bounds check). Low priority — KEM is per-connection. | <2% of encap/decap cost expected; minor. |
| **PERF-0008** | **P3** | RSA keygen pins 2048 bits; no API to choose 3072/4096, and the keygen `EVP_PKEY_CTX` is rebuilt each call. | `src/sig.zig:169-176` | Expose an RSA bit-size param; allow reuse of a keygen context if batch-generating. Keygen is rare (not a per-request hot path), hence P3. | Negligible for typical request paths; matters only for key-provisioning batch jobs. |
| **PERF-0009** | **P3** | `git rev-parse` per bench process (env capture). | `benchmarks/framework.zig:558-575` | None needed (one-time, untimed). | None. |

---

## What would confirm the magnitudes (consolidated validation plan)

1. **Land PERF-0006 first.** Without real crypto benchmarks, every magnitude
   below is an estimate. The single most important new scenario is the
   **fetch-per-call vs cached-cipher A/B for `Aead.seal` on a 64-byte and a
   1350-byte payload** — it prices PERF-0001/0002 directly.
2. **PERF-0001 fetch cost**: `ltrace -c -e 'EVP_CIPHER_fetch+malloc+free'` (or
   `valgrind --tool=callgrind`) on a 1e6-iteration `Aead.seal` loop. Compare
   against a loop that fetches once and reuses. Expect the cached loop to drop
   the per-op `EVP_CIPHER_fetch` (and its internal allocs) entirely; quantify
   the records/sec delta, especially at 64 B where setup dominates.
3. **PERF-0004 clone**: micro-bench `Hash.Stream.clone()` as-is vs an
   `EVP_MD_up_ref` variant; expect the up-ref path ≈ `EVP_MD_CTX_dup` cost (no
   fetch).
4. **PERF-0005 race**: `zig build test-stress -Dtsan=true` with an N-thread
   first-call test on `assertActive()`; expect a TSan data-race report on
   `g_ctx`/`g_fips` today, clean after the `std.Thread.Once` fix.
5. **PERF-0003 sign/KEM**: bench `verify_ecdsa_p256` and `kem_mlkem768_encap`
   with per-call ctx vs a key-bound reused `EVP_PKEY_CTX`; size the handshake
   throughput gain.

## Notes on scope and what is explicitly *good*

- RAII discipline is correct everywhere (`defer`/`errdefer` pair every
  fetch/new). No leaks in one-shot paths.
- Caller-owned output buffers; no hidden large allocations; streaming hash
  exists for large inputs.
- The benchmark *framework* is production-grade; only the *scenarios* are stubs.
- The `fips=yes` property guarantee is correctly applied on every fetch today;
  all proposed caching must (and can) preserve it by caching the *result* of a
  `fips=yes` fetch over the FIPS `OSSL_LIB_CTX`.
- Steady-state `assertActive()` is genuinely cheap; the brief's hypothesis that
  it "short-circuits on `g_fips!=null`" is confirmed — it is **not** a material
  hot-path cost after warmup. The provider-init concern is the cold-start race
  (PERF-0005), not steady-state.
