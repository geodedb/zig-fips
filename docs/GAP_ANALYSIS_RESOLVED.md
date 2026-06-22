<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2024-2026 CodePros -->

# GAP_ANALYSIS_RESOLVED — fips crypto-seam library

Consolidated resolved-items log across all four gap-analysis domains
(`GAP_ANALYSIS.md`, `QUALITY_GAP_ANALYSIS.md`, `PERF_GAP_ANALYSIS.md`,
`SECURITY_GAP_ANALYSIS.md`).

- **Round-1 closure date:** 2026-06-22
- **Branch:** `audit/round-1-hardening`

Items are organized by domain. Within each domain: Closed → Resolved-by-doc →
Not-a-defect → Partially-addressed. Deferred items remain in their source doc;
they are not duplicated here.

---

## Domain: GAP (General / Cross-cutting)

| ID | Title | Status | Commit(s) | Verifying evidence |
|----|-------|--------|-----------|-------------------|
| GAP-0021 | `secureZero` + `timingSafeEql` absent from seam | Closed | `4eacfcf`, `0668f00` | `src/util.zig`; seam parity tests |
| GAP-0023 | SLH-DSA — only 1 of 12 variants tested | Closed | `421923e` | `src/sig.zig` (all 12 SLH-DSA variants) |
| GAP-0024 | ML-DSA — only ML-DSA-65 tested | Closed | `399921f` | `src/sig.zig` (ML-DSA-44/65/87) |
| GAP-0025 | ECDSA P-521 and hybrid KEMs untested in fips backend | Closed | `43f98ed` | `src/sig.zig`, `src/kem.zig` |
| GAP-0026 | README scaffold with broken API / CLI / build steps | Closed | `c63bd73` | README code blocks compile against real API |
| GAP-0029 | CHANGELOG.md unfilled template | Closed | `242740a` | No `YYYY-MM-DD` placeholder remains |
| GAP-0022 | ZL109 lint gate not wired in this repo | Resolved-by-doc | `2c9661f` | `FIPS_SPECIFICATION.md` language updated; deferred follow-up tracked |
| GAP-0028 | AES-256-CBC in `approved_names` but no API | Resolved-by-doc | `2c9661f` | `policy.zig` comment; spec updated |

**GAP-0027** (CSPRNG portability): PARTIALLY-CLOSED for compile
(`1100939`, `8b8fa0d`; `zig build-obj` verified Linux/macOS/Windows).
macOS/Windows runtime coverage remains DEFERRED — tracked in `GAP_ANALYSIS.md`.

**GAP-0030** (publish `.path`→`git+https` swap): DEFERRED — tracked in
`GAP_ANALYSIS.md`.

---

## Domain: QUALITY

| ID | Title | Status | Commit(s) | Verifying evidence |
|----|-------|--------|-----------|-------------------|
| QUAL-0001 | README is a stale scaffold | Closed | `c63bd73` | README snippets compile |
| QUAL-0002 | Benchmark suites measure `version.len` | Closed | `90ba16d` | Real crypto scenarios in `benchmarks/` |
| QUAL-0006 | fips `Aead.seal`/`open` skip all length validation | Closed | `80220f5` | `tests/aead.zig` negative tests |
| QUAL-0011 | `Hash.Stream.update` panics in fips | Closed | `9830b02` | `src/hash.zig` tests; `Error!void` signature |
| QUAL-0013 | No fips error-path tests | Closed | `5bdab65`, `e740b37` | `src/*.zig` negative tests; all Error members covered |
| QUAL-0014 | Integration + stress suites are placeholders | Closed | `e49c75e` | `tests/integration.zig`, `tests/stress.zig` |
| QUAL-0015 | No concurrency test; `g_ctx`/`g_fips` race | Closed | `db54ab2`, `1f25ebb` | `src/provider.zig` TSan concurrency test |
| QUAL-0016 | `ecGroup` `else => unreachable` UB | Closed | `84c6ea9` | `src/sig.zig` exhaustive match |
| QUAL-0017 | CHANGELOG unfilled template | Closed | `242740a` | No `YYYY-MM-DD` placeholder |
| QUAL-0018 | `Hash.Stream` doc comment overstates invariant | Closed | `9830b02` | Doc comment updated alongside `Error!void` change |
| QUAL-0019 | `SEAM_CONTRACT.md` omits encoding/`alg` divergences | Closed | `2c9661f` | `docs/SEAM_CONTRACT.md` caveats subsection |
| QUAL-0007 | Shim `Sig.sign`/`verify` ignore `alg` | Resolved-by-doc | `2c9661f` | `SEAM_CONTRACT.md` cross-backend caveats |
| QUAL-0008 | ECDSA/RSA public-key encoding differs per backend | Resolved-by-doc | `2c9661f` | `SEAM_CONTRACT.md` encoding portability note |
| QUAL-0010 | `Kem.encapsulate`/`decapsulate` discard `alg` | Resolved-by-doc | `2c9661f` | `SEAM_CONTRACT.md` advisory-param note |
| QUAL-0005 | `Csprng.bytes` length→`c_int` bound unverified | Not-a-defect | — | `RAND_bytes_ex` takes `size_t`; no truncation possible |
| QUAL-0003 | Hardcoded RSA modulus size | Partially-addressed | `e08c480` | `min_rsa_bits` const for verify floor; keygen size open-minor |

**QUAL-0004** (duplicate helpers), **QUAL-0009** (publicBytes bound),
**QUAL-0012** (assertActive in Stream) remain OPEN-MINOR — tracked in
`QUALITY_GAP_ANALYSIS.md`.

---

## Domain: PERF

| ID | Title | Status | Commit(s) | Verifying evidence |
|----|-------|--------|-----------|-------------------|
| PERF-0001 | `EVP_*_fetch` on every AEAD/MAC/hash/KDF call | Closed | `9a01666` | Benchmarks: ~44% AES-256-GCM-64B, ~40% SHA-256-64B, ~32% HMAC lift |
| PERF-0004 | `Hash.Stream.clone()` re-fetches `EVP_MD` | Closed | `9830b02` | `src/hash.zig` clone tests |
| PERF-0005 | Unsynchronized lazy global init | Closed | `db54ab2`, `1f25ebb` | `src/provider.zig` TSan concurrency test |
| PERF-0006 | Benchmark suite measures no crypto | Closed | `90ba16d` | Real benchmarks in `benchmarks/` |
| PERF-0009 | `git rev-parse` per bench process | Not-a-defect | — | One-time, untimed; no action needed |

**PERF-0002/0003** (cached-primitive reuse API): SUBSTANTIALLY-ADDRESSED by
PERF-0001 cache; explicit cached-handle API DEFERRED.

**PERF-0007** (KEM two-call size query) and **PERF-0008** (RSA keygen
bit-size): DEFERRED — tracked in `PERF_GAP_ANALYSIS.md`.

---

## Domain: SECURITY

| ID | Title | Status | Commit(s) | Verifying evidence |
|----|-------|--------|-----------|-------------------|
| SEC-1001 | Supply-chain: unpinned/unverified OpenSSL build | Closed | `d8661c1` | `scripts/verify-fips-provider.sh`; CI `fips-deps` fails on checksum mismatch |
| SEC-1002 (F3) | AEAD `seal`/`open` missing length validation → OOB write | Closed | `80220f5`, `16eac47` | `tests/aead.zig` negative/boundary tests |
| SEC-1003 | RSA verify accepts weak/undersized key on import | Closed | `e08c480` | `tests/sig.zig` weak-key, type-binding tests |
| SEC-1004 (F1) | No zeroization of secret material | Closed | `4eacfcf`, `16eac47` | `src/util.zig`, `tests/aead.zig` |
| SEC-1005 (F2) | No constant-time comparison | Closed | `0668f00` | Parity test in shim + fips backends |
| SEC-1006 (F4) | Unsynchronized provider globals | Closed | `db54ab2`, `1f25ebb` | `src/provider.zig` TSan concurrency test |
| SEC-1007 (F5) | Length truncation to `c_int` | Closed | `91563c1`, `16eac47` | `src/ffi.zig` toCInt/toCLong helpers + tests |
| SEC-1008 (F6) | Stream.update panics on EVP failure | Closed | `9830b02` | `src/hash.zig` tests; `Error!void` signature |
| SEC-1009 (F7) | PBKDF2 disables FIPS minimums | Closed | `f22c4b9` | `src/kdf.zig` tests |
| SEC-1011 | No nonce-uniqueness / 96-bit-length contract on AES-GCM | Closed | `80220f5`, `2c9661f` | `tests/aead.zig` (negative nonce-length); `SEAM_CONTRACT.md` guidance |
| SEC-1013 | `OSSL_PROVIDER_load("base")` return ignored | Closed | `db54ab2` | `src/provider.zig` tests |
| SEC-1015 | CSPRNG shim infinite retry on any errno | Closed | `8b8fa0d` | `src/csprng.zig` / `src/std_shim.zig` tests |
| SEC-1017 (NEW) | Hash.digest / Stream.final output-buffer overrun | Closed | `e740b37` | `tests/hash.zig` buffer-too-small negative tests |
| SEC-1010 (F8) | `assertActive()` panics as enforcement | Resolved-by-doc | `2c9661f` | `SEAM_CONTRACT.md`; fail-closed by design |
| SEC-1016 | `error.Unsupported` can mask mis-provisioned provider | Resolved-by-doc | `2c9661f` | `SEAM_CONTRACT.md` no-fallback caveat |

**SEC-1012** (OPENSSL_CONF env config): DEFERRED — tracked in
`SECURITY_GAP_ANALYSIS.md`.

**SEC-1014** (CI fips-deps pinning): PARTIALLY-CLOSED via SEC-1001 (`d8661c1`);
artifact scope narrowing DEFERRED — tracked in `SECURITY_GAP_ANALYSIS.md`.

---

## Round-1 Totals

| Domain | Closed | Resolved-by-doc | Not-a-defect | Partially-addressed | Deferred |
|--------|--------|-----------------|--------------|---------------------|----------|
| GAP | 6 | 2 | 0 | 0 | 2 (+1 partial) |
| QUALITY | 11 | 3 | 1 | 1 | 0 (4 open-minor) |
| PERF | 4 | 0 | 1 | 0 | 2 (+2 substantially-addressed) |
| SECURITY | 13 | 2 | 0 | 0 | 2 (+1 partial) |
| **Total** | **34** | **7** | **2** | **1** | **6+** |

**Net still-open (not deferred):** QUAL-0004, QUAL-0009, QUAL-0012 (open-minor),
QUAL-0003 (open-minor, partial), GAP-0027 runtime, GAP-0030, SEC-1012, SEC-1014
partial, PERF-0007, PERF-0008.

## Round-2/3 resolved (2026-06-22)

| ID | Title | Commit |
| --- | --- | --- |
| SEC-2001 | provider partial-init fail-open | `5325d0f` |
| SEC-2002 | CI GPG authenticity check + REQUIRE_GPG | `5395288` |
| SEC-2003 | RSA exponent FIPS validation (`e` odd, >=65537) | `f55d176` |
| PERF-0010 | KDF fetch cache | `8b859a1` |
| PERF-0011 | `Stream.init` MD up_ref | `b8410f9` |
| PERF-0012 | bench optimize-mode note | `07ccfa1` |
| GAP-0031 | CHANGELOG/spec accuracy | `2805a55` |
| QUAL-0020..0023 | stale comments/citations + policy scaffolding note | `07ccfa1` |
