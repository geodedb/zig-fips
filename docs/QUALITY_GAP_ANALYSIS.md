<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2024-2026 CodePros -->

# Code Quality Gap Analysis — `fips` crypto-seam library

> **Round-1 closure applied 2026-06-22 on branch audit/round-1-hardening.**
> All findings are re-dispositioned below. Closed and resolved items have been
> moved to the "Resolved" section and to `docs/GAP_ANALYSIS_RESOLVED.md`.
> Only genuinely still-open (open-minor) items remain in the open section.

Read-only manual code-quality review of the Zig FIPS crypto-seam library.
No source was modified. Every finding cites `file:line` with a minimal
snippet, a root-cause, a recommended fix, and acceptance criteria.

- **Scope:** `src/*.zig`, `templates/*.zig`, `build.zig`, `tests/*.zig`,
  `benchmarks/*.zig`.
- **Toolchain:** Zig 0.16.0 (confirmed on PATH); no third-party deps; FFI
  to OpenSSL 3.x FIPS provider.
- **Backends under contract:** `src/*` (OpenSSL FIPS backend) vs
  `src/std_shim.zig` (std.crypto backend), joined by the comptime seam
  `templates/crypto_backend.zig`.
- **Date:** 2026-06-22.

Confidence is labeled per finding: `confirmed` (verified directly from
source) or `suspected` (needs a build/runtime check to confirm; the
confirming step is stated).

## Strong points (bounding false positives)

These are genuinely good and should not be "fixed":

- **API parity is mostly excellent.** Both backends expose the same
  symbols with the same signatures (`Hash`/`Mac`/`Kdf`+`hkdfExpand`/
  `Aead`/`Sig`+`from*Bytes`/`verifyRsa`/`verifyEcdsa`/`Kem`+pinned
  `EncapResult`/`Csprng`/`assertActive`). The seam re-exports them and
  `tests/seam_template_test.zig` asserts the pinned types resolve.
- **fips-only algorithms degrade cleanly.** RSA, ECDSA P-521, ML-DSA,
  SLH-DSA, ML-KEM all return `error.Unsupported` in the shim, matching
  `docs/SEAM_CONTRACT.md` §2, and `tests/shim_parity.zig` asserts it.
- **KAT coverage of the happy path is strong** — RFC test vectors for
  HKDF, HKDF-Expand, PBKDF2, HMAC, SHA-2/3; GCM tags; sign/verify round
  trips incl. off-diagonal ECDSA and explicit-digest RSA; bidirectional
  ML-KEM and ML-DSA CLI interop.
- **Memory hygiene in the FFI layer is careful** — consistent
  `defer`/`errdefer` on every `EVP_*` allocation, and the `Hash.Stream
  .clone` comment explicitly explains the independent `EVP_MD` ref to
  avoid a double-free / use-after-free.
- **GAP-0020 build-graph hazard is documented, templated, and has a
  gated reproduction** (`-Drepro_dedup`, `tests/dedup_*`).

---

## Open Items (Open-minor — not addressed this round)

### QUAL-0003 — Hardcoded RSA modulus size — PARTIALLY-ADDRESSED / OPEN-MINOR

- **Status:** PARTIALLY-ADDRESSED — commit `e08c480` introduces a
  `min_rsa_bits` constant for the verify-floor check. A configurable RSA
  keygen bit-size (allowing callers to request 3072/4096) remains
  OPEN-MINOR. See PERF-0008 (DEFERRED) for the perf angle.
- **Severity:** Low
- **Location:** `src/sig.zig:170`

### QUAL-0004 — Duplicated `cliHasPqc`/`termOk` + triplicated SHA-2 name switch — OPEN-MINOR

- **Status:** OPEN-MINOR — not addressed this round. Low priority; no
  correctness impact, maintainability nit only.
- **Severity:** Low
- **Location:** `tests/pqc_*_interop.zig:17-39`; `src/sig.zig:54-59,427-432,454-459`

### QUAL-0009 — `publicBytes` does not bound `out` before OpenSSL call — OPEN-MINOR

- **Status:** OPEN-MINOR — `EVP_PKEY_get_raw_public_key` is documented to
  return failure (not overflow) when `out` is too small, so this is low
  risk. Not addressed this round.
- **Severity:** Low
- **Location:** `src/sig.zig:73-77`

### QUAL-0012 — `assertActive` not re-checked in `Stream.update`/`final`/`clone` — OPEN-MINOR

- **Status:** OPEN-MINOR — the once-at-init invariant is defensible (a
  valid `Stream` implies `init` succeeded). Lock-free check is cheap;
  the invariant is documented as of `2c9661f`. Not addressed this round.
- **Severity:** Low
- **Location:** `src/hash.zig:43-87`

---

## Resolved Items (Round-1)

### QUAL-0001 — README is a stale scaffold — CLOSED

- **Status:** CLOSED — commit `c63bd73` rewrites `README.md` to match the
  real library surface. All broken snippets, non-existent build steps,
  and CLI references removed.
- **Commit:** `c63bd73`
- **Original severity:** High

### QUAL-0002 — Benchmark suites measure `version.len` — CLOSED

- **Status:** CLOSED — commit `90ba16d` replaces all placeholder scenarios
  with real crypto workloads (Hash.digest, Aead.seal/open, Sig.sign/verify,
  Kem.encapsulate).
- **Commit:** `90ba16d`
- **Original severity:** Medium

### QUAL-0005 — `Csprng.bytes` length→`c_int` bound unverified — NOT-A-DEFECT

- **Status:** NOT-A-DEFECT — `RAND_bytes_ex` takes `size_t` in OpenSSL 3.x;
  `out.len` (usize) maps cleanly with no truncation. Confirmed by inspection
  of the OpenSSL 3.x prototype; no truncation possible.
- **Original severity:** Low

### QUAL-0006 — fips `Aead.seal`/`open` skip all length validation — CLOSED

- **Status:** CLOSED — commit `80220f5` adds key/nonce/tag/output-buffer
  length validation before all EVP calls in both `seal` and `open`, mirroring
  the shim's guards. The two backends now return the same error for the same
  out-of-bounds inputs.
- **Commit:** `80220f5`
- **Verifying tests:** `tests/aead.zig` (negative/boundary tests)
- **Original severity:** High

### QUAL-0007 — Shim `Sig.sign`/`verify` ignore `alg` — RESOLVED-by-doc

- **Status:** RESOLVED-by-doc — commit `2c9661f` documents in
  `SEAM_CONTRACT.md` cross-backend caveats: the shim dispatches on keypair
  type; `alg` is advisory in the shim. The documented behavior is now
  explicit and pinned.
- **Commit:** `2c9661f`
- **Original severity:** Medium

### QUAL-0008 — ECDSA/RSA public-key encoding differs per backend — RESOLVED-by-doc

- **Status:** RESOLVED-by-doc — commit `2c9661f` adds an "Encoding &
  behavioral caveats" subsection to `SEAM_CONTRACT.md` stating per-family
  public-key encoding and noting that ECDSA/RSA wire bytes are
  currently backend-specific by design.
- **Commit:** `2c9661f`
- **Original severity:** Medium

### QUAL-0010 — `Kem.encapsulate`/`decapsulate` discard `alg` — RESOLVED-by-doc

- **Status:** RESOLVED-by-doc — commit `2c9661f` adds a doc note that `alg`
  is advisory / retained for API symmetry in `SEAM_CONTRACT.md`.
- **Commit:** `2c9661f`
- **Original severity:** Low

### QUAL-0011 — `Hash.Stream.update` panics in fips — CLOSED

- **Status:** CLOSED — commit `9830b02` changes `Hash.Stream.update` to
  return `Error!void` in both backends, eliminating the `@panic`. The doc
  comment has been updated to reflect the new fallible contract.
- **Commit:** `9830b02`
- **Verifying tests:** `src/hash.zig` tests
- **Original severity:** Medium

### QUAL-0013 — No fips error-path tests — CLOSED

- **Status:** CLOSED — commits `5bdab65` and `e740b37` add comprehensive
  error-path tests for all fips primitive wrappers: buffer-too-small,
  Unsupported, OpensslFailure for Hash, Mac, Kdf, Aead, Kem, Csprng.
- **Commits:** `5bdab65`, `e740b37`
- **Verifying tests:** `src/*.zig` (negative tests now cover each Error member)
- **Original severity:** Medium

### QUAL-0014 — Integration and stress suites are version-string placeholders — CLOSED

- **Status:** CLOSED — commit `e49c75e` makes `stress.zig` drive real
  crypto wrappers in a loop (multi-thread, TSan-green) and `integration.zig`
  exercise per-family primitives end to end.
- **Commit:** `e49c75e`
- **Verifying tests:** `tests/integration.zig`, `tests/stress.zig`
- **Original severity:** Medium

### QUAL-0015 — No concurrency test; `g_ctx`/`g_fips` unsynchronized global race — CLOSED

- **Status:** CLOSED — commits `db54ab2` and `1f25ebb` synchronize lazy
  FIPS init with a mutex + lock-free fast path; a TSan-green multi-threaded
  test in `provider.zig` verifies no data race.
- **Commits:** `db54ab2`, `1f25ebb`
- **Verifying tests:** `tests/provider.zig` (TSan concurrency test)
- **Original severity:** High

### QUAL-0016 — `ecGroup` `else => unreachable` over a growing enum — CLOSED

- **Status:** CLOSED — commit `84c6ea9` makes `ecGroup` exhaustively match
  all variants (returning `error.Unsupported` for non-EC cases), eliminating
  the UB path.
- **Commit:** `84c6ea9`
- **Original severity:** Low

### QUAL-0017 — CHANGELOG is an unfilled template — CLOSED

- **Status:** CLOSED — commit `242740a` populates the changelog from the
  delivered features with a real date.
- **Commit:** `242740a`
- **Original severity:** Low

### QUAL-0018 — `Hash.Stream` doc comment overstates failure invariant — CLOSED

- **Status:** CLOSED — commit `9830b02` rewrites the doc comment alongside
  the `Error!void` change; the comment no longer claims the failure "cannot
  happen."
- **Commit:** `9830b02`
- **Original severity:** Low

### QUAL-0019 — `SEAM_CONTRACT.md` omits encoding/`alg` divergences — CLOSED

- **Status:** CLOSED — commit `2c9661f` adds the "Encoding & behavioral
  caveats" subsection addressing public-key encoding portability and
  `alg`-handling across backends.
- **Commit:** `2c9661f`
- **Verifying tests:** `docs/SEAM_CONTRACT.md` updated
- **Original severity:** Medium

---

## Summary table (post-Round-1)

| ID | Severity | Status | Commit(s) |
|----|----------|--------|-----------|
| QUAL-0001 | High | Closed | c63bd73 |
| QUAL-0002 | Medium | Closed | 90ba16d |
| QUAL-0003 | Low | Partially-addressed / Open-minor | e08c480 (partial) |
| QUAL-0004 | Low | Open-minor | — |
| QUAL-0005 | Low | Not-a-defect | — |
| QUAL-0006 | High | Closed | 80220f5 |
| QUAL-0007 | Medium | Resolved-by-doc | 2c9661f |
| QUAL-0008 | Medium | Resolved-by-doc | 2c9661f |
| QUAL-0009 | Low | Open-minor | — |
| QUAL-0010 | Low | Resolved-by-doc | 2c9661f |
| QUAL-0011 | Medium | Closed | 9830b02 |
| QUAL-0012 | Low | Open-minor | — |
| QUAL-0013 | Medium | Closed | 5bdab65, e740b37 |
| QUAL-0014 | Medium | Closed | e49c75e |
| QUAL-0015 | High | Closed | db54ab2, 1f25ebb |
| QUAL-0016 | Low | Closed | 84c6ea9 |
| QUAL-0017 | Low | Closed | 242740a |
| QUAL-0018 | Low | Closed | 9830b02 |
| QUAL-0019 | Medium | Closed | 2c9661f |

**Round-1 counts:** Closed 11 · Resolved-by-doc 3 · Not-a-defect 1 ·
Open-minor 4 (QUAL-0003 partially, QUAL-0004, QUAL-0009, QUAL-0012).
