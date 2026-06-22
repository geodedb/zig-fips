<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2024-2026 CodePros -->

# GAP_ANALYSIS — fips (Zig FIPS-140-3 / PQC crypto-seam library)

> **Round-1 closure applied 2026-06-22 on branch audit/round-1-hardening.**
> Closed and resolved items have been moved to the "Resolved" section below
> and to `docs/GAP_ANALYSIS_RESOLVED.md`. Only genuinely still-open items
> remain in the open section.

- **Date:** 2026-06-22
- **Analyst:** automated requirements-to-code gap determination
- **Repo:** `/home/benji/src/devnw/zig/fips` @ `main` (HEAD `65ba5a9`)
- **Toolchain present:** Zig 0.16.0; OpenSSL 3.6.2 FIPS build at `/usr/local/ssl` (fips provider active)
- **Scope:** `docs/FIPS_SPECIFICATION.md`, `docs/SEAM_CONTRACT.md`, `docs/PQC_ROADMAP.md`,
  `docs/2026-06-20-fips-pqc-design.md`, `docs/GAP-0020-module-dedup.md`, `README.md`, `CHANGELOG.md`
  vs `src/*.zig`, `templates/*`, `build.zig`, `.gitlab-ci.yml`, `Makefile`, `scripts/*`, `tests/*`.

This file tracks **open gaps only**. There was no prior `GAP_ANALYSIS.md` /
`GAP_ANALYSIS_RESOLVED.md`. `GAP-0020` is an already-assigned (and resolved)
ID owned by `docs/GAP-0020-module-dedup.md`, so new IDs start at **GAP-0021**.

## Evidence captured this run (commands + outcomes)

| Check | Command | Result |
|---|---|---|
| Shim-only path (no OpenSSL link) | `zig test --dep std_shim -Mroot=tests/shim_parity.zig -Mstd_shim=src/std_shim.zig` | **19/19 passed** |
| FIPS-backend unit + KATs | `OPENSSL_CONF=.../openssl.cnf zig build test -Dopenssl_path=/usr/local/ssl` | **63/63 passed, 15/15 steps** |
| FIPS integration + PQC CLI interop | `zig build test-integration -Dopenssl_path=/usr/local/ssl` | ML-DSA-65 sign/CLI-verify + ML-KEM-768 bidirectional **OK**; 7/7 steps |
| GAP-0020 dedup repro (negative) | `zig build test -Drepro_dedup=true` | **fails as documented**: `error: file exists in modules 'build_options' and 'build_options0'` |
| Format gate | `zig fmt --check src tests examples benchmarks build.zig` | **clean** |
| `secureZero`/`timing_safe` in code | `grep -rn` over `src/ templates/ tests/` | **NOT FOUND** (see GAP-0021) |
| `zlint`/`ZL109` in code/CI | `grep -rn` over non-docs | **only in docs/**, absent from `.gitlab-ci.yml`/Makefile/src (see GAP-0022) |
| `run`/`no-cli` build steps | `grep` `build.zig` | **absent** (see GAP-0026) |

## Summary

- **Requirements analyzed:** 38 discrete contract points (flag semantics, approved-algorithm
  policy, forced swaps, provider self-test, seam public surface, PQC roadmap, GAP-0020 rule,
  CI/CD gates, docs/compliance artifacts).
- **Implemented (verified):** 27
- **Partial:** 7
- **Not Implemented:** 3
- **Unknown:** 1
- **New gaps:** 10 (GAP-0021 … GAP-0030)
- **Previously open gaps resolved:** 0 (none existed)
- **Round-1 closed:** 6 (GAP-0021, GAP-0023, GAP-0024, GAP-0025, GAP-0026, GAP-0029)
- **Round-1 resolved/deferred:** 4 (GAP-0022 resolved-by-doc; GAP-0027 compile closed / runtime deferred; GAP-0028 resolved-by-doc; GAP-0030 deferred)
- **Total still-open (deferred/minor):** 4

### Implemented & verified (no gap — for traceability)

- Flag semantics / seam selection (`templates/crypto_backend.zig:16-37`, `build.zig:34`,
  `build_fips_snippet.zig`), lazy-dep posture (`build_zon_snippet.txt`), single
  `build_options` GAP-0020 rule **proven both ways** (`build.zig:227-269`, repro fails on demand).
- Provider lifecycle + startup self-test `assertActive`/`ensureFips`
  (`src/provider.zig:24-49`) forcing `EVP_default_properties fips=yes` + `OSSL_PROVIDER_self_test`.
- Approved primitives with KATs: SHA-2/3 + streaming (`src/hash.zig`), HMAC RFC 4231
  (`src/mac.zig:37`), HKDF/HKDF-Expand/PBKDF2 RFC vectors (`src/kdf.zig:76-118`),
  AES-128/256-GCM incl. tamper-detect (`src/aead.zig:82-123`), CSPRNG via `RAND_bytes_ex`
  (`src/csprng.zig`).
- Signatures: Ed25519, ECDSA P-256/P-384, RSA-PSS/PKCS1 (incl. explicit-digest `verifyRsa`,
  off-diagonal `verifyEcdsa`, JWKS `fromRsaComponents`, SPKI `fromRsaSpki`), ML-DSA-65,
  SLH-DSA-SHA2-128s (`src/sig.zig`).
- KEM ML-KEM-768 + X25519MLKEM768 with encap/decap agreement + CLI interop (`src/kem.zig`,
  `tests/pqc_kem_interop.zig`).
- `std_shim` API-parity backend incl. `Hash.Stream`, `hkdfExpand`, pinned `Kem.EncapResult`,
  `error.Unsupported` for RSA/P-521/PQC (`src/std_shim.zig`, `tests/shim_parity.zig` 19/19).
- Provider sourcing scripts + verify (`scripts/install-openssl-fips.sh`,
  `scripts/verify-fips-provider.sh`), dual-mode Makefile gate (`Makefile:88-99`),
  `fips-deps`/`test-fips` CI jobs (`.gitlab-ci.yml:306-328`).

---

## Open Items (Deferred / Open-minor)

### GAP-0022: ZL109 `fips_unguarded_crypto` lint gate — RESOLVED-by-doc (deferred follow-up tracked)

- **Status:** RESOLVED-by-doc — commit `2c9661f` clarifies that `zig-fips-lint` (ZL109)
  is a workspace-level `ci-catalog` component, not wired in this repo's own CI;
  the spec language has been softened to "planned" until the gate lands.
  A deferred follow-up to wire the component remains open.
- **Commit:** `2c9661f`
- **Remaining action:** Wire `gitlab.com/devnw/ci-catalog/zig-fips-lint` component into
  `.gitlab-ci.yml` + pre-commit hook; this is an infra/workspace task, not a fips-repo defect.
- **Category:** CI-CD / Deferred

### GAP-0027: `std_shim` CSPRNG macOS/Windows RUNTIME coverage — PARTIALLY-CLOSED / DEFERRED

- **Status:** PARTIALLY-CLOSED for compile — commits `1100939` and `8b8fa0d` replace the
  Linux-only `std.os.linux.getrandom` call with `std.crypto.random` (which abstracts the
  platform), verified compile on Linux/macOS/Windows via `zig build-obj`. macOS and Windows
  **runtime** coverage (actual entropy source exercised on those platforms) remains DEFERRED
  pending runners.
- **Commits:** `1100939`, `8b8fa0d`
- **Remaining:** Promote macOS/Windows CI shim jobs from `allow_failure` to required once
  runners are available; verify `Csprng.bytes` returns non-zero/non-repeating output on
  those platforms.
- **Category:** Feature / Deferred

### GAP-0028: AES-256-CBC in approved_names but no API — RESOLVED-by-doc

- **Status:** RESOLVED-by-doc — commit `2c9661f` adds a `policy.zig` comment explicitly
  noting that `AES-256-CBC` is present in `approved_names` as "available on request" but
  has no wrapped enum variant or API surface by design (no current consumer needs it). The
  spec language is updated to match.
- **Commit:** `2c9661f`
- **Category:** Feature / Resolved

### GAP-0030: `.path` → `git+https` publish swap — DEFERRED

- **Status:** DEFERRED — intentional. Cannot publish until `fips` is tagged; the placeholder
  URL/hash in `build_zon_snippet.txt` + `README.md` remains until that publish event.
  This is a release-mechanics task, not a code defect.
- **Remaining:** On tagging `fips` v0.1.0: compute real `zig fetch` hash, fill snippet/README,
  swap each consumer's `.path` dep.
- **Category:** Requirement / Deferred

---

## Resolved Items (Round-1)

### GAP-0021: `secureZero` + `timingSafeEql` absent from seam — CLOSED

- **Status:** CLOSED — commit `4eacfcf` adds `secureZero` (wrapping `OPENSSL_cleanse`)
  to both backends; commit `0668f00` adds `timingSafeEql` to both backends.
- **Commits:** `4eacfcf`, `0668f00`
- **Verifying tests:** `src/util.zig`, seam parity tests
- **Original severity:** High

### GAP-0023: SLH-DSA — only 1 of 12 variants tested — CLOSED

- **Status:** CLOSED — commit `421923e` adds a table-driven sign→verify+tamper test
  iterating all 12 `policy.SigAlg` SLH-DSA variants.
- **Commit:** `421923e`
- **Verifying tests:** `src/sig.zig` (all 12 SLH-DSA variants)
- **Original severity:** Medium

### GAP-0024: ML-DSA — only ML-DSA-65 tested — CLOSED

- **Status:** CLOSED — commit `399921f` extends the ML-DSA test to cover all three
  variants (ML-DSA-44, ML-DSA-65, ML-DSA-87) with sign→verify+tamper.
- **Commit:** `399921f`
- **Verifying tests:** `src/sig.zig` (ML-DSA-44, ML-DSA-65, ML-DSA-87)
- **Original severity:** Medium

### GAP-0025: ECDSA P-521 and hybrid KEMs untested in fips backend — CLOSED

- **Status:** CLOSED — commit `43f98ed` adds P-521 sign→verify test and table-driven
  KEM agreement tests for all four hybrids plus ML-KEM-512/1024.
- **Commit:** `43f98ed`
- **Verifying tests:** `src/sig.zig`, `src/kem.zig` (P-521, all hybrids, ML-KEM-512/1024)
- **Original severity:** Medium

### GAP-0026: README scaffold with broken API / CLI / build steps — CLOSED

- **Status:** CLOSED — commit `c63bd73` rewrites `README.md` to describe the real seam
  surface: `-Dfips` flag semantics, three copy-verbatim files, `crypto_backend` usage,
  OpenSSL FIPS provisioning via `make deps`, dual-mode test gate. All CLI / `fips.init` /
  `-Dno-cli` / "zero dependencies" content removed.
- **Commit:** `c63bd73`
- **Verifying tests:** README code blocks compile against current public API
- **Original severity:** Medium

### GAP-0029: CHANGELOG.md unfilled template — CLOSED

- **Status:** CLOSED — commit `242740a` populates `CHANGELOG.md` with the real 0.1.0
  delivery (seam, FIPS backend, std_shim, PQC sign/KEM, provider self-test, dual-mode gate,
  GAP-0020 rule) and sets a real date.
- **Commit:** `242740a`
- **Verifying tests:** No `YYYY-MM-DD` placeholder remains
- **Original severity:** Low

---

## Unknown

### Cross-OS FIPS-backend behavior (macOS/Windows) — undetermined here

- The `link.zig` macOS (Homebrew `openssl@3`) and Windows (`VCPKG_ROOT`) branches
  (`src/link.zig:32-41`) are unexercised in this environment (Linux-only host, advisory cross-OS CI).
  Whether the FIPS backend links + self-tests on macOS/Windows is **Unknown**. To verify: run
  `zig build test -Dopenssl_path=<prefix>` on a macOS and a Windows runner with a FIPS-enabled OpenSSL
  present. (Related to but distinct from GAP-0027, which is about the non-FIPS shim CSPRNG compiling
  off-Linux.) Not promoted to a numbered gap pending an attempt on those targets.

---

## Gap Priority Matrix (post-Round-1)

| Severity | Count | Gap-IDs |
|----------|-------|---------|
| Critical | 0 | — |
| High | 0 | (GAP-0021 closed) |
| Medium | 0 | (GAP-0023, GAP-0024, GAP-0025, GAP-0026 closed; GAP-0027 partially closed) |
| Low | 0 | (GAP-0028, GAP-0029 closed/resolved; GAP-0030 deferred) |
| Deferred | 3 | GAP-0022 (follow-up), GAP-0027 (runtime), GAP-0030 |
| Resolved-by-doc | 2 | GAP-0022, GAP-0028 |

## Category rollup (post-Round-1)

| Category | Gap-IDs | Status |
|----------|---------|--------|
| Security | GAP-0021 | Closed |
| CI-CD | GAP-0022 | Resolved-by-doc / deferred follow-up |
| Test | GAP-0023, GAP-0024, GAP-0025 | All closed |
| Docs | GAP-0026, GAP-0029 | Both closed |
| Feature | GAP-0027, GAP-0028 | Partially-closed+deferred; resolved-by-doc |
| Requirement | GAP-0030 | Deferred |
