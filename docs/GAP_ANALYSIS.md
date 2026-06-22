<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2024-2026 CodePros -->

# GAP_ANALYSIS — fips (Zig FIPS-140-3 / PQC crypto-seam library)

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
- **Total open gaps:** 10

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

## New Gaps

### GAP-0021: Spec asserts `secureZero` + `timing_safe` "remain available" but neither exists in the seam/code

- **Category:** Security
- **Severity:** High
- **Requirement source:** `docs/FIPS_SPECIFICATION.md:256` ("…constant-time compare (`timing_safe`),
  and memory zeroing (`secureZero`) remain available (not FIPS-governed…)"). Constant-time tag/secret
  comparison and key zeroization are baseline expectations for a crypto seam used by `tls`/`auth`/`hsm`/`encrypted-fs`.
- **Current state (evidence):**
  - `grep -rn 'secureZero\|timing_safe\|timingSafe\|constantTimeCompare'` over `src/ templates/ tests/`
    → **no matches**. Neither symbol is defined or re-exported anywhere.
  - Seam re-exports (`templates/crypto_backend.zig:20-37`) list `Aead/Hash/HashStream/Mac/Kdf/Sig/Kem/
    Csprng/policy/assertActive` only — no `secureZero`, no `timing_safe`/constant-time compare.
  - `src/root.zig:23-29` (the `fips` backend surface) likewise omits both.
- **Why this is a gap:** The published, "Verified" capability matrix states these primitives *remain
  available* through the seam. They are not present in either backend, so any consumer following the
  spec will fail to compile against them, or (worse) reach for a non-seam `std`/ad-hoc implementation —
  the exact leakage the seam exists to prevent.
- **Impact/Risk:** Consumers performing MAC/tag verification or comparing secrets may use
  variable-time `std.mem.eql`/`==` (timing side-channel), and key material may not be zeroed
  (secret-in-memory exposure). Directly undercuts the SC-13/SI-7 posture the doc claims.
- **Recommended fix:** Add `pub fn secureZero(bytes: []u8) void` (e.g. `std.crypto.secureZero`/
  `OPENSSL_cleanse`) and `pub fn timingSafeEql(a, b) bool` (`std.crypto.timing_safe.eql`/`CRYPTO_memcmp`)
  to BOTH `src/` (fips) and `src/std_shim.zig`, re-export through `templates/crypto_backend.zig`, and
  document them in `SEAM_CONTRACT.md` §2. If the intent is NOT to ship them, delete the assertion at
  `FIPS_SPECIFICATION.md:256` (then this becomes a docs gap instead).
- **Acceptance criteria:** `crypto_backend.secureZero` and `crypto_backend.timingSafeEql` exist and
  re-export in both backends; a test proves `timingSafeEql` returns correct equality and `secureZero`
  zeroes a buffer; `SEAM_CONTRACT.md` §2 pinned list includes both; spec line 256 matches reality.
- **Verification plan:** `grep` shows the symbols in both backends + the seam; `zig build test` covers
  the new tests in both `-Dfips` modes (shim + FIPS).

### GAP-0022: ZL109 `fips_unguarded_crypto` lint gate is a "required" + "Verified" enforcement claim with no implementation or CI wiring in this repo

- **Category:** CI-CD
- **Severity:** High
- **Requirement source:** `docs/FIPS_SPECIFICATION.md:26` ("the `zig-fips-lint` (ZL109) gate enforces
  the seam statically"), `:109`, `:229-231`, `:241-247` ("Workspace-wide ZL109 … = 0 … Enforced
  automatically by the ZL109 lint gate"); `docs/SEAM_CONTRACT.md:33`; design `:102`, `:149`.
- **Current state (evidence):**
  - `grep -rn 'zlint\|ZL109\|fips_unguarded_crypto\|zig-fips-lint\|zig-fips-build'` over all non-docs
    files → **zero hits**. The strings appear only inside `docs/`.
  - `.gitlab-ci.yml` includes `zig-format`, `zig-build`, `zig-test*`, `zig-fuzz`, security/SBOM/release
    components and the bespoke `fips-deps`/`test-fips` jobs — but **no `zig-fips-lint` / `zig-fips-build`
    ci-catalog component** and no lint stage running ZL109.
  - No `.pre-commit-config.yaml` rule for the fips exemption exists (design `:102` says "Wired into
    pre-commit + CI").
- **Why this is a gap:** The spec repeatedly states ZL109 is a *required* gate and that the workspace is
  *verified* ZL109=0, but nothing in this repo defines or runs that rule. The enforcement is asserted,
  not implemented here. (Also note `.gitlab-ci.yml:26/88-92` of the spec describe a `zig-fips-build`
  component running `make deps` + `-Dfips=true`; the actual CI uses custom `fips-deps`/`test-fips` jobs
  instead — functionally close, but the named required component is absent.)
- **Impact/Risk:** A consumer (or this repo) could introduce unguarded `std.crypto` in a security path
  and CI would not fail, contradicting the SC-13+CM-7 "least functionality" control mapping the spec
  claims is enforced automatically.
- **Recommended fix:** Either (a) wire the `gitlab.com/devnw/ci-catalog/zig-fips-lint` component (and/or
  the `zig-fips-build` component) into `.gitlab-ci.yml` and add the pre-commit hook, with the ZL109 rule
  source pinned per `FIPS_SPECIFICATION.md:261`; or (b) downgrade the "required"/"Verified automatically"
  language in the spec to "planned" until the gate lands. Track the existing deferral
  (`FIPS_SPECIFICATION.md:261`, re-pin `zlint_ref`) against this gap.
- **Acceptance criteria:** `.gitlab-ci.yml` contains a lint job that runs ZL109 and fails on unguarded
  `std.crypto`/`std.hash`; a deliberately-unguarded fixture proves the job goes red; pre-commit runs the
  same rule; spec language matches the wired reality.
- **Verification plan:** Inspect pipeline for a ZL109 lint job; add a temporary unguarded-crypto fixture
  on a branch and confirm CI fails; revert.

### GAP-0023: SLH-DSA — 12 algorithms are policy-approved but only 1 (`SLH-DSA-SHA2-128s`) has a KAT/round-trip test

- **Category:** Test
- **Severity:** Medium
- **Requirement source:** `docs/FIPS_SPECIFICATION.md:43` (all 12 SLH-DSA approved); design `:127`
  ("KAT/known-answer tests for each approved algorithm"); `PQC_ROADMAP.md:17,33`.
- **Current state (evidence):**
  - `src/policy.zig:29-40` enumerates all 12 SLH-DSA variants (SHA2/SHAKE × 128/192/256 × s/f).
  - `src/sig.zig` exercises only `slh_dsa_sha2_128s` (`src/sig.zig:402-408`). The other 11 (notably all
    6 SHAKE variants, and the 192/256 SHA2 variants) have **no test**.
  - `scripts/verify-fips-provider.sh:18` only asserts `SLH-DSA-SHA2-128s` is listed by the provider.
- **Why this is a gap:** "KAT for each approved algorithm" is unmet for 11/12 SLH-DSA names; a name could
  be mis-mapped (`policy.sigName`) or unsupported by the provider build and go undetected. The generic
  sign→verify path is shared, but name-string correctness and provider availability are per-algorithm.
- **Impact/Risk:** A consumer selecting e.g. `SLH-DSA-SHAKE-256f` could hit `error.Unsupported`/
  `OpensslFailure` at runtime that no test would have caught.
- **Recommended fix:** Add a table-driven sign→verify+tamper test iterating all 12 `policy.SigAlg`
  SLH-DSA variants (and assert `policy.sigName` ↔ provider fetch succeeds). Mark long-running `s`
  variants appropriately if runtime is a concern.
- **Acceptance criteria:** A test covers all 12 SLH-DSA variants (generate/sign/verify + tamper-reject);
  `zig build test -Dfips=true` green.
- **Verification plan:** Run the new test against `/usr/local/ssl`; confirm each variant fetches and
  round-trips.

### GAP-0024: ML-DSA — only `ML-DSA-65` is tested; `ML-DSA-44` and `ML-DSA-87` have no KAT

- **Category:** Test
- **Severity:** Medium
- **Requirement source:** `docs/FIPS_SPECIFICATION.md:42`; `PQC_ROADMAP.md:16,27,33` (zign lists
  ML-DSA-44/65/87); design `:127`.
- **Current state (evidence):**
  - `src/policy.zig:27-28` defines `ml_dsa_44`, `ml_dsa_65`, `ml_dsa_87`.
  - `src/sig.zig:393-400` tests `ml_dsa_65` only; no `ml_dsa_44` / `ml_dsa_87` test exists.
- **Why this is a gap:** Same per-algorithm name/availability risk as GAP-0023 for the other two
  parameter sets that consumers (`zign`) are documented to use.
- **Impact/Risk:** Mis-mapping or provider-coverage gaps for 44/87 would surface only in a downstream
  consumer.
- **Recommended fix:** Extend the ML-DSA test to iterate all three variants (sign→verify + tamper).
- **Acceptance criteria:** ML-DSA-44/65/87 each covered by a sign→verify+tamper test; FIPS test suite green.
- **Verification plan:** Run against the local FIPS provider.

### GAP-0025: ECDSA P-521 and hybrid KEMs X448MLKEM1024 / SecP256r1MLKEM768 / SecP384r1MLKEM1024 are approved but untested in the fips backend

- **Category:** Test
- **Severity:** Medium
- **Requirement source:** `FIPS_SPECIFICATION.md:41,45`; `SEAM_CONTRACT.md:52` ("`Sig` ECDSA P-521 …
  full" in fips); `PQC_ROADMAP.md:14-15`.
- **Current state (evidence):**
  - ECDSA P-521: `src/sig.zig:31` (`ecdsa_p521 => "P-521"`) and `:263` accept it, but no P-521
    generate/sign/verify test exists in `src/sig.zig`; only P-256/P-384 are tested (`:376,549,559`).
    The shim correctly returns `error.Unsupported` for P-521 (tested at `tests/shim_parity.zig:196`),
    but the fips-side "full" claim is unverified.
  - Hybrid KEMs: `src/policy.zig:51-54` define all four hybrids; `src/kem.zig` tests only
    `x25519_ml_kem_768` (`:79`). `X448MLKEM1024`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` have no
    encap/decap agreement test. The mixed-case `SecP*` tokens (`FIPS_SPECIFICATION.md:45`) are exactly
    the kind of string that needs a test.
- **Why this is a gap:** The contract advertises these as fully supported under fips; without tests, a
  name typo or provider-coverage gap is undetected.
- **Impact/Risk:** Consumers requesting P-521 certs or a non-default hybrid group could fail at runtime.
- **Recommended fix:** Add a P-521 sign→verify test and a table-driven KEM agreement test over all four
  hybrids + all three ML-KEM sizes (`ml_kem_512/768/1024`; note `ml_kem_512`/`ml_kem_1024` are also only
  implicitly covered).
- **Acceptance criteria:** P-521 and all four hybrids (and ML-KEM 512/1024) each have a passing
  round-trip/agreement test under `-Dfips=true`.
- **Verification plan:** Run against the local FIPS provider; confirm fetch + agreement for each token.

### GAP-0026: README documents a generic template API/CLI that does not exist; `make run` and `-Dno-cli` are broken

- **Category:** Docs
- **Severity:** Medium
- **Requirement source:** `README.md` (project's own public documentation). The library is the FIPS
  crypto seam, not a generic CLI template.
- **Current state (evidence):**
  - `README.md:42-49` Quick Start calls `fips.init(.{ .debug = true })` — `src/root.zig` exports **no
    `init`** and no options struct (`grep 'pub fn init' src/` only finds `Hash.Stream.init`). This
    snippet will not compile.
  - `README.md:6` "A Zig library for fips"; `:11` "Zero dependencies: pure Zig standard library only" —
    contradicts the OpenSSL-FFI core (`src/ffi.zig:7-20`, `src/link.zig`). True only for the `std_shim`
    path, not the library's primary (fips) surface.
  - `README.md:12,51-55,68` advertise "Library + CLI", `zig build run`, `make run`. `build.zig` defines
    **no `run` step** (`grep 'b.step("run"'` → none); `Makefile:53-54 run: zig build run` will fail.
  - `README.md:72` "`zig build -Dno-cli=true` produces a library-only build" — **no `-Dno-cli` option**
    in `build.zig`.
- **Why this is a gap:** The README is unmodified scaffold boilerplate that materially misrepresents the
  package (wrong API, wrong dependency posture, references non-existent build steps). A user following it
  hits compile/build failures immediately.
- **Impact/Risk:** Broken onboarding; false "zero dependencies" claim for a crypto library is
  particularly misleading for a FIPS posture.
- **Recommended fix:** Rewrite `README.md` to describe the seam: `-Dfips` flag semantics, the three
  copy-verbatim files, `crypto_backend` usage, OpenSSL FIPS provisioning via `make deps`, and the
  dual-mode test gate. Remove the `fips.init`/CLI/`-Dno-cli`/"zero dependencies" claims (or add the
  missing `run`/`-Dno-cli` build steps if a CLI is actually intended — currently it is not).
- **Acceptance criteria:** Every command and code snippet in `README.md` executes/compiles as written;
  no reference to non-existent symbols or build steps; dependency posture stated accurately.
- **Verification plan:** Copy each README snippet/command and run it; all succeed.

### GAP-0027: `std_shim` CSPRNG is Linux-`getrandom`-only; macOS/Windows paths unimplemented and not gated

- **Category:** Feature
- **Severity:** Medium
- **Requirement source:** `docs/FIPS_SPECIFICATION.md:206-222` (Published deferred item #2),
  `:260` (Deferred follow-up); `SEAM_CONTRACT.md` cross-platform implication; design `:121` (no-crypto
  cross-OS) and README "Cross-platform: Linux, macOS, Windows".
- **Current state (evidence):**
  - `src/std_shim.zig:17-29 randomBytes` calls `std.os.linux.getrandom` unconditionally; comment line 18
    says "Linux getrandom syscall". There is **no macOS (`SecRandomCopyBytes`) or Windows
    (`BCryptGenRandom`) branch**, and no `comptime` OS switch.
  - This file references `std.os.linux`, so it will **fail to compile** when targeting macOS/Windows
    (the symbol is Linux-only) — meaning the shim is not just untested cross-OS, it is non-portable.
  - CI macOS/Windows jobs exist but are advisory (`.gitlab-ci.yml:182-217`, `*cross-os-rules` +
    `allow_failure`), so this is not caught.
- **Why this is a gap:** It is an acknowledged deferral, but the spec frames it as "not yet *gated*";
  the stronger reality is the code path does not compile off-Linux. For a seam whose entire value is
  backend-agnostic portability, a non-portable default (`-Dfips=false`) backend is a real gap, not
  merely a missing test.
- **Impact/Risk:** Any consumer building the default (non-FIPS) backend on macOS/Windows fails to build;
  the documented "FIPS mode is the cross-platform CSPRNG of record" mitigation only helps `-Dfips=true`.
- **Recommended fix:** Add a `comptime` OS switch in `randomBytes` (Linux `getrandom`, macOS
  `SecRandomCopyBytes`/`getentropy`, Windows `BCryptGenRandom`), or delegate to
  `std.crypto.random`/`std.posix.getrandom` which already abstract the platform. Add a CSPRNG unit test
  and promote the macOS/Windows shim jobs to required (per the spec's own follow-up).
- **Acceptance criteria:** `src/std_shim.zig` compiles and `Csprng.bytes` returns non-zero/non-repeating
  output on Linux, macOS, and Windows targets; a gated CI job exercises it on each OS.
- **Verification plan:** `zig build test -Dtarget=aarch64-macos`/`x86_64-windows` (compile) + run the
  CSPRNG test on macOS/Windows runners.

### GAP-0028: AES-256-CBC is in the approved-name allow-list but has no `policy.Aead` enum variant and no wrapper

- **Category:** Feature
- **Severity:** Low
- **Requirement source:** `docs/FIPS_SPECIFICATION.md:40` ("`AES-256-GCM` (+ `AES-256-CBC` where a
  CBC+HMAC construction is required)"); design `:50` ("AES-CBC + HMAC where needed").
- **Current state (evidence):**
  - `src/policy.zig:115` lists `"AES-256-CBC"` in `approved_names` (so `isApproved("AES-256-CBC")` is
    true), but `policy.Aead` (`src/policy.zig:18`) has only `aes_128_gcm`/`aes_256_gcm` — **no CBC
    variant** — and `src/aead.zig` exposes only GCM seal/open. `grep` confirms no `cbc` enum/wrapper.
- **Why this is a gap:** The allow-list advertises CBC as approved, but no API can produce it, so the
  "where a CBC+HMAC construction is required" path is unsatisfiable through the seam. Inconsistent
  surface (approved-but-unreachable).
- **Impact/Risk:** Low today (no consumer in-tree needs CBC), but a consumer told CBC is approved cannot
  use it without bypassing the seam.
- **Recommended fix:** Either add an `aes_256_cbc` path (encrypt/decrypt + an Encrypt-then-MAC helper),
  with a KAT, OR remove `"AES-256-CBC"` from `approved_names` and soften the spec to "available on
  request" until a consumer needs it.
- **Acceptance criteria:** `approved_names` and the implemented surface agree — every approved AEAD/cipher
  name maps to a reachable wrapper with a KAT, or is explicitly documented as not-yet-wrapped.
- **Verification plan:** Cross-check `approved_names` against wrappers; add/remove to reconcile; test.

### GAP-0029: CHANGELOG.md is unfilled template boilerplate (`YYYY-MM-DD`, "Basic functionality")

- **Category:** Docs
- **Severity:** Low
- **Requirement source:** `CHANGELOG.md` (Keep a Changelog convention the file itself adopts); design
  `:139` (per-repo docs/compliance artifacts) and publish-readiness implied by
  `FIPS_SPECIFICATION.md` "Published deferred items".
- **Current state (evidence):**
  - `CHANGELOG.md:18` `## [0.1.0] - YYYY-MM-DD` (placeholder date); `:11-16,21-24` generic entries
    ("Initial project structure", "Basic functionality") that do not mention the FIPS seam, PQC,
    OpenSSL provisioning, or the GAP-0020 rule actually delivered (`git log` shows 8 substantive feat/ci
    commits).
- **Why this is a gap:** The changelog does not reflect the shipped capability; for a package about to be
  tagged + published (per the deferred items), an accurate changelog is part of the release contract.
- **Impact/Risk:** Low; release hygiene / consumer trust.
- **Recommended fix:** Populate `[0.1.0]` with the real date and the delivered features (seam, FIPS
  backend, std_shim, PQC sign/KEM, provider self-test, dual-mode gate, GAP-0020 rule).
- **Acceptance criteria:** `CHANGELOG.md` has a dated `0.1.0` entry enumerating delivered features; no
  `YYYY-MM-DD` placeholder.
- **Verification plan:** Read CHANGELOG; entries match `git log` feature commits.

### GAP-0030: Publish-time `.path` → lazy `git+https` dependency swap and `build.zig.zon` URL/hash are not yet real (tracked deferral)

- **Category:** Requirement
- **Severity:** Low
- **Requirement source:** `docs/FIPS_SPECIFICATION.md:152-204` (Local-path-dep → git+https publish
  follow-up; Published deferred item #1), `:259`; `SEAM_CONTRACT.md` lazy-dep contract;
  `templates/build_zon_snippet.txt`.
- **Current state (evidence):**
  - `build.zig.zon:6` `.dependencies = .{}` (this repo has none — correct, it is the foundation).
  - `templates/build_zon_snippet.txt:11` and `README.md:24` ship **placeholder** URL/`<commit-sha>`/
    `<zig-fetch-computed-hash>` values; no consumer swap has occurred and `fips`/`tls` are not yet tagged
    - published, so consumers remain on local `.path` deps (per the spec's stated temporary state).
- **Why this is a gap:** This is an explicitly intentional deferral, recorded here only so it is tracked
  (per the prompt's "are they tracked?" requirement) and not silently lost. It is not a code defect in
  `fips` itself; it is a cross-repo mechanical follow-up blocked on publishing.
- **Impact/Risk:** Low/none until publish; afterwards, failing to swap leaves consumers on local paths.
- **Recommended fix:** On tagging `fips` v0.1.0: compute the real `zig fetch` hash, fill
  `build_zon_snippet.txt` + README, then swap each consumer's `.path` dep to the pinned lazy
  `git+https` form (publish order: `fips` → `tls` → fan-out), re-running `make test-dual` per consumer.
- **Acceptance criteria:** `fips` tagged + published; snippet/README carry the real `#<sha>` + `.hash`;
  consumers' `build.zig.zon` use the lazy `git+https` form; `make test-dual` green per consumer.
- **Verification plan:** After publish, `zig fetch --save=fips <url>` resolves; a consumer default build
  fetches nothing and `-Dfips=true` resolves the lazy dep.

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

## Gap Priority Matrix

| Severity | Count | Gap-IDs |
|----------|-------|---------|
| Critical | 0 | — |
| High | 2 | GAP-0021, GAP-0022 |
| Medium | 5 | GAP-0023, GAP-0024, GAP-0025, GAP-0026, GAP-0027 |
| Low | 3 | GAP-0028, GAP-0029, GAP-0030 |

## Category rollup

| Category | Gap-IDs |
|----------|---------|
| Security | GAP-0021 |
| CI-CD | GAP-0022 |
| Test | GAP-0023, GAP-0024, GAP-0025 |
| Docs | GAP-0026, GAP-0029 |
| Feature | GAP-0027, GAP-0028 |
| Requirement | GAP-0030 |
