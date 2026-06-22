<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2024-2026 CodePros -->

# Code Quality Gap Analysis — `fips` crypto-seam library

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
- **Status of all findings below:** OPEN.

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

## Findings

### Readability & Maintainability

#### QUAL-0001 — README is a stale project-scaffold; documents APIs and a CLI that do not exist

- **Severity:** High
- **Confidence:** confirmed
- **Location:** `README.md:8-13`, `README.md:42-55`, `README.md:64`,
  `README.md:72-73`
- **Evidence:**
  - `README.md:46-48` shows the entire Quick Start as:

    ```zig
    pub fn main() !void {
        try fips.init(.{ .debug = true });
    }
    ```

    There is no `fips.init`. `grep "pub fn init" src/root.zig
    src/provider.zig` returns nothing; the public surface
    (`src/root.zig:23-29`) is `Hash`/`Mac`/`Kdf`/`Aead`/`Csprng`/`Sig`/
    `Kem` + `assertActive`/`ensureFips`/`libCtx`.
  - `README.md:8-10`: "**Zero dependencies**: pure Zig standard library
    only" and "**Library + CLI**: ships as both a Zig module and a
    standalone binary". The fips backend links libcrypto/libssl
    (`src/link.zig:42-44`) and the package is library-only — `build.zig`
    has no CLI artifact; the build step is described as "library-only; no
    CLI" (`build.zig:67`).
  - `README.md:51-55` and `:64` reference `zig build run -- <args...>`
    and `make build # library + CLI`; no `run` step exists in
    `build.zig`.
  - `README.md:72`: "`zig build -Dno-cli=true` produces a library-only
    build" — there is no `no-cli` option (`build.zig` only defines
    `tsan`, `fips`, `repro_dedup`, `openssl_path`).
- **Root cause:** README was generated from a generic Zig
  library/CLI template and never rewritten for this project.
- **Impact:** The first file a consumer reads actively misleads them: a
  copy-pasted Quick Start does not compile, the dependency/CLI claims are
  false, and the documented build flags do not exist. For a security
  library that downstream teams must wire correctly (the seam, `-Dfips`,
  OpenSSL prefix), an inaccurate README is a real adoption hazard.
- **Recommended fix:** Replace the README body with the real surface:
  the comptime seam model, the three copy-verbatim files, `-Dfips`,
  `-Dopenssl_path`, and a Quick Start that calls an actual API (e.g.
  `Hash.digest`). Cross-link `docs/SEAM_CONTRACT.md`. Remove all CLI /
  `fips.init` / "zero dependencies" language.
- **Acceptance criteria:** Every code block in `README.md` compiles
  against the current public API; no reference to `fips.init`, a CLI,
  `zig build run`, or `-Dno-cli`; dependency claims match `src/link.zig`
  (OpenSSL in the fips backend).

#### QUAL-0002 — Benchmark suites never touch the crypto surface (placeholder scenarios)

- **Severity:** Medium
- **Confidence:** confirmed
- **Location:** `benchmarks/bench.zig:55-67`, `benchmarks/scale.zig:49-61`,
  `benchmarks/micro/example.zig:42-47`
- **Evidence:** Every scenario body loops on `std.mem.doNotOptimizeAway(
  lib.version.len)` or `&lib.version`:

  ```zig
  fn benchInitDefault(ctx: *framework.Context) anyerror!void {
      var i: u64 = 0;
      while (i < ctx.scenario.ops_per_iteration) : (i += 1) {
          std.mem.doNotOptimizeAway(lib.version.len);
      }
  }
  ```

  Scenarios are named `init_default_config`, `init_custom_config`,
  `init_default_x1m`, etc. — none calls `Hash`/`Aead`/`Sig`/`Kem`. The
  file headers even say "Replace the placeholder scenarios below"
  (`benchmarks/bench.zig:6-9`).
- **Root cause:** Benchmark scaffolding was wired (the framework is real
  and good) but the project-specific scenarios were never written.
- **Impact:** `zig build bench` / `scale-bench` / `bench-micro` produce
  numbers that measure a length read, not crypto. Any CI regression gate
  (`compare.zig`) is gating on noise. Misleading: the README advertises a
  benchmark workflow that measures nothing relevant.
- **Recommended fix:** Replace bodies with real workloads
  (`Hash.digest`, `Aead.seal`/`open`, `Sig.sign`/`verify`,
  `Kem.encapsulate`) at representative sizes; keep the placeholder file as
  a clearly-labeled template under `benchmarks/micro/` if desired.
- **Acceptance criteria:** At least one scenario per primitive family
  (hash, aead, sig, kem) invokes the corresponding `fips` API; scenario
  names reflect the measured operation; `--list` shows crypto scenarios.

#### QUAL-0003 — Hardcoded RSA modulus size (2048) and key/buffer sizes are unnamed magic numbers

- **Severity:** Low
- **Confidence:** confirmed
- **Location:** `src/sig.zig:170`
- **Evidence:**

  ```zig
  } else if (sigIsRsa(alg)) {
      var bits: c_int = 2048;
      var params = [_]c.OSSL_PARAM{
          c.OSSL_PARAM_construct_int(c.OSSL_PKEY_PARAM_RSA_BITS, &bits),
  ```

  The RSA key size for `generate(.rsa_pss)` / `generate(.rsa_pkcs1)` is a
  bare `2048` with no named constant or doc comment, and no way for a
  caller to request 3072/4096. Related undocumented sizes: GCM tag "16
  bytes for GCM" appears only in a doc comment (`src/aead.zig:13`) and the
  12-byte IV assumption (`src/aead.zig:14`); KAT/test buffer sizes (e.g.
  `[512]u8`, `[8192]u8`) are scattered but those are test-local and lower
  priority.
- **Root cause:** Default chosen inline; no policy constant for approved
  RSA key sizes.
- **Impact:** A consumer cannot generate a >2048-bit RSA key through the
  seam, and the security-relevant default is invisible at the policy
  layer where other approved-parameter decisions live (`src/policy.zig`).
  Changing it later is a code edit, not a config/policy change.
- **Recommended fix:** Introduce a named constant (e.g.
  `policy.rsa_default_bits` or a `bits` parameter on `generate` for RSA),
  document the FIPS minimum (2048) in the doc comment, and reference it
  from `src/sig.zig`.
- **Acceptance criteria:** No bare integer literal for RSA bits in
  `sig.zig`; the value is a named, documented constant; a test asserts the
  generated RSA key modulus length matches the constant.

#### QUAL-0004 — Duplicated `cliHasPqc` / `termOk` and digest-name switch logic across files

- **Severity:** Low
- **Confidence:** confirmed
- **Location:** `tests/pqc_sig_interop.zig:21-39` vs
  `tests/pqc_kem_interop.zig:17-35`; `src/sig.zig:53-60` (`explicitDigest`)
  vs `src/sig.zig:427-432` and `:454-459` (KAT helpers `rsaSignExplicit`
  /`ecdsaSignExplicit`)
- **Evidence:** `cliHasPqc` and `termOk` are byte-for-byte identical in
  the two interop files (the `OpenSSL 3.5..3.9 / 3.1` substring probe is
  copy-pasted). Separately, the SHA-2 name mapping
  `.sha256 => "SHA2-256", .sha384 => "SHA2-384", .sha512 => "SHA2-512",
  else => error.Unsupported` is written three times in `sig.zig`
  (`explicitDigest` at :54-59 and the two KAT signers at :427-432,
  :454-459).
- **Root cause:** No shared interop helper module; KAT helpers re-derive a
  mapping that already exists in `explicitDigest`.
- **Impact:** Triple-maintenance: a change to the approved-digest set or
  the OpenSSL version probe must be made in 2-3 places, and the KAT
  signer's mapping can silently drift from `explicitDigest` (the
  production path), weakening the KATs' guarantee.
- **Recommended fix:** Extract `cliHasPqc`/`termOk`/`runCli` into a small
  `tests/interop_util.zig` imported by both. In `sig.zig`, have the KAT
  helpers call `explicitDigest` (or a shared private `sha2Name`) instead
  of re-listing the mapping.
- **Acceptance criteria:** The version-probe and `termOk` exist once;
  `sig.zig` has a single SHA-2-name source of truth used by both the
  production verify path and the KAT signers.

#### QUAL-0005 — `Csprng.bytes` cannot signal a too-large request; `RAND_bytes_ex` length is `usize`→`c_int` without bound check

- **Severity:** Low
- **Confidence:** suspected
- **Location:** `src/csprng.zig:11-14`
- **Evidence:**

  ```zig
  pub fn bytes(out: []u8) Error!void {
      provider.assertActive();
      if (c.RAND_bytes_ex(provider.libCtx(), out.ptr, out.len, 0) != 1) return error.OpensslFailure;
  }
  ```

  `RAND_bytes_ex`'s count parameter is `size_t` in OpenSSL 3.x, so
  `out.len` (usize) maps cleanly here — but the shim equivalent loops on
  `getrandom` with no length ceiling either. Confirm the prototype emitted
  by `@cImport` for `RAND_bytes_ex` (size_t vs int) to be certain there is
  no truncation on a >2GiB request.
- **Root cause:** Thin wrapper trusts the FFI prototype; no defensive
  bound.
- **Impact:** Low in practice (no caller requests gigabytes of random),
  but worth confirming the parameter type so a future caller cannot
  silently truncate.
- **Recommended fix / how to confirm:** `zig build check` then inspect the
  generated decl, or add a debug-only `std.debug.assert(out.len <=
  std.math.maxInt(c_int))` if the prototype is `int`. If it is `size_t`,
  mark this finding resolved with a one-line code comment noting the type.
- **Acceptance criteria:** Documented confirmation that the count
  parameter is `size_t` (no truncation), or a guard added.

---

### API & Contract Consistency

#### QUAL-0006 — fips `Aead.seal`/`open` perform NO length validation; shim validates key/nonce/tag/buffer — divergent contract and a buffer-overrun risk

- **Severity:** High
- **Confidence:** confirmed
- **Location:** `src/aead.zig:15-79` vs `src/std_shim.zig:207-216`
- **Evidence:** The shim explicitly validates and rejects mismatches:

  ```zig
  // src/std_shim.zig:208
  if (key.len != A.key_length or nonce.len != A.nonce_length or
      tag.len != A.tag_length or ct.len < pt.len) return error.OpensslFailure;
  ```

  The fips backend does none of this. It passes `key.ptr`/`nonce.ptr`
  straight to OpenSSL and writes ciphertext via raw pointer arithmetic
  without checking `ciphertext.len >= plaintext.len`:

  ```zig
  // src/aead.zig:39 and :42
  if (c.EVP_EncryptUpdate(ctx, ciphertext.ptr, &outl, plaintext.ptr, @intCast(plaintext.len)) != 1) ...
  if (c.EVP_EncryptFinal_ex(ctx, ciphertext.ptr + @as(usize, @intCast(outl)), &finl) != 1) ...
  ```

  For an undersized `ciphertext` (or `plaintext` in `open`), this is an
  out-of-bounds write into the caller's buffer — undefined behavior, not a
  returned error. Similarly an over-long `key` is silently truncated/over-
  read by OpenSSL rather than rejected as the shim would.
- **Root cause:** The fips wrapper delegates all validation to OpenSSL,
  but OpenSSL's GCM update writes `len` bytes to the output pointer
  regardless of the Zig slice length (the slice length is discarded at the
  `.ptr` boundary).
- **Impact:** (1) **Contract divergence**: the same call that returns
  `error.OpensslFailure` under `-Dfips=false` can corrupt memory under
  `-Dfips=true` — exactly the kind of behavioral skew the seam exists to
  prevent. (2) **Memory safety**: a caller bug (wrong buffer size) is a
  silent overrun in the FIPS path. (3) The doc comment "16 bytes for GCM"
  / "12-byte IV" (`src/aead.zig:13-14`) is unenforced.
- **Recommended fix:** In `seal`/`open`, validate before the EVP calls:
  `ciphertext.len >= plaintext.len` (and `plaintext.len >= ciphertext.len`
  in `open`), and the GCM constraints (nonce length, tag length 12-16,
  key length per alg). Return `error.OpensslFailure` (or a new
  `error.BadLength` added to BOTH backends) on mismatch so the two
  backends agree. Prefer named constants for the GCM tag/nonce sizes
  (ties to QUAL-0003).
- **Acceptance criteria:** A test in both backends passes an undersized
  `ciphertext`/`tag`/`nonce` and asserts the SAME error; no raw-pointer
  write occurs before the length check; KATs still pass.

#### QUAL-0007 — `Sig.sign`/`Sig.verify` in the shim ignore the `alg` argument; the fips backend uses it — silent algorithm/keypair mismatch

- **Severity:** Medium
- **Confidence:** confirmed
- **Location:** `src/std_shim.zig:310-330` (`_ = alg;` at :311 and :321)
  vs `src/sig.zig:185-210`
- **Evidence:** Shim:

  ```zig
  pub fn sign(alg: policy.SigAlg, kp: *KeyPair, msg: []const u8, sig_out: []u8) Error!usize {
      _ = alg;                 // <- discarded
      return switch (kp.inner) { ... };
  }
  pub fn verify(alg: policy.SigAlg, kp: *KeyPair, ...) Error!void {
      _ = alg;                 // <- discarded
      switch (kp.inner) { ... }
  }
  ```

  The shim dispatches purely on the runtime keypair tag, so
  `sign(.ecdsa_p384, &ed25519_kp, ...)` quietly signs with Ed25519. The
  fips backend instead drives the digest/padding from `alg`
  (`initSignDigest`/`initVerifyDigest`, `src/sig.zig:281-297`), so the
  same mismatched call selects a digest for the *passed* alg and behaves
  differently (and `generate`/`from*Bytes` there derived the key from
  `alg`).
- **Root cause:** Shim was written to dispatch on the stored key union;
  `alg` kept only for signature parity.
- **Impact:** A caller passing an `alg` inconsistent with the keypair gets
  backend-dependent behavior — one backend honors `alg`, the other ignores
  it. This undermines the "byte-for-byte API-compatible" promise in
  `docs/SEAM_CONTRACT.md:9` for the misuse case and can mask bugs that
  only surface when switching `-Dfips`.
- **Recommended fix:** In the shim, assert/verify that `alg` matches the
  keypair's stored curve/scheme and return `error.Unsupported` (or a
  shared error) on mismatch, so both backends reject the same misuse;
  alternatively document explicitly that `alg` is advisory in the shim and
  add a parity test pinning the chosen behavior.
- **Acceptance criteria:** A parity test feeds a mismatched
  `(alg, keypair)` to both backends and asserts identical outcomes; the
  decision (reject vs honor-key) is documented in `SEAM_CONTRACT.md`.

#### QUAL-0008 — `Sig.publicBytes`/`fromPublicBytes` produce/accept different encodings per backend with no documented contract

- **Severity:** Medium
- **Confidence:** confirmed
- **Location:** `src/sig.zig:72-90` vs `src/std_shim.zig:244-262`
- **Evidence:** For ECDSA, the shim emits **compressed SEC1**
  (`toCompressedSec1()`, `src/std_shim.zig:248-251`, 33 bytes for P-256)
  and parses via `fromSec1`. The fips backend uses
  `EVP_PKEY_get_raw_public_key` for Ed25519/PQC but **DER
  SubjectPublicKeyInfo** for the `.der` family (ECDSA/RSA) via
  `d2i_PUBKEY` (`src/sig.zig:84-87`). So `Sig.publicBytes` of an ECDSA key
  yields 33-byte compressed SEC1 under the shim but raw-public-key
  semantics differ under fips, and `fromPublicBytes(.ecdsa_p256, ...)`
  expects SEC1 (shim) vs SPKI-DER (fips). The wire bytes are NOT
  interchangeable across backends for ECDSA/RSA.
- **Root cause:** Each backend used the encoding most natural to its
  library; the seam pins the *type signature* (`[]u8` in/out) but not the
  *encoding*.
- **Impact:** A key serialized under `-Dfips=true` will not import under
  `-Dfips=false` (and vice-versa) for ECDSA/RSA — a latent
  interoperability break for any consumer that persists keys and later
  flips the backend, exactly the swap the seam is meant to make safe.
  `tests/shim_parity.zig` only round-trips within the shim, so it does not
  catch the cross-backend mismatch.
- **Recommended fix:** Document the on-wire encoding per family in
  `SEAM_CONTRACT.md` and in the `publicBytes`/`fromPublicBytes` doc
  comments (e.g. "ECDSA public bytes are compressed SEC1" — and make the
  fips backend match by exporting/parsing SEC1 via `OSSL_PARAM
  pub`/`EC_POINT` rather than SPKI, OR explicitly state the encodings
  differ and are not portable). At minimum, add the contract so consumers
  know not to assume portability.
- **Acceptance criteria:** The encoding for each `SigAlg` family is stated
  in the contract and the doc comments; either a cross-backend
  round-trip test passes, or a test/comment documents that ECDSA/RSA wire
  bytes are backend-specific by design.

#### QUAL-0009 — `Sig.KeyPair.publicBytes` does not bound `out` before passing to OpenSSL; relies on caller-sized buffer

- **Severity:** Low
- **Confidence:** suspected
- **Location:** `src/sig.zig:73-77`
- **Evidence:**

  ```zig
  pub fn publicBytes(self: *KeyPair, out: []u8) Error!usize {
      var len: usize = out.len;
      if (c.EVP_PKEY_get_raw_public_key(self.pkey, out.ptr, &len) != 1) return error.OpensslFailure;
      return len;
  }
  ```

  `EVP_PKEY_get_raw_public_key` is documented to return failure (not
  overflow) when `out` is too small because `len` is passed in as the
  buffer capacity — so this is likely safe. Confirm against the
  OpenSSL 3.x contract that passing a non-NULL `pub` with an undersized
  `*pub_len` returns 0 rather than writing. The shim path (`copyOut`,
  `src/std_shim.zig:448-452`) explicitly checks `out.len < src.len`.
- **Root cause:** Thin FFI wrapper; relies on OpenSSL's documented
  capacity semantics.
- **Impact:** Low if the OpenSSL contract holds; included for parity
  completeness with the shim's explicit check.
- **Recommended fix / how to confirm:** Add a doc-comment noting the
  capacity-in/length-out contract; optionally a debug assert. Confirm via
  OpenSSL man page / a unit test passing a 1-byte `out` and asserting
  `error.OpensslFailure`.
- **Acceptance criteria:** A test passes an undersized `out` to
  `publicBytes` and asserts a returned error (no overrun); behavior
  matches the shim.

#### QUAL-0010 — `Kem.encapsulate`/`decapsulate` discard the `alg` argument; KEM identity comes only from the stored pkey

- **Severity:** Low
- **Confidence:** confirmed
- **Location:** `src/kem.zig:38-39`, `src/kem.zig:55-57` (`_ = alg;`)
- **Evidence:** Both functions take `alg: policy.KemAlg` and immediately
  `_ = alg;`, then derive everything from `kp.pkey`. The shim mirrors this
  (all KEM ops return `Unsupported`), so the *signature* parity holds, but
  the `alg` parameter is dead in the fips backend — a caller could pass
  `.ml_kem_512` while operating an `.ml_kem_768` key and nothing checks.
- **Root cause:** The OpenSSL `EVP_PKEY` already encodes the algorithm, so
  `alg` is redundant once the key exists; it was kept for a uniform
  signature.
- **Impact:** Minor: a misleading parameter that is never validated. Low
  risk because the pkey is authoritative, but it is dead surface that
  invites incorrect assumptions.
- **Recommended fix:** Either validate `alg` against the pkey's algorithm
  name (defensive) or document in the doc comment that `alg` is advisory /
  retained for signature symmetry with `generate`. Prefer a one-line doc
  note to avoid churn.
- **Acceptance criteria:** The `alg` parameter's role is documented (or
  validated); no behavioral change to passing KATs.

---

### Reliability Enablers (error handling, tests)

#### QUAL-0011 — `Hash.Stream.update` panics on EVP failure while every other op returns an error; backends diverge (shim cannot fail)

- **Severity:** Medium
- **Confidence:** confirmed
- **Location:** `src/hash.zig:53-60`
- **Evidence:**

  ```zig
  /// Infallible at the API level (matches the shim): an OpenSSL update
  /// failure on a correctly-initialised context cannot happen for a
  /// software digest, so it panics rather than poisoning the type ...
  pub fn update(self: *Stream, bytes: []const u8) void {
      if (c.EVP_DigestUpdate(self.ctx, bytes.ptr, bytes.len) != 1) @panic("EVP_DigestUpdate failed");
  }
  ```

  Every sibling operation returns `Error` (`digest`, `Stream.init`,
  `Stream.final`, `Stream.clone`, and all of `Aead`/`Mac`/`Kdf`/`Sig`/
  `Kem`). The shim's `Stream.update` (`src/std_shim.zig:89-93`) genuinely
  cannot fail. So the API is `void` in both, but the fips backend can
  `@panic` mid-stream and crash a process, whereas the shim never will.
- **Root cause:** Deliberate design choice (documented) to keep `update`
  off the error path, justified by "cannot happen for a software digest".
  But the FIPS provider is not purely software in all states (a provider
  in an error/self-test-failed state, or a corrupted context, can make
  `EVP_DigestUpdate` return 0), so the invariant is weaker than the
  comment claims.
- **Impact:** A library consumed by "concurrent servers" (per the task
  context) can be brought down by a `@panic` from a crypto update — a
  denial-of-service surface that does not exist in the shim. The
  panic-vs-error inconsistency also forces callers to handle the same
  logical failure two different ways depending on `-Dfips`.
- **Recommended fix:** Make `update` return `Error!void` in BOTH backends
  (the shim's becomes `Error!void` returning nothing-on-success), so the
  contract is uniform and the FIPS path can surface a provider failure
  without crashing. If the infallible signature must be kept for
  ergonomics, downgrade the panic to a stored "poisoned" flag checked at
  `final` (still no panic). Update the doc comment to stop asserting the
  failure "cannot happen".
- **Acceptance criteria:** Neither backend can `@panic` from `update`; the
  signature is identical across backends; the Stream KATs still pass; a
  test (fips) that forces a failed/uninitialized context observes an error
  rather than a crash.

#### QUAL-0012 — `provider.assertActive()` is not re-checked in `Stream.update`/`final`/`clone`; a Stream can outlive/precede provider readiness

- **Severity:** Low
- **Confidence:** confirmed
- **Location:** `src/hash.zig:43-87` (assert only in `init` at :44; absent
  in `update`/`final`/`clone`)
- **Evidence:** `Hash.digest` (`:14`), `Aead.seal`/`open`, `Mac.hmac`,
  `Kdf.*`, `Csprng.bytes`, and `Sig`/`Kem` entry points all call
  `provider.assertActive()` first. `Stream.init` does too (`:44`), but
  `update`/`final`/`clone` do not. Since `assertActive` is the
  hard-fail gate that guarantees the FIPS provider is loaded + self-tested,
  the streaming path only checks it once at construction.
- **Root cause:** The one-shot pattern asserts per-call; the streaming
  type asserts once. Defensible (the context cannot exist without a prior
  successful `init`), but inconsistent with the rest of the module.
- **Impact:** Low — a valid `Stream` implies `init` succeeded. The concern
  is consistency and the (narrow) case of provider state changing between
  `init` and `final`. Mostly a maintainability/uniformity nit.
- **Recommended fix:** Either document that the streaming type asserts
  once at `init` (the chosen invariant), or add `provider.assertActive()`
  to `final`/`clone` for uniformity. Prefer the documented-invariant route
  to avoid hot-path overhead.
- **Acceptance criteria:** The assertion policy for the streaming type is
  explicit in the doc comment, or applied uniformly.

#### QUAL-0013 — No error-path tests for the fips primitive wrappers (buffer-too-small, Unsupported, OpensslFailure)

- **Severity:** Medium
- **Confidence:** confirmed
- **Location:** `src/hash.zig` (tests :90-191), `src/mac.zig` (test
  :37-46), `src/kdf.zig` (tests :76-118), `src/kem.zig` (tests :69-93),
  `src/csprng.zig` (test :17-24)
- **Evidence:** `grep expectError` across the fips primitive modules
  returns exactly one hit — `Aead.open` AuthFailed (`src/aead.zig:110`).
  None of the following error paths is tested in the fips backend:
  `Hash.digest`/`Stream.final` with `out` smaller than the digest;
  `Mac.hmac` undersized `out`; `Kdf.hkdf`/`hkdfExpand`/`pbkdf2` with an
  oversized `out` (the `>255*HashLen` rejection); `Hash.digest` /
  `Stream.init` with an algorithm OpenSSL rejects (`error.Unsupported`);
  `Kem.encapsulate`/`decapsulate` with an undersized `ct_out`/`ss_out`
  (the explicit `> ...len` checks at `src/kem.zig:48,63`). The shim has
  partial coverage of `Unsupported`, but the FIPS path's
  `error.OpensslFailure`/`error.Unsupported` branches are largely
  unexercised.
- **Root cause:** KATs prioritized correct-output verification; negative
  paths were not added.
- **Impact:** The error branches — the ones that protect callers from
  buffer overruns and unsupported algorithms — are the least-tested code
  in the security-critical module. Regressions (e.g. dropping the
  `ss_len > ss_out.len` guard in `kem.zig`) would pass CI.
- **Recommended fix:** Add negative tests: undersized output buffers per
  primitive; over-length HKDF output; an unsupported digest/alg; KEM
  output buffer too small. Mirror them in the shim where the corresponding
  guard exists.
- **Acceptance criteria:** Each documented error in `Hash`/`Mac`/`Kdf`/
  `Aead`/`Kem`/`Csprng` `Error` sets has at least one test asserting it;
  `grep expectError src/*.zig` shows coverage beyond the single AuthFailed
  case.

#### QUAL-0014 — Integration and stress suites are version-string placeholders; no real integration/stress coverage

- **Severity:** Medium
- **Confidence:** confirmed
- **Location:** `tests/integration.zig:14-16`, `tests/stress.zig:14-19`
- **Evidence:**

  ```zig
  // tests/integration.zig
  test "integration: version is defined" {
      try std.testing.expectEqualStrings("0.1.0", lib.version);
  }
  // tests/stress.zig
  test "stress: version constant is stable across repeated reads" {
      var i: usize = 0;
      while (i < 100_000) : (i += 1) { try std.testing.expectEqualStrings("0.1.0", lib.version); }
  }
  ```

  The `test-integration` step's real value is the two PQC interop
  executables (wired in `build.zig:105-124`); the `.zig` integration file
  itself only checks a constant. The `test-stress` step loops on a string
  compare — it never exercises a crypto wrapper under load, despite the
  header claiming to "exercise the crypto wrappers" and despite the build
  forcing `ReleaseFast`/TSan for it (`build.zig:127-135`).
- **Root cause:** Placeholder scaffolding left in place after the interop
  executables became the real integration coverage.
- **Impact:** `zig build test-stress` gives false confidence — it cannot
  catch a concurrency/throughput regression in any primitive. The stress
  step's TSan wiring (`build.zig:134`) instruments a string compare.
- **Recommended fix:** Make `stress.zig` drive real wrappers in a loop
  (e.g. many `Hash.digest`/`Aead` round trips) and ideally from multiple
  threads (see QUAL-0015). Make `integration.zig` exercise the seam end to
  end (digest + aead + sign/verify) rather than a constant.
- **Acceptance criteria:** Stress test performs >0 crypto operations and
  is meaningful under TSan; integration test invokes at least one
  primitive per family.

#### QUAL-0015 — No concurrency test despite a process-global lib context and "concurrent server" consumers

- **Severity:** High
- **Confidence:** confirmed
- **Location:** `src/provider.zig:11-21` (mutable `g_ctx`/`g_fips`
  globals; lazy first-use init); `build.zig:26,87,96,134` (TSan plumbing
  exists); `tests/stress.zig` (no threads)
- **Evidence:** The provider holds process-global mutable state:

  ```zig
  // src/provider.zig:11-12
  var g_ctx: ?*c.OSSL_LIB_CTX = null;
  var g_fips: ?*c.OSSL_PROVIDER = null;
  ```

  `libCtx()` and `ensureFips()` perform a check-then-set on these globals
  with **no synchronization** (`src/provider.zig:16-21`, `:24-43`). Every
  primitive calls `provider.assertActive()` → `ensureFips()` on first use.
  The build wires `-Dtsan` onto unit/integration/stress artifacts
  (`build.zig:87,96,134`) and forces stress to Debug under TSan
  (`build.zig:127`) — i.e. the project clearly anticipates race testing —
  but no test spawns threads. The task context states the library is
  consumed by concurrent servers.
- **Root cause:** Lazy global init was written single-threaded; the race
  test the TSan plumbing was built for was never authored.
- **Impact:** First-use initialization of `g_ctx`/`g_fips` from multiple
  threads is a classic data race: two threads can both observe `null` and
  both run `OSSL_LIB_CTX_new`/`OSSL_PROVIDER_load`, leaking a context and
  potentially double-loading the provider. Under concurrent-server load
  this is a real correctness/leak hazard, and there is zero test pressure
  on it. The TSan infrastructure gives a false impression that races are
  covered.
- **Recommended fix:** (1) Make `ensureFips`/`libCtx` initialization
  thread-safe (`std.once`/`std.Thread.Once` or an atomic/`Mutex` guard).
  (2) Add a stress/concurrency test that calls `Hash.digest` (or
  `assertActive`) from N threads simultaneously and runs green under
  `-Dtsan`. Wire it into `test-stress`.
- **Acceptance criteria:** A multi-threaded test exercising first-use
  provider init passes under `-Dtsan` with no reported data race; the
  init path uses an explicit synchronization primitive.

#### QUAL-0016 — `ecGroup` uses `unreachable` for the non-EC default; a future `SigAlg` addition becomes UB instead of a compile error or handled error

- **Severity:** Low
- **Confidence:** confirmed
- **Location:** `src/sig.zig:28-35`
- **Evidence:**

  ```zig
  fn ecGroup(alg: policy.SigAlg) [:0]const u8 {
      return switch (alg) {
          .ecdsa_p256 => "P-256",
          .ecdsa_p384 => "P-384",
          .ecdsa_p521 => "P-521",
          else => unreachable,
      };
  }
  ```

  `ecGroup` is only called from `generate` under
  `if (family == .der and !sigIsRsa(alg))` (`src/sig.zig:162-168`), so
  today the `else` is genuinely unreachable. But it is an `else =>
  unreachable` over a 21-variant enum: if a new EC-family `SigAlg` is added
  and the caller guard is updated but this switch is not, it is
  `unreachable` (UB in ReleaseFast), not a caught error.
- **Root cause:** Reachability depends on a guard in a different function;
  the enum is open to growth.
- **Impact:** Low now; a maintenance landmine. Most other switches in the
  file are exhaustive without `else` (which would force a compile error on
  a new variant) — this one opts out of that safety.
- **Recommended fix:** Replace `else => unreachable` with explicit
  handling of the remaining variants (so adding a `SigAlg` forces a
  compile error here), or return `error.Unsupported` and make `ecGroup`
  fallible. Prefer exhaustive matching for compile-time safety.
- **Acceptance criteria:** Adding a new `SigAlg` variant causes a
  compile-time error at `ecGroup` (or a handled runtime error), never UB.

---

### Documentation Gaps

#### QUAL-0017 — CHANGELOG is an unfilled template (placeholder bullets, `YYYY-MM-DD` release date)

- **Severity:** Low
- **Confidence:** confirmed
- **Location:** `CHANGELOG.md:8-26`
- **Evidence:** The `[Unreleased]`/`[0.1.0]` sections contain only generic
  bullets ("Initial project structure", "Core library implementation",
  "Basic functionality") and the release date is literally `YYYY-MM-DD`
  (`CHANGELOG.md:18`). None of the substantial, dated work visible in
  `git log` (FIPS seam, streaming Hash.Stream, classical VERIFY routing,
  PQC roadmap, dual-mode CI) is recorded.
- **Root cause:** Template not maintained alongside feature commits.
- **Impact:** Consumers cannot tell what `0.1.0` actually contains or when
  it shipped; the changelog adds no information over the commit log.
- **Recommended fix:** Populate `[Unreleased]`/`[0.1.0]` from the commit
  history (Hash.Stream API, RSA/ECDSA explicit-digest verify seam, KEM
  interop, GAP-0020 tooling) and set a real date on release.
- **Acceptance criteria:** No `YYYY-MM-DD` placeholder; entries reflect the
  actual shipped surface.

#### QUAL-0018 — `Hash.Stream` doc comment overstates the failure invariant ("cannot happen")

- **Severity:** Low
- **Confidence:** confirmed
- **Location:** `src/hash.zig:53-57`
- **Evidence:** The doc comment for `update` asserts an OpenSSL update
  failure "cannot happen for a software digest, so it panics rather than
  poisoning the type with an error on the hot path." This conflates "the
  digest algorithm is software" with "EVP_DigestUpdate cannot return 0",
  which is not guaranteed (a provider in a failed self-test / error state,
  or a misused context, can return 0). The comment documents a guarantee
  the code does not actually have (see QUAL-0011).
- **Root cause:** Comment written from the happy-path mental model.
- **Impact:** A reader trusts that `update` is panic-free in practice and
  may not defend against the panic. Documentation that promises behavior
  not guaranteed is a maintenance trap.
- **Recommended fix:** Reword to "EVP_DigestUpdate on a correctly
  initialised context returns failure only in exceptional provider error
  states; this wrapper currently treats that as fatal" — and pair with the
  QUAL-0011 fix (return an error instead of panicking), then update the
  comment accordingly.
- **Acceptance criteria:** The doc comment no longer claims the failure
  "cannot happen"; it matches whatever behavior QUAL-0011 settles on.

#### QUAL-0019 — `SEAM_CONTRACT.md` claims byte-for-byte API compatibility but does not document the ECDSA/RSA public-key encoding divergence or the `alg`-ignored shim behavior

- **Severity:** Medium
- **Confidence:** confirmed
- **Location:** `docs/SEAM_CONTRACT.md:8-11`, `:36-54`
- **Evidence:** The contract says the seam routes "every security-relevant
  crypto call through either the OpenSSL FIPS-140-3 provider ... or a
  byte-for-byte API-compatible `std.crypto` backend" (`:8-10`) and the
  support matrix (`:46-54`) lists Sig/`from*Bytes` as "full" in both
  backends — with no note that the *wire encoding* of ECDSA/RSA public
  keys differs (QUAL-0008) or that `Sig.sign`/`verify` ignore `alg` in the
  shim (QUAL-0007). "API-compatible" is true at the type level but not at
  the byte/behavior level for these cases.
- **Root cause:** The contract documents symbol/type parity, not encoding
  or misuse-behavior parity.
- **Impact:** Consumers reading the authoritative contract will reasonably
  assume keys and behavior are portable across `-Dfips`, then hit the
  divergences at runtime. The doc is the source of truth for 12 downstream
  plans (`:6-7`), so the gap propagates.
- **Recommended fix:** Add a "Encoding & behavioral caveats" subsection:
  state the per-family public-key encoding, note that ECDSA/RSA wire bytes
  are (currently) backend-specific, and document the `alg`-handling
  difference in `Sig.sign`/`verify`. Align with whatever QUAL-0007/0008
  resolve to.
- **Acceptance criteria:** The contract explicitly addresses public-key
  encoding portability and `alg` handling; no remaining unqualified
  "byte-for-byte compatible" claim for the diverging cases.

---

## Summary table

| ID | Severity | Title | Location | Recommended fix |
|----|----------|-------|----------|-----------------|
| QUAL-0001 | High | README is a stale scaffold; documents `fips.init`, a CLI, "zero deps", and flags that don't exist | `README.md:8-13,42-55,64,72` | Rewrite README around the real seam/`-Dfips`/OpenSSL surface; remove CLI/`fips.init`/zero-dep claims |
| QUAL-0002 | Medium | Benchmark suites measure `version.len`, never the crypto API | `benchmarks/bench.zig:55-67`, `scale.zig:49-61`, `micro/example.zig:42-47` | Replace bodies with real Hash/Aead/Sig/Kem workloads |
| QUAL-0003 | Low | Hardcoded RSA `2048` and unnamed GCM/key sizes | `src/sig.zig:170` | Promote to named/documented `policy` constant (or `bits` param) |
| QUAL-0004 | Low | Duplicated `cliHasPqc`/`termOk` + triplicated SHA-2 name switch | `tests/pqc_*_interop.zig:17-39`; `src/sig.zig:54-59,427-432,454-459` | Extract shared interop util; single SHA-2-name source in `sig.zig` |
| QUAL-0005 | Low | `Csprng.bytes` length→`c_int` bound unverified | `src/csprng.zig:11-14` | Confirm `RAND_bytes_ex` count is `size_t`; doc/guard otherwise |
| QUAL-0006 | High | fips `Aead.seal`/`open` skip all length validation (shim validates) → contract skew + buffer-overrun | `src/aead.zig:15-79` vs `src/std_shim.zig:207-216` | Validate ct/pt/nonce/tag/key lengths before EVP calls; same error in both backends |
| QUAL-0007 | Medium | Shim `Sig.sign`/`verify` ignore `alg`; fips uses it | `src/std_shim.zig:311,321` vs `src/sig.zig:185-210` | Reject mismatched `(alg,key)` in shim or document advisory role; add parity test |
| QUAL-0008 | Medium | ECDSA/RSA public-key encoding differs per backend (SEC1 vs SPKI-DER) | `src/sig.zig:72-90` vs `src/std_shim.zig:244-262` | Document/align per-family wire encoding; cross-backend round-trip test |
| QUAL-0009 | Low | `publicBytes` doesn't bound `out` before OpenSSL call | `src/sig.zig:73-77` | Confirm capacity-in/len-out contract; doc/assert + undersized-buffer test |
| QUAL-0010 | Low | `Kem.encapsulate`/`decapsulate` discard `alg` | `src/kem.zig:38-39,55-57` | Validate `alg` vs pkey or document advisory role |
| QUAL-0011 | Medium | `Hash.Stream.update` panics in fips, infallible in shim → DoS + panic-vs-error skew | `src/hash.zig:53-60` | Make `update` return `Error!void` in both backends (or poison-flag, no panic) |
| QUAL-0012 | Low | `assertActive` not re-checked in `Stream.update`/`final`/`clone` | `src/hash.zig:43-87` | Document the once-at-init invariant or assert uniformly |
| QUAL-0013 | Medium | No fips error-path tests (buffer-too-small / Unsupported / OpensslFailure) | `src/{hash,mac,kdf,kem,csprng}.zig` tests | Add negative tests per `Error` member; mirror in shim |
| QUAL-0014 | Medium | Integration + stress suites are version-string placeholders | `tests/integration.zig:14-16`, `tests/stress.zig:14-19` | Exercise real wrappers (stress: under load/threads); integration: per-family |
| QUAL-0015 | High | No concurrency test; `g_ctx`/`g_fips` first-use init is an unsynchronized global race | `src/provider.zig:11-43`; `build.zig:127-134` | Make init thread-safe (`std.once`/Mutex); add N-thread TSan-green test |
| QUAL-0016 | Low | `ecGroup` `else => unreachable` over a growing enum (UB on new variant) | `src/sig.zig:28-35` | Exhaustive match (compile-time safety) or fallible `Unsupported` |
| QUAL-0017 | Low | CHANGELOG is an unfilled template (`YYYY-MM-DD`) | `CHANGELOG.md:8-26` | Populate from commit history; set real release date |
| QUAL-0018 | Low | `Hash.Stream` doc comment overstates "cannot happen" failure invariant | `src/hash.zig:53-57` | Reword to match real provider-error semantics (pair with QUAL-0011) |
| QUAL-0019 | Medium | `SEAM_CONTRACT.md` claims byte-for-byte compatibility but omits encoding/`alg` divergences | `docs/SEAM_CONTRACT.md:8-11,36-54` | Add encoding-portability + `alg`-handling caveats subsection |

**Severity counts:** High 3 · Medium 7 · Low 9 · (Total 19).
