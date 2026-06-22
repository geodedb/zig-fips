<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2024-2026 CodePros -->

# Security Gap Analysis — fips crypto-seam library

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

## Part 1 — Disposition of the prior OWASP findings (F1–F8)

| Prior | SEC id | Verdict | One-line basis |
|------|--------|---------|----------------|
| F1 zeroization absent | SEC-1004 | **CONFIRMED** | No `secureZero`/`OPENSSL_cleanse` anywhere; spec promises it (`FIPS_SPECIFICATION.md:256`) but no symbol exists. |
| F2 no constant-time compare | SEC-1005 | **CONFIRMED** | `timing_safe` promised (`FIPS_SPECIFICATION.md:256`); grep finds zero implementations. |
| F3 aead.zig missing length validation | SEC-1002 | **CONFIRMED** | `src/aead.zig` `seal`/`open` perform no length checks; `src/std_shim.zig:208,214` does. Out-of-bounds write when `plaintext.len < ciphertext.len`. |
| F4 provider globals unsynchronized | SEC-1006 | **CONFIRMED** | `src/provider.zig:11-12,16-21,24-43` mutate `g_ctx`/`g_fips` with no lock/atomic/`Once`. |
| F5 unchecked `@intCast usize→c_int` | SEC-1007 | **CONFIRMED** | `src/aead.zig:31,36,39,43,64,69,72,75`, `src/sig.zig:86,100,113,128,130` cast untrusted lengths; UB in ReleaseFast. |
| F6 `hash.zig` Stream.update panics | SEC-1008 | **CONFIRMED** | `src/hash.zig:58-60` `@panic("EVP_DigestUpdate failed")`. |
| F7 pbkdf2 PKCS5=1 unconditional | SEC-1009 | **CONFIRMED** | `src/kdf.zig:63,69` sets `pkcs5=1` for every caller, disabling FIPS min salt/iter/keylen. |
| F8 `assertActive()` panics as enforcement | SEC-1010 | **CONFIRMED** | `src/provider.zig:47-49` `@panic` on every crypto entry; availability/DoS. |

All eight are confirmed. Details and acceptance criteria are folded into
the SEC entries below so this file is the single tracking source.

---

## Part 2 — Findings table (NEW findings first, then confirmed F1–F8)

| Finding | Severity | File:Line | Attack Scenario | CWE / OWASP | Confidence |
|---|---|---|---|---|---|
| **SEC-1001** OpenSSL FIPS provider built from unpinned "latest", no checksum/GPG verify, `sudo make install` | **High** | `scripts/install-openssl-fips.sh:53-67,95-114`; `build.zig:370-373` | MITM/compromised-mirror serves a trojaned tarball → arbitrary code as root in build/CI; "latest" silently changes the validated module out from under the FIPS claim | CWE-494, CWE-829, A08:2021 | confirmed |
| **SEC-1002** AEAD `seal`/`open` lack output/nonce/tag length validation → OOB heap write | **High** | `src/aead.zig:38-43,71-78` | Caller passes `ciphertext`/`plaintext` shorter than input; OpenSSL writes past buffer end (heap overflow) | CWE-787, CWE-131, A06:2021 | confirmed |
| **SEC-1003** RSA verify accepts attacker-chosen undersized/weak key on import; no key-strength floor, no key-type binding (**CONFIDENTIAL**) | **High** | `src/sig.zig:110-146,220-245,254-279` | JWKS/SPKI import of a 512-bit (forgeable) RSA key, or a key whose actual type ≠ requested `alg`, is accepted for verification → signature forgery / trust-decision bypass | CWE-326, CWE-347, A02:2021 | suspected |
| **SEC-1011** No nonce-uniqueness/96-bit-length contract on AES-GCM seal; caller-supplied IV | **High** | `src/aead.zig:15-44`; `templates/crypto_backend.zig` (no guidance); README/SECURITY silent | A consumer reuses a (key, nonce) pair under GCM → catastrophic loss of confidentiality + trivial forgery (authentication-key recovery) | CWE-323, CWE-1204, A02:2021 | confirmed |
| **SEC-1012** `OSSL_LIB_CTX_load_config` reads attacker-influenced `OPENSSL_CONF`; provider/config injection | **Medium** | `src/provider.zig:33-34`; `ffi.zig:19` | Process env controls which OpenSSL config (hence which providers / `default_properties`) loads; a hostile env can point at a config that activates a non-FIPS or rogue provider while the seam still believes it is FIPS | CWE-15, CWE-426, A05:2021 | suspected |
| **SEC-1013** `OSSL_PROVIDER_load(ctx,"base")` return value ignored | **Medium** | `src/provider.zig:37` | If `base` fails to load, `ensureFips()` proceeds; later key-serialization/encoder operations fail or silently degrade with no fail-closed signal at provider init | CWE-252, A04:2021 | confirmed |
| **SEC-1014** FIPS dual-mode gate depends on an unpinned, side-effecting `fips-deps` job; `/usr/local/ssl` published as artifact | **Medium** | `.gitlab-ci.yml:306-329` | A "latest" OpenSSL change can flip the gate's meaning between runs (non-reproducible attestation); the full FIPS install (incl. `fipsmodule.cnf` install-MAC) is exposed as a 1-day artifact | CWE-1104, CWE-200, A08:2021 | confirmed |
| **SEC-1015** `csprng.zig` ignores partial `RAND_bytes_ex` semantics / no reseed-failure differentiation; shim CSPRNG silent-degrade loop | **Low** | `src/csprng.zig:11-14`; `src/std_shim.zig:17-29` | `RAND_bytes_ex` is treated as all-or-nothing (true for OpenSSL); shim `getrandom` maps ALL negative `rc` (incl. `ENOSYS`/`EFAULT`) to an infinite busy-retry → hang / silent weak entropy on unexpected errno | CWE-332, CWE-835, A02:2021 | confirmed |
| **SEC-1016** `error.OpensslFailure` collapses crypto-fault and programmer-error into one class; `Unsupported` on `EVP_*_fetch` can mask a mis-provisioned (non-FIPS) provider as "alg not supported" | **Low** | `src/aead.zig:25,58`; `src/hash.zig:15`; `src/sig.zig` (fetch sites) | A consumer that treats `Unsupported` as "skip / try fallback" could silently route around FIPS when the real cause is a missing provider | CWE-391, A09:2021 | suspected |
| SEC-1004 (=F1) No zeroization of private keys / shared secrets / derived material | **High** | `src/sig.zig:68-70`, `src/kem.zig:20-22`, `src/kdf.zig`, `src/std_shim.zig:240-242`; spec `FIPS_SPECIFICATION.md:256` | Key/secret bytes linger in heap/stack and core dumps; spec advertises a `secureZero` that does not exist | CWE-226, CWE-212, A02:2021 | confirmed |
| SEC-1005 (=F2) No constant-time comparison primitive | **Medium** | (absent) seam surface; spec `FIPS_SPECIFICATION.md:256` | Consumers fall back to `std.mem.eql` for MAC/tag/secret comparison → timing oracle | CWE-208, A02:2021 | confirmed |
| SEC-1006 (=F4) Unsynchronized provider globals | **Medium** | `src/provider.zig:11-21,24-43` | Concurrent first-use races init of `g_ctx`/`g_fips`: double provider load / leaked ctx / torn read of FIPS-active state | CWE-362, CWE-567, A04:2021 | confirmed |
| SEC-1007 (=F5) Unchecked length truncation to `c_int` | **Low** | `src/aead.zig:31,36,39,43,64,69,72,75`; `src/sig.zig:86,100,113,128,130`; `src/kdf.zig:59` | Inputs >2 GiB truncate/UB in ReleaseFast; wrong length to OpenSSL | CWE-197, CWE-190, A06:2021 | confirmed |
| SEC-1008 (=F6) Stream.update panics on EVP failure | **Low** | `src/hash.zig:58-60` | Crafted/edge state aborts the process instead of returning an error | CWE-248, CWE-754, A04:2021 | confirmed |
| SEC-1009 (=F7) PBKDF2 disables FIPS minimums for all callers | **Low** | `src/kdf.zig:63,69` | Weak password KDF params (short salt, 1 iteration) silently accepted in production | CWE-916, CWE-521, A07:2021 | confirmed |
| SEC-1010 (=F8) `assertActive()` panics as production enforcement | **Low** | `src/provider.zig:47-49`; called from every primitive | Provider-load failure aborts the whole process (DoS) rather than a recoverable error | CWE-248, A04:2021 | confirmed |

Severity uses CVSS-style qualitative bands. "High" here means a
plausible path to memory corruption, signature/trust bypass, or
confidentiality loss; the absolute risk is gated by how each downstream
consumer drives the seam, so several Highs are correctly *suspected*
pending the consumer call-site review.

---

## Part 3 — NEW findings in detail

### SEC-1001 — Supply-chain: unpinned, unverified OpenSSL FIPS build installed as root  (High, confirmed) — CONFIDENTIAL

**Evidence.** `scripts/install-openssl-fips.sh`:

- `resolve_latest()` (`:53-64`) pulls `api.github.com/.../releases/latest`
  and takes whatever 3.x tag is returned — there is **no pinned version**
  and no allow-list of acceptable versions.
- The header comment states the design intent: *"ALWAYS upgrades to the
  latest 3.x release"* (`:7`) and `build.zig:372` advertises the `deps`
  step as *"always upgrades to latest"*.
- The tarball is fetched over the network (`:97`
  `wget ... openssl-${VER}.tar.gz`) and **immediately** `tar xzf`-ed and
  built. A repo-wide grep for `sha256|sha512|gpg|\.asc|\.sig|checksum`
  in this script returns **nothing** — the download is never verified
  against a known good hash or the OpenSSL release signing key.
- It is then installed system-wide as root: `:105-106`
  `sudo make install_sw install_ssldirs` / `sudo make install_fips`, and
  `:112-114` runs `sudo openssl fipsinstall`.

**Why it matters.** Two distinct risks:

1. **Integrity (CWE-494/829).** A compromised mirror, a MITM on the
   redirect chain, or a malicious GitHub release asset yields arbitrary
   tarball contents that are compiled and `sudo make install`-ed —
   i.e. **arbitrary code execution as root** on every build/CI host that
   runs `make deps`. Contrast with `scripts/install-zig.sh:45-49`, which
   *does* `sha256sum --check --strict` the Zig tarball; the OpenSSL path
   has no equivalent.
2. **FIPS provenance.** The whole point of the library is to route
   through a *validated* module. "Always latest" means the validated
   artifact silently changes between builds; the binary's FIPS posture is
   not reproducible and cannot be attested to a specific validated
   version.

**Remediation.**

- Pin `OPENSSL_VERSION` to an exact, reviewed 3.x release (the env hook
  at `:66` already exists — make a pin the default, not "latest").
- After download, verify **both** a pinned SHA-256 of the tarball **and**
  the OpenSSL release GPG signature (`.asc`) against the OpenSSL signing
  keys bundled in-repo. Fail closed on mismatch before `tar`.
- Record the installed version + tarball hash + `fipsmodule.cnf` MAC into
  a build attestation.
- Prefer a non-root prefix where the host allows; if `sudo` is required,
  scope it and document it.

**Acceptance criteria.** `make deps` refuses to build when (a) no pinned
version is set, or (b) the downloaded tarball's SHA-256 or GPG signature
does not match the pinned values; CI records the version+hash as an
artifact; a test asserts the script contains a verification step.

---

### SEC-1002 — AEAD `seal`/`open` missing length validation → OOB heap write  (High, confirmed)

**Evidence.** `src/aead.zig`:

- `seal` writes ciphertext via `EVP_EncryptUpdate(ctx, ciphertext.ptr, &outl, plaintext.ptr, @intCast(plaintext.len))` (`:39`) and the final block at `ciphertext.ptr + outl` (`:42`), and the tag at `tag.ptr` with length `@intCast(tag.len)` (`:43`) — **without ever checking** `ciphertext.len >= plaintext.len`, `tag.len == 16`, `nonce.len == 12`, or `key.len`.
- `open` likewise writes plaintext via `EVP_DecryptUpdate(ctx, plaintext.ptr, ...)` (`:72`) and the final block at `plaintext.ptr + outl` (`:78`) with no `plaintext.len >= ciphertext.len` check.
- The std_shim backend, which the seam claims is API-parity-equivalent, **does** validate: `src/std_shim.zig:208` (`...or ct.len < pt.len) return error.OpensslFailure;`) and `:214` (`...or pt.len < ct.len) ...`).

**Attack scenario.** Any consumer that sizes the output buffer from an
attacker-influenced length (e.g. a length field in a wire frame) and
passes a `ciphertext`/`plaintext` slice shorter than the actual input
causes OpenSSL to write past the end of the slice — a heap/stack buffer
overflow (CWE-787). For GCM the ciphertext length equals the plaintext
length, so the bug triggers on the very first byte of mismatch. This is
the single highest-impact memory-safety gap in the seam and is a
**behavioral divergence** from the shim it is supposed to mirror.

**Remediation.** Mirror the shim's guard at the top of both functions:
reject unless `key.len` matches the algorithm key size, `nonce.len == 12`
(see SEC-1011), `tag.len == 16`, and the output slice is at least as long
as the input. Return `error.OpensslFailure` (or a dedicated
`error.BadLength`).

**Acceptance criteria.** A negative test passing `ciphertext` one byte
short of `plaintext` returns an error (not UB / not a crash) under
ReleaseSafe and ReleaseFast; the fips and shim backends return the same
error for the same out-of-bounds inputs (parity test in
`tests/shim_parity.zig`).

---

### SEC-1003 — RSA verify accepts attacker-chosen weak/undersized key on import; no key-strength floor or type binding  (High, suspected) — CONFIDENTIAL

**Evidence.** `src/sig.zig`:

- `fromRsaComponents(n, e)` (`:121-146`) builds an `EVP_PKEY` straight
  from caller-supplied big-endian `n`/`e` with **no bound on the modulus
  size** and **no validation of `e`** (e.g. rejecting `e=1`, even `e`, or
  absurdly large `e`). A grep for any modulus/bit check in this file
  finds only the `generate()` hard-coded `bits = 2048` (`:170`) — that
  governs *generation*, not *import*.
- `fromRsaSpki(der)` (`:110-115`) and the `.der` arm of `fromPublicBytes`
  (`:84-87`) decode an arbitrary `SubjectPublicKeyInfo` via `d2i_PUBKEY`
  with no post-decode strength check.
- `verifyRsa(scheme, digest, kp, msg, sig)` (`:220-245`) and
  `verifyEcdsa(alg, digest, kp, msg, sig)` (`:254-279`) **never call**
  `EVP_PKEY_get_bits` / `EVP_PKEY_is_a` / `EVP_PKEY_get_security_bits`
  (grep: none). `verifyRsa` does not confirm `kp.pkey` is actually an RSA
  key, and `verifyEcdsa` checks only that `alg` is an `ecdsa_p*` value —
  not that the *imported key* matches that curve.

**Attack scenario.** A relying party (e.g. JWT/JWKS or X.509 path
validation built on this seam) imports an attacker-supplied public key
and verifies a signature with it. If the attacker can present a 512- or
1024-bit RSA key (factorable / forgeable) — or, via
`fromPrivateBytes(.der)` with the caller-chosen type tag at `:99`, a key
whose real type differs from the requested `alg` — the verify can succeed
on a forged signature, defeating the trust decision (CWE-347, CWE-326).
Marked **suspected** because OpenSSL's FIPS provider *may* itself reject
sub-2048-bit RSA in the signature operation; that backstop is
**version-dependent and undocumented here**, and FIPS historically
enforces the floor on *signing*, not always on *verification* of legacy
signatures. The seam must not rely on an unstated provider behavior for a
security-critical floor.

**What would confirm.** A test that imports a 1024-bit (and a 512-bit)
RSA public key via `fromRsaComponents`/`fromRsaSpki` and calls
`verifyRsa` against a signature produced by the matching small key, under
the actual FIPS build, observing whether verify returns success or
`error.OpensslFailure`. Also a test importing an EC key bytes through
`fromPrivateBytes(.rsa_pkcs1, ...)` to confirm the type-tag path cannot
be confused.

**Remediation.** On every RSA import path, enforce
`EVP_PKEY_get_bits(pkey) >= 2048` (and reject non-standard `e`); on
`verifyRsa`/`verifyEcdsa`, assert `EVP_PKEY_is_a(kp.pkey, "RSA")` /
`"EC"` and (for EC) that the key's group equals `alg`'s curve, before the
verify. Fail closed with `error.Unsupported`.

**Acceptance criteria.** Undersized RSA import (or verify) returns an
error regardless of provider version; a key whose type/curve disagrees
with the requested algorithm is rejected before any `EVP_DigestVerify`.

---

### SEC-1011 — No nonce-uniqueness / 96-bit-length contract on AES-GCM  (High, confirmed)

**Evidence.** `src/aead.zig:15-44` (`seal`) takes `nonce: []const u8`
directly from the caller and feeds it to OpenSSL with
`EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, @intCast(nonce.len), null)`
(`:31`) — i.e. **any** length is accepted (a non-96-bit IV silently
changes GCM's derivation), and there is **no uniqueness mechanism**
(counter, random-nonce helper, or misuse-resistant mode). A repo-wide
grep for `nonce.reuse|unique|deterministic IV|96-bit` across `docs/`,
`README.md`, `SECURITY.md`, and `templates/crypto_backend.zig` finds **no
guidance to consumers** about the catastrophic (key,nonce)-reuse
requirement.

**Attack scenario.** GCM is fragile under nonce reuse: encrypting two
messages under the same (key, nonce) leaks the XOR of plaintexts **and**
allows recovery of the GHASH authentication subkey, enabling forgery of
arbitrary ciphertexts. Because the seam neither enforces a 12-byte IV nor
provides/recommends a unique-nonce strategy, a downstream consumer that,
say, uses a random 8-byte IV or a per-connection counter that resets is
silently exposed. This is the classic "the API made the wrong thing
easy" foot-gun (CWE-323, CWE-1204).

**Remediation.** (1) Enforce `nonce.len == 12` in `seal`/`open` (folds
into SEC-1002's guard). (2) Provide a nonce-management helper or a
sealing API that accepts a key + monotonic counter and constructs the IV
internally, and/or document in `SEAM_CONTRACT.md` + `SECURITY.md` the
hard requirement that (key, nonce) never repeats, with a recommended
construction. (3) Consider exposing a misuse-resistant option for
consumers who cannot guarantee uniqueness.

**Acceptance criteria.** `seal`/`open` reject a non-12-byte nonce;
`SECURITY.md`/`SEAM_CONTRACT.md` document the uniqueness invariant and a
safe construction; a KAT covers the 12-byte path and a negative test
covers a wrong-length nonce.

---

### SEC-1012 — Provider config loaded from attacker-influenced `OPENSSL_CONF`  (Medium, suspected)

**Evidence.** `src/provider.zig:33-34`:
`const conf = c.getenv("OPENSSL_CONF"); if (c.OSSL_LIB_CTX_load_config(ctx, conf) != 1) return error.FipsProviderUnavailable;`
The process environment selects which OpenSSL configuration file is
loaded into the lib context that *all* seam operations subsequently use.

**Attack scenario.** In a deployment where an attacker can influence the
process environment (shared CI runner, a service that inherits env from a
less-trusted parent, container with injectable env), pointing
`OPENSSL_CONF` at a hostile config can change which providers activate and
what `default_properties` is set — potentially activating a non-FIPS or
attacker-controlled provider while `ensureFips()` still succeeds (it only
checks that *a* provider named `fips` self-tests, after the config it was
told to load). The seam then believes it is FIPS while the active
algorithm set has been tampered with (CWE-15/426). Marked **suspected**
because exploitability depends on the deployment's env trust boundary and
on whether a hostile config can pass the subsequent `fips` self-test
check; the design point — *security posture is environment-controlled* —
is real regardless.

**Remediation.** Document the env trust requirement loudly. For hardened
deployments, support an explicit, in-process config path (or a pinned
default) that does not read `OPENSSL_CONF`, and after load, assert the
*expected* providers are the only active ones (enumerate providers and
reject unknowns) rather than only checking that `fips` is present.

**Acceptance criteria.** A documented, opt-in mode ignores `OPENSSL_CONF`
and loads a pinned config; `ensureFips()` verifies the active provider
set matches an allow-list, not merely that `fips` exists.

---

### SEC-1013 — `OSSL_PROVIDER_load(ctx,"base")` return ignored  (Medium, confirmed)

**Evidence.** `src/provider.zig:37` `_ = c.OSSL_PROVIDER_load(ctx, "base");`
— the result is explicitly discarded, immediately after a comment (`:35-36`)
explaining the base provider is *required* for key serialization the FIPS
provider relies on.

**Attack scenario / impact.** If `base` fails to load (mis-provisioned
prefix, partial install), `ensureFips()` continues and reports FIPS
active. Operations that need base-provider encoders (key import/export in
`sig.zig`, KEM) then fail later — or, depending on fallback, behave
unexpectedly — with no fail-closed signal at the single init choke point.
This is unchecked-return (CWE-252) at a security-relevant boundary.

**Remediation.** Treat a `base` load failure as fatal init failure:
`_ = c.OSSL_PROVIDER_load(ctx, "base") orelse return error.FipsProviderUnavailable;`

**Acceptance criteria.** `ensureFips()` returns
`error.FipsProviderUnavailable` when the base provider cannot load.

---

### SEC-1014 — FIPS dual-mode CI gate rests on an unpinned, side-effecting deps job; full install exported as artifact  (Medium, confirmed)

**Evidence.** `.gitlab-ci.yml:306-329`. `test-fips` (`:320-328`) is a
**real** gate (it is *not* `allow_failure` — good), but it `needs:
["fips-deps"]`, and `fips-deps` runs `make deps` (`:311`) which executes
the unpinned always-latest `install-openssl-fips.sh` (see SEC-1001). The
job also publishes the entire FIPS install tree as an artifact:
`artifacts: paths: [/usr/local/ssl] expire_in: 1 day` (`:312-315`), which
includes `fipsmodule.cnf` (the install-time integrity MAC).

**Impact.** (1) The gate's meaning is non-reproducible: a new upstream
OpenSSL release changes the validated module between two otherwise
identical pipeline runs (CWE-1104 — reliance on an untrusted/uncontrolled
dependency version). (2) Exposing `/usr/local/ssl` as a downloadable
artifact widens what a reader of the pipeline can obtain about the FIPS
module configuration (CWE-200); low sensitivity, but unnecessary.

**Remediation.** Pin the OpenSSL version in CI (set `OPENSSL_VERSION`),
inherit SEC-1001's checksum/signature verification, and narrow the
`fips-deps` artifact to only what `test-fips` needs (or drop the artifact
and rebuild/cache by pinned version key).

**Acceptance criteria.** CI builds a pinned OpenSSL version with verified
integrity; the published artifact excludes config/MAC material not needed
downstream.

---

### SEC-1015 — CSPRNG error handling: all-or-nothing assumption + shim infinite-retry on any errno  (Low, confirmed)

**Evidence.**

- `src/csprng.zig:11-14`: `if (c.RAND_bytes_ex(provider.libCtx(), out.ptr, out.len, 0) != 1) return error.OpensslFailure;` — correct for OpenSSL (it is all-or-nothing), so the fips path is fine; noted only for completeness.
- `src/std_shim.zig:17-29` `randomBytes`: on `getrandom`, `const n: isize = @bitCast(rc); if (n < 0) { continue; }` — **every** negative return (including non-retryable `ENOSYS`, `EFAULT`, `EINVAL`) is treated as retryable and loops forever. The comment claims "EINTR/EAGAIN: retry; anything else: fall back to a re-seed," but the code performs neither a re-seed nor an errno discrimination — it just spins.

**Impact.** On a platform/configuration where `getrandom` returns a
non-retryable error (older kernel, seccomp filter blocking the syscall),
the non-FIPS shim CSPRNG hangs the thread (CWE-835) instead of failing
closed. A subtler concern: if a future edit ever made `getrandom` return
short reads silently acceptable, it would weaken entropy (CWE-332). The
shim is the `-Dfips=false` path, so impact is bounded, but key/seed
generation (`std_shim.zig:299-308`) depends on it.

**Remediation.** Discriminate errno: retry only on `EINTR`/`EAGAIN`;
return `error.OpensslFailure` on anything else. Add macOS/Windows CSPRNG
branches (already noted as a deferred item in `FIPS_SPECIFICATION.md:260`).

**Acceptance criteria.** A simulated non-retryable `getrandom` errno
returns an error rather than looping; entropy source has a per-OS branch.

---

### SEC-1016 — Error taxonomy conflates crypto faults, programmer errors, and provider-absence  (Low, suspected)

**Evidence.** Across the seam, `error.OpensslFailure` is returned for
context-allocation failure, bad params, *and* genuine crypto failures
(e.g. `src/sig.zig:209,244,278` map a non-0/non-1 verify rc to
`OpensslFailure`). Separately, `EVP_*_fetch` failures map to
`error.Unsupported` (`src/aead.zig:25,58`; `src/hash.zig:15`;
`src/kem.zig:28`). A mis-provisioned (or non-FIPS) provider causes the
*same* `error.Unsupported` a genuinely unavailable algorithm would.

**Impact.** A consumer reasonably treating `error.Unsupported` as "this
algorithm isn't available here, try an alternative" could **silently
route around FIPS** when the true cause is a missing/broken provider —
a fail-open hazard for the library's core guarantee. The verify-vs-fault
conflation also makes it harder for callers to distinguish "signature is
bad" (`VerifyFailed`, which is correctly separated) from "the operation
errored," but that one is handled well; the fetch/provider conflation is
the real gap. Marked **suspected** because impact depends on consumer
handling.

**Remediation.** Introduce a distinct `error.ProviderUnavailable` (or
reuse `FipsProviderUnavailable`) returned when a fetch fails *and* the
provider is not active, distinct from `error.Unsupported` for a genuinely
absent-but-provider-present algorithm. Document that `Unsupported` must
never be treated as a cue to fall back to non-FIPS crypto.

**Acceptance criteria.** Fetch failure while the FIPS provider is absent
yields `ProviderUnavailable`, not `Unsupported`; `SEAM_CONTRACT.md`
states the no-fallback rule.

---

## Part 4 — Confirmed prior findings (F1–F8) detail

### SEC-1004 (=F1) — No zeroization of secret material  (High, confirmed)

**Evidence.** `Sig.KeyPair.deinit` only `EVP_PKEY_free`s (`src/sig.zig:68-70`);
`Kem.KeyPair.deinit` likewise (`src/kem.zig:20-22`); derived KDF output,
KEM shared secrets (`src/kem.zig:49,64`), and shim private-key structs
(`src/std_shim.zig:240-242` is a no-op `deinit`) are never wiped, including
on error paths. `FIPS_SPECIFICATION.md:256` advertises a `secureZero` that
does not exist anywhere (grep: single hit, the spec line itself).
**Remediation.** Provide `secureZero` (wrapping `OPENSSL_cleanse`) and call
it on all transient secret buffers (shared secrets, PRKs, derived keys,
seed buffers) in `defer`/`errdefer`; for `EVP_PKEY` rely on OpenSSL's own
clearing but wipe any raw key bytes the seam copies out.
**Acceptance.** A `secureZero` exists and is invoked on every secret-bearing
stack/heap buffer; a test asserts the symbol is present (closing the
spec-vs-code gap).

### SEC-1005 (=F2) — No constant-time comparison  (Medium, confirmed)

**Evidence.** No `timing_safe`/`CRYPTO_memcmp` anywhere (grep: only the
`FIPS_SPECIFICATION.md:256` promise). Consumers comparing MACs/tags/secrets
must reach for `std.mem.eql`, which short-circuits.
**Remediation.** Expose `timing_safe(a, b) bool` over `CRYPTO_memcmp`
(fips) / `std.crypto.timing_safe.eql` (shim).
**Acceptance.** A constant-time compare is exported by both backends and
covered by a parity test.

### SEC-1006 (=F4) — Unsynchronized provider globals  (Medium, confirmed)

**Evidence.** `src/provider.zig:11-12` plain `var g_ctx/g_fips`; `libCtx()`
(`:16-21`) and `ensureFips()` (`:24-43`) read-modify-write them with no
mutex/atomic/`std.once`. First concurrent use races.
**Remediation.** Guard init with `std.once`/`std.Thread.Mutex` (or an
atomic CAS publishing the ctx), making first-use idempotent and
data-race-free. Add a real multi-threaded stress test (the current
`tests/stress.zig:14-19` only re-reads a string constant 100k times — it
exercises **no** concurrency and **no** crypto).
**Acceptance.** A `-Dtsan` stress test that calls `ensureFips()`/a primitive
from N threads is clean under ThreadSanitizer.

### SEC-1007 (=F5) — Length truncation to `c_int`  (Low, confirmed)

**Evidence.** See table; e.g. `src/aead.zig:39` `@intCast(plaintext.len)`,
`src/sig.zig:128` `@intCast(n.len)`, `src/kdf.zig:59` `@intCast(iters)`.
**Remediation.** Bound-check lengths against `c_int`/`INT_MAX` before the
cast (or use the size-typed OpenSSL APIs) and return an error on overflow.
**Acceptance.** A >2 GiB (or mocked oversize) input returns an error rather
than truncating, under ReleaseFast.

### SEC-1008 (=F6) — Stream.update panics  (Low, confirmed)

**Evidence.** `src/hash.zig:58-60` `@panic("EVP_DigestUpdate failed")`.
**Remediation.** Return `error.OpensslFailure` (change `update` to
`Error!void`), or document the infallibility contract and guarantee it.
**Acceptance.** No reachable `@panic` on an EVP return in the hot path.

### SEC-1009 (=F7) — PBKDF2 disables FIPS minimums  (Low, confirmed)

**Evidence.** `src/kdf.zig:63` `var pkcs5: c_int = 1;` set
unconditionally (`:69`), with a comment acknowledging it disables the
SP 800-132 min salt/iter/keylen checks "so the RFC 6070 short-vector KAT
can run" — but production callers get the same relaxed mode.
**Remediation.** Default `pkcs5=0` (enforce minimums); gate the relaxed
mode behind a test-only parameter, or enforce min salt(>=128-bit)/iters
(>=1000)/keylen in the wrapper itself.
**Acceptance.** A production call with a 1-iteration / short-salt PBKDF2 is
rejected; KATs run via an explicitly test-scoped path.

### SEC-1010 (=F8) — `assertActive()` panics as enforcement  (Low, confirmed)

**Evidence.** `src/provider.zig:47-49` `@panic(...)`; invoked at the top of
every primitive (`aead.zig:24,57`; `hash.zig:14,44`; `sig.zig:80,...`;
`kem.zig:27,40,57`; `kdf.zig:14,36,54`; `mac.zig:15`; `csprng.zig:12`).
**Remediation.** Make primitives return `error.FipsProviderUnavailable`
(they already have error unions) instead of aborting the process; reserve
panic for a single explicit startup assertion the application opts into.
**Acceptance.** A primitive called without the provider returns an error;
no library API aborts the host process on provider absence.

---

## Part 5 — Items explicitly checked and found OK (no finding)

- **`EVP_EncryptUpdate` `outl` offset (`aead.zig:39-42`).** For GCM,
  Update emits the full plaintext length into `outl` and `EncryptFinal`
  emits 0 bytes; `ciphertext.ptr + outl` is the correct offset. Correct
  given the length precondition is met (which SEC-1002 is about).
- **Verify return-code handling (`sig.zig:206-209,241-244,275-278`;
  `kem` decap mismatch).** `EVP_DigestVerify` rc is correctly tri-stated:
  `1`→ok, `0`→`VerifyFailed`, else→`OpensslFailure`. No crypto failure is
  mapped to success. AEAD `open` maps a failed `DecryptFinal` to
  `AuthFailed` (`aead.zig:78`). Tamper KATs exist
  (`aead.zig:107-110`, `sig.zig:336,373,390,399`).
- **`policy.zig` allow-list.** `isApproved` is `comptime`-only over a
  fixed `approved_names` table (`:123-126`); algorithm selection flows
  through typed enums (`SigAlg`/`Aead`/`KemAlg`) and `switch`es with no
  reachable runtime-string path into a fetch name. No allow-list bypass
  found. (Note: `AES-256-CBC` is present in `approved_names:115` but has
  no enum/wrapper exposure — dead-but-harmless.)
- **`install-zig.sh`.** Correctly verifies the Zig tarball SHA-256
  (`:45-49`) against the official index — this is the *positive* model
  SEC-1001 says the OpenSSL script should follow.
- **`test-fips` gate is not `allow_failure`** (`.gitlab-ci.yml:320-328`)
  — the FIPS dual-mode test is a hard gate (the weakness is its
  unpinned dependency, SEC-1014, not the gate itself).

---

## Part 6 — Summary

- **Confirmed all 8 prior findings** (F1→SEC-1004, F2→SEC-1005,
  F3→SEC-1002, F4→SEC-1006, F5→SEC-1007, F6→SEC-1008, F7→SEC-1009,
  F8→SEC-1010).
- **9 NEW findings** (SEC-1001, 1002 is the F3 confirmation with
  expanded impact, 1011, 1012, 1013, 1014, 1015, 1016, and the
  RSA-import SEC-1003). New, not in the prior list: **SEC-1001,
  SEC-1003, SEC-1011, SEC-1012, SEC-1013, SEC-1014, SEC-1015, SEC-1016**.
- **Highest priority:** SEC-1002 (OOB write — confirmed memory safety),
  SEC-1001 (root-level supply-chain RCE + FIPS provenance), SEC-1011
  (GCM nonce-reuse foot-gun), SEC-1003 (signature-forgery via weak-key
  import). The first two are confirmed; the latter two are
  confirmed-design-gap / suspected-exploitability pending the consumer
  call-site review.
- **CONFIDENTIAL:** SEC-1001 and SEC-1003.
