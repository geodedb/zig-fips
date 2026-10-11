<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2024-2026 CodePros -->

# FIPS-140-3 / FedRAMP Specification — DevNW Zig Workspace

- **Date:** 2026-06-20
- **Status:** Authoritative workspace spec (companion to the per-repo `docs/FIPS.md`)
- **Provider validated against:** OpenSSL 3.6.2 (7 Apr 2026); `make deps` always upgrades to the latest OpenSSL 3.x.
- **Toolchain:** Zig 0.16.0; Apache-2.0.

This document defines the cross-repo FIPS contract. It lives in the
`fips` repo's `docs/` and is the source of truth; each consumer repo
additionally carries a `docs/FIPS.md` with its own algorithm-swap notes.

## Flag semantics

| Aspect | Behavior |
|---|---|
| Build flag | `-Dfips` (bool), declared once per consumer via `b.option(bool, "fips", ...)`, default **false**. |
| Off (`-Dfips=false`, default) | Crypto routes through `std_shim` (std.crypto). **Zero** OpenSSL link, zero comptime/runtime overhead, no `fips` dependency fetched (it is `.lazy = true`). |
| On (`-Dfips=true`) | Crypto routes through the `fips` backend (OpenSSL FIPS provider). The lazy `fips` dependency resolves; `link.linkOpenssl` links libssl/libcrypto **dynamically** — forced `preferred_link_mode = .dynamic` with `search_strategy = .no_fallback`, so a static `.a` is never linked even though the `enable-fips` build installs both. This guarantees the binary depends on the certified **shared** OpenSSL build, not a static embed that could diverge from the dynamically-loaded `fips.so` module and void the validation; the build fails loudly if only a static OpenSSL is present. |
| Prefix override | `-Dopenssl_path=<prefix>` selects a non-standard OpenSSL install (default search is system; CI sets `/usr/local/ssl`). The prefix `lib64`/`lib` are added to the binary RPATH so the certified shared `libcrypto.so` (and the `fips.so` it loads from its compiled-in MODULESDIR) is what resolves at runtime — not a system libcrypto lacking the FIPS provider. Verify with `ldd <bin>` / `readelf -d <bin>`: `libcrypto.so.3 => <prefix>/lib64/libcrypto.so.3`. |
| Propagation | A SINGLE `build_options` module instance carries `fips` into every compile unit and into the lazy `fips` dependency (see Dependency DAG + GAP-0020 note). |
| Seam | Call sites import `crypto_backend` (`src/crypto_backend.zig`), never `std.crypto` directly in a security path. `crypto_backend` re-exports `Aead`/`Hash`/`Mac`/`Kdf`/`Sig`/`Kem`/`Csprng`/`policy`/`assertActive` and exposes `pub const fips_enabled`. |
| Startup self-test | `assertActive()` (no-op in the shim; in fips it loads fips+base, forces `EVP_default_properties fips=yes`, runs `OSSL_PROVIDER_self_test`, and panics if the validated module is absent). `ensureFips()` is the fallible variant returning `error.FipsProviderUnavailable`. |
| Test gate | Every touched repo must be green with BOTH `-Dfips=false` and `-Dfips=true` (`make test-dual`). The Linux `-Dfips=true` job is a required CI gate via the `zig-fips-build` ci-catalog component. The `zig-fips-lint` (ZL109) gate is a workspace-level `ci-catalog` component applied across consumer repos; it is NOT yet wired into this foundational repo's `.gitlab-ci.yml` (tracked as a deferred follow-up — see note below). The in-repo enforcement of record is `make test-dual` + the comptime `policy.isApproved` allow-list. |

## Approved-algorithm policy

The comptime allow-list lives in `fips.policy` (consumer libs gate on
`policy.isApproved(comptime name)`; the `zlint` ZL109 rule references the
same seam contract). Names are the exact OpenSSL 3.x EVP fetch strings,
confirmed via `openssl list` on 3.6.2.

| Class | Approved (fetch name) | Enum |
|---|---|---|
| Hash | `SHA2-256`, `SHA2-384`, `SHA2-512`, `SHA3-256`, `SHA3-384`, `SHA3-512` | `policy.Hash` |
| MAC | `HMAC` (over an approved SHA-2/3) | `policy.Mac` |
| KDF | `HKDF` (SP 800-56C), `PBKDF2` (SP 800-132) | `policy.Kdf` |
| AEAD/cipher | `AES-128-GCM`, `AES-256-GCM` (+ `AES-256-CBC` where a CBC+HMAC construction is required) | `policy.Aead` |
| Signature (classical) | `ECDSA` (P-256/384/521 via `OSSL_PKEY_PARAM_GROUP_NAME`), `RSA` (PSS via `OSSL_SIGNATURE_PARAM_PAD_MODE=pss`, or PKCS1), `ED25519` | `policy.SigAlg` |
| Signature (ML-DSA) | `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` | `policy.SigAlg` |
| Signature (SLH-DSA) | all 12: `SLH-DSA-SHA2-{128,192,256}{s,f}`, `SLH-DSA-SHAKE-{128,192,256}{s,f}` | `policy.SigAlg` |
| KEM (ML-KEM) | `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` | `policy.KemAlg` |
| KEM (hybrid) | `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` (note the mixed-case `SecP*` tokens) | `policy.KemAlg` |

**2026-10-11 correction (SONNY-4782).** OpenSSL 3.6.5 registers
`X448MLKEM1024` with `fips=no` for key management and encapsulation.
Its enum and fetch-name mapping remain for source compatibility, but
`policy.isApproved` / `policy.isKemApproved` reject it and every FIPS
KEM operation returns `error.Unsupported`. Tests explicitly verify both
the provider rejection and unchanged output buffers; no provider fallback
is permitted. The other six KEM variants retain real round-trip coverage.
The authenticated release source `providers/fips/fipsprov.c` is the
reference for these version-specific properties; provider availability
alone is not algorithm approval.

**Forbidden under `-Dfips=true`** (rejected at comptime / compiled out;
`policy.isApproved` returns false): ChaCha20-Poly1305, Argon2id, BLAKE3,
SHA-1, MD5, and any non-allow-listed primitive. Non-security uses
(`Wyhash` hashmaps, `std.Random` jitter/backoff, CRC32 integrity) are
exempt and annotated `// fips-exempt: non-security — <reason>`.

### Forced behavior changes under `-Dfips=true`

| Library | Non-FIPS default | Under FIPS | Rationale |
|---|---|---|---|
| `encrypted-fs` | Argon2id | **PBKDF2** (SP 800-132) | Argon2 is not a FIPS-approved KDF; PBKDF2 with an approved PRF (HMAC-SHA-2) and a compliant iteration count/salt is the SP 800-132 password-based key-derivation path. |
| `tls`, `quic`, `fle` | ChaCha20-Poly1305 | **AES-GCM** (AES-128/256-GCM) | ChaCha20-Poly1305 is not a FIPS-approved AEAD; AES-GCM is the SP 800-38D approved authenticated cipher and is the TLS 1.3 / QUIC mandatory-to-implement suite under FIPS. |
| `mcp` | SHA-1 | **removed** (SHA-256+) | SHA-1 is disallowed for security use; integrity/identity uses move to SHA-2. |
| `raft`, `graph-storage` | BLAKE3 / CRC32 | allowed only as **non-security integrity** (else SHA-2); documented exempt | BLAKE3/CRC32 are non-FIPS; permitted only where the use is non-security (error-detection), annotated `// fips-exempt: non-security`. Any security use switches to SHA-2. |

The **Argon2id → PBKDF2** and **ChaCha20-Poly1305 → AES-GCM** swaps are
the two load-bearing approved-algorithm substitutions; both are
documented in the affected repo's `docs/FIPS.md` and covered by the
dual-mode (`make test-dual`) tests so the behavior change is exercised in
both backends.

## Provider sourcing + self-test

- **Sourcing:** `make deps` (`zig build deps` shells the same script) runs
  `scripts/install-openssl-fips.sh`, which: installs OS build prereqs;
  resolves the latest OpenSSL 3.x release (overridable with
  `OPENSSL_VERSION=`); rebuilds from source unless the installed version
  already matches AND the fips provider loads (always-upgrade-to-latest);
  `./Configure enable-fips --prefix=$OPENSSL_PREFIX`; `make -j`;
  `sudo make install_sw install_ssldirs install_fips`; runs
  `openssl fipsinstall` to emit `fipsmodule.cnf`; writes `openssl.cnf`
  with `[provider_sect]` activating `fips` + `base` and
  `[algorithm_sect] default_properties = fips=yes`. `OPENSSL_PREFIX`
  defaults to `/usr/local/ssl`.
- **Verification:** `scripts/verify-fips-provider.sh` asserts
  `openssl list -providers` shows `fips status: active` and that
  `ML-KEM-768`, `ML-DSA-65`, `SLH-DSA-SHA2-128s` are listed.
- **Runtime self-test:** every fips-mode entrypoint calls
  `assertActive()` which runs `OSSL_PROVIDER_self_test` (KATs) and
  hard-fails if the validated module is not loaded. This makes a green
  `-Dfips=true` test run empirical proof of an active, self-tested module.
- **CI:** the `zig-fips-build` ci-catalog component runs `make deps` in
  `before_script` (caching the built prefix), then
  `zig build <step> -Dfips=true -Dopenssl_path=<prefix>` with
  `OPENSSL_CONF` set to `<prefix>/ssl/openssl.cnf`. `make deps` is the
  required setup job before any `-Dfips=true` build/test.

## FedRAMP control mapping

Mapping of FIPS capabilities to FedRAMP (NIST SP 800-53 Rev. 5)
controls. This is an engineering control-mapping aid, not an ATO
assertion; formal validation is the OpenSSL FIPS module certificate.

| Control | Title | How this capability satisfies it |
|---|---|---|
| SC-13 | Cryptographic Protection | All security crypto uses the FIPS-140-3 validated OpenSSL provider; non-approved algorithms compiled out under `-Dfips=true`. |
| SC-12 | Cryptographic Key Establishment & Management | KEM (ML-KEM + hybrids) and key generation via the validated provider (`Kem.generate`/`encapsulate`/`decapsulate`, `Sig.generate`). |
| SC-12(3) | Asymmetric keys | ECDSA/RSA/Ed25519 + ML-DSA/SLH-DSA key generation under the validated module. |
| SC-8 / SC-8(1) | Transmission Confidentiality & Integrity | AES-GCM AEAD + HKDF key schedule for `tls`/`quic`/`wireguard`; hybrid PQC KEM in TLS 1.3. |
| SC-17 | PKI Certificates | `zign`/`dns` ML-DSA + SLH-DSA certificate/DNSSEC profiles. |
| SC-28 / SC-28(1) | Protection of Information at Rest | `encrypted-fs`/`fle` AES-GCM with PBKDF2 key derivation under FIPS. |
| IA-7 | Cryptographic Module Authentication | `assertActive()` startup self-test enforces use of the validated module; hard-fail otherwise. |
| SC-13 + CM-7 | Least Functionality for crypto | Approved-algorithm allow-list (`fips.policy`) + zlint ZL109 rule reject non-approved crypto in security paths. |
| SI-7 | Software/Firmware Integrity | Provider self-test (KATs via `OSSL_PROVIDER_self_test`) on load. |
| SC-13 (PQC posture) | Quantum-resistant readiness | ML-KEM/ML-DSA/SLH-DSA available from the validated provider; hybrid KEM default `X25519MLKEM768`. See `PQC_ROADMAP.md`. |

## Dependency DAG

```text
                     ┌─────────────────────────────┐
                     │ OpenSSL 3.x FIPS provider    │
                     │ (built by `make deps`)       │
                     └──────────────┬──────────────┘
                                    │ linked via src/link.zig (linkOpenssl)
                                    ▼
                      ┌──────────────────────────┐
                      │ fips package (lazy dep)  │
                      │ policy · Hash · Mac ·    │
                      │ Kdf · Aead · Sig · Kem · │
                      │ Csprng · assertActive    │
                      └─────────────┬────────────┘
          -Dfips=true               │   (std_shim when -Dfips=false)
                                    ▼
                      ┌──────────────────────────┐
                      │ src/crypto_backend.zig   │  ← single seam each repo copies
                      └─────────────┬────────────┘
                                    ▼
   crypto-core (full):  tls ─┬─ quic ─ wireguard
                             ├─ auth   dns   zign   hsm ─ encrypted-fs   fle
   incidental (route security uses through the seam):
     uuid · oauth · oidc · fts-storage · wal · timeseries-storage · grpc-zig · mcp
   incidental (audit + document exempt):
     audit · cli · raft · graph-storage · ai · dpi · ds · entropy · hnsw · json ·
     config · metrics · otel · timeseries · zcap · zlint
```

Build-graph rule (GAP-0020): materialize EXACTLY ONE `build_options`
module (`b.addOptions()` once → `createModule()` once) and thread that
single `*std.Build.Module` into every compile unit AND into the lazy
`fips` dependency. The seam (`crypto_backend.zig`) and `std_shim.zig` are
shared named modules (`b.addModule`) reached through one module identity.
Calling `createModule()` on a second options instance reachable from the
same source-file graph triggers the Zig 0.16 `file exists in modules X
and Y` dedup error. See `docs/GAP-0020-module-dedup.md`.

### Local-path-dep → git+https publish follow-up

During the one-push rollout, consumers wire the `fips` (and, for PQC
consumers, `tls`) dependency as a **local `.path` dependency** in
`build.zig.zon` so the whole workspace builds against unpublished source
in lockstep:

```zig
.fips = .{ .path = "../fips", .lazy = true },
// PQC consumers (quic, wireguard, …) additionally:
.tls  = .{ .path = "../tls",  .lazy = true },
```

This is a deliberate, temporary state. Once `fips` and `tls` are tagged
and published, every consumer's local `.path` dependency MUST be swapped
to a **lazy `git+https`** dependency pinned to a published tag + hash:

```zig
.fips = .{
    .url  = "git+https://gitlab.com/devnw/zig/fips#v<X.Y.Z>",
    .hash = "<zig-package-hash>",
    .lazy = true,
},
```

See the "Published deferred items" section below for the full
publish-and-swap checklist. The `.lazy = true` attribute is preserved
through the swap so the default (`-Dfips=false`) build still fetches
nothing.

## Published deferred items

These items are intentionally deferred until the foundation packages are
published; they are tracked here so no consumer is left on a temporary
local dependency or a non-portable code path.

1. **Swap every consumer's local `.path fips`/`tls` dep to lazy
   `git+https` once published.**
   - **`fips` — DONE (v0.1.0, 2026-06-22).** `fips` is tagged `v0.1.0` and
     published **public** at `gitlab.com/devnw/zig/fips`. Every consumer that
     wired the seam now pins the lazy `git+https` form
     `git+https://gitlab.com/devnw/zig/fips.git#v0.1.0` with
     `.hash = "fips-0.1.0-1wf3nbxWBgAp6yAk6cPRrF5l_U1tbblcVcN9xcjJDddy"`,
     `.lazy = true` (each verified with `zig build --fetch`): auth, dns,
     encrypted-fs, fle, fts-storage, grpc-zig, hsm, mcp, oauth, oidc, quic,
     timeseries-storage, tls, uuid, wal, wireguard, zign, zlint.
   - **`tls` — DONE (v0.1.16, 2026-06-22).** `tls` is tagged `v0.1.16`
     (public), carrying the `-Dfips` seam and pinning the published fips
     `git+https#v0.1.0`. Published form:
     `git+https://gitlab.com/devnw/zig/tls.git#v0.1.16` with
     `.hash = "tls-0.1.16-mtEaLPssFgDXM8r7HPoDgZaqNfrAZbAhTQvk7SDmprqu"`.
   - **Consumer `.tls` swap — gated on a workspace-wide diamond cascade.**
     A consumer cannot pin `tls@v0.1.16` while still pulling an older `tls`
     transitively; the `detect-diamond-deps` gate (GAP-0020 single-version
     rule) rejects two `tls` hashes in one graph. For **quic** this was
     resolved (2026-06-22): the only tls-bearing intermediate in quic's tree
     was `otel`, so **otel was released as v0.1.14** pinning `tls@v0.1.16`,
     and quic then pinned `tls@v0.1.16` + `otel@v0.1.14` → `detect-diamond-deps`
     clean (14 packages, 0 diamonds), builds + tests green. No active
     local-`.path` fips/tls deps remain in the workspace. Independent tls
     consumers outside quic's tree (`ai`, `http3`) still pin older tls and
     can be bumped separately when convenient.
   This is a mechanical, per-repo follow-up; it does not change any
   algorithm or seam behavior.

2. **`std_shim` macOS / Windows CSPRNG portability.** The non-FIPS
   backend (`std_shim.zig`) sources randomness from the `getrandom` syscall
   (Linux); macOS and Windows runtime paths (`SecRandomCopyBytes` /
   `BCryptGenRandom`) are **not yet gated** because the cross-OS FIPS jobs
   are advisory (`*cross-os-rules`, `allow_failure: true`). Follow-up:
   - Add a small `std_shim` CSPRNG unit test that asserts non-zero,
     non-repeating output and run it on the macOS + Windows runners via
     the gated `zig-fips-build` cross-OS variants (or a dedicated
     `zig-test-macos`/`zig-test-windows` job) before promoting those
     jobs to required.
   - Confirm `std`'s platform CSPRNG selection compiles and links on each
     target (no `getrandom` assumption on macOS/Windows).
   - Until then, the documented posture is: FIPS mode (OpenSSL
     `RAND_bytes` under the validated DRBG) is the cross-platform CSPRNG
     of record; the `std_shim` CSPRNG is fully validated only on Linux.

## CI/CD

- Provisioning: `gitlab.com/devnw/ci-catalog/zig-fips-build` runs
  `make deps` then `zig build <step> -Dfips=true -Dopenssl_path=<prefix>`
  with `OPENSSL_CONF=<prefix>/ssl/openssl.cnf`.
- Lint gate (workspace-level, deferred for this repo): `gitlab.com/devnw/ci-catalog/zig-fips-lint`
  builds `zlint` and runs `ZL109.fips_unguarded_crypto`, failing CI on
  unguarded `std.crypto`/`std.hash` in a security path. **This component is
  applied across consumer repos in the workspace and is NOT yet wired into
  this foundational `fips` repo's `.gitlab-ci.yml`** (tracked as a deferred
  follow-up; the `zlint_ref` also awaits a stable published tag on `zlint`'s
  default branch). The in-repo enforcement of record for this repo is the
  dual-mode `make test-dual` gate plus the comptime `policy.isApproved`
  allow-list.
- Per consumer repo: a Linux `-Dfips=true` unit + integration job (required)
  plus the ZL109 lint gate (required once wired), plus macOS/Windows variants
  gated behind `*cross-os-rules` (default branch / schedule /
  `RUN_CROSS_OS=true` / manual), mirroring the existing `zig-*-macos` /
  `zig-*-windows` jobs in `fts-storage/.gitlab-ci.yml`.

---

## Strict Enforcement — Verified

Workspace-wide **ZL109 (`fips_unguarded_crypto`) = 0**: under `-Dfips=true` no
`std.crypto` algorithm executes in any security path. All FIPS-approved crypto
routes through the OpenSSL FIPS-validated provider; non-approved algorithms
fail closed or `@compileError`. The non-FIPS (`-Dfips=false`) standard-library
paths are comptime-dead under fips.

**In-repo enforcement (this repo):** the dual-mode `make test-dual` gate (both
`-Dfips=false` and `-Dfips=true` must be green) plus the comptime
`policy.isApproved` allow-list provide the enforcement of record. The
`zig-fips-lint` ZL109 ci-catalog component is applied across consumer repos at
the workspace level but is **not yet wired into this repo's `.gitlab-ci.yml`**
(deferred follow-up pending a stable `zlint` published tag).

### Capabilities removed / fail-closed under `-Dfips=true`

- **mcp**: WebSocket `Sec-WebSocket-Accept` (SHA-1, RFC 6455) → `@compileError`; front MCP with a TLS-terminating proxy or non-WebSocket transport.
- **oauth**: OAuth 1.0a (HMAC-SHA1, RFC 5849) → `@compileError`; use OAuth 2.0.
- **tls**: standalone X25519 key agreement → fails closed; only ECDHE P-256/384 and the `X25519MLKEM768` hybrid are offered under fips.
- **tls / quic / fle**: ChaCha20-Poly1305 → rejected; AES-GCM used.
- **encrypted-fs**: Argon2id → PBKDF2 (SP 800-132); XChaCha20-Poly1305 → AES-256-GCM.
- **tls x509 / certificate verify**: any (curve, hash) or RSA scheme outside the validated set → certificate rejected (fail closed); never a std fallback.
- non-security hashing (BLAKE3 snapshot integrity, CRC32 checksums, Wyhash maps), constant-time compare (`timingSafeEql`), and memory zeroing (`secureZero`) remain available (not FIPS-governed; annotated `// fips-exempt: non-security`).

### Deferred (publish-time) follow-ups

- Swap each consumer's local `.path` `fips`/`tls` dependency to `b.lazyDependency` `git+https?ref=<tag>#<hash>` once the `fips` and `tls` packages are pushed and tagged.
- Add `std_shim` CSPRNG branches for macOS/Windows (current shim CSPRNG is Linux `getrandom`).
- Re-pin the `zig-fips-lint` `zlint_ref` to a published tag/SHA once ZL109 lands on `zlint`'s default branch.
- Port `wireguard` application sources to Zig 0.16 `std.Io` (pre-existing drift, unrelated to FIPS; the FIPS seam already passes via `zig build test-fips-seam`).
