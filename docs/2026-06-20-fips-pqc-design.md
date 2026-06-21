# FedRAMP / FIPS-140-3 / Post-Quantum Crypto Capability — Design Spec

- **Date:** 2026-06-20
- **Status:** Approved (architectural decisions confirmed by user)
- **Scope:** All libraries under `/home/benji/src/devnw/zig` (58 repos)
- **Method:** `superpowers:writing-plans` → `superpowers:subagent-driven-development`
- **Target toolchain:** Zig 0.16.0; OpenSSL 3.x (latest) with FIPS provider; Apache-2.0; GitLab CI via `gitlab.com/devnw/ci-catalog`

> This is the authoritative working spec. It will be committed into the new `fips` repo's `docs/` during foundation implementation; per-repo `docs/FIPS.md` + `REQUIREMENTS.md` entries are created per library during implementation.

---

## 1. Goal

Add a build-flag-gated FIPS-140-3 mode (with FedRAMP-oriented compliance posture) and post-quantum cryptography to every crypto-relevant library in the workspace. When `-Dfips=true`:

1. All **security-relevant** cryptography routes through a **linked FIPS-140-3 validated module** (OpenSSL 3.x FIPS provider).
2. **Non-FIPS security crypto is removed** — compiled out or rejected at comptime.
3. **Post-quantum** algorithms (ML-KEM, ML-DSA, SLH-DSA) are available, sourced from OpenSSL (not re-implemented).

The flag mirrors the existing `otel` build flag: off by default, zero overhead when off, lazily-fetched dependency, per-library seam.

## 2. Confirmed decisions

| # | Decision | Choice |
|---|----------|--------|
| 1 | Backend home | **New dedicated `fips` package** (consumed lazily like `otel`); not overloaded into `tls` |
| 2 | Enforcement | **Strict for security crypto** (compile out / `@compileError`); **non-security uses exempt** (allow-listed) |
| 3 | FIPS module sourcing | **Build the OpenSSL FIPS provider** (via `make deps`, always latest) + **runtime self-test** that hard-fails if absent |
| 4 | Rollout | **Everything in one push** — foundation + all crypto-core + crypto-incidental + PQC + CI + docs |

**Defaults taken** (changeable): dynamic link to system `libcrypto`/`libssl` with `-Dopenssl_path=` override; `-Dfips` propagates build-wide through the dependency tree; master spec lives in the `fips` repo.

## 3. The `fips` foundation package

Scaffolded from `zig-template` (`bootstrap.sh fips`), module name `fips`. Responsibilities:

### 3.1 OpenSSL FFI + provider lifecycle

- `@cImport` of `openssl/evp.h`, `openssl/provider.h`, `openssl/core_names.h`, `openssl/rand.h`, `openssl/kdf.h`; `link_libc = true`; `linkSystemLibrary("crypto")` + `linkSystemLibrary("ssl")`. Reuses the linking precedent in `tls`'s OpenSSL/BoringSSL conformance tests, promoted to production.
- `OSSL_PROVIDER_load(ctx, "fips")`, set default property query `"fips=yes"`, run the module self-test (KATs), expose `fips.assertActive()` which **panics/errors at startup** if the validated FIPS provider is not loaded and self-tested.
- `-Dopenssl_path=` build option for non-standard installs; platform branches (Linux system / macOS / Windows vcpkg) following the `hsm` PC/SC linking precedent.

### 3.2 FIPS-approved primitive API (stable Zig surface, OpenSSL-backed)

- **Hash:** SHA-256/384/512, SHA-3 (FIPS 202)
- **MAC:** HMAC-SHA2
- **KDF:** HKDF (SP 800-56C), **PBKDF2** (SP 800-132)
- **AEAD:** AES-128/256-GCM (+ AES-CBC + HMAC where needed)
- **Signatures:** ECDSA (P-256/384/521), RSA-PSS / RSA-PKCS1, Ed25519 (FIPS 186-5)
- **DRBG/CSPRNG:** SP 800-90A via OpenSSL `RAND_bytes` under the FIPS provider

### 3.3 PQC wrappers (`fips.kem`, `fips.sig`) — all from OpenSSL

- **KEM:** ML-KEM-512/768/1024; **hybrids** X25519MLKEM768 (default), X448MLKEM1024, SecP256r1MLKEM768, SecP384r1MLKEM1024
- **Signature:** ML-DSA-44/65/87; SLH-DSA (all 12 SHA2/SHAKE × 128/192/256 × s/f)

### 3.4 Algorithm-policy table

A comptime-known FIPS-approved allow-list (`fips.policy`) that consumer libs gate against and that the `zlint` rule references.

### 3.5 `make deps` (dependency provisioning — always latest)

Makefile `deps` target (alongside the template's `dev`/`ci`/`pre-commit-install`) that:

1. Installs OS build prerequisites (Linux apt: `build-essential perl`; macOS brew; Windows vcpkg).
2. Resolves the **latest** OpenSSL 3.x release (queries upstream; rebuilds if newer than installed — **always upgrade to latest**).
3. Configures with `enable-fips`, builds, and installs to a pinned prefix (default `/usr/local/ssl`, override `OPENSSL_PREFIX=`).
4. Runs `openssl fipsinstall` to generate `fipsmodule.cnf` and writes/links an `openssl.cnf` that activates the `fips` + `base` providers.
5. Verifies: `openssl list -providers` shows `fips` active and `openssl list -kem-algorithms`/`-signature-algorithms` shows ML-KEM/ML-DSA/SLH-DSA.
6. Idempotent + re-runnable; prints the resolved version. Exposed in Zig build as `zig build deps` shelling to the script too.

`make deps` is **run as the first foundation step** and is a **required setup job in the ci-catalog FIPS/PQC build component** (see §8).

## 4. Seam pattern (mirrors `otel`) + module-dedup fix

Each crypto-relevant library:

- Adds `-Dfips` via `b.option(bool, "fips", ...)`, `opts.addOption(bool, "fips", fips)`, **one** `opts.createModule()` (`build_options`).
- Threads the **same** `*build_options` module instance into every compile unit and into the lazily-resolved `fips` dependency (`.lazy = true` in `build.zig.zon`, fetched only when `-Dfips=true`).
- Adds seam `src/crypto_backend.zig`:

  ```zig
  const build_options = @import("build_options");
  pub const fips_enabled = build_options.fips;
  const backend = if (fips_enabled) @import("fips") else @import("std_shim.zig");
  pub const Aead = backend.Aead;        // shim & fips backend share one API
  pub const Hash = backend.Hash;
  pub const Kdf  = backend.Kdf;
  pub const Sig  = backend.Sig;
  pub const Csprng = backend.Csprng;
  ```

- A `std`-backed `std_shim.zig` implements the identical API so call sites are backend-agnostic.

**Module-dedup hazard (their GAP-0020):** A Zig 0.16 bug (`"file exists in modules X and Y"`) already forced `concurrency`'s otel seam to be hardcoded `enabled = false`. Foundation work will: reproduce it, pin the canonical single-`build_options`-instance wiring that avoids it, capture it as a reusable build helper, prove it on `tls`/`auth`, and **re-enable `concurrency`'s otel seam** as the proof point.

## 5. Enforcement (strict security, exempt non-security)

- Security primitives route through the seam; non-FIPS security crypto is compiled out / `@compileError` under `-Dfips=true`.
- Non-security uses (hashmap `Wyhash`, jitter/backoff `std.Random`, CRC32 integrity) are allow-listed with `// fips-exempt: non-security — <reason>` comments.
- **New `zlint` rule** fails any `std.crypto`/`std.hash` usage in a fips build that is neither routed through the seam nor annotated exempt. Wired into pre-commit + CI.

### Behavior changes forced under `-Dfips=true`

| Library | Non-FIPS today | Under FIPS |
|---------|----------------|------------|
| encrypted-fs | Argon2id | **PBKDF2** (SP 800-132) |
| tls, quic, fle | ChaCha20-Poly1305 | **AES-GCM** |
| mcp | SHA-1 | **removed** (SHA-256+) |
| raft, graph-storage | BLAKE3 / CRC32 | allowed only as **non-security integrity** (else SHA-2); documented exempt |

All swaps are documented and covered by tests.

## 6. Per-library work matrix

- **Crypto-core (9) — full treatment:** `tls`, `quic`, `wireguard`, `auth`, `dns`, `zign`, `hsm`, `encrypted-fs`, `fle`
- **PQC consumers:** `tls` (hybrid KEM in TLS 1.3 key schedule + ML-DSA cert/handshake sigs), `quic`/`wireguard` (inherit via tls), `zign` (ML-DSA + SLH-DSA cert profiles & code signing), `dns` (ML-DSA DNSSEC), `hsm` (ML-KEM/ML-DSA token ops)
- **Incidental — route security uses through seam:** `uuid` (CSPRNG), `oauth`/`oidc` (SHA/PKCE), `fts-storage`/`wal` (HMAC), `timeseries-storage` (AES-GCM), `grpc-zig` (HMAC), `mcp` (TLS + drop SHA-1)
- **Incidental — audit + document exempt:** `audit`, `cli`, `raft`, `graph-storage`, `ai`, `dpi`, `ds`, `entropy`, `hnsw`, `json`, `config`, `metrics`, `otel`, `timeseries`, `zcap`, `zlint`
- **No-crypto (~26):** matrix entry only (advanced-types, capture, concurrency, cuda, ebnf, gql, http3, i18n, ldap, oui, protobuf, repl, rtree, slog, spice, strings, thread-pool, toml, uri, vulkan, yaml, zig-template, zig-tool, zp4, zvm)

## 7. Testing & verification

- Every touched lib: `zig build test` green with **both** `-Dfips=false` (default; std shim; zero comptime overhead) **and** `-Dfips=true` (OpenSSL FIPS backend).
- **KAT/known-answer tests** for each approved algorithm; provider self-test.
- **Negative test:** a non-FIPS security primitive under fips fails to compile; unannotated `std.crypto` under fips fails the zlint rule.
- PQC interop tests against OpenSSL CLI / test vectors.
- Benchmarks confirm no regression in the default (non-fips) path.

## 8. CI/CD (ci-catalog)

- New/extended ci-catalog component (e.g. `zig-fips-build`) whose setup runs **`make deps`** (builds latest OpenSSL + FIPS provider) before any FIPS/PQC build or test job.
- Each touched repo's `.gitlab-ci.yml` gains a `-Dfips=true` matrix job using that component (Linux required; macOS/Windows gated like existing cross-OS rules).
- Pre-commit gains the zlint fips-exemption rule.

## 9. Docs & compliance artifacts

- Per-repo `docs/FIPS.md` + `REQUIREMENTS.md` REQ-IDs (existing convention) + GAP_ANALYSIS updates.
- Workspace `docs/FIPS_SPECIFICATION.md`: flag semantics, approved-algorithm policy, provider sourcing/self-test, FedRAMP control mapping, dependency DAG.
- `PQC_ROADMAP.md`: per-library PQC algorithm status.
- `zig-template`-based pure-Zig PQC project documented as a **fallback only** (not built; OpenSSL covers the full suite incl. SLH-DSA).

## 10. Execution order (within the one push)

1. **`fips` foundation:** scaffold from zig-template → `make deps` (run, verify provider) → OpenSSL FFI → provider self-test → approved primitives → PQC wrappers → KATs → **nail module-dedup wiring + build helper**.
2. **`tls`** (hub): seam, AES-GCM selection, hybrid PQC KEM, ML-DSA sigs — proves the pattern on the hardest lib.
3. **Crypto-core fan-out** (dependency order): `auth` · `quic`→`wireguard` · `dns` · `zign` · `hsm`→`encrypted-fs` · `fle`.
4. **Incidental:** route security uses; audit+exempt the rest; ship the `zlint` rule.
5. **CI matrices + docs/compliance artifacts.**

## 11. Risks & mitigations

| Risk | Mitigation |
|------|------------|
| Zig 0.16 module-dedup bug | Reproduce + pin canonical wiring in foundation; prove on tls/auth; re-enable concurrency otel seam |
| FIPS provider absent at runtime | `make deps` builds it; `fips.assertActive()` startup self-test hard-fails otherwise |
| FIPS provider won't build on a platform | `make deps` runs first in foundation as a go/no-go gate; platform branches; `-Dopenssl_path` override |
| Algorithm swaps change behavior (Argon2→PBKDF2, ChaCha→AES) | Documented in docs/FIPS.md; covered by dual-mode tests |
| Accidental non-FIPS crypto in security path | zlint rule + mandatory exemption comments + negative tests |
| Dirty/feature-branch repos (config, dns, zig-tool, graph-storage, quic) | Branch/commit hygiene per repo before editing |
| Perf regression from abstraction | Comptime seam (no runtime indirection); benchmark gate |

## 12. Hygiene preconditions

- `graph-storage` on `fix-label-scan-race`, `quic` on `fix-recovery-on2-sequential` (untracked feature branches) — coordinate before editing.
- `config`, `dns`, `zig-tool` have uncommitted changes — review/stash/commit before editing.
- Each repo: create a feature branch (e.g. `feat/fips-pqc`) before changes.
