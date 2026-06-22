# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-22

### Added

#### Core seam infrastructure

- Dual-mode comptime crypto seam (`templates/crypto_backend.zig`) selects
  between the OpenSSL FIPS provider backend and the `std.crypto` shim at
  build time via `-Dfips`; call sites are backend-agnostic
- `std_shim.zig` + `policy.zig` copy-verbatim pattern: the non-fips path
  requires only `std` (no OpenSSL, no `@cImport`, no lazy dependency fetch)
- GAP-0020 single-`build_options` dedup rule enforced and documented;
  `templates/build_fips_snippet.zig` canonical wiring template
- `fips_enabled` comptime bool exported by both backends
- `assertActive()` startup FIPS self-test (panics if the validated module
  is absent); `ensureFips()` fallible variant
- FIPS provider self-test on load via `OSSL_PROVIDER_self_test` (KATs)
- Thread-safe + lock-free fast-path FIPS provider initialization
  (`src/provider.zig`); `EVP_default_properties fips=yes` set on the
  library context; base provider loaded alongside FIPS provider
- Per-call EVP fetch cache (`provider.cipherFor`/`mdFor`/`hmacMac`/`kdfHkdf`/`kdfPbkdf2`)
  over the FIPS library context; eliminates per-call provider lookups on
  the hot path while preserving the `fips=yes` guarantee

#### Symmetric / MAC / KDF

- `Hash.digest` one-shot SHA-2 (256/384/512) and SHA-3 (256/384/512)
- `Hash.Stream` incremental hashing API: `init`, `update` (`Error!void`),
  `clone`, `final`; `update` is fallible to propagate OpenSSL errors; the
  cached MD is up-ref'd on `init` and `clone` and released by `deinit`
- `Hash.digest` and `Hash.Stream.final` bounds-check the output buffer
- `Mac.hmac` HMAC over any approved SHA-2/3 digest
- `Kdf.hkdf` (SP 800-56C extract+expand), `Kdf.hkdfExpand` (expand-only)
- `Kdf.pbkdf2` (SP 800-132); enforces minimum 1000 iterations (SP 800-132)
  and 16-byte salt (128-bit minimum per SP 800-132)
- `Aead.seal`/`open` AES-128-GCM and AES-256-GCM; validates exact
  `key.len`, `nonce.len == 12`, `tag.len == 16`, and output-buffer size;
  wipes unverified plaintext on authentication failure in `open`

#### Asymmetric / signatures / KEM

- `Sig` ECDSA P-256/384/521, RSA-PSS, RSA-PKCS1, Ed25519 — sign + verify
  + `KeyPair.generate`/`fromPublicBytes`/`fromPrivateBytes`
- All classical VERIFY paths (RSA + off-diagonal ECDSA) routed through the
  FIPS seam via `EVP_DigestVerify`; RSA verify enforces a 2048-bit floor
  and key-type/curve binding
- `Sig` ML-DSA-44/65/87 sign + verify + KAT coverage
- `Sig` SLH-DSA: all 12 variants (SHA2/SHAKE × 128/192/256 × s/f)
  sign + verify + KAT coverage
- `Kem.generate`/`encapsulate`/`decapsulate` for ML-KEM-512/768/1024
- Hybrid KEMs: `X25519MLKEM768`, `X448MLKEM1024`, `SecP256r1MLKEM768`,
  `SecP384r1MLKEM1024`; `Kem.EncapResult` type pinned on the seam

#### Constant-time utilities

- `secureZero(buf: []u8)` — memory wipe primitive (non-FIPS governed;
  always available on both backends); `std_shim` uses it to wipe key
  buffers after use
- `timingSafeEql(a, b: []const u8) bool` — constant-time byte-slice
  comparison on both backends

#### CSPRNG

- `Csprng.bytes(out)` SP 800-90A DRBG via `RAND_bytes` under the validated
  provider (fips backend); `getrandom` syscall path on Linux (shim;
  macOS / Windows runtime deferred)

#### Comptime policy

- `policy.isApproved(comptime name)` comptime FIPS-approved algorithm
  allow-list; gates consumer call sites; every string is the exact
  OpenSSL 3.x EVP fetch name confirmed against 3.6.2
- `policy.hashName`/`aeadName`/`kdfName`/`sigName`/`kemName` helpers

#### CI / tooling

- Dual-mode CI gate: `make test-shim` (std backend, no OpenSSL) and
  `make test-fips` (OpenSSL FIPS backend); `make test-dual` runs both;
  both must be green on every change
- `make deps` / `scripts/install-openssl-fips.sh`: builds and installs
  latest OpenSSL 3.x FIPS provider from source; runs `openssl fipsinstall`
- `scripts/verify-fips-provider.sh`: asserts `fips status: active` and
  that ML-KEM-768, ML-DSA-65, SLH-DSA-SHA2-128s are listed
- ThreadSanitizer gate: `zig build test -Dtsan`
- Integration and stress test suites with real crypto workloads
- Benchmark suite with per-algorithm scenarios (SHA-256 64B/8KB, HMAC,
  HKDF, AES-256-GCM 64B/1350B, Ed25519, ECDSA P-256, ML-KEM-768,
  CSPRNG 32B)

[Unreleased]: https://gitlab.com/devnw/zig/fips/-/compare/v0.1.0...HEAD
[0.1.0]: https://gitlab.com/devnw/zig/fips/-/releases/v0.1.0
