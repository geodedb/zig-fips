# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Ecdh` (ENG-7617): SP 800-56A Rev. 3 ECDH over P-256 / P-384 on both
  backends. SEC1 uncompressed export/import only; import runs full public-key
  validation (`EVP_PKEY_public_check`) and rejects compressed, hybrid,
  infinity and off-curve encodings with `error.InvalidPublicKey`. The fips
  backend's `derive` re-validates the peer and requires the provider's
  approved-mode indicator. `ECDH` joins the approved table;
  `policy.EcdhCurve`, `ecdhPublicLen`, `ecdhSecretLen`.
- `policy.kemEncapsulationKeyLen` / `kemCiphertextLen` / `kemSharedSecretLen`
  and `kem_max_*` constants, plus `policy.kemEncapsulationKeyCheck` (FIPS 203
  §7.2 type + modulus check).
- Known-answer tests: NIST ACVP ML-KEM-768/1024 keyGen (seed -> exported ek)
  and encapDecap (imported ek + m -> c, K), unreduced-ek negatives, NIST CAVP
  KAS-ECC-CDH P-256/P-384, and decapsulation cross-checked against std's
  independent ML-KEM (`src/testdata_pubkey_kat.txt`).

### Changed

- `Kem.importPublic` applies the FIPS 203 §7.2 checks in the seam before the
  provider; `Kem.exportPublic` requires the exact FIPS 203 length;
  `Kem.decapsulate` applies the §7.3 ciphertext length check. All three
  still report `error.OpensslFailure` as before.

## [0.1.3] - 2026-10-11

### Added

- KEM public-key wire format (SONNY-4793): `Kem.exportPublic` writes a key
  pair's provider-native public key, `Kem.importPublic` builds a public-only
  `Kem.PublicKey` from a peer's share, and `Kem.encapsulatePublic`
  encapsulates to it. TLS needs these to send a ClientHello key share and to
  accept a peer's share through the FIPS seam. The `std_shim` backend has the
  same API and returns `error.Unsupported`.

### Fixed

- KEM operations now check the approval policy, that the key's algorithm
  matches the one requested, and that the active FIPS provider context owns
  the key. Before this, a request for one variant could run against a key of
  another (SONNY-4793). When a cryptographic operation fails, its
  shared-secret output buffer is wiped.
- `X448MLKEM1024` is no longer advertised as approved: OpenSSL 3.6.5
  registers it with `fips=no`. Generate, encapsulate and decapsulate reject it
  before touching any buffer. The enum value and name mapping stay for source
  compatibility (SONNY-4782).
- `scripts/install-openssl-fips.sh` rejected authentic OpenSSL releases that
  were signed by a certified subkey. It now reads GnuPG's machine-readable
  status output (`scripts/verify-release-signature.sh`) and requires exactly
  one good signature whose primary fingerprint is pinned (SONNY-4781).

### Changed

- CI builds the pinned OpenSSL 3.6.5 FIPS provider once and hands it to
  every Linux build and test job as a verified archive. Native Windows and
  macOS jobs now provision OpenSSL themselves (SONNY-2770).
- Pre-commit hooks that run external tools now unset Git's
  repository-steering variables (SONNY-4778). The gitleaks exception for the
  public OpenSSL signing-key fingerprints applies only to the installer path
  (SONNY-4789).

## [0.1.2] - 2026-09-25

### Fixed

- `std_shim.zig` `randomBytes` (`Csprng.bytes`) compiled only on Linux: it
  called `std.posix.system.getrandom`, which is `void` on Windows and macOS.
  It now uses `std.Io.randomSecure` (getrandom on Linux, arc4random_buf on
  macOS, the CNG device on Windows), still fail-closed with no PRNG fallback
  and the same `error{OpensslFailure}` error set (SONNY-2763). Consumers that
  copy `std_shim.zig` verbatim must re-copy it.
- `zig build check -Dtarget=<other OS>` now compiles the OpenSSL-free shim,
  shim-parity and seam artifacts; the OpenSSL-linked backend is skipped for a
  cross-OS target unless `-Dopenssl_path` is set.

### Added

- `std_shim` in-file tests now run under `zig build test`, including an
  entropy test (non-zero output, two draws differ).

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
