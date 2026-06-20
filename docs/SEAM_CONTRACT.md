<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2024-2026 CodePros -->

# FIPS Seam Contract

This is the shared contract the 12 downstream `devnw/zig` crypto plans
consume. The `fips` package exposes a single comptime seam that routes
every security-relevant crypto call through either the OpenSSL FIPS-140-3
provider (`-Dfips=true`) or a byte-for-byte API-compatible `std.crypto`
backend (`-Dfips=false`, the default).

## 1. The three canonical copy-verbatim files

Consumers copy **three** files into their own `src/`:

| File | Source of truth | Role |
|------|-----------------|------|
| `crypto_backend.zig` | `fips/templates/crypto_backend.zig` | the seam — selects backend at comptime |
| `std_shim.zig` | `fips/src/std_shim.zig` | non-fips backend (std.crypto) |
| `policy.zig` | `fips/src/policy.zig` | comptime FIPS-approved allow-list |

`std_shim.zig` imports the **local** sibling `policy.zig`
(`@import("policy.zig")`). Keep `std_shim.zig` + `policy.zig`
**byte-identical** to the canonical sources in this repo.

Because the non-fips path is just these three local files + `std`, a
default build needs **no `fips` dependency** — no lazy fetch, no OpenSSL,
no `@cImport`. The lazy `fips` dependency is fetched **only** when
`-Dfips=true`.

Call sites import the seam module (`crypto_backend`); they must **never**
reach `std.crypto`/`std.hash` directly in a security path (the `zlint`
fips rule enforces this).

## 2. Public surface (pinned)

The seam re-exports these names; both the `fips` backend and `std_shim`
implement them identically (see the spec's "Shared contract"):
`fips_enabled`, `assertActive()`, `policy`, `Hash`, `Mac`, `Kdf` (incl.
`hkdfExpand`), `Aead`, `Sig` (incl. `KeyPair.fromPublicBytes` /
`fromPrivateBytes`), `Kem` (incl. the pinned `Kem.EncapResult`),
`Csprng`.

### Backend support matrix

| Symbol | fips (OpenSSL FIPS provider) | std_shim (non-fips) |
|---|---|---|
| Hash / Mac / Kdf / Aead / Csprng | full | full |
| `Kdf.hkdfExpand` | `EVP_KDF` HKDF EXPAND_ONLY | `std.crypto.kdf.hkdf.Hkdf.expand` |
| `Sig` Ed25519 / ECDSA P-256/P-384 | full incl. `from*Bytes` | full incl. `from*Bytes` |
| `Sig` ECDSA P-521 | full | `error.Unsupported` (std has no P-521) |
| `Sig` RSA | full (RSA-PSS / PKCS1) | `error.Unsupported` (std has no RSA) |
| `Sig` ML-DSA / SLH-DSA | full | `error.Unsupported` (fips-only) |
| `Kem` ML-KEM + hybrids | full | `error.Unsupported` (fips-only) |

## 3. GAP-0020 — the single-`build_options` dedup rule

Materialize **exactly one** `build_options` module via `b.addOptions()` +
`.createModule()` and pass that single `*std.Build.Module` to every
compile unit and to the lazy `fips` dependency. **Never** call
`.createModule()` on a second options instance reachable from the same
file graph — Zig 0.16 then errors with
`file '...' exists in modules 'build_options' and 'build_options0'`. See
`docs/GAP-0020-module-dedup.md` and `templates/build_fips_snippet.zig`.

## 4. RSA / PQC in NON-fips mode (escape hatch)

`std_shim` returns `error.Unsupported` for RSA, ECDSA P-521, and all PQC.
A consumer that genuinely needs those in **non-fips** mode does **not**
modify `std_shim.zig`. Instead it replaces the seam's
`@import("std_shim")` with a **consumer-owned** backend module that
delegates to `std_shim` for std-covered algorithms and to the consumer's
existing RSA/PQC implementation for the rest. This keeps the fips path
pure-OpenSSL while letting non-fips consumers retain RSA/PQC without
depending on `fips`.
