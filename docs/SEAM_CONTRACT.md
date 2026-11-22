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
`fips_enabled`, `assertActive()`, `ensureFips()`, `policy`, `Hash`, `Mac`,
`Kdf` (incl. `hkdfExpand`), `Aead`, `Sig` (incl. `KeyPair.fromPublicBytes` /
`fromPrivateBytes`), `Kem` (incl. the pinned `Kem.EncapResult`), `Ecdh`,
`Csprng`, `secureZero`, `timingSafeEql`.

### Backend support matrix

| Symbol | fips (OpenSSL FIPS provider) | std_shim (non-fips) |
|---|---|---|
| Hash / Mac / Kdf / Aead / Csprng | full | full |
| `Kdf.hkdfExpand` | `EVP_KDF` HKDF EXPAND_ONLY | `std.crypto.kdf.hkdf.Hkdf.expand` |
| `Sig` Ed25519 / ECDSA P-256/P-384 | full incl. `from*Bytes` | full incl. `from*Bytes` |
| `Sig` ECDSA P-521 | full | `error.Unsupported` (std has no P-521) |
| `Sig` RSA | full (RSA-PSS / PKCS1) | `error.Unsupported` (std has no RSA) |
| `Sig` ML-DSA / SLH-DSA | full | `error.Unsupported` (fips-only) |
| `Kem` ML-KEM + approved hybrids, incl. public wire-key import/export | full | `error.Unsupported` (fips-only) |
| `Ecdh` P-256 / P-384 (SEC1 uncompressed import/export, derive) | full (KAS-ECC, approved indicator enforced) | full (`std.crypto.ecc`, same validation) |
| `secureZero(buf: []u8)` | `OPENSSL_cleanse` | `std.crypto.secureZero(u8, buf)` |
| `timingSafeEql(a, b: []const u8) bool` | `CRYPTO_memcmp` | constant-time `diff \|= x ^ y` loop |

### KEM peer public keys

`Kem.exportPublic(alg, *KeyPair, out) Error!usize` exports the provider's
encoded public key, without SPKI/PEM framing or private material.
`Kem.importPublic(alg, wire) Error!PublicKey` imports those bytes as an owned,
public-only key. Call `PublicKey.deinit()` when finished. Use
`Kem.encapsulatePublic(alg, *PublicKey, ct_out, ss_out) Error!EncapResult`
on the responding peer and the existing `Kem.decapsulate` with the original
`KeyPair` on the initiating peer. Both peers must select the same algorithm.

Before the provider sees a peer key, `importPublic` applies the FIPS 203
§7.2 encapsulation-key checks itself (`policy.kemEncapsulationKeyCheck`):
the type check (exact `policy.kemEncapsulationKeyLen(alg)` bytes) and the
modulus check (every packed t-hat coefficient < 3329, on the ML-KEM component
of a hybrid at its wire offset). `decapsulate` applies the §7.3 ciphertext
type check (`policy.kemCiphertextLen(alg)`). `policy.kemSharedSecretLen` and
the `policy.kem_max_*` constants size buffers. ACVP keyGen/encapDecap vectors
and unreduced-key negatives live in `src/testdata_pubkey_kat.txt`.

All operations reject unapproved algorithms, keys of a different algorithm,
and keys owned by another provider/lib context with `error.Unsupported`.
The provider checks the imported key's length and encoding. Malformed input
or insufficient output capacity returns `error.OpensslFailure`; callers
must fail closed. Policy, key-binding, and output-size rejection leave
outputs unchanged. Once a cryptographic operation starts, failure wipes its
shared-secret output region, which must never be consumed after an error.
Importing X25519 bytes does not prove that they admit a valid shared secret;
low-order inputs are rejected by encapsulation.

Do not reorder hybrid components. In particular, X25519MLKEM768 uses the
ML-KEM component first in its public key (1184 + 32 bytes), ciphertext
(1088 + 32 bytes), and shared secret (32 + 32 bytes). The P-256/P-384 hybrid
groups use their own provider-defined ordering. See
[the TLS hybrid group specification](https://datatracker.ietf.org/doc/html/draft-ietf-tls-ecdhe-mlkem-05)
and [OpenSSL's ML-KEM key encoding](https://docs.openssl.org/3.6/man7/EVP_PKEY-ML-KEM/).
The canonical non-FIPS shim exposes the same types and functions and returns
`error.Unsupported`, without an implicit fallback or OpenSSL dependency.

### ECDH (P-256 / P-384)

`Ecdh` is SP 800-56A Rev. 3 elliptic-curve Diffie-Hellman (the KAS-ECC
primitive) for callers that build their own hybrid combiner (for example
`p256 + ml_kem_768` through an SP 800-56C / SP 800-227 KDF) instead of the
provider's named `SecP*MLKEM*` groups.

- `Ecdh.generate(curve) Error!KeyPair`; `KeyPair.deinit()`.
- `Ecdh.exportPublic(curve, *KeyPair, out) Error!usize` writes the SEC1
  uncompressed point `0x04 || X || Y` (`policy.ecdhPublicLen`: 65 / 97 bytes).
- `Ecdh.importPublic(curve, sec1) Error!PublicKey` accepts only that exact
  length and the `0x04` prefix (compressed, hybrid and infinity encodings are
  `error.InvalidPublicKey`), then runs SP 800-56A §5.6.2.3.3 full public-key
  validation (`EVP_PKEY_public_check`: coordinates < p, on the curve, not the
  identity, order check). Off-curve points are `error.InvalidPublicKey`.
- `Ecdh.derive(curve, *KeyPair, *PublicKey, out) Error!usize` writes Z, the
  x-coordinate (`policy.ecdhSecretLen`: 32 / 48 bytes). Z is raw key
  material: pass it through an approved KDF. In the fips backend the derive
  re-validates the peer (`EVP_PKEY_derive_set_peer_ex(..., 1)`) and fails
  closed with `error.Unsupported` unless the exchange's
  `OSSL_EXCHANGE_PARAM_FIPS_APPROVED_INDICATOR` is 1.

Keys on the wrong curve, from another provider/lib context, or a curve the
policy does not approve are `error.Unsupported`; undersized outputs are
`error.OpensslFailure`. Every rejection leaves the output buffer unchanged.
NIST CAVP `KAS_ECC_CDH_PrimitiveTest` vectors (P-256 / P-384) are in
`src/testdata_pubkey_kat.txt`.

### Cross-backend caveats

These differences are by design. Consumers MUST NOT assume byte portability
across backends without explicitly accounting for them.

**(a) Public-key encoding differs by backend for ECDSA.**
The fips backend serialises ECDSA public keys as SPKI-DER via
`d2i_PUBKEY`; `std_shim` uses compressed SEC1. A public key byte-string
produced by one backend is NOT valid input for `fromPublicBytes` on the
other backend. Consumers that store or transmit public keys must re-import
them after switching `-Dfips` state.

**(b) The `alg` argument to `Sig.sign`/`Sig.verify` has different authority
by backend.** The fips backend uses `alg` authoritatively to select the
algorithm and the digest. The shim derives the algorithm from the stored
key type (the `alg` arg is advisory/informational there). Write call sites
that always supply the intended `alg` explicitly; do not rely on the shim's
key-driven dispatch as a substitute for a correct `alg` argument.

**(c) `Aead` nonce and tag sizes are fixed on both backends.**
`seal`/`open` require `nonce.len == 12` and `tag.len == 16`; both backends
return `error.OpensslFailure` on length violations. There is no negotiable
nonce or tag size.

**(d) `error.Unsupported` / `error.OpensslFailure` from a FIPS fetch MUST NOT
be treated as license to fall back to a non-FIPS algorithm (SEC-1016).**
These errors signal that the requested algorithm is unavailable or invalid
under the FIPS policy. A consumer that catches these errors and retries with
a non-approved primitive has violated the FIPS boundary. The correct response
is to propagate the error and fail closed.

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
