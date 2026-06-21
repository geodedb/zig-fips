<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2024-2026 CodePros -->

# Post-Quantum Cryptography Roadmap — DevNW Zig Workspace

- **Date:** 2026-06-20
- **Source of algorithms:** OpenSSL 3.x FIPS provider (built via `make deps`); nothing is re-implemented. A pure-Zig PQC project is documented as a fallback only (not built — OpenSSL covers the full suite incl. SLH-DSA).
- **PQC is available only under `-Dfips=true`.** The `std_shim` backend returns `error.Unsupported` for every ML-KEM/ML-DSA/SLH-DSA call (std.crypto has no PQC), which is the documented fips-only boundary.

## Algorithm inventory (from `fips.policy`)

| Family | Algorithms | API |
|---|---|---|
| KEM (ML-KEM) | ML-KEM-512, ML-KEM-768, ML-KEM-1024 | `fips.Kem` (`generate`/`encapsulate`/`decapsulate`) |
| KEM (hybrid) | X25519MLKEM768 (default), X448MLKEM1024, SecP256r1MLKEM768, SecP384r1MLKEM1024 | `fips.Kem` |
| Signature (ML-DSA) | ML-DSA-44, ML-DSA-65, ML-DSA-87 | `fips.Sig` (`generate`/`sign`/`verify`) |
| Signature (SLH-DSA) | all 12: SLH-DSA-SHA2-{128,192,256}{s,f}, SLH-DSA-SHAKE-{128,192,256}{s,f} | `fips.Sig` |

Status legend: **Available** = wrapped + KAT/interop-tested in the `fips`
package (foundation Tasks 8-9). **Planned** = consumer integration
tracked in that repo's plan. **N/A** = no PQC role.

## Per-library PQC status

| Library | PQC role | KEM | Signature | Status |
|---|---|---|---|---|
| `fips` | Provider wrappers + KATs/interop | ML-KEM 512/768/1024 + all 4 hybrids | ML-DSA 44/65/87 + all 12 SLH-DSA | Available |
| `tls` | Hybrid KEM in TLS 1.3 key schedule; ML-DSA cert/handshake sigs | X25519MLKEM768 (default) + SecP256r1MLKEM768 | ML-DSA-65 cert + handshake | Planned (hub) |
| `quic` | Inherits PQC handshake via `tls` | via tls | via tls | Planned |
| `wireguard` | Inherits hybrid KEM via `tls` patterns | X25519MLKEM768 | — | Planned |
| `auth` | PQC session/token signatures | — | ML-DSA-65 | Planned |
| `dns` | DNSSEC PQC signing | — | ML-DSA-65 (DNSSEC profile) | Planned |
| `zign` | Code-signing + cert profiles | — | ML-DSA-44/65/87 + SLH-DSA (long-term) | Planned |
| `hsm` | Token KEM/sign operations | ML-KEM-768 | ML-DSA-65 | Planned |
| `encrypted-fs` | Key wrapping (KEM) | ML-KEM-768 | — | Planned |
| `fle` | Field-level encryption key exchange | ML-KEM-768 | — | Planned |
| `uuid` | CSPRNG only (no PQC) | — | — | N/A |
| `oauth` / `oidc` | SHA/PKCE via seam (no PQC primitives) | — | (consumes ML-DSA via auth) | N/A / via auth |
| `fts-storage` / `wal` | HMAC via seam (no PQC) | — | — | N/A |
| `timeseries-storage` | AES-GCM via seam (no PQC) | — | — | N/A |
| `grpc-zig` | HMAC via seam (no PQC) | — | — | N/A |
| `mcp` | TLS transport (inherits via tls); SHA-1 dropped | via tls | via tls | Planned (via tls) |
| other no-crypto repos | matrix entry only | — | — | N/A |

## Hybrid KEM default rationale

`X25519MLKEM768` is the workspace default hybrid: it combines a
well-understood classical X25519 ECDH with ML-KEM-768, so a break of
either component alone does not compromise the shared secret. OpenSSL
exposes it as a single caseless KEM token (`X25519MLKEM768`), used
directly via `EVP_PKEY_encapsulate`/`decapsulate` in `fips.Kem`. This is
the IETF-aligned default hybrid group for TLS 1.3, so `tls` (and the
`quic`/`wireguard` consumers that inherit from it) standardize on it.

## Verification

- `fips` package: ML-KEM encap/decap shared-secret agreement +
  X25519MLKEM768 hybrid agreement; ML-DSA-65 and SLH-DSA-SHA2-128s
  sign→verify + tamper-detect; OpenSSL-CLI interop (foundation Tasks
  8-9).
- Consumers: PQC interop against OpenSSL CLI / NIST test vectors, plus
  dual-mode `make test-dual` (shim returns `error.Unsupported` for PQC;
  fips exercises the real algorithms).

## Fallback (documented, not built)

A `zig-template`-based pure-Zig PQC implementation is recorded as a
contingency if OpenSSL FIPS coverage ever regresses. It is NOT built:
OpenSSL 3.x already provides the full ML-KEM/ML-DSA/SLH-DSA suite under
the validated FIPS module.
