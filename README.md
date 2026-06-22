# fips

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/Zig-0.16.0+-orange.svg)](https://ziglang.org/)

A FIPS-140-3 / PQC crypto seam for Zig 0.16. Routes every security-relevant
crypto call through either the OpenSSL 3.x FIPS provider (`-Dfips=true`) or a
byte-for-byte API-compatible `std.crypto` backend (`-Dfips=false`, the default).

This is a **library** — it ships no CLI binary.

## Features

- **Dual-mode crypto seam**: the same `Hash`/`Mac`/`Kdf`/`Aead`/`Sig`/`Kem`/`Csprng` API compiles against either backend without call-site changes
- **FIPS-140-3 validated provider**: under `-Dfips=true` all crypto executes inside the OpenSSL 3.x FIPS module (AES-GCM, SHA-2/3, HMAC, HKDF/PBKDF2, ECDSA, RSA-PSS, Ed25519, ML-DSA, SLH-DSA, ML-KEM + hybrids)
- **Comptime approved-algorithm policy**: `policy.isApproved` rejects non-FIPS algorithms at compile time; runtime FIPS self-test via `assertActive()`/`ensureFips()`
- **PQC-ready**: ML-KEM-512/768/1024, ML-DSA-44/65/87, all 12 SLH-DSA variants, hybrid KEMs (`X25519MLKEM768`, etc.)
- **Constant-time utilities**: `secureZero(buf)` and `timingSafeEql(a, b)` on both backends
- **Non-fips mode is zero-dependency**: the shim path (`-Dfips=false`) needs only `std`; no OpenSSL, no `@cImport`, no network fetch

## Requirements

- **Zig 0.16.0** (both backends)
- **OpenSSL 3.x ≥ 3.5** with the FIPS provider — required only for `-Dfips=true`; install via `make deps`

## Installation

### Using the Zig package manager

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .fips = .{
        .url = "git+https://gitlab.com/devnw/zig/fips.git#v0.1.0",
        .hash = "fips-0.1.0-1wf3nbxWBgAp6yAk6cPRrF5l_U1tbblcVcN9xcjJDddy",
        .lazy = true,  // only fetched when -Dfips=true
    },
},
```

Then in your `build.zig` (wire the seam — see `templates/build_fips_snippet.zig`):

```zig
const fips = b.lazyDependency("fips", .{
    .target = target,
    .optimize = optimize,
});
// pass the fips module to your library/exe as "fips", and copy
// src/std_shim.zig + src/policy.zig + templates/crypto_backend.zig into
// your src/ so the non-fips path works without fetching anything.
```

Call sites import the seam, never `std.crypto` directly in a security path:

```zig
const crypto = @import("crypto_backend");
```

## Quick Start

AES-256-GCM round-trip (works identically with `-Dfips=false` and `-Dfips=true`):

```zig
const crypto = @import("crypto_backend");

const key = [_]u8{0x42} ** 32;
const nonce = [_]u8{0x24} ** 12;  // MUST be unique per (key, message)
const plaintext = "hello, FIPS";

var ciphertext: [plaintext.len]u8 = undefined;
var tag: [16]u8 = undefined;
try crypto.Aead.seal(.aes_256_gcm, &key, &nonce, "", plaintext, &ciphertext, &tag);

var recovered: [plaintext.len]u8 = undefined;
try crypto.Aead.open(.aes_256_gcm, &key, &nonce, "", &ciphertext, &tag, &recovered);
```

SHA-256 one-shot digest:

```zig
const crypto = @import("crypto_backend");
var out: [32]u8 = undefined;
try crypto.Hash.digest(.sha256, "hello", &out);
```

Startup FIPS self-test (call once at program entry under `-Dfips=true`):

```zig
const crypto = @import("crypto_backend");
crypto.assertActive();  // panics if the validated provider is not loaded
// or: try crypto.ensureFips();  // fallible variant
```

## Public API

Both backends (`fips` OpenSSL backend and `std_shim`) expose an identical surface:

| Symbol | Description |
|---|---|
| `Hash` | SHA-2/3 one-shot (`Hash.digest`) and streaming (`Hash.Stream`) |
| `Mac` | HMAC over an approved digest |
| `Kdf` | HKDF (SP 800-56C) + HKDF-Expand + PBKDF2 (SP 800-132) |
| `Aead` | AES-128-GCM / AES-256-GCM seal + open |
| `Sig` | ECDSA P-256/384/521, RSA-PSS/PKCS1, Ed25519, ML-DSA-44/65/87, all 12 SLH-DSA variants |
| `Kem` | ML-KEM-512/768/1024 + hybrid KEMs (`X25519MLKEM768`, etc.) |
| `Csprng` | SP 800-90A DRBG (fips) / OS entropy via `getrandom` (Linux; macOS/Windows runtime support deferred per docs/FIPS_SPECIFICATION.md) (shim) |
| `secureZero(buf: []u8)` | Constant-time memory wipe (non-FIPS governed, always available) |
| `timingSafeEql(a, b: []const u8) bool` | Constant-time byte-slice comparison |
| `assertActive()` | Panics if the validated FIPS module is not loaded (no-op in shim) |
| `ensureFips() !void` | Fallible variant of `assertActive` |
| `policy` | Comptime FIPS-approved algorithm allow-list (`policy.isApproved`) |
| `fips_enabled` | `comptime bool` — true under `-Dfips=true` |

## Building and Testing

```bash
make deps           # build + install latest OpenSSL 3.x FIPS provider to /usr/local/ssl
make test-shim      # non-fips backend only (no OpenSSL link); fast, no OPENSSL_CONF needed
make test-fips      # fips backend against the installed provider
make test-dual      # BOTH backends must be green (the spec gate)
make test           # unit + integration + stress (shim mode, no -Dfips)
zig build test -Dfips=true -Dopenssl_path=/usr/local/ssl --summary all
zig build test -Dtsan  # rebuild tests under ThreadSanitizer
zig build bench    # run benchmark suite
```

Build flags:

| Flag | Default | Description |
|---|---|---|
| `-Dfips` | `false` | Enable OpenSSL FIPS provider backend |
| `-Dopenssl_path=<dir>` | system | OpenSSL install prefix (CI uses `/usr/local/ssl`) |
| `-Dtsan` | `false` | Enable ThreadSanitizer |

## Benchmarks

```bash
make bench           # default suite -> benchmarks/results/latest.json
make bench-compare   # diff against benchmarks/results/baseline.json
make bench-micro     # micro-benchmarks
make scale-bench     # larger grid
```

The benchmark framework lives in `benchmarks/framework.zig` and is
library-agnostic. See [`benchmarks/README.md`](benchmarks/README.md) for the
JSON schema, how to register a new scenario, and how the CI regression gate is
wired.

## Documentation

See the [docs](docs/) directory for detailed documentation:

- [`docs/FIPS_SPECIFICATION.md`](docs/FIPS_SPECIFICATION.md) — workspace-wide FIPS-140-3 / FedRAMP spec
- [`docs/SEAM_CONTRACT.md`](docs/SEAM_CONTRACT.md) — cross-repo seam contract and parity invariant
- [`docs/PQC_ROADMAP.md`](docs/PQC_ROADMAP.md) — post-quantum cryptography roadmap

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for security policy, vulnerability reporting,
and cryptographic guidance (including AES-GCM nonce handling).

## License

This project is licensed under the Apache License 2.0 - see the
[LICENSE](LICENSE) file for details.
