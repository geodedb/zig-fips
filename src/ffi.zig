// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Raw OpenSSL 3.x FFI surface. Every other module in `fips` reaches
//! libcrypto/libssl through `ffi.c`. Linking + include paths are wired
//! by `src/link.zig` (consumed by build.zig).
pub const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/provider.h");
    @cInclude("openssl/core_names.h");
    @cInclude("openssl/params.h");
    @cInclude("openssl/param_build.h"); // OSSL_PARAM_BLD_* (RSA from n,e import)
    @cInclude("openssl/bn.h"); // BN_bin2bn (JWKS big-endian RSA components)
    @cInclude("openssl/rand.h");
    @cInclude("openssl/kdf.h"); // EVP_KDF_*, EVP_KDF_HKDF_MODE_*
    @cInclude("openssl/decoder.h"); // OSSL_DECODER_* (key import)
    @cInclude("openssl/x509.h"); // d2i_PUBKEY / d2i_PrivateKey / i2d_PrivateKey
    @cInclude("openssl/err.h");
    @cInclude("stdlib.h"); // getenv (OPENSSL_CONF lookup)
    @cInclude("openssl/crypto.h"); // OPENSSL_cleanse, CRYPTO_memcmp
});

const std = @import("std");

test "openssl version is 3.x and >= 3.5 (PQC) and EVP symbols resolve" {
    // OPENSSL_VERSION_NUMBER major nibble == 3.
    try std.testing.expect((c.OPENSSL_VERSION_NUMBER >> 28) == 3);
    // ML-KEM/ML-DSA/SLH-DSA require OpenSSL >= 3.5.0; encoded as
    // 0x30500000 in the MNNFFPPS layout. Hard-require it here so the
    // build fails loud on an older libcrypto.
    try std.testing.expect(c.OPENSSL_VERSION_NUMBER >= 0x30500000);
    // A representative EVP fetch must be callable (null ctx, null props).
    const md = c.EVP_MD_fetch(null, "SHA2-256", null);
    try std.testing.expect(md != null);
    c.EVP_MD_free(md);
}
