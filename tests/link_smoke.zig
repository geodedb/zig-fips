// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
const std = @import("std");
const ffi = @import("ffi");
const c = ffi.c;

// Proves libcrypto is LINKED (not just headers present): calls a real
// exported symbol and a self-test-relevant fetch. A missing -lcrypto
// fails this at link time with `undefined symbol: OpenSSL_version`.
test "libcrypto links and resolves runtime symbols" {
    const v = c.OpenSSL_version(c.OPENSSL_VERSION);
    try std.testing.expect(v != null);
    try std.testing.expect(std.mem.indexOf(u8, std.mem.span(v), "OpenSSL 3.") != null);
    const cph = c.EVP_CIPHER_fetch(null, "AES-256-GCM", null);
    try std.testing.expect(cph != null);
    c.EVP_CIPHER_free(cph);
}
