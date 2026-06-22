// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
const std = @import("std");
const shim = @import("std_shim");

test "shim SHA2-256(\"abc\") matches FIPS KAT" {
    var out: [32]u8 = undefined;
    _ = try shim.Hash.digest(.sha256, "abc", &out);
    const expect = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    try std.testing.expectEqualSlices(u8, &expect, &out);
}
test "shim Stream chunked update equals one-shot SHA2-256 (same KAT as fips backend)" {
    const msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    var oneshot: [32]u8 = undefined;
    const n1 = try shim.Hash.digest(.sha256, msg, &oneshot);

    var s = try shim.Hash.Stream.init(.sha256);
    defer s.deinit();
    s.update(msg[0..1]);
    s.update(msg[1..10]);
    s.update(msg[10..40]);
    s.update(msg[40..]);
    var streamed: [32]u8 = undefined;
    const n2 = try s.final(&streamed);

    try std.testing.expectEqual(n1, n2);
    try std.testing.expectEqualSlices(u8, oneshot[0..n1], streamed[0..n2]);
    const expect = [_]u8{
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
    };
    try std.testing.expectEqualSlices(u8, &expect, &streamed);
}
test "shim Stream clone finalizes identically to its source (SHA2-384)" {
    var s = try shim.Hash.Stream.init(.sha384);
    defer s.deinit();
    s.update("hello, ");
    s.update("world");

    var clone = try s.clone();
    defer clone.deinit();

    var a: [48]u8 = undefined;
    var b: [48]u8 = undefined;
    const na = try s.final(&a);
    const nb = try clone.final(&b);
    try std.testing.expectEqual(na, nb);
    try std.testing.expectEqualSlices(u8, a[0..na], b[0..nb]);
}
test "shim Stream clone diverges after independent updates (SHA2-512)" {
    var s = try shim.Hash.Stream.init(.sha512);
    defer s.deinit();
    s.update("common-prefix");

    var clone = try s.clone();
    defer clone.deinit();

    s.update("-A");
    clone.update("-B");

    var a: [64]u8 = undefined;
    var b: [64]u8 = undefined;
    _ = try s.final(&a);
    _ = try clone.final(&b);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));

    var ref_a: [64]u8 = undefined;
    var ref_b: [64]u8 = undefined;
    _ = try shim.Hash.digest(.sha512, "common-prefix-A", &ref_a);
    _ = try shim.Hash.digest(.sha512, "common-prefix-B", &ref_b);
    try std.testing.expectEqualSlices(u8, &ref_a, &a);
    try std.testing.expectEqualSlices(u8, &ref_b, &b);
}
test "shim Stream supports SHA-3 (incremental == one-shot SHA3-256)" {
    const msg = "the quick brown fox";
    var s = try shim.Hash.Stream.init(.sha3_256);
    defer s.deinit();
    s.update(msg[0..4]);
    s.update(msg[4..]);
    var streamed: [32]u8 = undefined;
    const n = try s.final(&streamed);
    var oneshot: [32]u8 = undefined;
    _ = try shim.Hash.digest(.sha3_256, msg, &oneshot);
    try std.testing.expectEqualSlices(u8, oneshot[0..n], streamed[0..n]);
}
test "shim hkdfExpand matches RFC 5869 Test Case 1 (same KAT as fips backend)" {
    const prk = [_]u8{
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
        0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
    };
    const info = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };
    var okm: [42]u8 = undefined;
    try shim.Kdf.hkdfExpand(.sha256, &prk, &info, &okm);
    const expect = [_]u8{
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    };
    try std.testing.expectEqualSlices(u8, &expect, &okm);
}
test "shim hkdf (extract+expand) matches RFC 5869 Test Case 1" {
    const ikm = [_]u8{0x0b} ** 22;
    const salt = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
    const info = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };
    var okm: [42]u8 = undefined;
    try shim.Kdf.hkdf(.sha256, &ikm, &salt, &info, &okm);
    const expect = [_]u8{
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    };
    try std.testing.expectEqualSlices(u8, &expect, &okm);
}
test "shim HMAC-SHA256 matches RFC 4231 Test Case 2" {
    var out: [32]u8 = undefined;
    _ = try shim.Mac.hmac(.sha256, "Jefe", "what do ya want for nothing?", &out);
    const expect = [_]u8{
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };
    try std.testing.expectEqualSlices(u8, &expect, &out);
}
test "shim AES-256-GCM round-trip + tamper detect" {
    const key = [_]u8{0x42} ** 32;
    const iv = [_]u8{0x24} ** 12;
    const msg = "shim aead";
    var ct: [msg.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    try shim.Aead.seal(.aes_256_gcm, &key, &iv, "ad", msg, &ct, &tag);
    var pt: [msg.len]u8 = undefined;
    try shim.Aead.open(.aes_256_gcm, &key, &iv, "ad", &ct, &tag, &pt);
    try std.testing.expectEqualSlices(u8, msg, &pt);
    var bad = tag;
    bad[0] ^= 1;
    try std.testing.expectError(error.AuthFailed, shim.Aead.open(.aes_256_gcm, &key, &iv, "ad", &ct, &bad, &pt));
}
test "shim Ed25519 fromPublicBytes round-trips" {
    var kp = try shim.Sig.generate(.ed25519);
    defer kp.deinit();
    var sig: [64]u8 = undefined;
    const n = try shim.Sig.sign(.ed25519, &kp, "shim msg", &sig);
    var pub_raw: [32]u8 = undefined;
    const pn = try kp.publicBytes(&pub_raw);
    var pub_kp = try shim.Sig.KeyPair.fromPublicBytes(.ed25519, pub_raw[0..pn]);
    defer pub_kp.deinit();
    try shim.Sig.verify(.ed25519, &pub_kp, "shim msg", sig[0..n]);
}
test "shim ECDSA P-256 sign->verify round trip" {
    var kp = try shim.Sig.generate(.ecdsa_p256);
    defer kp.deinit();
    var sig: [80]u8 = undefined;
    const n = try shim.Sig.sign(.ecdsa_p256, &kp, "hello", &sig);
    try shim.Sig.verify(.ecdsa_p256, &kp, "hello", sig[0..n]);
}
test "shim RSA + PQC import report Unsupported (fips-only)" {
    try std.testing.expectError(error.Unsupported, shim.Sig.KeyPair.fromPublicBytes(.rsa_pss, "x"));
    try std.testing.expectError(error.Unsupported, shim.Sig.KeyPair.fromPrivateBytes(.ml_dsa_65, "x"));
    try std.testing.expectError(error.Unsupported, shim.Sig.generate(.rsa_pss));
    // New RSA import paths are fips-only in the shim.
    try std.testing.expectError(error.Unsupported, shim.Sig.KeyPair.fromRsaSpki("x"));
    try std.testing.expectError(error.Unsupported, shim.Sig.KeyPair.fromRsaComponents("n", "e"));
}
test "shim verifyRsa is fips-only (Unsupported)" {
    var kp = try shim.Sig.generate(.ecdsa_p256); // any keypair; RSA path is unconditional Unsupported
    defer kp.deinit();
    try std.testing.expectError(error.Unsupported, shim.Sig.verifyRsa(.pkcs1, .sha256, &kp, "m", "s"));
    try std.testing.expectError(error.Unsupported, shim.Sig.verifyRsa(.pss, .sha384, &kp, "m", "s"));
}
test "shim verifyEcdsa off-diagonal P-256/SHA-384 routes via std" {
    var kp = try shim.Sig.generate(.ecdsa_p256);
    defer kp.deinit();
    const msg = "shim off-diagonal p256/sha384";
    // Sign with the matching off-diagonal std scheme, then verify via seam.
    const Scheme = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P256, std.crypto.hash.sha2.Sha384);
    var pub_sec1: [33]u8 = undefined;
    const pn = try kp.publicBytes(&pub_sec1);
    // Re-derive a signing keypair under the off-diagonal scheme is not
    // possible from a public key; instead generate a fresh off-diagonal
    // keypair and verify against ITS public key imported into the shim.
    var seed: [Scheme.KeyPair.seed_length]u8 = undefined;
    try shim.Csprng.bytes(&seed);
    const okp = try Scheme.KeyPair.generateDeterministic(seed);
    const sig = try okp.sign(msg, null);
    var shim_pk = try shim.Sig.KeyPair.fromPublicBytes(.ecdsa_p256, &okp.public_key.toCompressedSec1());
    defer shim_pk.deinit();
    try shim.Sig.verifyEcdsa(.ecdsa_p256, .sha384, &shim_pk, msg, &sig.toBytes());
    try std.testing.expectError(error.VerifyFailed, shim.Sig.verifyEcdsa(.ecdsa_p256, .sha384, &shim_pk, "tampered", &sig.toBytes()));
    _ = pn;
}
test "shim verifyEcdsa rejects P-521 / SHA-3 / RSA as Unsupported" {
    var kp = try shim.Sig.generate(.ecdsa_p256);
    defer kp.deinit();
    try std.testing.expectError(error.Unsupported, shim.Sig.verifyEcdsa(.ecdsa_p521, .sha256, &kp, "m", "s"));
    try std.testing.expectError(error.Unsupported, shim.Sig.verifyEcdsa(.ecdsa_p256, .sha3_256, &kp, "m", "s"));
    try std.testing.expectError(error.Unsupported, shim.Sig.verifyEcdsa(.rsa_pss, .sha256, &kp, "m", "s"));
}
test "shim assertActive is a no-op" {
    shim.assertActive(); // must not panic when fips is off
}
test "shim PQC KEM reports Unsupported and EncapResult is the pinned type" {
    comptime {
        _ = shim.Kem.EncapResult;
    }
    try std.testing.expectError(error.Unsupported, shim.Kem.generate(.ml_kem_768));
}
test "shim Csprng yields distinct draws" {
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    try shim.Csprng.bytes(&a);
    try shim.Csprng.bytes(&b);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}
test "shim policy is the local canonical table" {
    try std.testing.expect(shim.policy.isApproved("AES-256-GCM"));
    try std.testing.expect(!shim.policy.isApproved("ChaCha20-Poly1305"));
}
test "shim secureZero wipes buffer" {
    var buf = [_]u8{0x7e} ** 32;
    shim.secureZero(&buf);
    try std.testing.expect(std.mem.allEqual(u8, &buf, 0));
}
test "shim timingSafeEql matches on equal, differs on any byte or length" {
    const a = [_]u8{ 1, 2, 3, 4 };
    try std.testing.expect(shim.timingSafeEql(&a, &a));
    const b = [_]u8{ 1, 2, 3, 5 };
    try std.testing.expect(!shim.timingSafeEql(&a, &b));
    try std.testing.expect(!shim.timingSafeEql(&a, a[0..3]));
}
