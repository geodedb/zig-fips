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
    try s.update(msg[0..1]);
    try s.update(msg[1..10]);
    try s.update(msg[10..40]);
    try s.update(msg[40..]);
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
    try s.update("hello, ");
    try s.update("world");

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
    try s.update("common-prefix");

    var clone = try s.clone();
    defer clone.deinit();

    try s.update("-A");
    try clone.update("-B");

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
    try s.update(msg[0..4]);
    try s.update(msg[4..]);
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
test "shim KAT HMAC-SHA1 RFC 2202 Test Case 2 (key=Jefe)" {
    var out: [20]u8 = undefined;
    const n = try shim.Mac.hmacSha1("Jefe", "what do ya want for nothing?", &out);
    try std.testing.expectEqual(@as(usize, 20), n);
    const expect = [_]u8{
        0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74,
        0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79,
    };
    try std.testing.expectEqualSlices(u8, &expect, &out);
}
test "shim hmacSha1 rejects undersized output buffer" {
    var tiny: [19]u8 = undefined;
    try std.testing.expectError(error.OpensslFailure, shim.Mac.hmacSha1("key", "msg", &tiny));
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
test "shim Ed25519 fromPrivateBytes accepts a 32-byte seed and signs" {
    // geode stores the 32-byte Ed25519 SEED (not the 64-byte expanded
    // key). Build a std keypair from a known seed, import the SAME seed
    // through the seam, and confirm both produce verifiable signatures
    // over the same message (i.e. the seam rebuilt the identical key).
    const Ed = std.crypto.sign.Ed25519;
    var seed: [Ed.KeyPair.seed_length]u8 = undefined; // 32 bytes
    try shim.Csprng.bytes(&seed);
    const ref = try Ed.KeyPair.generateDeterministic(seed);

    var seam_kp = try shim.Sig.KeyPair.fromPrivateBytes(.ed25519, &seed);
    defer seam_kp.deinit();

    const msg = "ed25519 seed import";
    var sig: [64]u8 = undefined;
    const n = try shim.Sig.sign(.ed25519, &seam_kp, msg, &sig);
    try std.testing.expectEqual(@as(usize, 64), n);
    // The seam-imported key's public half must equal the reference key's.
    var seam_pub: [32]u8 = undefined;
    const pn = try seam_kp.publicBytes(&seam_pub);
    try std.testing.expectEqualSlices(u8, &ref.public_key.toBytes(), seam_pub[0..pn]);
    // And the reference key verifies the seam-produced signature.
    const s = Ed.Signature.fromBytes(sig[0..64].*);
    try s.verify(msg, ref.public_key);
}

test "shim fromEcPublicPoint + fromEcPrivateScalar round-trip P-256 and P-384" {
    // For each curve: derive a std keypair, export its raw scalar +
    // compressed SEC1 point, import each through the seam, sign with the
    // scalar-imported key, verify with the point-imported key.
    inline for (.{
        .{ shim.policy.SigAlg.ecdsa_p256, std.crypto.sign.ecdsa.EcdsaP256Sha256 },
        .{ shim.policy.SigAlg.ecdsa_p384, std.crypto.sign.ecdsa.EcdsaP384Sha384 },
    }) |t| {
        const alg = t[0];
        const S = t[1];
        var seed: [S.KeyPair.seed_length]u8 = undefined;
        try shim.Csprng.bytes(&seed);
        const ref = try S.KeyPair.generateDeterministic(seed);

        const scalar = ref.secret_key.toBytes(); // fixed-width 32B/48B
        const point = ref.public_key.toCompressedSec1(); // 33B/49B

        var priv_kp = try shim.Sig.KeyPair.fromEcPrivateScalar(alg, &scalar);
        defer priv_kp.deinit();
        var pub_kp = try shim.Sig.KeyPair.fromEcPublicPoint(alg, &point);
        defer pub_kp.deinit();

        const msg = "shim raw-ec import round-trip";
        var sig: [128]u8 = undefined;
        const n = try shim.Sig.sign(alg, &priv_kp, msg, &sig);
        try shim.Sig.verify(alg, &pub_kp, msg, sig[0..n]);
        try std.testing.expectError(error.VerifyFailed, shim.Sig.verify(alg, &pub_kp, "tampered", sig[0..n]));
    }
}

test "shim fromEcPublicPoint accepts an uncompressed SEC1 point" {
    // Verify the uncompressed (0x04-prefixed) encoding imports too.
    const S = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    var seed: [S.KeyPair.seed_length]u8 = undefined;
    try shim.Csprng.bytes(&seed);
    const ref = try S.KeyPair.generateDeterministic(seed);
    const point = ref.public_key.toUncompressedSec1(); // 65 bytes
    try std.testing.expectEqual(@as(u8, 0x04), point[0]);
    var pub_kp = try shim.Sig.KeyPair.fromEcPublicPoint(.ecdsa_p256, &point);
    defer pub_kp.deinit();
    // sign via the seam so the output is DER (matching the updated seam contract).
    var der_buf: [128]u8 = undefined;
    var seam_kp = try shim.Sig.KeyPair.fromEcPublicPoint(.ecdsa_p256, &point);
    defer seam_kp.deinit();
    // Use a fresh signing keypair from the same scalar so we get a DER sig.
    var priv_kp = try shim.Sig.KeyPair.fromEcPrivateScalar(.ecdsa_p256, &ref.secret_key.toBytes());
    defer priv_kp.deinit();
    const n = try shim.Sig.sign(.ecdsa_p256, &priv_kp, "uncompressed", &der_buf);
    try shim.Sig.verify(.ecdsa_p256, &pub_kp, "uncompressed", der_buf[0..n]);
}

test "shim fromEcPublicPoint / fromEcPrivateScalar reject non-P256/384 algs" {
    const fake_point = [_]u8{0x04} ++ [_]u8{0} ** 64;
    const fake_scalar = [_]u8{1} ** 32;
    inline for (.{ shim.policy.SigAlg.ecdsa_p521, shim.policy.SigAlg.ed25519, shim.policy.SigAlg.rsa_pss, shim.policy.SigAlg.ml_dsa_65 }) |alg| {
        try std.testing.expectError(error.Unsupported, shim.Sig.KeyPair.fromEcPublicPoint(alg, &fake_point));
        try std.testing.expectError(error.Unsupported, shim.Sig.KeyPair.fromEcPrivateScalar(alg, &fake_scalar));
    }
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
    const raw_sig = try okp.sign(msg, null);
    // Convert the raw r||s signature to DER so verifyEcdsa (which now
    // expects DER matching the FIPS backend contract) can parse it.
    var der_buf: [Scheme.Signature.der_encoded_length_max]u8 = undefined;
    const der = raw_sig.toDer(&der_buf);
    var shim_pk = try shim.Sig.KeyPair.fromPublicBytes(.ecdsa_p256, &okp.public_key.toCompressedSec1());
    defer shim_pk.deinit();
    try shim.Sig.verifyEcdsa(.ecdsa_p256, .sha384, &shim_pk, msg, der);
    try std.testing.expectError(error.VerifyFailed, shim.Sig.verifyEcdsa(.ecdsa_p256, .sha384, &shim_pk, "tampered", der));
    _ = pn;
}
test "shim verifyEcdsa rejects P-521 / SHA-3 / RSA as Unsupported" {
    var kp = try shim.Sig.generate(.ecdsa_p256);
    defer kp.deinit();
    try std.testing.expectError(error.Unsupported, shim.Sig.verifyEcdsa(.ecdsa_p521, .sha256, &kp, "m", "s"));
    try std.testing.expectError(error.Unsupported, shim.Sig.verifyEcdsa(.ecdsa_p256, .sha3_256, &kp, "m", "s"));
    try std.testing.expectError(error.Unsupported, shim.Sig.verifyEcdsa(.rsa_pss, .sha256, &kp, "m", "s"));
}
test "shim ecPublicPoint exports compressed SEC1 for P-256 (33B) and P-384 (49B)" {
    // For each curve: generate a keypair, call ecPublicPoint, verify size
    // and 0x02/0x03 prefix, re-import via fromEcPublicPoint, sign with
    // the original key, verify with the re-imported public key.
    inline for (.{
        .{ shim.policy.SigAlg.ecdsa_p256, @as(usize, 33) },
        .{ shim.policy.SigAlg.ecdsa_p384, @as(usize, 49) },
    }) |t| {
        const alg = t[0];
        const expected_len = t[1];

        var kp = try shim.Sig.generate(alg);
        defer kp.deinit();

        // Export compressed point.
        var point_buf: [49]u8 = undefined;
        const plen = try kp.ecPublicPoint(alg, &point_buf);
        try std.testing.expectEqual(expected_len, plen);
        try std.testing.expect(point_buf[0] == 0x02 or point_buf[0] == 0x03);

        // Re-import the compressed point and verify a signature.
        var pub_kp = try shim.Sig.KeyPair.fromEcPublicPoint(alg, point_buf[0..plen]);
        defer pub_kp.deinit();

        const msg = "shim ecPublicPoint compressed SEC1 export";
        var sig_buf: [128]u8 = undefined;
        const n = try shim.Sig.sign(alg, &kp, msg, &sig_buf);
        try shim.Sig.verify(alg, &pub_kp, msg, sig_buf[0..n]);
        try std.testing.expectError(error.VerifyFailed, shim.Sig.verify(alg, &pub_kp, "tampered", sig_buf[0..n]));
    }
}

test "shim ecPublicPoint rejects non-EC algs and short output buffers" {
    var ed_kp = try shim.Sig.generate(.ed25519);
    defer ed_kp.deinit();
    var buf49: [49]u8 = undefined;
    try std.testing.expectError(error.Unsupported, ed_kp.ecPublicPoint(.ed25519, &buf49));

    // Buffer too short returns OpensslFailure.
    var ec_kp = try shim.Sig.generate(.ecdsa_p256);
    defer ec_kp.deinit();
    var buf16: [16]u8 = undefined;
    try std.testing.expectError(error.OpensslFailure, ec_kp.ecPublicPoint(.ecdsa_p256, &buf16));
}

test "shim ecPublicPoint: wrong-curve alg (P-256 alg on P-384 key) returns Unsupported" {
    // A P-384 key with .ecdsa_p256 alg hits the inner-type mismatch branch
    // (self.inner is .p384 / .p384_pub, not .p256 / .p256_pub), returning
    // error.Unsupported — matching the FIPS backend's curve-match guard.
    var kp = try shim.Sig.generate(.ecdsa_p384);
    defer kp.deinit();
    var buf: [49]u8 = undefined;
    try std.testing.expectError(error.Unsupported, kp.ecPublicPoint(.ecdsa_p256, &buf));
}

test "shim ecPublicPoint: fromEcPublicPoint key (public-only) exports correctly" {
    // Import a compressed point, then re-export via ecPublicPoint — proves
    // public-only KeyPairs (inner = .p256_pub / .p384_pub) work with ecPublicPoint.
    const S = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    var seed: [S.KeyPair.seed_length]u8 = undefined;
    try shim.Csprng.bytes(&seed);
    const ref = try S.KeyPair.generateDeterministic(seed);
    const compressed_ref = ref.public_key.toCompressedSec1();

    var pub_kp = try shim.Sig.KeyPair.fromEcPublicPoint(.ecdsa_p256, &compressed_ref);
    defer pub_kp.deinit();
    var reexport: [33]u8 = undefined;
    const rlen = try pub_kp.ecPublicPoint(.ecdsa_p256, &reexport);
    try std.testing.expectEqual(@as(usize, 33), rlen);
    try std.testing.expectEqualSlices(u8, &compressed_ref, reexport[0..rlen]);
}

test "shim ecPublicPoint cross-backend parity: std matches toCompressedSec1 directly" {
    // This test proves the 0x02/0x03 sign-bit convention in ecPublicPoint is
    // identical to toCompressedSec1() for the same key material — i.e. the
    // shim's ecPublicPoint is simply a copyOut-wrapped toCompressedSec1, so
    // both backends produce the same bytes from the same raw scalar.
    // Also asserts the exported compressed point round-trips through
    // fromEcPublicPoint + sign + verify (byte-equality proof).
    inline for (.{
        .{ shim.policy.SigAlg.ecdsa_p256, std.crypto.sign.ecdsa.EcdsaP256Sha256 },
        .{ shim.policy.SigAlg.ecdsa_p384, std.crypto.sign.ecdsa.EcdsaP384Sha384 },
    }) |t| {
        const alg = t[0];
        const S = t[1];

        var seed: [S.KeyPair.seed_length]u8 = undefined;
        try shim.Csprng.bytes(&seed);
        const ref = try S.KeyPair.generateDeterministic(seed);

        // Import the scalar through the seam.
        const scalar = ref.secret_key.toBytes();
        var seam_kp = try shim.Sig.KeyPair.fromEcPrivateScalar(alg, &scalar);
        defer seam_kp.deinit();

        // Export via ecPublicPoint (the seam API).
        var seam_compressed: [49]u8 = undefined;
        const clen = try seam_kp.ecPublicPoint(alg, &seam_compressed);

        // The reference is toCompressedSec1() directly from std.
        const ref_compressed = ref.public_key.toCompressedSec1();
        try std.testing.expectEqual(ref_compressed.len, clen);
        try std.testing.expectEqualSlices(u8, &ref_compressed, seam_compressed[0..clen]);

        // Round-trip: import the compressed point, sign with original, verify.
        var pub_kp = try shim.Sig.KeyPair.fromEcPublicPoint(alg, seam_compressed[0..clen]);
        defer pub_kp.deinit();
        const msg = "cross-backend parity round-trip";
        var sig_buf: [128]u8 = undefined;
        const n = try shim.Sig.sign(alg, &seam_kp, msg, &sig_buf);
        try shim.Sig.verify(alg, &pub_kp, msg, sig_buf[0..n]);
        try std.testing.expectError(error.VerifyFailed, shim.Sig.verify(alg, &pub_kp, "tampered", sig_buf[0..n]));
    }
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

// -------------------------------------------------------------------------
// DER parity: ECDSA sign/verify must use DER on the std_shim backend,
// matching the FIPS/OpenSSL backend contract (EVP_DigestSign / EVP_DigestVerify
// both produce and consume ASN.1 DER-encoded SEQUENCE { INTEGER r, INTEGER s }).
//
// This test proves three things:
//   1. sign() emits DER (first byte 0x30, variable length ≤ der_encoded_length_max).
//   2. verify() accepts the DER that sign() emits (round-trip).
//   3. verify() rejects raw r||s bytes (proving it is NOT raw-compatible).
//
// A consumer (e.g. geode) that calls DER→raw conversion before verifying
// under the FIPS backend must work identically under the shim backend,
// because both backends now use DER as the canonical wire format.
// -------------------------------------------------------------------------
test "shim ECDSA P-256 sign emits DER and verify accepts it (parity with FIPS backend)" {
    const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    var kp = try shim.Sig.generate(.ecdsa_p256);
    defer kp.deinit();

    const msg = "cross-backend DER parity P-256";
    var sig_buf: [128]u8 = undefined;
    const n = try shim.Sig.sign(.ecdsa_p256, &kp, msg, &sig_buf);
    const der = sig_buf[0..n];

    // 1. First byte of a DER SEQUENCE is 0x30.
    try std.testing.expectEqual(@as(u8, 0x30), der[0]);
    // 2. Length is within the DER max (72 bytes for P-256).
    try std.testing.expect(n <= P256.Signature.der_encoded_length_max);
    // 3. Verify accepts the DER output.
    try shim.Sig.verify(.ecdsa_p256, &kp, msg, der);
    // 4. Tampered message is rejected.
    try std.testing.expectError(error.VerifyFailed, shim.Sig.verify(.ecdsa_p256, &kp, "tampered", der));
    // 5. Raw r||s is rejected (proves we are NOT in raw mode).
    const raw_sig = try P256.KeyPair.generateDeterministic(
        blk: {
            var seed: [P256.KeyPair.seed_length]u8 = undefined;
            try shim.Csprng.bytes(&seed);
            break :blk seed;
        },
    );
    const raw_bytes = (try raw_sig.sign(msg, null)).toBytes();
    try std.testing.expectError(error.VerifyFailed, shim.Sig.verify(.ecdsa_p256, &kp, msg, &raw_bytes));
}

test "shim ECDSA P-384 sign emits DER and verify accepts it (parity with FIPS backend)" {
    const P384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
    var kp = try shim.Sig.generate(.ecdsa_p384);
    defer kp.deinit();

    const msg = "cross-backend DER parity P-384";
    var sig_buf: [128]u8 = undefined;
    const n = try shim.Sig.sign(.ecdsa_p384, &kp, msg, &sig_buf);
    const der = sig_buf[0..n];

    // 1. First byte of a DER SEQUENCE is 0x30.
    try std.testing.expectEqual(@as(u8, 0x30), der[0]);
    // 2. Length is within the DER max (104 bytes for P-384).
    try std.testing.expect(n <= P384.Signature.der_encoded_length_max);
    // 3. Round-trip verify.
    try shim.Sig.verify(.ecdsa_p384, &kp, msg, der);
    try std.testing.expectError(error.VerifyFailed, shim.Sig.verify(.ecdsa_p384, &kp, "tampered", der));
    // 4. Raw r||s (96 bytes) is rejected.
    const raw_sig = try P384.KeyPair.generateDeterministic(
        blk: {
            var seed: [P384.KeyPair.seed_length]u8 = undefined;
            try shim.Csprng.bytes(&seed);
            break :blk seed;
        },
    );
    const raw_bytes = (try raw_sig.sign(msg, null)).toBytes();
    try std.testing.expectError(error.VerifyFailed, shim.Sig.verify(.ecdsa_p384, &kp, msg, &raw_bytes));
}

test "SONNY-4793 shim public KEM API stays unsupported without touching outputs" {
    var kp: shim.Kem.KeyPair = .{};
    defer kp.deinit();
    var pk: shim.Kem.PublicKey = .{};
    defer pk.deinit();
    var out = [_]u8{0xa5} ** 32;
    var ss = [_]u8{0x5a} ** 32;
    try std.testing.expectError(error.Unsupported, shim.Kem.importPublic(.x25519_ml_kem_768, &.{}));
    try std.testing.expectError(error.Unsupported, shim.Kem.exportPublic(.x25519_ml_kem_768, &kp, &out));
    try std.testing.expectError(error.Unsupported, shim.Kem.encapsulatePublic(.x25519_ml_kem_768, &pk, &out, &ss));
    try std.testing.expect(std.mem.allEqual(u8, &out, 0xa5));
    try std.testing.expect(std.mem.allEqual(u8, &ss, 0x5a));
}

// ENG-7617: shim Ecdh mirrors the fips backend's SEC1/validation contract.
fn hexArr(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "ENG-7617 shim Ecdh KAT: NIST CAVP KAS_ECC_CDH P-256/P-384 count 0" {
    const cases = .{
        .{
            shim.policy.EcdhCurve.p256,
            "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
            "04ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b23028af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141",
            "04700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
            "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b",
        },
        .{
            shim.policy.EcdhCurve.p384,
            "3cc3122a68f0d95027ad38c067916ba0eb8c38894d22e1b15618b6818a661774ad463b205da88cf699ab4d43c9cf98a1",
            "049803807f2f6d2fd966cdd0290bd410c0190352fbec7ff6247de1302df86f25d34fe4a97bef60cff548355c015dbb3e5fba26ca69ec2f5b5d9dad20cc9da711383a9dbe34ea3fa5a2af75b46502629ad54dd8b7d73a8abb06a3a3be47d650cc99",
            "04a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272734466b400091adbf2d68c58e0c50066ac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915ed0905a32b060992b468c64766fc8437a",
            "5f9d29dc5e31a163060356213669c8ce132e22f57c9a04f40ba7fcead493b457e5621e766c40a2e3d4d6a04b25e533f1",
        },
    };
    inline for (cases) |case| {
        const curve = case[0];
        const d = hexArr(case[1]);
        const q_own = hexArr(case[2]);
        const q_peer = hexArr(case[3]);
        const z_want = hexArr(case[4]);
        var kp: shim.Ecdh.KeyPair = .{ .curve = curve, .sk = @splat(0), .pk = @splat(0) };
        defer kp.deinit();
        @memcpy(kp.sk[0..d.len], &d);
        @memcpy(kp.pk[0..q_own.len], &q_own);
        var peer = try shim.Ecdh.importPublic(curve, &q_peer);
        defer peer.deinit();
        var z: [shim.policy.ecdh_max_secret_len]u8 = undefined;
        const n = try shim.Ecdh.derive(curve, &kp, &peer, &z);
        try std.testing.expectEqualSlices(u8, &z_want, z[0..n]);
    }
}

test "ENG-7617 shim Ecdh two-party agreement and malformed-point rejection" {
    inline for (.{ shim.policy.EcdhCurve.p256, shim.policy.EcdhCurve.p384 }) |curve| {
        const n = comptime shim.policy.ecdhPublicLen(curve);
        const fl = (n - 1) / 2;
        var a = try shim.Ecdh.generate(curve);
        defer a.deinit();
        var b = try shim.Ecdh.generate(curve);
        defer b.deinit();
        var wa: [n]u8 = undefined;
        var wb: [n]u8 = undefined;
        try std.testing.expectEqual(n, try shim.Ecdh.exportPublic(curve, &a, &wa));
        _ = try shim.Ecdh.exportPublic(curve, &b, &wb);
        var pa = try shim.Ecdh.importPublic(curve, &wa);
        var pb = try shim.Ecdh.importPublic(curve, &wb);
        var za: [48]u8 = undefined;
        var zb: [48]u8 = undefined;
        const la = try shim.Ecdh.derive(curve, &a, &pb, &za);
        const lb = try shim.Ecdh.derive(curve, &b, &pa, &zb);
        try std.testing.expectEqual(shim.policy.ecdhSecretLen(curve), la);
        try std.testing.expectEqualSlices(u8, za[0..la], zb[0..lb]);

        var w: [n + 1]u8 = undefined;
        try std.testing.expectError(error.InvalidPublicKey, shim.Ecdh.importPublic(curve, wa[0 .. n - 1]));
        @memcpy(w[0..n], &wa);
        w[n] = 0;
        try std.testing.expectError(error.InvalidPublicKey, shim.Ecdh.importPublic(curve, w[0 .. n + 1]));
        var comp: [fl + 1]u8 = undefined;
        comp[0] = 0x02 | (wa[n - 1] & 1);
        @memcpy(comp[1..], wa[1 .. 1 + fl]);
        try std.testing.expectError(error.InvalidPublicKey, shim.Ecdh.importPublic(curve, &comp));
        try std.testing.expectError(error.InvalidPublicKey, shim.Ecdh.importPublic(curve, &[_]u8{0x00}));
        @memset(w[0..n], 0);
        w[0] = 0x04;
        try std.testing.expectError(error.InvalidPublicKey, shim.Ecdh.importPublic(curve, w[0..n]));
        @memcpy(w[0..n], &wa);
        w[n - 1] ^= 0x01;
        try std.testing.expectError(error.InvalidPublicKey, shim.Ecdh.importPublic(curve, w[0..n]));
        @memcpy(w[0..n], &wa);
        @memset(w[1 .. 1 + fl], 0xff);
        try std.testing.expectError(error.InvalidPublicKey, shim.Ecdh.importPublic(curve, w[0..n]));

        // Curve binding and output bounds leave buffers untouched.
        var out = [_]u8{0xa5} ** 97;
        const other: shim.policy.EcdhCurve = if (curve == .p256) .p384 else .p256;
        try std.testing.expectError(error.Unsupported, shim.Ecdh.exportPublic(other, &a, &out));
        try std.testing.expectError(error.OpensslFailure, shim.Ecdh.exportPublic(curve, &a, out[0 .. n - 1]));
        try std.testing.expectError(error.OpensslFailure, shim.Ecdh.derive(curve, &a, &pb, out[0 .. la - 1]));
        try std.testing.expect(std.mem.allEqual(u8, &out, 0xa5));
    }
}
