// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
const std = @import("std");
const ffi = @import("ffi.zig");
const c = ffi.c;
const policy = @import("policy.zig");
const provider = @import("provider.zig");

pub const Aead = struct {
    pub const Error = error{ Unsupported, AuthFailed, OpensslFailure };

    /// AEAD seal: encrypts `plaintext` into `ciphertext` (same length)
    /// and writes the authentication tag into `tag` (16 bytes for GCM).
    /// `nonce` is the 12-byte IV; `ad` is the associated data.
    pub fn seal(
        alg: policy.Aead,
        key: []const u8,
        nonce: []const u8,
        ad: []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: []u8,
    ) Error!void {
        provider.assertActive();
        const cipher = c.EVP_CIPHER_fetch(provider.libCtx(), policy.aeadName(alg), "fips=yes") orelse return error.Unsupported;
        defer c.EVP_CIPHER_free(cipher);
        const ctx = c.EVP_CIPHER_CTX_new() orelse return error.OpensslFailure;
        defer c.EVP_CIPHER_CTX_free(ctx);

        if (c.EVP_EncryptInit_ex2(ctx, cipher, null, null, null) != 1) return error.OpensslFailure;
        if (c.EVP_CIPHER_CTX_ctrl(ctx, c.EVP_CTRL_AEAD_SET_IVLEN, @intCast(nonce.len), null) != 1) return error.OpensslFailure;
        if (c.EVP_EncryptInit_ex2(ctx, null, key.ptr, nonce.ptr, null) != 1) return error.OpensslFailure;

        var outl: c_int = 0;
        if (ad.len != 0) {
            if (c.EVP_EncryptUpdate(ctx, null, &outl, ad.ptr, @intCast(ad.len)) != 1) return error.OpensslFailure;
        }
        if (plaintext.len != 0) {
            if (c.EVP_EncryptUpdate(ctx, ciphertext.ptr, &outl, plaintext.ptr, @intCast(plaintext.len)) != 1) return error.OpensslFailure;
        }
        var finl: c_int = 0;
        if (c.EVP_EncryptFinal_ex(ctx, ciphertext.ptr + @as(usize, @intCast(outl)), &finl) != 1) return error.OpensslFailure;
        if (c.EVP_CIPHER_CTX_ctrl(ctx, c.EVP_CTRL_AEAD_GET_TAG, @intCast(tag.len), tag.ptr) != 1) return error.OpensslFailure;
    }

    /// AEAD open: decrypts `ciphertext` into `plaintext` and verifies
    /// `tag`. Returns `error.AuthFailed` if the tag does not match.
    pub fn open(
        alg: policy.Aead,
        key: []const u8,
        nonce: []const u8,
        ad: []const u8,
        ciphertext: []const u8,
        tag: []const u8,
        plaintext: []u8,
    ) Error!void {
        provider.assertActive();
        const cipher = c.EVP_CIPHER_fetch(provider.libCtx(), policy.aeadName(alg), "fips=yes") orelse return error.Unsupported;
        defer c.EVP_CIPHER_free(cipher);
        const ctx = c.EVP_CIPHER_CTX_new() orelse return error.OpensslFailure;
        defer c.EVP_CIPHER_CTX_free(ctx);

        if (c.EVP_DecryptInit_ex2(ctx, cipher, null, null, null) != 1) return error.OpensslFailure;
        if (c.EVP_CIPHER_CTX_ctrl(ctx, c.EVP_CTRL_AEAD_SET_IVLEN, @intCast(nonce.len), null) != 1) return error.OpensslFailure;
        if (c.EVP_DecryptInit_ex2(ctx, null, key.ptr, nonce.ptr, null) != 1) return error.OpensslFailure;

        var outl: c_int = 0;
        if (ad.len != 0) {
            if (c.EVP_DecryptUpdate(ctx, null, &outl, ad.ptr, @intCast(ad.len)) != 1) return error.OpensslFailure;
        }
        if (ciphertext.len != 0) {
            if (c.EVP_DecryptUpdate(ctx, plaintext.ptr, &outl, ciphertext.ptr, @intCast(ciphertext.len)) != 1) return error.OpensslFailure;
        }
        // Set the expected tag before the final call.
        if (c.EVP_CIPHER_CTX_ctrl(ctx, c.EVP_CTRL_AEAD_SET_TAG, @intCast(tag.len), @constCast(tag.ptr)) != 1) return error.OpensslFailure;
        var finl: c_int = 0;
        // A non-1 final indicates the tag failed to authenticate.
        if (c.EVP_DecryptFinal_ex(ctx, plaintext.ptr + @as(usize, @intCast(outl)), &finl) != 1) return error.AuthFailed;
    }
};

test "KAT AES-256-GCM zero-key/zero-IV empty msg tag" {
    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 12;
    var ct: [0]u8 = undefined;
    var tag: [16]u8 = undefined;
    try Aead.seal(.aes_256_gcm, &key, &iv, &.{}, &.{}, &ct, &tag);
    const expect_tag = [_]u8{
        0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b,
    };
    try std.testing.expectEqualSlices(u8, &expect_tag, &tag);
}

test "AES-256-GCM round-trip + tamper detect" {
    const key = [_]u8{0x42} ** 32;
    const iv = [_]u8{0x24} ** 12;
    const ad = "header";
    const msg = "the quick brown fox";
    var ct: [msg.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    try Aead.seal(.aes_256_gcm, &key, &iv, ad, msg, &ct, &tag);

    var pt: [msg.len]u8 = undefined;
    try Aead.open(.aes_256_gcm, &key, &iv, ad, &ct, &tag, &pt);
    try std.testing.expectEqualSlices(u8, msg, &pt);

    // Tamper the tag: must fail to authenticate.
    var bad_tag = tag;
    bad_tag[0] ^= 0x01;
    try std.testing.expectError(error.AuthFailed, Aead.open(.aes_256_gcm, &key, &iv, ad, &ct, &bad_tag, &pt));
}

test "AES-128-GCM round-trip" {
    const key = [_]u8{0x11} ** 16;
    const iv = [_]u8{0x22} ** 12;
    const msg = "aes128";
    var ct: [msg.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    try Aead.seal(.aes_128_gcm, &key, &iv, &.{}, msg, &ct, &tag);
    var pt: [msg.len]u8 = undefined;
    try Aead.open(.aes_128_gcm, &key, &iv, &.{}, &ct, &tag, &pt);
    try std.testing.expectEqualSlices(u8, msg, &pt);
}
