//! Ed25519 (RFC 8032) through Zig's standard library.
//!
//! The secret is the 32-byte RFC 8032 seed (SLIP-0010 derives exactly this), never the expanded scalar. A key is
//! kept as a `KeyPair`: the seed with its public key beside it, computed once, so a signature costs one scalar
//! multiplication rather than two. Signing is deterministic. Verification is strict: a non-canonical S or an
//! encoding that is not a point is `InvalidSignature` / `InvalidPublicKey`, a small-order public key is
//! `InvalidPublicKey`, and a well-formed signature that does not match is `VerificationFailed`.

const std = @import("std");

const secure = @import("../core/secure.zig");
const Error = @import("../core/status.zig").Error;

const Ed25519 = std.crypto.sign.Ed25519;

pub const seed_length = Ed25519.KeyPair.seed_length;
pub const public_key_length = Ed25519.PublicKey.encoded_length;
pub const signature_length = Ed25519.Signature.encoded_length;

pub const Seed = [seed_length]u8;

/// The seed, then its public key: the layout of Zig's `SecretKey`, and what the vault stores for an Ed25519 key.
pub const KeyPair = [Ed25519.SecretKey.encoded_length]u8;

/// The one place the public key is computed from the seed.
pub fn keyPair(seed: *const Seed) Error!KeyPair {
    var pair = Ed25519.KeyPair.generateDeterministic(seed.*) catch return error.InvalidPrivateKey;
    defer secure.zeroValue(&pair.secret_key);
    return pair.secret_key.toBytes();
}

pub fn publicKey(pair: *const KeyPair) [public_key_length]u8 {
    return pair[seed_length..].*;
}

/// Signs with the public key the pair carries, as RFC 8032 hashes it into the signature: built by `keyPair`, it is
/// the seed's own.
pub fn sign(pair: *const KeyPair, message: []const u8) Error![signature_length]u8 {
    var std_pair: Ed25519.KeyPair = .{
        .public_key = Ed25519.PublicKey.fromBytes(publicKey(pair)) catch return error.InvalidPrivateKey,
        .secret_key = try Ed25519.SecretKey.fromBytes(pair.*),
    };
    defer secure.zeroValue(&std_pair.secret_key);
    const signature = std_pair.sign(message, null) catch return error.Internal;
    return signature.toBytes();
}

pub fn verify(
    public_key_bytes: *const [public_key_length]u8,
    message: []const u8,
    signature_bytes: *const [signature_length]u8,
) Error!void {
    const public_key = Ed25519.PublicKey.fromBytes(public_key_bytes.*) catch return error.InvalidPublicKey;
    const signature = Ed25519.Signature.fromBytes(signature_bytes.*);
    signature.verify(message, public_key) catch |err| return switch (err) {
        // The public key: the identity, or another point of small order.
        error.IdentityElement, error.WeakPublicKey => error.InvalidPublicKey,
        // The signature: S not below the group order, or R not the encoding of a point.
        error.NonCanonical, error.InvalidEncoding => error.InvalidSignature,
        error.SignatureVerificationFailed => error.VerificationFailed,
    };
}

const testing = std.testing;

test "a key pair is the seed, then the public key Zig derives from it" {
    const seed: Seed = @splat(9);
    const pair = try keyPair(&seed);
    const expected = try Ed25519.KeyPair.generateDeterministic(seed);
    try testing.expectEqualSlices(u8, &seed, pair[0..seed_length]);
    try testing.expectEqualSlices(u8, &expected.public_key.toBytes(), &publicKey(&pair));
    try testing.expectEqualSlices(u8, &(try expected.sign("hello", null)).toBytes(), &try sign(&pair, "hello"));
}

test "sign and verify round-trip; a changed message or signature fails" {
    const pair = try keyPair(&@as(Seed, @splat(9)));
    const public_key = publicKey(&pair);
    const signature = try sign(&pair, "hello");
    try verify(&public_key, "hello", &signature);
    try testing.expectError(error.VerificationFailed, verify(&public_key, "hellO", &signature));

    // The low byte of S: still canonical, no longer the signature.
    var tampered_s = signature;
    tampered_s[32] ^= 1;
    try testing.expectError(error.VerificationFailed, verify(&public_key, "hello", &tampered_s));
}

test "an R that encodes no point is a malformed signature" {
    const pair = try keyPair(&@as(Seed, @splat(9)));
    const public_key = publicKey(&pair);
    var signature = try sign(&pair, "hello");
    // y = 2 is not the y-coordinate of any point on edwards25519.
    @memset(signature[0..32], 0);
    signature[0] = 2;
    try testing.expectError(error.InvalidSignature, verify(&public_key, "hello", &signature));
}

test "a non-canonical S (S >= L) is refused" {
    const pair = try keyPair(&@as(Seed, @splat(9)));
    const public_key = publicKey(&pair);
    var signature = try sign(&pair, "hello");
    // S occupies the second half, little-endian; all ones is far above the group order L.
    @memset(signature[32..64], 0xFF);
    try testing.expectError(error.InvalidSignature, verify(&public_key, "hello", &signature));
}

test "small-order public keys are refused" {
    const pair = try keyPair(&@as(Seed, @splat(9)));
    const signature = try sign(&pair, "hello");
    // The identity point (0, 1) has order 1.
    var identity: [32]u8 = @splat(0);
    identity[0] = 1;
    try testing.expectError(error.InvalidPublicKey, verify(&identity, "hello", &signature));
    // (0, -1) has order 2.
    var order_two: [32]u8 = @splat(0xFF);
    order_two[0] = 0xEC;
    order_two[31] = 0x7F;
    try testing.expectError(error.InvalidPublicKey, verify(&order_two, "hello", &signature));
}
