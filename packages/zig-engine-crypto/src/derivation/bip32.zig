//! BIP-32 private derivation for secp256k1, from a seed down a path.
//!
//! Master: HMAC-SHA512("Bitcoin seed", seed). Child i of (k, c): I = HMAC-SHA512(c, data) with data
//! 0x00 || k || ser32(i) for a hardened i and serP(point(k)) || ser32(i) otherwise; the child is
//! (IL + k mod n, IR). An IL not below n, or a zero child, is BIP-32's invalid key; the spec's remedy is to
//! skip to the next index, which would silently change the path the caller asked for, so this fails instead
//! (`DerivationFailed`, probability about 2^-127 per step).

const std = @import("std");

const hash = @import("../hash.zig");
const path_mod = @import("path.zig");
const secp256k1 = @import("../curves/secp256k1.zig");
const secure = @import("../core/secure.zig");
const Error = @import("../core/status.zig").Error;

const master_key = "Bitcoin seed";

/// A private key and its chain code. Secret: zero it when done.
pub const ExtendedKey = struct {
    key: secp256k1.PrivateKey,
    chain_code: [32]u8,

    pub fn zero(self: *ExtendedKey) void {
        secure.zeroValue(self);
    }

    fn fromHmac(output: *[64]u8) ExtendedKey {
        defer secure.zero(output);
        return .{ .key = output[0..32].*, .chain_code = output[32..64].* };
    }
};

pub fn master(seed: []const u8) Error!ExtendedKey {
    if (seed.len < 16 or seed.len > 64) return error.InvalidLength;
    var output = hash.hmacSha512(master_key, seed);
    var extended = ExtendedKey.fromHmac(&output);
    secp256k1.validatePrivateKey(&extended.key) catch {
        extended.zero();
        return error.DerivationFailed;
    };
    return extended;
}

pub fn child(parent: *const ExtendedKey, index: u32) Error!ExtendedKey {
    var data: [37]u8 = undefined;
    defer secure.zero(&data);
    if (index >= path_mod.hardened) {
        data[0] = 0;
        data[1..33].* = parent.key;
    } else {
        const public_key = try secp256k1.publicKeyFromPrivate(&parent.key);
        data[0..33].* = secp256k1.compressedPublicKey(&public_key);
    }
    std.mem.writeInt(u32, data[33..37], index, .big);

    var output = hash.hmacSha512(&parent.chain_code, &data);
    var derived = ExtendedKey.fromHmac(&output);
    // IL is the tweak; the child key is IL + k.
    var tweak = derived.key;
    defer secure.zero(&tweak);
    derived.key = parent.key;
    secp256k1.addTweak(&derived.key, &tweak) catch |err| {
        derived.zero();
        return err;
    };
    return derived;
}

pub fn derive(seed: []const u8, path: *const path_mod.Path) Error!ExtendedKey {
    var current = try master(seed);
    for (path.steps()) |index| {
        const next = child(&current, index) catch |err| {
            current.zero();
            return err;
        };
        current.zero();
        current = next;
    }
    return current;
}

/// The fingerprint BIP-32 gives a key: the first four bytes of HASH160 of its compressed public key.
pub fn fingerprint(key: *const secp256k1.PrivateKey) Error!u32 {
    const public_key = try secp256k1.publicKeyFromPrivate(key);
    const digest = hash.hash160(&secp256k1.compressedPublicKey(&public_key));
    return std.mem.readInt(u32, digest[0..4], .big);
}

const testing = std.testing;

test "seed length bounds" {
    try testing.expectError(error.InvalidLength, master(&[_]u8{0} ** 15));
    try testing.expectError(error.InvalidLength, master(&[_]u8{0} ** 65));
    var key = try master(&[_]u8{0} ** 16);
    key.zero();
}

test "derive matches step-by-step derivation" {
    const seed = [_]u8{7} ** 32;
    const path = try path_mod.parse("m/44'/60'/0'/0/3");
    const direct = try derive(&seed, &path);

    var manual = try master(&seed);
    for (path.steps()) |index| manual = try child(&manual, index);
    try testing.expectEqualSlices(u8, &manual.key, &direct.key);
    try testing.expectEqualSlices(u8, &manual.chain_code, &direct.chain_code);
}
