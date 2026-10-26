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
    return publicFingerprint(&secp256k1.compressedPublicKey(&public_key));
}

fn publicFingerprint(compressed: *const [secp256k1.compressed_length]u8) u32 {
    const digest = hash.hash160(compressed);
    return std.mem.readInt(u32, digest[0..4], .big);
}

/// An extended public key as BIP-32 serializes one, without the 4-byte version that names its network and script
/// (xpub, tpub, zpub: a chain's choice, made above the engine): depth (1), the parent's fingerprint (4, big-endian),
/// the child number (4, big-endian), the chain code (32) and the compressed public key (33).
pub const extended_public_length = 74;

pub const ExtendedPublicKey = [extended_public_length]u8;

fn serializeExtendedPublic(depth: u8, parent: u32, index: u32, chain_code: *const [32]u8, key: *const [33]u8) ExtendedPublicKey {
    var out: ExtendedPublicKey = undefined;
    out[0] = depth;
    std.mem.writeInt(u32, out[1..5], parent, .big);
    std.mem.writeInt(u32, out[5..9], index, .big);
    out[9..41].* = chain_code.*;
    out[41..74].* = key.*;
    return out;
}

/// The extended public key at `path`: what a watch-only wallet derives the addresses of an account from, and
/// what hardware wallets share to pair. The master's (depth 0) is refused: below it lies every non-hardened key of
/// the wallet. The chain code is not secret alone, but with it any non-hardened child's private key gives away
/// its parent's: the engine never exports a private key, which is what keeps that true here (docs/adr/0007).
pub fn extendedPublic(seed: []const u8, path: *const path_mod.Path) Error!ExtendedPublicKey {
    const steps = path.steps();
    if (steps.len == 0) return error.InvalidPath;

    var current = try master(seed);
    defer current.zero();
    var parent: u32 = 0;
    for (steps, 0..) |index, position| {
        if (position + 1 == steps.len) parent = try fingerprint(&current.key);
        const next = try child(&current, index);
        current.zero();
        current = next;
    }

    const public_key = try secp256k1.publicKeyFromPrivate(&current.key);
    return serializeExtendedPublic(
        @intCast(steps.len),
        parent,
        steps[steps.len - 1],
        &current.chain_code,
        &secp256k1.compressedPublicKey(&public_key),
    );
}

/// CKDpub: the non-hardened child `index` of an extended public key. I = HMAC-SHA512(c, serP(K) || ser32(i)), and
/// the child is (point(IL) + K, IR). A hardened index has no public derivation (`InvalidPath`); an IL not below n,
/// or a child at infinity, is BIP-32's invalid key and fails (`DerivationFailed`) rather than skip an index.
pub fn publicChild(parent: *const ExtendedPublicKey, index: u32) Error!ExtendedPublicKey {
    if (index >= path_mod.hardened or parent[0] == std.math.maxInt(u8)) return error.InvalidPath;

    const parent_key = parent[41..74];
    var public_key = try secp256k1.parsePublicKey(parent_key);
    var data: [37]u8 = undefined;
    data[0..33].* = parent_key.*;
    std.mem.writeInt(u32, data[33..37], index, .big);
    const output = hash.hmacSha512(parent[9..41], &data);
    try secp256k1.addTweakToPublicKey(&public_key, output[0..32]);

    return serializeExtendedPublic(
        parent[0] + 1,
        publicFingerprint(parent_key),
        index,
        output[32..64],
        &secp256k1.compressedPublicKey(&public_key),
    );
}

/// The extended public key at `path` below `parent`, every step non-hardened: "m/0/5" is the parent's sixth
/// receiving key. "m" is the parent itself.
pub fn publicDerive(parent: *const ExtendedPublicKey, path: *const path_mod.Path) Error!ExtendedPublicKey {
    // The key must be a key: an extended key whose point does not parse is refused even with nothing to derive.
    _ = try secp256k1.parsePublicKey(parent[41..74]);
    var current = parent.*;
    for (path.steps()) |index| current = try publicChild(&current, index);
    return current;
}

const testing = std.testing;

test "seed length bounds" {
    try testing.expectError(error.InvalidLength, master(&[_]u8{0} ** 15));
    try testing.expectError(error.InvalidLength, master(&[_]u8{0} ** 65));
    var key = try master(&[_]u8{0} ** 16);
    key.zero();
}

test "an extended public key: the private derivation's key and chain code, its depth, parent and number" {
    const seed = [_]u8{7} ** 32;
    const path = try path_mod.parse("m/44'/60'/0'");
    const extended = try extendedPublic(&seed, &path);
    const private = try derive(&seed, &path);
    const parent = try derive(&seed, &try path_mod.parse("m/44'/60'"));
    const public_key = try secp256k1.publicKeyFromPrivate(&private.key);

    try testing.expectEqual(@as(u8, 3), extended[0]);
    try testing.expectEqual(try fingerprint(&parent.key), std.mem.readInt(u32, extended[1..5], .big));
    try testing.expectEqual(@as(u32, 0x8000_0000), std.mem.readInt(u32, extended[5..9], .big));
    try testing.expectEqualSlices(u8, &private.chain_code, extended[9..41]);
    try testing.expectEqualSlices(u8, &secp256k1.compressedPublicKey(&public_key), extended[41..74]);
    try testing.expectError(error.InvalidPath, extendedPublic(&seed, &try path_mod.parse("m")));
}

test "public derivation agrees with private derivation, and refuses hardened steps" {
    const seed = [_]u8{9} ** 64;
    const account = try extendedPublic(&seed, &try path_mod.parse("m/84'/0'/0'"));
    const derived = try publicDerive(&account, &try path_mod.parse("m/1/7"));
    try testing.expectEqualSlices(u8, &try extendedPublic(&seed, &try path_mod.parse("m/84'/0'/0'/1/7")), &derived);
    try testing.expectEqualSlices(u8, &account, &try publicDerive(&account, &try path_mod.parse("m")));
    try testing.expectError(error.InvalidPath, publicDerive(&account, &try path_mod.parse("m/0'")));

    var broken = account;
    broken[41] = 0x05;
    try testing.expectError(error.InvalidPublicKey, publicDerive(&broken, &try path_mod.parse("m/0")));
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
