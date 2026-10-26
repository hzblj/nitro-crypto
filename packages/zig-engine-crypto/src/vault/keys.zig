//! What can be done with secrets behind handles: seeds from mnemonics, keys derived, generated or imported,
//! their public keys, and signatures. Each operation copies the one secret it needs out of the vault, works on
//! the copy, and zeroes it before returning.

const std = @import("std");

const bip32 = @import("../derivation/bip32.zig");
const bip39 = @import("../derivation/bip39.zig");
const ed25519 = @import("../curves/ed25519.zig");
const entropy = @import("../os/entropy.zig");
const handles = @import("handles.zig");
const path_mod = @import("../derivation/path.zig");
const secp256k1 = @import("../curves/secp256k1.zig");
const secure = @import("../core/secure.zig");
const slip10 = @import("../derivation/slip10.zig");
const Error = @import("../core/status.zig").Error;

const Handle = handles.Handle;
const Kind = handles.Kind;

pub const Vault = handles.Table(handles.capacity);

/// The `NC_SCHEME_*` ids.
pub const Scheme = enum(u32) {
    bip32_secp256k1 = 1,
    slip10_ed25519 = 2,

    pub fn fromInt(value: u32) Error!Scheme {
        return std.enums.fromInt(Scheme, value) orelse error.InvalidArgument;
    }
};

/// The `NC_CURVE_*` ids.
pub const Curve = enum(u32) {
    secp256k1 = 1,
    ed25519 = 2,

    pub fn fromInt(value: u32) Error!Curve {
        return std.enums.fromInt(Curve, value) orelse error.InvalidArgument;
    }
};

/// A secret copied out of the vault, on the stack, zeroed by `zero`.
const Secret = struct {
    bytes: [handles.max_secret_length]u8 = undefined,
    entry: handles.Entry = undefined,

    fn load(vault: *Vault, handle: Handle) Error!Secret {
        var secret: Secret = .{};
        secret.entry = vault.read(handle, &secret.bytes) catch |err| {
            secret.zero();
            return err;
        };
        return secret;
    }

    fn loadKind(vault: *Vault, handle: Handle, kind: Kind) Error!Secret {
        var secret = try load(vault, handle);
        if (secret.entry.kind != kind) {
            secret.zero();
            return error.InvalidHandle;
        }
        return secret;
    }

    fn slice(secret: *const Secret) []const u8 {
        return secret.bytes[0..secret.entry.length];
    }

    /// The secret as the array its kind stores: `secp256k1.PrivateKey`, `ed25519.KeyPair`.
    fn as(secret: *const Secret, comptime T: type) *const T {
        std.debug.assert(secret.entry.length == @sizeOf(T));
        return secret.bytes[0..@sizeOf(T)];
    }

    fn zero(secret: *Secret) void {
        secure.zero(&secret.bytes);
    }
};

// --- seeds -----------------------------------------------------------------------------------------------

pub fn seedFromMnemonic(vault: *Vault, mnemonic: []const u8, passphrase: []const u8) Error!Handle {
    try bip39.validate(mnemonic);
    return storeSeed(vault, mnemonic, passphrase);
}

/// A seed from a mnemonic made of fresh OS entropy. The mnemonic exists only on this stack frame.
pub fn seedGenerate(vault: *Vault, words: u32, passphrase: []const u8) Error!Handle {
    const length = bip39.entropyLength(words) catch return error.InvalidArgument;
    var bytes: [32]u8 = undefined;
    defer secure.zero(&bytes);
    try entropy.fill(bytes[0..length]);

    var sentence: bip39.Sentence = .{};
    defer sentence.zero();
    try bip39.fromEntropy(bytes[0..length], &sentence);
    return storeSeed(vault, sentence.slice(), passphrase);
}

fn storeSeed(vault: *Vault, mnemonic: []const u8, passphrase: []const u8) Error!Handle {
    var seed: [bip39.seed_length]u8 = undefined;
    defer secure.zero(&seed);
    try bip39.toSeed(mnemonic, passphrase, &seed);
    return vault.insert(.seed, &seed);
}

pub fn seedFingerprint(vault: *Vault, seed_handle: Handle) Error!u32 {
    var seed = try Secret.loadKind(vault, seed_handle, .seed);
    defer seed.zero();
    var master = try bip32.master(seed.slice());
    defer master.zero();
    return bip32.fingerprint(&master.key);
}

// --- keys ------------------------------------------------------------------------------------------------

pub fn derive(vault: *Vault, seed_handle: Handle, scheme: Scheme, path_text: []const u8) Error!Handle {
    const path = try path_mod.parse(path_text);
    var seed = try Secret.loadKind(vault, seed_handle, .seed);
    defer seed.zero();
    return switch (scheme) {
        .bip32_secp256k1 => {
            var extended = try bip32.derive(seed.slice(), &path);
            defer extended.zero();
            return storeKey(vault, .secp256k1, &extended.key);
        },
        .slip10_ed25519 => {
            var extended = try slip10.derive(seed.slice(), &path);
            defer extended.zero();
            return storeKey(vault, .ed25519, &extended.key);
        },
    };
}

/// A secp256k1 key from 32 random bytes is invalid with probability 2^-128; past this many draws the
/// generator is broken, not unlucky.
const max_generation_attempts = 8;

pub fn generate(vault: *Vault, curve: Curve) Error!Handle {
    var secret: [32]u8 = undefined;
    defer secure.zero(&secret);
    for (0..max_generation_attempts) |_| {
        try entropy.fill(&secret);
        return storeKey(vault, curve, &secret) catch |err| switch (err) {
            error.InvalidPrivateKey => continue,
            else => err,
        };
    }
    return error.EntropyUnavailable;
}

/// Raw secret material in: a secp256k1 private key, or an Ed25519 seed. There is no way back out.
pub fn import(vault: *Vault, curve: Curve, secret: []const u8) Error!Handle {
    if (secret.len != 32) return error.InvalidLength;
    return storeKey(vault, curve, secret[0..32]);
}

/// Every key enters the vault here: a valid secp256k1 private key, or an Ed25519 seed with its public key.
fn storeKey(vault: *Vault, curve: Curve, secret: *const [32]u8) Error!Handle {
    switch (curve) {
        .secp256k1 => {
            try secp256k1.validatePrivateKey(secret);
            return vault.insert(.secp256k1_key, secret);
        },
        .ed25519 => {
            var pair = try ed25519.keyPair(secret);
            defer secure.zero(&pair);
            return vault.insert(.ed25519_key, &pair);
        },
    }
}

pub fn publicKey(vault: *Vault, key_handle: Handle, compressed: bool, out: []u8) Error!usize {
    var secret = try Secret.load(vault, key_handle);
    defer secret.zero();
    switch (secret.entry.kind) {
        .secp256k1_key => {
            const public_key = try secp256k1.publicKeyFromPrivate(secret.as(secp256k1.PrivateKey));
            return secp256k1.serializePublicKey(&public_key, compressed, out);
        },
        .ed25519_key => {
            if (out.len < ed25519.public_key_length) return error.BufferTooSmall;
            out[0..ed25519.public_key_length].* = ed25519.publicKey(secret.as(ed25519.KeyPair));
            return ed25519.public_key_length;
        },
        .seed => return error.InvalidHandle,
    }
}

/// secp256k1: `data` is a 32-byte digest, 65 bytes out. Ed25519: `data` is the message, 64 bytes out.
pub fn sign(vault: *Vault, key_handle: Handle, data: []const u8, out: []u8) Error!usize {
    var secret = try Secret.load(vault, key_handle);
    defer secret.zero();
    switch (secret.entry.kind) {
        .secp256k1_key => {
            if (data.len != secp256k1.digest_length) return error.InvalidLength;
            if (out.len < secp256k1.recoverable_signature_length) return error.BufferTooSmall;
            const signature = try secp256k1.sign(secret.as(secp256k1.PrivateKey), data[0..secp256k1.digest_length]);
            out[0..signature.len].* = signature;
            return signature.len;
        },
        .ed25519_key => {
            if (out.len < ed25519.signature_length) return error.BufferTooSmall;
            const signature = try ed25519.sign(secret.as(ed25519.KeyPair), data);
            out[0..signature.len].* = signature;
            return signature.len;
        },
        .seed => return error.InvalidHandle,
    }
}

const testing = std.testing;

const abandon = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

test "a seed from a mnemonic derives keys of both schemes, and destroying everything empties the vault" {
    var vault: Vault = .{};
    const seed = try seedFromMnemonic(&vault, abandon, "");
    try testing.expectEqual(Kind.seed, try vault.kindOf(seed));

    const ethereum = try derive(&vault, seed, .bip32_secp256k1, "m/44'/60'/0'/0/0");
    const solana = try derive(&vault, seed, .slip10_ed25519, "m/44'/501'/0'/0'");
    try testing.expectEqual(Kind.secp256k1_key, try vault.kindOf(ethereum));
    try testing.expectEqual(Kind.ed25519_key, try vault.kindOf(solana));
    try testing.expectEqual(@as(u32, 3), vault.count());

    for ([_]Handle{ seed, ethereum, solana }) |handle| try vault.destroy(handle);
    try testing.expectEqual(@as(u32, 0), vault.count());
}

test "a mnemonic with a bad checksum stores nothing" {
    var vault: Vault = .{};
    const bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    try testing.expectError(error.MnemonicChecksum, seedFromMnemonic(&vault, bad, ""));
    try testing.expectEqual(@as(u32, 0), vault.count());
}

test "generated seeds differ, and odd word counts are refused" {
    var vault: Vault = .{};
    const a = try seedGenerate(&vault, 12, "");
    const b = try seedGenerate(&vault, 24, "");
    try testing.expect(try seedFingerprint(&vault, a) != try seedFingerprint(&vault, b));
    try testing.expectError(error.InvalidArgument, seedGenerate(&vault, 13, ""));
}

test "handles are used only for what they hold" {
    var vault: Vault = .{};
    const seed = try seedFromMnemonic(&vault, abandon, "");
    const key = try generate(&vault, .ed25519);
    var out: [65]u8 = undefined;
    try testing.expectError(error.InvalidHandle, sign(&vault, seed, "x", &out));
    try testing.expectError(error.InvalidHandle, publicKey(&vault, seed, true, &out));
    try testing.expectError(error.InvalidHandle, derive(&vault, key, .bip32_secp256k1, "m/0"));
    try testing.expectError(error.InvalidHandle, seedFingerprint(&vault, key));
}

test "derive refuses bad paths without storing anything" {
    var vault: Vault = .{};
    const seed = try seedFromMnemonic(&vault, abandon, "");
    try testing.expectError(error.InvalidPath, derive(&vault, seed, .bip32_secp256k1, "m/44'/60'/x"));
    try testing.expectError(error.InvalidPath, derive(&vault, seed, .slip10_ed25519, "m/44'/501'/0'/0"));
    try testing.expectEqual(@as(u32, 1), vault.count());
}

test "import validates and signs; secp256k1 wants a 32-byte digest" {
    var vault: Vault = .{};
    try testing.expectError(error.InvalidLength, import(&vault, .secp256k1, &([_]u8{1} ** 31)));
    try testing.expectError(error.InvalidPrivateKey, import(&vault, .secp256k1, &([_]u8{0} ** 32)));
    const key = try import(&vault, .secp256k1, &([_]u8{1} ** 32));
    var out: [65]u8 = undefined;
    try testing.expectError(error.InvalidLength, sign(&vault, key, "short", &out));
    var short: [64]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, sign(&vault, key, &([_]u8{0} ** 32), &short));
    try testing.expectEqual(@as(usize, 65), try sign(&vault, key, &([_]u8{0} ** 32), &out));

    var public_key: [65]u8 = undefined;
    try testing.expectEqual(@as(usize, 33), try publicKey(&vault, key, true, &public_key));
    try testing.expectEqual(@as(usize, 65), try publicKey(&vault, key, false, &public_key));
}

test "generate produces distinct valid keys on both curves" {
    var vault: Vault = .{};
    var first: [65]u8 = undefined;
    var second: [65]u8 = undefined;
    for ([_]Curve{ .secp256k1, .ed25519 }) |curve| {
        const a = try generate(&vault, curve);
        const b = try generate(&vault, curve);
        const length = try publicKey(&vault, a, true, &first);
        _ = try publicKey(&vault, b, true, &second);
        try testing.expect(!std.mem.eql(u8, first[0..length], second[0..length]));
    }
}
