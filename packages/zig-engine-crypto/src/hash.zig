//! Hashes and HMAC by algorithm id, as the C ABI addresses them. SHA-2 is hash/sha2.zig's: on the processor's
//! instructions wherever it has them.

const std = @import("std");

const Error = @import("core/status.zig").Error;
const Ripemd160 = @import("hash/ripemd160.zig").Ripemd160;
const sha2 = @import("hash/sha2.zig");

const Sha256 = sha2.Sha256;
const Sha512 = sha2.Sha512;
const Keccak256 = std.crypto.hash.sha3.Keccak256;
/// What a key-sealed backup's HKDF builds on (backup/backup.zig).
pub const HmacSha256 = std.crypto.auth.hmac.Hmac(Sha256);

/// What BIP-32, SLIP-0010 and BIP-39's PBKDF2 build on.
pub const HmacSha512 = std.crypto.auth.hmac.Hmac(Sha512);

/// The `NC_HASH_*` ids. Keccak-256 is Ethereum's (padding 0x01), not NIST SHA3-256 (padding 0x06).
pub const Algorithm = enum(u32) {
    sha256 = 1,
    sha512 = 2,
    keccak256 = 3,
    ripemd160 = 4,

    pub fn fromInt(value: u32) Error!Algorithm {
        return std.enums.fromInt(Algorithm, value) orelse error.InvalidArgument;
    }

    pub fn length(algorithm: Algorithm) usize {
        return switch (algorithm) {
            inline else => |tag| Hasher(tag).digest_length,
        };
    }
};

fn Hasher(comptime algorithm: Algorithm) type {
    return switch (algorithm) {
        .sha256 => Sha256,
        .sha512 => Sha512,
        .keccak256 => Keccak256,
        .ripemd160 => Ripemd160,
    };
}

/// Writes the digest of `data` into the front of `out`.
pub fn digest(algorithm: Algorithm, data: []const u8, out: []u8) Error!void {
    if (out.len < algorithm.length()) return error.BufferTooSmall;
    switch (algorithm) {
        inline else => |tag| {
            const H = Hasher(tag);
            H.hash(data, out[0..H.digest_length], .{});
        },
    }
}

pub fn sha256(data: []const u8) [Sha256.digest_length]u8 {
    var out: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &out, .{});
    return out;
}

/// RIPEMD-160 of SHA-256: what BIP-32 fingerprints a key with.
pub fn hash160(data: []const u8) [Ripemd160.digest_length]u8 {
    var inner = sha256(data);
    var out: [Ripemd160.digest_length]u8 = undefined;
    Ripemd160.hash(&inner, &out, .{});
    return out;
}

/// HMAC over SHA-256 or SHA-512, into the front of `out`.
pub fn hmac(algorithm: Algorithm, key: []const u8, data: []const u8, out: []u8) Error!void {
    switch (algorithm) {
        .sha256 => {
            if (out.len < HmacSha256.mac_length) return error.BufferTooSmall;
            HmacSha256.create(out[0..HmacSha256.mac_length], data, key);
        },
        .sha512 => {
            if (out.len < HmacSha512.mac_length) return error.BufferTooSmall;
            HmacSha512.create(out[0..HmacSha512.mac_length], data, key);
        },
        .keccak256, .ripemd160 => return error.InvalidArgument,
    }
}

pub fn hmacSha512(key: []const u8, data: []const u8) [HmacSha512.mac_length]u8 {
    var out: [HmacSha512.mac_length]u8 = undefined;
    HmacSha512.create(&out, data, key);
    return out;
}

const testing = std.testing;

fn expectDigest(algorithm: Algorithm, expected_hex: []const u8, input: []const u8) !void {
    var out: [64]u8 = undefined;
    try digest(algorithm, input, &out);
    var expected: [64]u8 = undefined;
    const decoded = try std.fmt.hexToBytes(&expected, expected_hex);
    try testing.expectEqual(algorithm.length(), decoded.len);
    try testing.expectEqualSlices(u8, decoded, out[0..decoded.len]);
}

// FIPS 180-4 examples (NIST CSRC "Examples with Intermediate Values"), and Keccak-256 as Ethereum uses it.
test "published digests" {
    try expectDigest(.sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "");
    try expectDigest(.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "abc");
    try expectDigest(
        .sha256,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    );
    try expectDigest(
        .sha512,
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "abc",
    );
    try expectDigest(
        .sha512,
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "",
    );
    try expectDigest(.keccak256, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "");
    try expectDigest(.keccak256, "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", "abc");
    try expectDigest(.ripemd160, "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", "abc");
}

test "keccak256 is not sha3-256" {
    var keccak: [32]u8 = undefined;
    try digest(.keccak256, "", &keccak);
    var sha3: [32]u8 = undefined;
    std.crypto.hash.sha3.Sha3_256.hash("", &sha3, .{});
    try testing.expect(!std.mem.eql(u8, &keccak, &sha3));
}

test "digest rejects a short output and unknown ids" {
    var out: [31]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, digest(.sha256, "abc", &out));
    try testing.expectError(error.InvalidArgument, Algorithm.fromInt(0));
    try testing.expectError(error.InvalidArgument, Algorithm.fromInt(5));
}

fn expectHmac(algorithm: Algorithm, key_hex: []const u8, data_hex: []const u8, expected_hex: []const u8) !void {
    var key: [256]u8 = undefined;
    var data: [256]u8 = undefined;
    var expected: [64]u8 = undefined;
    const k = try std.fmt.hexToBytes(&key, key_hex);
    const d = try std.fmt.hexToBytes(&data, data_hex);
    const e = try std.fmt.hexToBytes(&expected, expected_hex);
    var out: [64]u8 = undefined;
    try hmac(algorithm, k, d, &out);
    try testing.expectEqualSlices(u8, e, out[0..e.len]);
}

// RFC 4231, test cases 1, 2 and 6 (a key longer than the block).
test "RFC 4231 HMAC vectors" {
    const key1 = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    const data1 = "4869205468657265"; // "Hi There"
    try expectHmac(.sha256, key1, data1, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    try expectHmac(
        .sha512,
        key1,
        data1,
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
    );
    const key2 = "4a656665"; // "Jefe"
    const data2 = "7768617420646f2079612077616e7420666f72206e6f7468696e673f";
    try expectHmac(.sha256, key2, data2, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    try expectHmac(
        .sha512,
        key2,
        data2,
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
    );
    const key6 = "aa" ** 131;
    const data6 = "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374";
    try expectHmac(.sha256, key6, data6, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    try expectHmac(
        .sha512,
        key6,
        data6,
        "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
    );
}

test "hmac refuses hashes it is not defined over here" {
    var out: [64]u8 = undefined;
    try testing.expectError(error.InvalidArgument, hmac(.keccak256, "k", "d", &out));
    var short: [63]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, hmac(.sha512, "k", "d", &short));
}

test "hash160 of the secp256k1 generator" {
    var point: [33]u8 = undefined;
    _ = try std.fmt.hexToBytes(&point, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    var expected: [20]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "751e76e8199196d454941c45d1b3a323f1433bd6");
    try testing.expectEqualSlices(u8, &expected, &hash160(&point));
}
