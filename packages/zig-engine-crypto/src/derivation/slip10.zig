//! SLIP-0010 derivation for Ed25519: hardened steps only.
//!
//! Master: HMAC-SHA512("ed25519 seed", seed). Child i of (k, c): I = HMAC-SHA512(c, 0x00 || k || ser32(i)),
//! child (IL, IR). Every IL is a valid Ed25519 seed, so this never fails for a valid path; a normal step has no
//! definition for Ed25519 and is `InvalidPath`.

const std = @import("std");

const ed25519 = @import("../curves/ed25519.zig");
const hash = @import("../hash.zig");
const path_mod = @import("path.zig");
const secure = @import("../core/secure.zig");
const Error = @import("../core/status.zig").Error;

const master_key = "ed25519 seed";

/// An Ed25519 seed and its chain code. Secret: zero it when done.
pub const ExtendedKey = struct {
    key: ed25519.Seed,
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
    return ExtendedKey.fromHmac(&output);
}

pub fn child(parent: *const ExtendedKey, index: u32) Error!ExtendedKey {
    if (index < path_mod.hardened) return error.InvalidPath;
    var data: [37]u8 = undefined;
    defer secure.zero(&data);
    data[0] = 0;
    data[1..33].* = parent.key;
    std.mem.writeInt(u32, data[33..37], index, .big);
    var output = hash.hmacSha512(&parent.chain_code, &data);
    return ExtendedKey.fromHmac(&output);
}

pub fn derive(seed: []const u8, path: *const path_mod.Path) Error!ExtendedKey {
    if (!path.allHardened()) return error.InvalidPath;
    var current = try master(seed);
    for (path.steps()) |index| {
        const next = try child(&current, index);
        current.zero();
        current = next;
    }
    return current;
}

const testing = std.testing;

test "normal steps are refused" {
    const seed = [_]u8{1} ** 16;
    try testing.expectError(error.InvalidPath, derive(&seed, &(try path_mod.parse("m/44'/501'/0'/0"))));
    var key = try master(&seed);
    defer key.zero();
    try testing.expectError(error.InvalidPath, child(&key, 0));
}
