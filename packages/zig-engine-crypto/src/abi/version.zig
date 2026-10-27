//! What this build is and what it can do: the ABI version hosts check, the engine version, and capabilities.

const std = @import("std");
const build_options = @import("build_options");

/// Bump with any incompatible change to include/nitro_crypto.h (see its compatibility policy).
pub const abi_version: u32 = 1;

pub const engine_version: [:0]const u8 = std.fmt.comptimePrint("{s}", .{build_options.version});

/// libsecp256k1's verification table size this build was compiled with (build.zig, `-Decmult-window`).
pub const ecmult_window: u8 = build_options.ecmult_window;

/// What this build was made with, for people: "zig 0.16.0, libsecp256k1 0.8.0, ecmult window 8".
pub const build_info: [:0]const u8 = std.fmt.comptimePrint("zig {s}, libsecp256k1 {s}, ecmult window {d}", .{
    @import("builtin").zig_version_string,
    build_options.secp256k1_version,
    ecmult_window,
});

/// One bit each, in the header's order (`NC_CAP_*`). The names are what TypeScript adapters declare they need.
pub const Capability = enum(u6) {
    random,
    sha256,
    sha512,
    keccak256,
    ripemd160,
    @"hmac-sha256",
    @"hmac-sha512",
    @"secp256k1-ecdsa",
    @"secp256k1-recovery",
    ed25519,
    bip39,
    @"bip32-secp256k1",
    @"slip10-ed25519",
    @"mnemonic-generate",
    @"bip32-extended-public",
    @"bip32-public-derivation",
    @"bip39-entropy",
    @"backup-argon2id",
    @"secp256k1-schnorr",
    @"taproot-tweak",

    pub fn bit(capability: Capability) u64 {
        return @as(u64, 1) << @intFromEnum(capability);
    }
};

/// Every capability this build has: all of them, as nothing is optional yet.
pub fn capabilities() u64 {
    var mask: u64 = 0;
    for (std.enums.values(Capability)) |capability| mask |= capability.bit();
    return mask;
}

pub fn capabilityName(index: u32) ?[:0]const u8 {
    const capability = std.enums.fromInt(Capability, std.math.cast(u6, index) orelse return null) orelse return null;
    return @tagName(capability);
}

const testing = std.testing;

test "capability bits match the header" {
    try testing.expectEqual(@as(u64, 1 << 0), Capability.random.bit());
    try testing.expectEqual(@as(u64, 1 << 3), Capability.keccak256.bit());
    try testing.expectEqual(@as(u64, 1 << 12), Capability.@"slip10-ed25519".bit());
    try testing.expectEqual(@as(u64, 1 << 13), Capability.@"mnemonic-generate".bit());
    try testing.expectEqual(@as(u64, 1 << 16), Capability.@"bip39-entropy".bit());
    try testing.expectEqual(@as(u64, 1 << 17), Capability.@"backup-argon2id".bit());
    try testing.expectEqual(@as(u64, 1 << 18), Capability.@"secp256k1-schnorr".bit());
    try testing.expectEqual(@as(u64, 1 << 19), Capability.@"taproot-tweak".bit());
    try testing.expectEqual(@as(u64, (1 << 20) - 1), capabilities());
}

test "capability names" {
    try testing.expectEqualStrings("random", capabilityName(0).?);
    try testing.expectEqualStrings("secp256k1-recovery", capabilityName(8).?);
    try testing.expectEqualStrings("mnemonic-generate", capabilityName(13).?);
    try testing.expectEqualStrings("bip32-extended-public", capabilityName(14).?);
    try testing.expectEqualStrings("bip32-public-derivation", capabilityName(15).?);
    try testing.expectEqualStrings("bip39-entropy", capabilityName(16).?);
    try testing.expectEqualStrings("backup-argon2id", capabilityName(17).?);
    try testing.expectEqualStrings("secp256k1-schnorr", capabilityName(18).?);
    try testing.expectEqualStrings("taproot-tweak", capabilityName(19).?);
    try testing.expectEqual(@as(?[:0]const u8, null), capabilityName(20));
    try testing.expectEqual(@as(?[:0]const u8, null), capabilityName(1000));
}

test "build info names the toolchain and the pinned dependency" {
    try testing.expect(std.mem.startsWith(u8, build_info, "zig 0.16."));
    try testing.expect(std.mem.indexOf(u8, build_info, "libsecp256k1 0.8.0") != null);
}

test "the engine version is semantic" {
    _ = try std.SemanticVersion.parse(engine_version);
}
