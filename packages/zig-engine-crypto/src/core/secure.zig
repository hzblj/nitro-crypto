//! Handling secret bytes: zeroization that the optimizer may not remove, and comparison in constant time.
//!
//! Best effort, as everywhere in managed runtimes: the engine zeroes every buffer it puts a secret in, but a
//! secret the host passed in (a mnemonic, an imported key) has already been copied by the host's runtime.

const std = @import("std");

/// Overwrites `bytes` with zeros through a volatile pointer, so the store survives dead-store elimination.
pub fn zero(bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
}

/// `zero` for anything held by value: an array, a struct of arrays.
pub fn zeroValue(value: anytype) void {
    const pointer_info = @typeInfo(@TypeOf(value)).pointer;
    comptime std.debug.assert(pointer_info.size == .one);
    zero(std.mem.asBytes(value));
}

/// Equality of two byte strings of the same length without a data-dependent branch.
pub fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var difference: u8 = 0;
    for (a, b) |x, y| difference |= x ^ y;
    return difference == 0;
}

/// `if (condition) a else b` for bytes, without a data-dependent branch.
pub fn select(condition: bool, a: u8, b: u8) u8 {
    const mask: u8 = @as(u8, 0) -% @intFromBool(condition);
    return (a & mask) | (b & ~mask);
}

const testing = std.testing;

test "zero clears every byte" {
    var bytes = [_]u8{0xAA} ** 37;
    zero(&bytes);
    try testing.expect(std.mem.allEqual(u8, &bytes, 0));
}

test "zeroValue clears a struct" {
    var value: struct { a: [16]u8, b: [16]u8 } = .{ .a = @splat(1), .b = @splat(2) };
    zeroValue(&value);
    try testing.expect(std.mem.allEqual(u8, &value.a, 0));
    try testing.expect(std.mem.allEqual(u8, &value.b, 0));
}

test "eql compares length and content" {
    try testing.expect(eql("abc", "abc"));
    try testing.expect(!eql("abc", "abd"));
    try testing.expect(!eql("abc", "ab"));
    try testing.expect(eql("", ""));
}

test "select picks by condition" {
    try testing.expectEqual(@as(u8, 7), select(true, 7, 9));
    try testing.expectEqual(@as(u8, 9), select(false, 7, 9));
}
