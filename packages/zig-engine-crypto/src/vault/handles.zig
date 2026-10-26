//! Opaque handles to secret material held inside the engine.
//!
//! A fixed table, never an allocator: a secret lives in exactly one place, which `destroy` zeroes, instead of
//! wherever a heap moved it. A handle is `generation << 32 | (slot + 1)`; every reuse of a slot bumps its
//! generation, so a destroyed handle, a forged one or one from an earlier life of the slot is refused
//! (`InvalidHandle`) rather than reaching whichever secret lives there now. 0 is never a handle.
//!
//! Operations copy a secret out under the lock (`read`) and work on the copy, zeroing it after, so the lock is
//! held for a lookup and a copy, never for a signature or a PBKDF2.

const std = @import("std");

const secure = @import("../core/secure.zig");
const SpinLock = @import("../core/lock.zig").SpinLock;
const Error = @import("../core/status.zig").Error;

pub const Handle = u64;

/// The `NC_KIND_*` ids.
pub const Kind = enum(u32) {
    seed = 1,
    secp256k1_key = 2,
    ed25519_key = 3,
};

/// The largest secret a slot holds: a BIP-39 seed, or an Ed25519 seed with its public key (`ed25519.KeyPair`).
pub const max_secret_length = 64;

pub const capacity = 1024;

pub const Entry = struct { kind: Kind, length: usize };

const Slot = struct {
    generation: u32 = 0,
    kind: ?Kind = null,
    secret: [max_secret_length]u8 = @splat(0),
    length: u8 = 0,
};

pub fn Table(comptime slot_count: usize) type {
    return struct {
        const Self = @This();

        slots: [slot_count]Slot = @splat(.{}),
        live: u32 = 0,
        lock: SpinLock = .{},

        /// Stores a copy of `secret` and returns its handle. The caller still owns (and zeroes) `secret`.
        pub fn insert(self: *Self, kind: Kind, secret: []const u8) Error!Handle {
            if (secret.len == 0 or secret.len > max_secret_length) return error.InvalidLength;
            self.lock.lock();
            defer self.lock.unlock();

            for (&self.slots, 0..) |*slot, index| {
                if (slot.kind != null) continue;
                slot.generation +%= 1;
                if (slot.generation == 0) slot.generation = 1;
                slot.kind = kind;
                slot.length = @intCast(secret.len);
                @memcpy(slot.secret[0..secret.len], secret);
                self.live += 1;
                return @as(Handle, slot.generation) << 32 | (index + 1);
            }
            return error.HandleLimit;
        }

        /// Zeroes the secret and frees the slot.
        pub fn destroy(self: *Self, handle: Handle) Error!void {
            self.lock.lock();
            defer self.lock.unlock();
            const slot = try self.find(handle);
            secure.zero(&slot.secret);
            slot.length = 0;
            slot.kind = null;
            self.live -= 1;
        }

        pub fn kindOf(self: *Self, handle: Handle) Error!Kind {
            self.lock.lock();
            defer self.lock.unlock();
            return (try self.find(handle)).kind.?;
        }

        /// Copies the secret of a live handle into the front of `out`, in one step with its kind, so the kind a
        /// caller acts on is the kind of the bytes it got. The caller zeroes `out`.
        pub fn read(self: *Self, handle: Handle, out: *[max_secret_length]u8) Error!Entry {
            self.lock.lock();
            defer self.lock.unlock();
            const slot = try self.find(handle);
            @memcpy(out[0..slot.length], slot.secret[0..slot.length]);
            return .{ .kind = slot.kind.?, .length = slot.length };
        }

        pub fn count(self: *Self) u32 {
            self.lock.lock();
            defer self.lock.unlock();
            return self.live;
        }

        /// The live slot a handle names. Call with the lock held.
        fn find(self: *Self, handle: Handle) Error!*Slot {
            const position: u32 = @truncate(handle);
            const generation: u32 = @truncate(handle >> 32);
            if (position == 0 or position > slot_count) return error.InvalidHandle;
            const slot = &self.slots[position - 1];
            if (slot.kind == null or slot.generation != generation) return error.InvalidHandle;
            return slot;
        }
    };
}

const testing = std.testing;

test "insert, read, kind and destroy" {
    var table: Table(4) = .{};
    const secret = [_]u8{0xAB} ** 32;
    const handle = try table.insert(.secp256k1_key, &secret);
    try testing.expect(handle != 0);
    try testing.expectEqual(@as(u32, 1), table.count());
    try testing.expectEqual(Kind.secp256k1_key, try table.kindOf(handle));

    var out: [max_secret_length]u8 = undefined;
    try testing.expectEqual(Entry{ .kind = .secp256k1_key, .length = 32 }, try table.read(handle, &out));
    try testing.expectEqualSlices(u8, &secret, out[0..32]);

    try table.destroy(handle);
    try testing.expectEqual(@as(u32, 0), table.count());
    try testing.expectError(error.InvalidHandle, table.read(handle, &out));
    try testing.expectError(error.InvalidHandle, table.destroy(handle));
}

test "destroy zeroes the slot" {
    var table: Table(1) = .{};
    const handle = try table.insert(.seed, &([_]u8{0xFF} ** 64));
    try table.destroy(handle);
    try testing.expect(std.mem.allEqual(u8, &table.slots[0].secret, 0));
}

test "a stale handle never reaches the slot's next secret" {
    var table: Table(1) = .{};
    const first = try table.insert(.seed, &([_]u8{1} ** 64));
    try table.destroy(first);
    const second = try table.insert(.seed, &([_]u8{2} ** 64));
    try testing.expect(first != second);
    var out: [max_secret_length]u8 = undefined;
    try testing.expectError(error.InvalidHandle, table.read(first, &out));
    try testing.expectEqual(@as(usize, 64), (try table.read(second, &out)).length);
}

test "zero, forged and out-of-range handles are refused" {
    var table: Table(2) = .{};
    const handle = try table.insert(.ed25519_key, &([_]u8{3} ** 32));
    try testing.expectError(error.InvalidHandle, table.kindOf(0));
    try testing.expectError(error.InvalidHandle, table.kindOf(handle + (1 << 32)));
    try testing.expectError(error.InvalidHandle, table.kindOf(3));
    try testing.expectError(error.InvalidHandle, table.kindOf(std.math.maxInt(u64)));
}

test "the table fills up and frees" {
    var table: Table(3) = .{};
    var issued: [3]Handle = undefined;
    for (&issued) |*handle| handle.* = try table.insert(.seed, "x");
    try testing.expectError(error.HandleLimit, table.insert(.seed, "x"));
    try table.destroy(issued[1]);
    _ = try table.insert(.seed, "y");
}

test "secret lengths are bounded" {
    var table: Table(1) = .{};
    try testing.expectError(error.InvalidLength, table.insert(.seed, ""));
    try testing.expectError(error.InvalidLength, table.insert(.seed, &([_]u8{0} ** (max_secret_length + 1))));
}

test "concurrent inserts and destroys keep the count and never hand out a slot twice" {
    const builtin = @import("builtin");
    if (builtin.single_threaded) return error.SkipZigTest;

    const Shared = struct {
        table: Table(64) = .{},

        fn run(shared: *@This(), byte: u8) void {
            for (0..2_000) |_| {
                const secret = [_]u8{byte} ** 32;
                const handle = shared.table.insert(.secp256k1_key, &secret) catch continue;
                var out: [max_secret_length]u8 = undefined;
                const entry = shared.table.read(handle, &out) catch unreachable;
                // Another thread's secret would show up as a different byte.
                std.debug.assert(entry.length == 32 and std.mem.allEqual(u8, out[0..32], byte));
                shared.table.destroy(handle) catch unreachable;
            }
        }
    };

    var shared: Shared = .{};
    var threads: [8]std.Thread = undefined;
    for (&threads, 0..) |*thread, index| thread.* = try std.Thread.spawn(.{}, Shared.run, .{ &shared, @as(u8, @intCast(index + 1)) });
    for (threads) |thread| thread.join();
    try testing.expectEqual(@as(u32, 0), shared.table.count());
}
