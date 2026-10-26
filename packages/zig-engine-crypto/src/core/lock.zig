//! A lock for the engine's few shared structures (the handle table, the signing context's one-time setup).
//!
//! Zig 0.16 moved its blocking mutex onto `std.Io`, which a C library called from foreign threads has no
//! instance of. Every critical section here lasts microseconds (a slot lookup, a 64-byte copy), so a spin lock
//! that yields the CPU under contention is enough, and it needs nothing from the host.

const std = @import("std");
const builtin = @import("builtin");

/// Spins this many times before yielding: about a microsecond, the length of the longest critical section.
const spins_before_yield = 128;

pub const SpinLock = struct {
    state: std.atomic.Mutex = .unlocked,

    pub fn lock(self: *SpinLock) void {
        if (builtin.single_threaded) return;
        var spins: u32 = 0;
        while (!self.state.tryLock()) {
            if (spins < spins_before_yield) {
                spins += 1;
                std.atomic.spinLoopHint();
            } else {
                std.Thread.yield() catch {};
            }
        }
    }

    pub fn unlock(self: *SpinLock) void {
        if (builtin.single_threaded) return;
        self.state.unlock();
    }
};

const testing = std.testing;

test "the lock serializes increments across threads" {
    if (builtin.single_threaded) return error.SkipZigTest;

    const Shared = struct {
        lock: SpinLock = .{},
        counter: u64 = 0,

        fn run(shared: *@This()) void {
            for (0..20_000) |_| {
                shared.lock.lock();
                // A read and a write that would lose updates without the lock.
                const value = shared.counter;
                std.atomic.spinLoopHint();
                shared.counter = value + 1;
                shared.lock.unlock();
            }
        }
    };

    var shared: Shared = .{};
    var threads: [8]std.Thread = undefined;
    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    for (threads) |thread| thread.join();
    try testing.expectEqual(@as(u64, 8 * 20_000), shared.counter);
}
