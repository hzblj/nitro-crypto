//! Property tests: the fuzz targets, driven by seeded random input in every `zig build test`.
//!
//! Zig 0.16.0's coverage-guided mode (`zig build test --fuzz`) does not build: its own test runner fails to
//! compile there (a `StackTrace` type mismatch in lib/compiler/test_runner.zig). Until it does, this runs each
//! target over random inputs instead. The seed is fixed, so a failure reproduces exactly.

const std = @import("std");

pub const Target = fn (void, *std.testing.Smith) anyerror!void;

/// Big enough for any target's draws: once the input runs out, `Smith` answers every draw with its minimum.
const input_length = 2048;

pub fn check(comptime target: Target, iterations: usize, seed: u64) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    var input: [input_length]u8 = undefined;
    for (0..iterations) |_| {
        prng.random().bytes(&input);
        var smith: std.testing.Smith = .{ .in = &input };
        try target({}, &smith);
    }
}
