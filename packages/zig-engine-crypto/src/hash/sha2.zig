//! SHA-256 and SHA-512 on the processor's instructions wherever it has them, and Zig's otherwise.
//!
//! Zig's library chooses its SHA-2 when it compiles, from the target's features, and has instructions for SHA-256
//! only. The engine is built for each platform's oldest processor (os/cpu.zig), so Zig's choice leaves most of them
//! hashing in software: SHA-256 on Android, SHA-512 everywhere. Here each is, by what the target settles:
//!
//!   - Zig's, where Zig already uses the instructions (SHA-256 on iOS) or there are none to use (WebAssembly).
//!   - `WithInstructions`, where the target guarantees them (SHA-512 on an M1 Mac).
//!   - `Dispatched` otherwise: the system is asked when a hash starts, and the hash runs on whichever fits.
//!
//! `WithInstructions` is the block buffering and padding of FIPS 180-4, written once for both widths around a
//! compression function from sha2/armv8.zig or sha2/x86.zig. Like Zig's, it branches on lengths, never on data. The
//! tests hold every compression function this processor can run to the FIPS 180-4 examples and to Zig's software
//! implementation: every length around the block and padding boundaries, every split of those, and random input in
//! random pieces.

const std = @import("std");
const builtin = @import("builtin");

const cpu = @import("../os/cpu.zig");
const armv8 = @import("sha2/armv8.zig");
const x86 = @import("sha2/x86.zig");

/// The engine's SHA-256 and SHA-512, in `std.crypto.hash`'s shape (`init`, `update`, `final`, `hash`), so HMAC and
/// PBKDF2 build on them.
pub const Sha256 = Choose(.sha256);
pub const Sha512 = Choose(.sha512);

const Zig = struct {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const Sha512 = std.crypto.hash.sha2.Sha512;
};

/// FIPS 180-4, 5.3.3 and 5.3.5.
const iv256 = [8]u32{ 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 };
const iv512 = [8]u64{
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
};

/// The instructions' SHA-256 or SHA-512 for this architecture, or null where there are none. Zig's C backend cannot
/// pass vectors to inline assembly, and its own x86-64 backend (Debug builds) cannot encode the SHA extensions.
fn Instructions(comptime feature: cpu.Feature) ?type {
    if (builtin.zig_backend == .stage2_c) return null;
    return switch (feature) {
        .sha256 => switch (builtin.cpu.arch) {
            .aarch64 => WithInstructions(u32, iv256, armv8.compress256),
            .x86_64 => if (builtin.zig_backend == .stage2_x86_64)
                null
            else
                WithInstructions(u32, iv256, x86.compress256),
            else => null,
        },
        .sha512 => switch (builtin.cpu.arch) {
            .aarch64 => WithInstructions(u64, iv512, armv8.compress512),
            else => null,
        },
    };
}

/// Zig's SHA-256 already runs on the instructions when the target promises them (on x86-64, with AVX2 too).
fn zigUsesInstructions(comptime feature: cpu.Feature) bool {
    return feature == .sha256 and switch (builtin.cpu.arch) {
        .aarch64 => builtin.cpu.has(.aarch64, .sha2),
        .x86_64 => builtin.cpu.hasAll(.x86, &.{ .sha, .avx2 }),
        else => false,
    };
}

fn Choose(comptime feature: cpu.Feature) type {
    const Software = switch (feature) {
        .sha256 => Zig.Sha256,
        .sha512 => Zig.Sha512,
    };
    const Hardware = Instructions(feature) orelse return Software;
    if (zigUsesInstructions(feature)) return Software;
    return switch (cpu.availability(feature)) {
        .promised => Hardware,
        .detected => Dispatched(feature, Software, Hardware),
        .absent => Software,
    };
}

/// Whether the engine's SHA-256 or SHA-512 runs on the processor's instructions here: what the benchmark reports.
pub fn usesInstructions(comptime feature: cpu.Feature) bool {
    if (comptime zigUsesInstructions(feature)) return true;
    if (comptime Instructions(feature) == null) return false;
    return cpu.has(feature);
}

/// `Software` or `Hardware`, chosen when a hash starts by what the system reports.
fn Dispatched(comptime feature: cpu.Feature, comptime Software: type, comptime Hardware: type) type {
    return union(enum) {
        software: Software,
        hardware: Hardware,

        const Self = @This();
        pub const block_length = Software.block_length;
        pub const digest_length = Software.digest_length;
        pub const Options = struct {};

        pub fn init(options: Options) Self {
            return with(cpu.has(feature), options);
        }

        fn with(instructions: bool, options: Options) Self {
            _ = options;
            return if (instructions) .{ .hardware = .init(.{}) } else .{ .software = .init(.{}) };
        }

        pub fn hash(data: []const u8, out: *[digest_length]u8, options: Options) void {
            var hasher = init(options);
            hasher.update(data);
            hasher.final(out);
        }

        pub fn update(self: *Self, data: []const u8) void {
            switch (self.*) {
                inline else => |*hasher| hasher.update(data),
            }
        }

        pub fn final(self: *Self, out: *[digest_length]u8) void {
            switch (self.*) {
                inline else => |*hasher| hasher.final(out),
            }
        }
    };
}

/// SHA-256 (`Word` u32) or SHA-512 (u64), compressed by `compress`, which takes whole blocks. Run only where the
/// processor has the instructions `compress` uses: elsewhere its first block is an illegal instruction.
fn WithInstructions(
    comptime Word: type,
    comptime iv: [8]Word,
    comptime compress: fn (state: *[8]Word, blocks: []const u8) void,
) type {
    return struct {
        const Self = @This();
        pub const block_length = 16 * @sizeOf(Word);
        pub const digest_length = 8 * @sizeOf(Word);
        pub const Options = struct {};

        /// The message length closes the padding: 64 bits for SHA-256, 128 for SHA-512.
        const Length = std.meta.Int(.unsigned, 16 * @sizeOf(Word));
        const length_end = block_length - @sizeOf(Length);

        state: [8]Word,
        buffer: [block_length]u8 = undefined,
        buffered: usize = 0,
        total: u64 = 0,

        pub fn init(options: Options) Self {
            _ = options;
            return .{ .state = iv };
        }

        pub fn hash(data: []const u8, out: *[digest_length]u8, options: Options) void {
            var hasher = init(options);
            hasher.update(data);
            hasher.final(out);
        }

        pub fn update(self: *Self, data: []const u8) void {
            var input = data;
            self.total +%= input.len;

            if (self.buffered > 0) {
                const take = @min(block_length - self.buffered, input.len);
                @memcpy(self.buffer[self.buffered..][0..take], input[0..take]);
                self.buffered += take;
                input = input[take..];
                if (self.buffered < block_length) return;
                compress(&self.state, &self.buffer);
                self.buffered = 0;
            }

            const whole = input.len - input.len % block_length;
            if (whole > 0) compress(&self.state, input[0..whole]);
            @memcpy(self.buffer[0 .. input.len - whole], input[whole..]);
            self.buffered = input.len - whole;
        }

        /// FIPS 180-4 padding: 0x80, zeros up to the length field, then the length in bits, big-endian.
        pub fn final(self: *Self, out: *[digest_length]u8) void {
            // Modulo 2^64 for SHA-256, as FIPS 180-4 has it; SHA-512's field holds any u64 length times eight.
            const bit_length = @as(Length, self.total) *% 8;
            var padding: [block_length * 2]u8 = @splat(0);
            padding[0] = 0x80;
            const pad_length = if (self.buffered < length_end)
                length_end - self.buffered
            else
                block_length + length_end - self.buffered;
            std.mem.writeInt(Length, padding[pad_length..][0..@sizeOf(Length)], bit_length, .big);
            self.update(padding[0 .. pad_length + @sizeOf(Length)]);
            std.debug.assert(self.buffered == 0);

            for (self.state, 0..) |word, index| {
                std.mem.writeInt(Word, out[index * @sizeOf(Word) ..][0..@sizeOf(Word)], word, .big);
            }
            self.* = undefined;
        }
    };
}

const testing = std.testing;

/// Each width's instructions on this architecture, with what this processor says about running them.
const cases = .{
    .{ .feature = cpu.Feature.sha256, .Software = Zig.Sha256 },
    .{ .feature = cpu.Feature.sha512, .Software = Zig.Sha512 },
};

/// Whether this processor runs `Instructions(feature)`. Comptime-known wherever the build knows, so the tests of
/// instructions a target cannot have compile to a skip rather than to assembly its assembler rejects.
inline fn runsInstructions(comptime feature: cpu.Feature) bool {
    if (comptime Instructions(feature) == null) return false;
    return cpu.has(feature);
}

/// A test of the instructions skips, visibly, on a processor that runs none of them.
fn requireInstructions() error{SkipZigTest}!void {
    if (!runsInstructions(.sha256) and !runsInstructions(.sha512)) return error.SkipZigTest;
}

fn digestOf(comptime H: type, data: []const u8) [H.digest_length]u8 {
    var out: [H.digest_length]u8 = undefined;
    H.hash(data, &out, .{});
    return out;
}

fn expectDigest(comptime H: type, expected_hex: []const u8, data: []const u8) !void {
    var expected: [H.digest_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try testing.expectEqualSlices(u8, &expected, &digestOf(H, data));
}

const two_block_256 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
const two_block_512 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

// FIPS 180-4 examples (NIST CSRC "Examples with Intermediate Values"): one block, an empty one, the messages whose
// padding takes a second block.
test "the instructions: the FIPS 180-4 examples" {
    try requireInstructions();
    if (runsInstructions(.sha256)) {
        const H = Instructions(.sha256).?;
        try expectDigest(H, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "abc");
        try expectDigest(H, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "");
        try expectDigest(H, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", two_block_256);
        try expectDigest(H, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1", two_block_512);
    }
    if (runsInstructions(.sha512)) {
        const H = Instructions(.sha512).?;
        try expectDigest(
            H,
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "abc",
        );
        try expectDigest(
            H,
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            "",
        );
        try expectDigest(
            H,
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
            two_block_512,
        );
    }
}

test "the instructions: one million times 'a', fed in uneven pieces" {
    try requireInstructions();
    const expected = .{
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
    };
    inline for (cases, expected) |case, expected_hex| {
        if (runsInstructions(case.feature)) {
            const H = Instructions(case.feature).?;
            var hasher = H.init(.{});
            const piece = [_]u8{'a'} ** 997;
            var remaining: usize = 1_000_000;
            while (remaining > 0) {
                const take = @min(remaining, piece.len);
                hasher.update(piece[0..take]);
                remaining -= take;
            }
            var digest: [H.digest_length]u8 = undefined;
            hasher.final(&digest);
            var want: [H.digest_length]u8 = undefined;
            _ = try std.fmt.hexToBytes(&want, expected_hex);
            try testing.expectEqualSlices(u8, &want, &digest);
        }
    }
}

test "the instructions: equal Zig's software SHA-2 at every length to 300 bytes" {
    try requireInstructions();
    var input: [300]u8 = undefined;
    for (&input, 0..) |*byte, index| byte.* = @truncate(index *% 31 +% 7);
    inline for (cases) |case| {
        if (runsInstructions(case.feature)) {
            for (0..input.len + 1) |length| {
                const data = input[0..length];
                try testing.expectEqualSlices(
                    u8,
                    &digestOf(case.Software, data),
                    &digestOf(Instructions(case.feature).?, data),
                );
            }
        }
    }
}

test "the instructions: streaming equals one-shot at every split around the block and padding boundaries" {
    try requireInstructions();
    var input: [272]u8 = undefined;
    for (&input, 0..) |*byte, index| byte.* = @truncate(index *% 31 +% 7);
    // Each width's block, its padding's last byte before the length, and their neighbours.
    const lengths = [_]usize{ 0, 1, 55, 56, 57, 63, 64, 65, 111, 112, 113, 119, 120, 127, 128, 129, 239, 240, 272 };
    inline for (cases) |case| {
        if (runsInstructions(case.feature)) {
            const H = Instructions(case.feature).?;
            for (lengths) |length| {
                const one_shot = digestOf(case.Software, input[0..length]);
                for (0..length + 1) |split| {
                    var hasher = H.init(.{});
                    hasher.update(input[0..split]);
                    hasher.update(input[split..length]);
                    var streamed: [H.digest_length]u8 = undefined;
                    hasher.final(&streamed);
                    try testing.expectEqualSlices(u8, &one_shot, &streamed);
                }
            }
        }
    }
}

fn fuzzInstructions(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [1500]u8 = undefined;
    const data = buffer[0..smith.slice(&buffer)];
    inline for (cases) |case| {
        if (runsInstructions(case.feature)) {
            const H = Instructions(case.feature).?;
            var hasher = H.init(.{});
            var rest: []const u8 = data;
            while (rest.len > 0) {
                // At least a byte a piece: once the input runs out, every draw is its minimum.
                const take = smith.valueRangeAtMost(u16, 1, @intCast(rest.len));
                hasher.update(rest[0..take]);
                rest = rest[take..];
            }
            var digest: [H.digest_length]u8 = undefined;
            hasher.final(&digest);
            try testing.expectEqualSlices(u8, &digestOf(case.Software, data), &digest);
        }
    }
}

test "property: the instructions equal Zig's SHA-2 on random input in random pieces" {
    try requireInstructions();
    try @import("../testing/property.zig").check(fuzzInstructions, 3000, 4);
}

test "fuzz: the instructions equal Zig's SHA-2 on random input in random pieces" {
    try requireInstructions();
    try testing.fuzz({}, fuzzInstructions, .{});
}

test "Dispatched hashes the same whichever it chooses" {
    var input: [300]u8 = undefined;
    for (&input, 0..) |*byte, index| byte.* = @truncate(index *% 13 +% 5);
    inline for (cases) |case| {
        if (comptime Instructions(case.feature)) |H| {
            const D = Dispatched(case.feature, case.Software, H);
            const choices: []const bool = if (runsInstructions(case.feature)) &.{ false, true } else &.{false};
            for (choices) |instructions| {
                for ([_]usize{ 0, 3, 55, 56, 64, 65, 112, 128, 129, 300 }) |length| {
                    var hasher = D.with(instructions, .{});
                    try testing.expectEqual(instructions, hasher == .hardware);
                    hasher.update(input[0 .. length / 2]);
                    hasher.update(input[length / 2 .. length]);
                    var digest: [D.digest_length]u8 = undefined;
                    hasher.final(&digest);
                    try testing.expectEqualSlices(u8, &digestOf(case.Software, input[0..length]), &digest);
                }
            }
        }
    }
}

test "where the system is asked, the engine's SHA-2 follows its answer" {
    inline for (.{ Sha256, Sha512 }, cases) |Engine, case| {
        if (comptime (cpu.availability(case.feature) == .detected and @typeInfo(Engine) == .@"union")) {
            try testing.expectEqual(cpu.has(case.feature), Engine.init(.{}) == .hardware);
        }
    }
}
