//! RIPEMD-160 (Dobbertin, Bosselaers, Preneel, 1996), which Zig's standard library does not have.
//!
//! A direct transcription of the reference description ("RIPEMD-160: A Strengthened Version of RIPEMD", and the
//! authors' reference implementation), in the shape of `std.crypto.hash`: `init`, `update`, `final`, `hash`.
//! It processes public data only (Bitcoin hashes public keys with it), so it makes no constant-time claims. The
//! tests are the reference vectors from the authors' page, and the TypeScript tests compare it against
//! `@noble/hashes` across random inputs.

const std = @import("std");

pub const Ripemd160 = struct {
    pub const block_length = 64;
    pub const digest_length = 20;
    pub const Options = struct {};

    state: [5]u32,
    buffer: [block_length]u8,
    buffered: usize,
    total: u64,

    pub fn init(options: Options) Ripemd160 {
        _ = options;
        return .{
            .state = .{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 },
            .buffer = undefined,
            .buffered = 0,
            .total = 0,
        };
    }

    pub fn hash(data: []const u8, out: *[digest_length]u8, options: Options) void {
        var hasher = init(options);
        hasher.update(data);
        hasher.final(out);
    }

    pub fn update(self: *Ripemd160, data: []const u8) void {
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

        while (input.len >= block_length) {
            compress(&self.state, input[0..block_length]);
            input = input[block_length..];
        }

        @memcpy(self.buffer[0..input.len], input);
        self.buffered = input.len;
    }

    /// MD4-style padding: 0x80, zeros to 56 mod 64, then the length in bits as a little-endian u64.
    pub fn final(self: *Ripemd160, out: *[digest_length]u8) void {
        const bit_length = self.total *% 8;
        var padding: [block_length * 2]u8 = @splat(0);
        padding[0] = 0x80;
        const pad_length = if (self.buffered < 56) 56 - self.buffered else 120 - self.buffered;
        std.mem.writeInt(u64, padding[pad_length..][0..8], bit_length, .little);
        self.update(padding[0 .. pad_length + 8]);
        std.debug.assert(self.buffered == 0);

        for (self.state, 0..) |word, index| std.mem.writeInt(u32, out[index * 4 ..][0..4], word, .little);
        self.* = undefined;
    }
};

/// Word selection, left line.
const r_left = [80]u5{
    0, 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    7, 4,  13, 1,  10, 6,  15, 3,  12, 0, 9,  5,  2,  14, 11, 8,
    3, 10, 14, 4,  9,  15, 8,  1,  2,  7, 0,  6,  13, 11, 5,  12,
    1, 9,  11, 10, 0,  8,  12, 4,  13, 3, 7,  15, 14, 5,  6,  2,
    4, 0,  5,  9,  7,  12, 2,  10, 14, 1, 3,  8,  11, 6,  15, 13,
};

/// Word selection, right line.
const r_right = [80]u5{
    5,  14, 7,  0, 9, 2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12,
    6,  11, 3,  7, 0, 13, 5,  10, 14, 15, 8,  12, 4,  9,  1,  2,
    15, 5,  1,  3, 7, 14, 6,  9,  11, 8,  12, 2,  10, 0,  4,  13,
    8,  6,  4,  1, 3, 11, 15, 0,  5,  12, 2,  13, 9,  7,  10, 14,
    12, 15, 10, 4, 1, 5,  8,  7,  6,  2,  13, 14, 0,  3,  9,  11,
};

/// Rotation amounts, left line.
const s_left = [80]u5{
    11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,
    7,  6,  8,  13, 11, 9,  7,  15, 7,  12, 15, 9,  11, 7,  13, 12,
    11, 13, 6,  7,  14, 9,  13, 15, 14, 8,  13, 6,  5,  12, 7,  5,
    11, 12, 14, 15, 14, 15, 9,  8,  9,  14, 5,  6,  8,  6,  5,  12,
    9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  6,
};

/// Rotation amounts, right line.
const s_right = [80]u5{
    8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,
    9,  13, 15, 7,  12, 8,  9,  11, 7,  7,  12, 7,  6,  15, 13, 11,
    9,  7,  15, 11, 8,  6,  6,  14, 12, 13, 5,  14, 13, 13, 7,  5,
    15, 5,  8,  11, 14, 14, 6,  14, 6,  9,  12, 9,  12, 5,  15, 8,
    8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 11,
};

const k_left = [5]u32{ 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E };
const k_right = [5]u32{ 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000 };

/// The five boolean functions, by round (0 to 4).
fn f(round: usize, x: u32, y: u32, z: u32) u32 {
    return switch (round) {
        0 => x ^ y ^ z,
        1 => (x & y) | (~x & z),
        2 => (x | ~y) ^ z,
        3 => (x & z) | (y & ~z),
        4 => x ^ (y | ~z),
        else => unreachable,
    };
}

const Line = struct {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,

    /// One step of a line: the new word goes into `b`, the others shift along.
    fn step(line: *Line, word: u32, function: u32, constant: u32, rotation: u5) void {
        const t = std.math.rotl(u32, line.a +% function +% word +% constant, rotation) +% line.e;
        line.a = line.e;
        line.e = line.d;
        line.d = std.math.rotl(u32, line.c, 10);
        line.c = line.b;
        line.b = t;
    }
};

fn compress(state: *[5]u32, block: *const [Ripemd160.block_length]u8) void {
    var words: [16]u32 = undefined;
    for (&words, 0..) |*word, index| word.* = std.mem.readInt(u32, block[index * 4 ..][0..4], .little);

    const initial: Line = .{ .a = state[0], .b = state[1], .c = state[2], .d = state[3], .e = state[4] };
    var left = initial;
    var right = initial;

    for (0..80) |j| {
        const round = j / 16;
        left.step(words[r_left[j]], f(round, left.b, left.c, left.d), k_left[round], s_left[j]);
        right.step(words[r_right[j]], f(4 - round, right.b, right.c, right.d), k_right[round], s_right[j]);
    }

    const t = state[1] +% left.c +% right.d;
    state[1] = state[2] +% left.d +% right.e;
    state[2] = state[3] +% left.e +% right.a;
    state[3] = state[4] +% left.a +% right.b;
    state[4] = state[0] +% left.b +% right.c;
    state[0] = t;
}

const testing = std.testing;

fn expectDigest(expected_hex: []const u8, input: []const u8) !void {
    var digest: [Ripemd160.digest_length]u8 = undefined;
    Ripemd160.hash(input, &digest, .{});
    var expected: [Ripemd160.digest_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try testing.expectEqualSlices(u8, &expected, &digest);
}

// https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
test "reference vectors" {
    try expectDigest("9c1185a5c5e9fc54612808977ee8f548b2258d31", "");
    try expectDigest("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe", "a");
    try expectDigest("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", "abc");
    try expectDigest("5d0689ef49d2fae572b881b123a85ffa21595f36", "message digest");
    try expectDigest("f71c27109c692c1b56bbdceb5b9d2865b3708dbc", "abcdefghijklmnopqrstuvwxyz");
    try expectDigest(
        "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    );
    try expectDigest(
        "b0e20b6e3116640286ed3a87a5713079b21f5189",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    );
    try expectDigest("9b752e45573d4b39f4dbd3323cab82bf63326bfb", "1234567890" ** 8);
}

test "one million times 'a', fed in uneven pieces" {
    var hasher = Ripemd160.init(.{});
    const piece = [_]u8{'a'} ** 997;
    var remaining: usize = 1_000_000;
    while (remaining > 0) {
        const take = @min(remaining, piece.len);
        hasher.update(piece[0..take]);
        remaining -= take;
    }
    var digest: [20]u8 = undefined;
    hasher.final(&digest);
    var expected: [20]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "52783243c1697bdbe16d37f97f68f08325dc1528");
    try testing.expectEqualSlices(u8, &expected, &digest);
}

test "streaming equals one-shot at every split around the block and padding boundaries" {
    var input: [200]u8 = undefined;
    for (&input, 0..) |*byte, index| byte.* = @truncate(index *% 31 +% 7);

    for ([_]usize{ 0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 128, 200 }) |length| {
        var one_shot: [20]u8 = undefined;
        Ripemd160.hash(input[0..length], &one_shot, .{});
        for (0..length + 1) |split| {
            var hasher = Ripemd160.init(.{});
            hasher.update(input[0..split]);
            hasher.update(input[split..length]);
            var streamed: [20]u8 = undefined;
            hasher.final(&streamed);
            try testing.expectEqualSlices(u8, &one_shot, &streamed);
        }
    }
}
