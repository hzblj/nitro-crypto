//! SHA-256 compression on x86's SHA extensions (`sha256rnds2`, `sha256msg1`, `sha256msg2`).
//!
//! Zig's instruction sequence (lib/std/crypto/sha2.zig), without the AVX its `vpalignr` needs: the four words it
//! aligns are a shuffle here, which the baseline compiles to SSE2. Run only where os/cpu.zig says the processor has
//! the extensions. The state stays in registers across blocks.

const std = @import("std");

const V4 = @Vector(4, u32);

/// FIPS 180-4, 4.2.2: the round constants, four to a vector.
const k256: [16]V4 = @bitCast([64]u32{
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
});

/// Compresses `blocks`, a whole number of 64-byte blocks, into `state`. The instructions keep the state as
/// (a, b, e, f) and (c, d, g, h), highest lane first.
pub fn compress256(state: *[8]u32, blocks: []const u8) void {
    std.debug.assert(blocks.len % 64 == 0);
    var abef: V4 = .{ state[5], state[4], state[1], state[0] };
    var cdgh: V4 = .{ state[7], state[6], state[3], state[2] };

    var rest = blocks;
    while (rest.len > 0) : (rest = rest[64..]) {
        // The message words are big-endian; x86 loads little-endian.
        var w: [4]V4 = undefined;
        inline for (&w, 0..) |*words, index| words.* = @byteSwap(@as(V4, @bitCast(rest[index * 16 ..][0..16].*)));

        const abef_before = abef;
        const cdgh_before = cdgh;
        inline for (0..16) |group| {
            const slot = group % 4;
            if (group >= 4) w[slot] = schedule(w[slot], w[(slot + 1) % 4], w[(slot + 2) % 4], w[(slot + 3) % 4]);
            fourRounds(&abef, &cdgh, w[slot] +% k256[group]);
        }
        abef +%= abef_before;
        cdgh +%= cdgh_before;
    }

    state.* = .{ abef[3], abef[2], cdgh[3], cdgh[2], abef[1], abef[0], cdgh[1], cdgh[0] };
}

/// The next four schedule words, from the sixteen before them (`w0` the oldest four): `sha256msg1` adds σ0, the
/// shuffle brings W[t-7] to W[t-4], `sha256msg2` adds σ1.
fn schedule(w0: V4, w1: V4, w2: V4, w3: V4) V4 {
    const partial = asm ("sha256msg1 %[w1], %[w0]"
        : [w0] "=x" (-> V4),
        : [_] "0" (w0),
          [w1] "x" (w1),
    );
    const back7 = @shuffle(u32, w2, w3, [4]i32{ 1, 2, 3, ~@as(i32, 0) });
    return asm ("sha256msg2 %[w3], %[sum]"
        : [sum] "=x" (-> V4),
        : [_] "0" (partial +% back7),
          [w3] "x" (w3),
    );
}

/// Four rounds, `wk` being the schedule words with their round constants added. Each `sha256rnds2` runs two, on the
/// two words in the low lanes of xmm0, and returns the new (a, b, e, f); the old one is the new (c, d, g, h).
fn fourRounds(abef: *V4, cdgh: *V4, wk: V4) void {
    cdgh.* = twoRounds(cdgh.*, abef.*, wk);
    abef.* = twoRounds(abef.*, cdgh.*, @shuffle(u32, wk, undefined, [4]i32{ 2, 3, 2, 3 }));
}

fn twoRounds(cdgh: V4, abef: V4, wk: V4) V4 {
    return asm ("sha256rnds2 %[abef], %[cdgh]"
        : [cdgh] "=x" (-> V4),
        : [_] "0" (cdgh),
          [abef] "x" (abef),
          [_] "{xmm0}" (wk),
    );
}
