//! SHA-256 and SHA-512 compression on ARMv8's instructions: the SHA-2 extension (`sha256h`, ARMv8.0, optional) and
//! the SHA-512 extension (`sha512h`, ARMv8.2, optional).
//!
//! Assembled for targets that do not promise them (`.arch_extension`; without it LLVM refuses, "instruction requires:
//! sha2"), so run only where os/cpu.zig says the processor has them. The state stays in registers across blocks.

const std = @import("std");

const V4 = @Vector(4, u32);
const V2 = @Vector(2, u64);

// --- SHA-256 ---------------------------------------------------------------------------------------------------

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

/// Compresses `blocks`, a whole number of 64-byte blocks, into `state`: Zig's instruction sequence
/// (lib/std/crypto/sha2.zig). Each four rounds are one `sha256h` and `sha256h2` pair; each four schedule words, from
/// the fifth group on, one `sha256su0` and `sha256su1` pair.
pub fn compress256(state: *[8]u32, blocks: []const u8) void {
    std.debug.assert(blocks.len % 64 == 0);
    var abcd: V4 = state[0..4].*;
    var efgh: V4 = state[4..8].*;

    var rest = blocks;
    while (rest.len > 0) : (rest = rest[64..]) {
        // The message words are big-endian; arm64 loads little-endian.
        var w: [4]V4 = undefined;
        inline for (&w, 0..) |*words, index| words.* = @byteSwap(@as(V4, @bitCast(rest[index * 16 ..][0..16].*)));

        const abcd_before = abcd;
        const efgh_before = efgh;
        inline for (0..16) |group| {
            const slot = group % 4;
            if (group >= 4) w[slot] = schedule256(w[slot], w[(slot + 1) % 4], w[(slot + 2) % 4], w[(slot + 3) % 4]);
            fourRounds(&abcd, &efgh, w[slot] +% k256[group]);
        }
        abcd +%= abcd_before;
        efgh +%= efgh_before;
    }

    state[0..4].* = abcd;
    state[4..8].* = efgh;
}

/// The next four schedule words, from the sixteen before them (`w0` the oldest four).
fn schedule256(w0: V4, w1: V4, w2: V4, w3: V4) V4 {
    return asm (
        \\.arch_extension sha2
        \\sha256su0.4s %[w0], %[w1]
        \\sha256su1.4s %[w0], %[w2], %[w3]
        : [w0] "=&w" (-> V4),
        : [_] "0" (w0),
          [w1] "w" (w1),
          [w2] "w" (w2),
          [w3] "w" (w3),
    );
}

/// Four rounds, `wk` being the schedule words with their round constants added.
fn fourRounds(abcd: *V4, efgh: *V4, wk: V4) void {
    const abcd_before = abcd.*;
    abcd.* = asm (
        \\.arch_extension sha2
        \\sha256h.4s %[abcd], %[efgh], %[wk]
        : [abcd] "=w" (-> V4),
        : [_] "0" (abcd_before),
          [efgh] "w" (efgh.*),
          [wk] "w" (wk),
    );
    efgh.* = asm (
        \\.arch_extension sha2
        \\sha256h2.4s %[efgh], %[abcd], %[wk]
        : [efgh] "=w" (-> V4),
        : [_] "0" (efgh.*),
          [abcd] "w" (abcd_before),
          [wk] "w" (wk),
    );
}

// --- SHA-512 ---------------------------------------------------------------------------------------------------

/// FIPS 180-4, 4.2.3: the round constants, two to a vector.
const k512: [40]V2 = @bitCast([80]u64{
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC, 0x3956C25BF348B538,
    0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118, 0xD807AA98A3030242, 0x12835B0145706FBE,
    0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2, 0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235,
    0xC19BF174CF692694, 0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5, 0x983E5152EE66DFAB,
    0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4, 0xC6E00BF33DA88FC2, 0xD5A79147930AA725,
    0x06CA6351E003826F, 0x142929670A0E6E70, 0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED,
    0x53380D139D95B3DF, 0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30, 0xD192E819D6EF5218,
    0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8, 0x19A4C116B8D2D0C8, 0x1E376C085141AB53,
    0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8, 0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373,
    0x682E6FF3D6B2B8A3, 0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B, 0xCA273ECEEA26619C,
    0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178, 0x06F067AA72176FBA, 0x0A637DC5A2C898A6,
    0x113F9804BEF90DAE, 0x1B710B35131C471B, 0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC,
    0x431D67C49C100D4C, 0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
});

/// Compresses `blocks`, a whole number of 128-byte blocks, into `state`. The state is four pairs, (a, b), (c, d),
/// (e, f), (g, h), low lane first; each two rounds are one `sha512h` and `sha512h2` pair; each two schedule words,
/// from the ninth pair on, one `sha512su0` and `sha512su1` pair. The same arrangement as the Linux kernel's
/// arch/arm64/crypto/sha512-ce-core.S, written from the instructions' definitions in the Arm Architecture Reference
/// Manual.
pub fn compress512(state: *[8]u64, blocks: []const u8) void {
    std.debug.assert(blocks.len % 128 == 0);
    var ab: V2 = state[0..2].*;
    var cd: V2 = state[2..4].*;
    var ef: V2 = state[4..6].*;
    var gh: V2 = state[6..8].*;

    var rest = blocks;
    while (rest.len > 0) : (rest = rest[128..]) {
        var w: [8]V2 = undefined;
        inline for (&w, 0..) |*words, index| words.* = @byteSwap(@as(V2, @bitCast(rest[index * 16 ..][0..16].*)));

        const before = .{ ab, cd, ef, gh };
        inline for (0..40) |pair| {
            const slot = pair % 8;
            if (pair >= 8) {
                // W[t-7], W[t-6]: the high word of the pair four back and the low word of the pair three back.
                const back7 = high(w[(slot + 4) % 8], w[(slot + 5) % 8]);
                w[slot] = schedule512(w[slot], w[(slot + 1) % 8], w[(slot + 7) % 8], back7);
            }
            twoRounds(&ab, &cd, &ef, &gh, w[slot] +% k512[pair]);
        }
        ab +%= before[0];
        cd +%= before[1];
        ef +%= before[2];
        gh +%= before[3];
    }

    state[0..2].* = ab;
    state[2..4].* = cd;
    state[4..6].* = ef;
    state[6..8].* = gh;
}

/// The high lane of `x` and the low lane of `y`: `ext #8`.
fn high(x: V2, y: V2) V2 {
    return @shuffle(u64, x, y, [2]i32{ 1, ~@as(i32, 0) });
}

/// Rounds t and t+1. `wk` holds W[t] + K[t] (low lane) and W[t+1] + K[t+1].
fn twoRounds(ab: *V2, cd: *V2, ef: *V2, gh: *V2, wk: V2) void {
    // sha512h takes h + W[t] + K[t] in its high lane and g + W[t+1] + K[t+1] in its low one (g being the next h),
    // with (f, g) and (d, e), and returns T1 for both rounds, round t's high.
    const partial = gh.* +% high(wk, wk);
    const t1 = sha512h(partial, high(ef.*, gh.*), high(cd.*, ef.*));
    // The new e and f: c + T1 for round t+1, d + T1 for round t.
    const ef_next = cd.* +% t1;
    // sha512h2 adds T2 to each T1, with c and (a, b): the new a and b.
    const ab_next = sha512h2(t1, cd.*, ab.*);

    gh.* = ef.*;
    ef.* = ef_next;
    cd.* = ab.*;
    ab.* = ab_next;
}

fn sha512h(sums: V2, fg: V2, de: V2) V2 {
    return asm (
        \\.arch_extension sha3
        \\sha512h %[sums:q], %[fg:q], %[de].2d
        : [sums] "=w" (-> V2),
        : [_] "0" (sums),
          [fg] "w" (fg),
          [de] "w" (de),
    );
}

fn sha512h2(t1: V2, cd: V2, ab: V2) V2 {
    return asm (
        \\.arch_extension sha3
        \\sha512h2 %[t1:q], %[cd:q], %[ab].2d
        : [t1] "=w" (-> V2),
        : [_] "0" (t1),
          [cd] "w" (cd),
          [ab] "w" (ab),
    );
}

/// W[t], W[t+1] from the pairs before: `w0` (W[t-16], W[t-15]), `w1` (W[t-14], W[t-13]), `w7` (W[t-2], W[t-1])
/// and `back7` (W[t-7], W[t-6]).
fn schedule512(w0: V2, w1: V2, w7: V2, back7: V2) V2 {
    return asm (
        \\.arch_extension sha3
        \\sha512su0 %[w0].2d, %[w1].2d
        \\sha512su1 %[w0].2d, %[w7].2d, %[back7].2d
        : [w0] "=&w" (-> V2),
        : [_] "0" (w0),
          [w1] "w" (w1),
          [w7] "w" (w7),
          [back7] "w" (back7),
    );
}
