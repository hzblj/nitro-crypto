//! BIP-39 mnemonics, English word list: fresh sentences from OS entropy, entropy to sentence, sentence to entropy
//! (with the checksum), and the seed (PBKDF2-HMAC-SHA512, 2048 rounds, salt "mnemonic" + passphrase).
//!
//! A mnemonic is a secret, so a word is never looked up by branching on it: both directions scan all 2048
//! entries and keep the match with masks, which costs about 20 µs per word and leaks nothing about which word
//! it was through timing or the cache. Normalization (NFKD) is the caller's: for the English list it means
//! lowercase ASCII, words separated by single spaces, which is what this file accepts and nothing else.

const std = @import("std");

const entropy_source = @import("../os/entropy.zig");
const hash = @import("../hash.zig");
const secure = @import("../core/secure.zig");
const Error = @import("../core/status.zig").Error;

pub const seed_length = 64;
pub const rounds = 2048;
pub const max_passphrase_length = 1024;

const word_count = 2048;
const max_word_length = 8;
const salt_prefix = "mnemonic";

/// The official English list (bitcoin/bips bip-0039/english.txt, SHA-256 2f5eed53…dbda; a test pins it).
const list_source = @embedFile("bip39_english.txt");

const Word = [max_word_length]u8;

/// Each word padded with zeros to eight bytes, and its length: a fixed shape to scan without branches.
const List = struct {
    words: [word_count]Word,
    lengths: [word_count]u8,
};

const list: List = parse: {
    @setEvalBranchQuota(100_000);
    var words: [word_count]Word = undefined;
    var lengths: [word_count]u8 = undefined;
    var lines = std.mem.tokenizeScalar(u8, list_source, '\n');
    var index: usize = 0;
    while (lines.next()) |line| : (index += 1) {
        if (line.len > max_word_length) @compileError("a BIP-39 word longer than eight letters");
        words[index] = @splat(0);
        @memcpy(words[index][0..line.len], line);
        lengths[index] = line.len;
    }
    if (index != word_count) @compileError("the BIP-39 list must have 2048 words");
    break :parse .{ .words = words, .lengths = lengths };
};

/// Entropy lengths BIP-39 defines (128 to 256 bits in steps of 32), and their word counts.
pub fn entropyLength(words: usize) Error!usize {
    return switch (words) {
        12, 15, 18, 21, 24 => words * 11 * 32 / 33 / 8,
        else => error.InvalidMnemonic,
    };
}

pub const max_words = 24;
pub const max_sentence_length = max_words * max_word_length + (max_words - 1);

/// The longest sentence of `words` words: every word eight letters, single spaces between them. What a caller
/// sizes its buffer by before a sentence of that many words is generated.
pub fn maxSentenceLength(words: usize) usize {
    return words * (max_word_length + 1) - 1;
}

/// A mnemonic sentence in a fixed buffer, so it never touches an allocator. Zero it when done.
pub const Sentence = struct {
    bytes: [max_sentence_length]u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *const Sentence) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn zero(self: *Sentence) void {
        secure.zero(&self.bytes);
        self.len = 0;
    }

    fn append(self: *Sentence, word: []const u8) void {
        if (self.len > 0) {
            self.bytes[self.len] = ' ';
            self.len += 1;
        }
        @memcpy(self.bytes[self.len..][0..word.len], word);
        self.len += word.len;
    }
};

/// All 0xFF when `a == b`, else 0, without a branch.
fn maskEqual(a: u16, b: u16) u8 {
    const difference: u32 = a ^ b;
    // (difference - 1) has its top bit set only when difference was 0.
    const is_zero: u32 = (difference -% 1) >> 31;
    return @as(u8, 0) -% @as(u8, @intCast(is_zero));
}

/// The word at `index`, gathered from every entry under a mask.
fn wordAt(index: u11, out: *Word) u8 {
    var length: u8 = 0;
    out.* = @splat(0);
    for (list.words, list.lengths, 0..) |word, word_length, candidate| {
        const mask = maskEqual(index, @intCast(candidate));
        for (out, word) |*byte, letter| byte.* |= letter & mask;
        length |= word_length & mask;
    }
    return length;
}

/// The index of `word`, compared against every entry; `null` when it is not in the list.
fn indexOf(word: []const u8) ?u11 {
    if (word.len == 0 or word.len > max_word_length) return null;
    var padded: Word = @splat(0);
    defer secure.zero(&padded);
    @memcpy(padded[0..word.len], word);

    var found: u8 = 0;
    var index: u16 = 0;
    for (list.words, list.lengths, 0..) |candidate, candidate_length, position| {
        var difference: u8 = @as(u8, @intCast(word.len)) ^ candidate_length;
        for (padded, candidate) |a, b| difference |= a ^ b;
        const mask = maskEqual(difference, 0);
        found |= mask;
        index |= @as(u16, @intCast(position)) & (@as(u16, mask) | (@as(u16, mask) << 8));
    }
    return if (found != 0) @intCast(index) else null;
}

/// Entropy and checksum bits (at most 256 + 8), and a spare byte for the three-byte window of the last group.
const Bits = [34]u8;

fn readGroup(bits: *const Bits, group: usize) u11 {
    const bit = group * 11;
    const window = @as(u32, bits[bit / 8]) << 16 | @as(u32, bits[bit / 8 + 1]) << 8 | bits[bit / 8 + 2];
    return @truncate(window >> @intCast(24 - 11 - bit % 8));
}

fn writeGroup(bits: *Bits, group: usize, value: u11) void {
    const bit = group * 11;
    const shifted = @as(u32, value) << @intCast(24 - 11 - bit % 8);
    bits[bit / 8] |= @truncate(shifted >> 16);
    bits[bit / 8 + 1] |= @truncate(shifted >> 8);
    bits[bit / 8 + 2] |= @truncate(shifted);
}

/// The first ENT / 32 bits of SHA-256(entropy), left-aligned in a byte.
fn checksum(entropy: []const u8) u8 {
    const digest = hash.sha256(entropy);
    const checksum_bits = entropy.len * 8 / 32; // 4 to 8
    const keep: u8 = @as(u8, 0xFF) << @intCast(8 - checksum_bits);
    return digest[0] & keep;
}

/// The mnemonic for `entropy` (16, 20, 24, 28 or 32 bytes).
pub fn fromEntropy(entropy: []const u8, out: *Sentence) Error!void {
    switch (entropy.len) {
        16, 20, 24, 28, 32 => {},
        else => return error.InvalidLength,
    }
    var bits: Bits = @splat(0);
    defer secure.zero(&bits);
    @memcpy(bits[0..entropy.len], entropy);
    bits[entropy.len] = checksum(entropy);

    out.* = .{};
    const words = (entropy.len * 8 + entropy.len * 8 / 32) / 11;
    var word: Word = undefined;
    defer secure.zero(&word);
    for (0..words) |group| {
        const length = wordAt(readGroup(&bits, group), &word);
        out.append(word[0..length]);
    }
}

/// A fresh mnemonic of `words` words (12, 15, 18, 21 or 24) from the OS CSPRNG, into `out`. The entropy is zeroed
/// before this returns; the sentence is the caller's to zero.
pub fn generate(words: usize, out: *Sentence) Error!void {
    const length = entropyLength(words) catch return error.InvalidArgument;
    var bytes: [32]u8 = undefined;
    defer secure.zero(&bytes);
    try entropy_source.fill(bytes[0..length]);
    try fromEntropy(bytes[0..length], out);
}

/// The entropy a mnemonic encodes, after its checksum: written into the front of `out`, length returned.
pub fn toEntropy(mnemonic: []const u8, out: *[32]u8) Error!usize {
    if (mnemonic.len == 0 or mnemonic.len > max_sentence_length) return error.InvalidMnemonic;

    var bits: Bits = @splat(0);
    defer secure.zero(&bits);
    var words: usize = 0;
    var tokens = std.mem.splitScalar(u8, mnemonic, ' ');
    while (tokens.next()) |token| : (words += 1) {
        if (words == max_words) return error.InvalidMnemonic;
        const index = indexOf(token) orelse return error.InvalidMnemonic;
        writeGroup(&bits, words, index);
    }

    const length = try entropyLength(words);
    const expected = checksum(bits[0..length]);
    const valid = maskEqual(expected, bits[length]) != 0;
    @memcpy(out[0..length], bits[0..length]);
    if (!valid) {
        secure.zero(out);
        return error.MnemonicChecksum;
    }
    return length;
}

pub fn validate(mnemonic: []const u8) Error!void {
    var entropy: [32]u8 = undefined;
    defer secure.zero(&entropy);
    _ = try toEntropy(mnemonic, &entropy);
}

/// The BIP-39 seed of a sentence, whatever its words: BIP-39 defines the seed for any string, and checking the
/// mnemonic first is the caller's choice (the C ABI always does).
pub fn toSeed(mnemonic: []const u8, passphrase: []const u8, out: *[seed_length]u8) Error!void {
    if (passphrase.len > max_passphrase_length) return error.InvalidLength;
    var salt: [salt_prefix.len + max_passphrase_length]u8 = undefined;
    defer secure.zero(&salt);
    @memcpy(salt[0..salt_prefix.len], salt_prefix);
    @memcpy(salt[salt_prefix.len..][0..passphrase.len], passphrase);

    std.crypto.pwhash.pbkdf2(out, mnemonic, salt[0 .. salt_prefix.len + passphrase.len], rounds, hash.HmacSha512) catch
        return error.Internal;
}

const testing = std.testing;

test "the embedded list is the official one" {
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda");
    try testing.expectEqualSlices(u8, &expected, &hash.sha256(list_source));
}

test "word lookups agree with the list in both directions" {
    var word: Word = undefined;
    for ([_]u11{ 0, 1, 3, 1024, 2046, 2047 }) |index| {
        const length = wordAt(index, &word);
        try testing.expectEqualSlices(u8, list.words[index][0..list.lengths[index]], word[0..length]);
        try testing.expectEqual(@as(?u11, index), indexOf(word[0..length]));
    }
    try testing.expectEqual(@as(?u11, 0), indexOf("abandon"));
    try testing.expectEqual(@as(?u11, 2047), indexOf("zoo"));
    try testing.expectEqual(@as(?u11, null), indexOf("abando"));
    try testing.expectEqual(@as(?u11, null), indexOf("abandons"));
    try testing.expectEqual(@as(?u11, null), indexOf("Abandon"));
    try testing.expectEqual(@as(?u11, null), indexOf(""));
    try testing.expectEqual(@as(?u11, null), indexOf("abandonabandon"));
}

test "every word round-trips through its index" {
    var word: Word = undefined;
    for (0..word_count) |index| {
        const length = wordAt(@intCast(index), &word);
        try testing.expectEqual(@as(?u11, @intCast(index)), indexOf(word[0..length]));
    }
}

test "entropy lengths and word counts" {
    try testing.expectEqual(@as(usize, 16), try entropyLength(12));
    try testing.expectEqual(@as(usize, 20), try entropyLength(15));
    try testing.expectEqual(@as(usize, 24), try entropyLength(18));
    try testing.expectEqual(@as(usize, 28), try entropyLength(21));
    try testing.expectEqual(@as(usize, 32), try entropyLength(24));
    try testing.expectError(error.InvalidMnemonic, entropyLength(13));
    try testing.expectError(error.InvalidMnemonic, entropyLength(0));
}

test "malformed sentences are refused" {
    const valid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    try validate(valid);
    try testing.expectError(error.InvalidMnemonic, validate(""));
    try testing.expectError(error.InvalidMnemonic, validate(" " ++ valid));
    try testing.expectError(error.InvalidMnemonic, validate(valid ++ " "));
    try testing.expectError(error.InvalidMnemonic, validate("abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"));
    try testing.expectError(error.InvalidMnemonic, validate("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"));
    try testing.expectError(error.InvalidMnemonic, validate("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon About"));
    try testing.expectError(error.InvalidMnemonic, validate("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon xyzzy"));
    try testing.expectError(error.MnemonicChecksum, validate("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"));
    try testing.expectError(error.InvalidMnemonic, validate(("abandon " ** 24) ++ "abandon"));
}

test "a short entropy buffer is refused" {
    var sentence: Sentence = .{};
    try testing.expectError(error.InvalidLength, fromEntropy(&[_]u8{0} ** 15, &sentence));
    try testing.expectError(error.InvalidLength, fromEntropy(&[_]u8{0} ** 33, &sentence));
}

test "generated sentences validate, have the asked word count, and differ" {
    for ([_]usize{ 12, 15, 18, 21, 24 }) |words| {
        var a: Sentence = .{};
        defer a.zero();
        var b: Sentence = .{};
        defer b.zero();
        try generate(words, &a);
        try generate(words, &b);
        try validate(a.slice());
        try testing.expectEqual(words, std.mem.count(u8, a.slice(), " ") + 1);
        try testing.expect(a.len <= maxSentenceLength(words));
        try testing.expect(!std.mem.eql(u8, a.slice(), b.slice()));
    }
    var sentence: Sentence = .{};
    try testing.expectError(error.InvalidArgument, generate(13, &sentence));
    try testing.expectError(error.InvalidArgument, generate(0, &sentence));
    try testing.expectEqual(max_sentence_length, maxSentenceLength(max_words));
}

test "an over-long passphrase is refused" {
    var seed: [seed_length]u8 = undefined;
    try testing.expectError(error.InvalidLength, toSeed("x", &[_]u8{'a'} ** (max_passphrase_length + 1), &seed));
    try toSeed("x", &[_]u8{'a'} ** max_passphrase_length, &seed);
}

fn fuzzMnemonic(_: void, smith: *testing.Smith) anyerror!void {
    // Either raw bytes, or a sentence assembled from real words with a random count: the second reaches the
    // checksum, the first the tokenizer.
    var buffer: [max_sentence_length + 16]u8 = undefined;
    var length: usize = 0;
    if (smith.value(bool)) {
        length = smith.slice(&buffer);
    } else {
        const words = smith.valueRangeAtMost(u8, 1, 26);
        for (0..words) |index| {
            const word_index = smith.value(u11);
            const word = list.words[word_index][0..list.lengths[word_index]];
            if (length + word.len + 1 > buffer.len) break;
            if (index > 0) {
                buffer[length] = ' ';
                length += 1;
            }
            @memcpy(buffer[length..][0..word.len], word);
            length += word.len;
        }
    }
    var entropy: [32]u8 = undefined;
    const entropy_length = toEntropy(buffer[0..length], &entropy) catch return;
    // Whatever validates re-encodes to exactly the same sentence.
    var sentence: Sentence = .{};
    try fromEntropy(entropy[0..entropy_length], &sentence);
    try testing.expectEqualStrings(buffer[0..length], sentence.slice());
}

test "property: mnemonics never crash the parser, and what validates round-trips" {
    try @import("../testing/property.zig").check(fuzzMnemonic, 3000, 2);
}

test "fuzz: mnemonics never crash the parser, and what validates round-trips" {
    try testing.fuzz({}, fuzzMnemonic, .{});
}
