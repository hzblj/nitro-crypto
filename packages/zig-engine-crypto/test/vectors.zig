//! The published test vectors, each from its standard's own document (see the `source` field of each JSON
//! file, and test/vectors/README.md for how they were extracted):
//!
//!   bip39.json    Trezor's reference vectors: entropy, mnemonic, seed (passphrase "TREZOR") and master xprv
//!   bip32.json    BIP-32 test vectors 1 to 4, extended keys decoded from their xprv
//!   slip10.json   SLIP-0010 test vectors 1 and 2, for secp256k1 and Ed25519
//!   rfc8032.json  RFC 8032 section 7.1, Ed25519

const std = @import("std");
const engine = @import("engine");

const testing = std.testing;

fn load(comptime T: type, comptime file: []const u8) !std.json.Parsed(T) {
    return std.json.parseFromSlice(T, testing.allocator, @embedFile("vectors/" ++ file), .{ .ignore_unknown_fields = true });
}

fn bytes(comptime length: usize, hex: []const u8) ![length]u8 {
    var out: [length]u8 = undefined;
    if ((try std.fmt.hexToBytes(&out, hex)).len != length) return error.TestUnexpectedResult;
    return out;
}

fn hexAlloc(hex: []const u8) ![]u8 {
    const out = try testing.allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

/// Base58Check, for reading the xprv strings the vectors carry. Test-only: the engine itself has no Base58,
/// which belongs to the chains that use it.
fn base58CheckDecode(text: []const u8, out: *[78]u8) !void {
    const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    var number: [82]u8 = @splat(0);
    for (text) |char| {
        var carry: u32 = @intCast(std.mem.indexOfScalar(u8, alphabet, char) orelse return error.InvalidCharacter);
        var index: usize = number.len;
        while (index > 0) {
            index -= 1;
            carry += @as(u32, number[index]) * 58;
            number[index] = @truncate(carry);
            carry >>= 8;
        }
        if (carry != 0) return error.Overflow;
    }
    const checksum = engine.hash.sha256(&engine.hash.sha256(number[0..78]));
    if (!std.mem.eql(u8, checksum[0..4], number[78..82])) return error.BadChecksum;
    out.* = number[0..78].*;
}

const ExtendedPrivate = struct { chain_code: [32]u8, key: [32]u8 };

fn decodeXprv(xprv: []const u8) !ExtendedPrivate {
    var raw: [78]u8 = undefined;
    try base58CheckDecode(xprv, &raw);
    try testing.expectEqualSlices(u8, &.{ 0x04, 0x88, 0xAD, 0xE4 }, raw[0..4]);
    try testing.expectEqual(@as(u8, 0), raw[45]);
    return .{ .chain_code = raw[13..45].*, .key = raw[46..78].* };
}

// --- BIP-39 ----------------------------------------------------------------------------------------------

const Bip39 = struct {
    passphrase: []const u8,
    vectors: []const struct { entropy: []const u8, mnemonic: []const u8, seed: []const u8, xprv: []const u8 },
};

test "BIP-39: entropy, mnemonic, seed and master key of every Trezor vector" {
    const parsed = try load(Bip39, "bip39.json");
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 24), parsed.value.vectors.len);

    for (parsed.value.vectors) |vector| {
        const entropy = try hexAlloc(vector.entropy);
        defer testing.allocator.free(entropy);

        var sentence: engine.bip39.Sentence = .{};
        try engine.bip39.fromEntropy(entropy, &sentence);
        try testing.expectEqualStrings(vector.mnemonic, sentence.slice());

        var recovered: [32]u8 = undefined;
        const length = try engine.bip39.toEntropy(vector.mnemonic, &recovered);
        try testing.expectEqualSlices(u8, entropy, recovered[0..length]);

        var seed: [64]u8 = undefined;
        try engine.bip39.toSeed(vector.mnemonic, parsed.value.passphrase, &seed);
        try testing.expectEqualSlices(u8, &try bytes(64, vector.seed), &seed);

        const master = try engine.bip32.master(&seed);
        const expected = try decodeXprv(vector.xprv);
        try testing.expectEqualSlices(u8, &expected.chain_code, &master.chain_code);
        try testing.expectEqualSlices(u8, &expected.key, &master.key);
    }
}

test "BIP-39: every single-word change of a vector mnemonic breaks its checksum or its words" {
    const parsed = try load(Bip39, "bip39.json");
    defer parsed.deinit();
    const mnemonic = parsed.value.vectors[5].mnemonic;
    var buffer: [engine.bip39.max_sentence_length]u8 = undefined;
    @memcpy(buffer[0..mnemonic.len], mnemonic);
    // Swap the first letter of the last word for every other letter: each result is either not a word, or a
    // word whose bits break the checksum (a 1 in 16 chance per swap of still matching is allowed for).
    const last = std.mem.lastIndexOfScalar(u8, mnemonic, ' ').? + 1;
    var accepted: usize = 0;
    for ('a'..'z' + 1) |letter| {
        if (letter == mnemonic[last]) continue;
        buffer[last] = @intCast(letter);
        engine.bip39.validate(buffer[0..mnemonic.len]) catch continue;
        accepted += 1;
    }
    try testing.expect(accepted <= 3);
}

// --- BIP-32 and SLIP-0010 --------------------------------------------------------------------------------

const Bip32 = struct {
    vectors: []const struct {
        seed: []const u8,
        chains: []const struct { path: []const u8, chainCode: []const u8, private: []const u8 },
    },
};

test "BIP-32: test vectors 1 to 4, every chain" {
    const parsed = try load(Bip32, "bip32.json");
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 4), parsed.value.vectors.len);

    for (parsed.value.vectors) |vector| {
        const seed = try hexAlloc(vector.seed);
        defer testing.allocator.free(seed);
        for (vector.chains) |chain| {
            const path = try engine.path.parse(chain.path);
            const derived = try engine.bip32.derive(seed, &path);
            try testing.expectEqualSlices(u8, &try bytes(32, chain.chainCode), &derived.chain_code);
            try testing.expectEqualSlices(u8, &try bytes(32, chain.private), &derived.key);
        }
    }
}

const Slip10 = struct {
    vectors: []const struct {
        curve: []const u8,
        seed: []const u8,
        chains: []const struct { path: []const u8, fingerprint: []const u8, chainCode: []const u8, private: []const u8, public: []const u8 },
    },
};

test "SLIP-0010: secp256k1 and Ed25519 vectors, keys, public keys and parent fingerprints" {
    const parsed = try load(Slip10, "slip10.json");
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 4), parsed.value.vectors.len);

    for (parsed.value.vectors) |vector| {
        const seed = try hexAlloc(vector.seed);
        defer testing.allocator.free(seed);
        const ed25519 = std.mem.eql(u8, vector.curve, "ed25519");

        for (vector.chains) |chain| {
            const path = try engine.path.parse(chain.path);
            const expected_public = try bytes(33, chain.public);
            if (ed25519) {
                const derived = try engine.slip10.derive(seed, &path);
                try testing.expectEqualSlices(u8, &try bytes(32, chain.chainCode), &derived.chain_code);
                try testing.expectEqualSlices(u8, &try bytes(32, chain.private), &derived.key);
                // SLIP-0010 writes an Ed25519 public key with a 0x00 prefix.
                try testing.expectEqual(@as(u8, 0), expected_public[0]);
                const pair = try engine.ed25519.keyPair(&derived.key);
                try testing.expectEqualSlices(u8, expected_public[1..], &engine.ed25519.publicKey(&pair));
            } else {
                const derived = try engine.bip32.derive(seed, &path);
                try testing.expectEqualSlices(u8, &try bytes(32, chain.chainCode), &derived.chain_code);
                try testing.expectEqualSlices(u8, &try bytes(32, chain.private), &derived.key);
                const public_key = try engine.secp256k1.publicKeyFromPrivate(&derived.key);
                try testing.expectEqualSlices(u8, &expected_public, &engine.secp256k1.compressedPublicKey(&public_key));
                if (path.depth > 0) {
                    var parent_path = path;
                    parent_path.depth -= 1;
                    const parent = try engine.bip32.derive(seed, &parent_path);
                    const expected_fingerprint = std.mem.readInt(u32, &try bytes(4, chain.fingerprint), .big);
                    try testing.expectEqual(expected_fingerprint, try engine.bip32.fingerprint(&parent.key));
                }
            }
        }
    }
}

// --- Ed25519 ---------------------------------------------------------------------------------------------

const Rfc8032 = struct {
    vectors: []const struct { name: []const u8, secretKey: []const u8, publicKey: []const u8, message: []const u8, signature: []const u8 },
};

test "RFC 8032: public keys, deterministic signatures and verification" {
    const parsed = try load(Rfc8032, "rfc8032.json");
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 5), parsed.value.vectors.len);

    for (parsed.value.vectors) |vector| {
        const secret = try bytes(32, vector.secretKey);
        const public_key = try bytes(32, vector.publicKey);
        const signature = try bytes(64, vector.signature);
        const message = try hexAlloc(vector.message);
        defer testing.allocator.free(message);

        const pair = try engine.ed25519.keyPair(&secret);
        try testing.expectEqualSlices(u8, &public_key, &engine.ed25519.publicKey(&pair));
        try testing.expectEqualSlices(u8, &signature, &try engine.ed25519.sign(&pair, message));
        try engine.ed25519.verify(&public_key, message, &signature);
    }
}

// --- the vault, end to end -------------------------------------------------------------------------------

test "the vault reproduces the vectors through handles" {
    var vault: engine.keys.Vault = .{};
    const abandon = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const seed = try engine.keys.seedFromMnemonic(&vault, abandon, "TREZOR");

    // Trezor vector 0's master key, by its BIP-32 fingerprint.
    const master = try decodeXprv("xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF");
    try testing.expectEqual(try engine.bip32.fingerprint(&master.key), try engine.keys.seedFingerprint(&vault, seed));

    // RFC 8032 test 1, imported and signed through a handle.
    const parsed = try load(Rfc8032, "rfc8032.json");
    defer parsed.deinit();
    const vector = parsed.value.vectors[0];
    const key = try engine.keys.import(&vault, .ed25519, &try bytes(32, vector.secretKey));
    var signature: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 64), try engine.keys.sign(&vault, key, "", &signature));
    try testing.expectEqualSlices(u8, &try bytes(64, vector.signature), &signature);

    try vault.destroy(seed);
    try vault.destroy(key);
    try testing.expectEqual(@as(u32, 0), vault.count());
}

// --- Wycheproof ------------------------------------------------------------------------------------------

const WycheproofTest = struct { tcId: u32, comment: []const u8, msg: []const u8, sig: []const u8, result: []const u8 };

const WycheproofEcdsa = struct {
    testGroups: []const struct { publicKey: struct { uncompressed: []const u8 }, tests: []const WycheproofTest },
};

/// Whether S (the second half of a 64-byte P1363 signature) is in the upper half of the group order.
fn upperS(signature: []const u8) bool {
    const half_order = [32]u8{
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
    };
    return std.mem.order(u8, signature[32..64], &half_order) == .gt;
}

// C2SP Wycheproof, ecdsa_secp256k1_sha256_p1363_test.json. Every invalid signature is refused. A valid one
// verifies unless its S is in the upper half: this engine's policy refuses those (`InvalidSignature`).
test "Wycheproof: secp256k1 ECDSA with SHA-256" {
    const parsed = try load(WycheproofEcdsa, "wycheproof_ecdsa_secp256k1_sha256_p1363_test.json");
    defer parsed.deinit();
    var counts: struct { verified: usize = 0, upper_s: usize = 0, refused: usize = 0 } = .{};

    for (parsed.value.testGroups) |group| {
        const public_key = try hexAlloc(group.publicKey.uncompressed);
        defer testing.allocator.free(public_key);
        for (group.tests) |case| {
            const message = try hexAlloc(case.msg);
            defer testing.allocator.free(message);
            const signature = try hexAlloc(case.sig);
            defer testing.allocator.free(signature);
            const digest = engine.hash.sha256(message);

            const result = if (signature.len == 64) engine.secp256k1.verify(public_key, &digest, signature[0..64]) else error.InvalidLength;
            const valid = std.mem.eql(u8, case.result, "valid");
            if (valid and signature.len == 64 and upperS(signature)) {
                try testing.expectError(error.InvalidSignature, result);
                counts.upper_s += 1;
            } else if (valid) {
                result catch |err| {
                    std.debug.print("tcId {d} ({s}): {s}\n", .{ case.tcId, case.comment, @errorName(err) });
                    return err;
                };
                counts.verified += 1;
            } else {
                if (result) |_| {
                    std.debug.print("tcId {d} ({s}) verified but is invalid\n", .{ case.tcId, case.comment });
                    return error.TestUnexpectedResult;
                } else |_| counts.refused += 1;
            }
        }
    }
    try testing.expectEqual(@as(usize, 252), counts.verified + counts.upper_s + counts.refused);
    try testing.expect(counts.verified > 0 and counts.upper_s > 0);
}

const WycheproofEddsa = struct {
    testGroups: []const struct { publicKey: struct { pk: []const u8 }, tests: []const WycheproofTest },
};

// C2SP Wycheproof, ed25519_test.json. Valid verifies, invalid is refused; "acceptable" (encodings some
// implementations take) only has to not crash.
test "Wycheproof: Ed25519" {
    const parsed = try load(WycheproofEddsa, "wycheproof_ed25519_test.json");
    defer parsed.deinit();
    var total: usize = 0;

    for (parsed.value.testGroups) |group| {
        const public_key = try hexAlloc(group.publicKey.pk);
        defer testing.allocator.free(public_key);
        for (group.tests) |case| {
            total += 1;
            const message = try hexAlloc(case.msg);
            defer testing.allocator.free(message);
            const signature = try hexAlloc(case.sig);
            defer testing.allocator.free(signature);

            const result = if (signature.len == 64 and public_key.len == 32)
                engine.ed25519.verify(public_key[0..32], message, signature[0..64])
            else
                error.InvalidLength;

            if (std.mem.eql(u8, case.result, "valid")) {
                result catch |err| {
                    std.debug.print("tcId {d} ({s}): {s}\n", .{ case.tcId, case.comment, @errorName(err) });
                    return err;
                };
            } else if (std.mem.eql(u8, case.result, "invalid")) {
                if (result) |_| {
                    std.debug.print("tcId {d} ({s}) verified but is invalid\n", .{ case.tcId, case.comment });
                    return error.TestUnexpectedResult;
                } else |_| {}
            }
        }
    }
    try testing.expectEqual(@as(usize, 210), total);
}
