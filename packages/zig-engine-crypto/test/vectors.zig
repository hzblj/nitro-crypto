//! The published test vectors, each from its standard's own document (see the `source` field of each JSON
//! file, and test/vectors/README.md for how they were extracted):
//!
//!   bip39.json    Trezor's reference vectors: entropy, mnemonic, seed (passphrase "TREZOR") and master xprv
//!   bip32.json    BIP-32 test vectors 1 to 4, extended keys decoded from their xprv
//!   slip10.json   SLIP-0010 test vectors 1 and 2, for secp256k1 and Ed25519
//!   rfc8032.json  RFC 8032 section 7.1, Ed25519
//!   bip340.csv    BIP-340's test-vectors.csv, Schnorr signatures (verbatim)
//!   bip341.json   BIP-341's wallet-test-vectors.json, Taproot output keys and key path signatures (verbatim)
//!
//! And two parity checks against an independent implementation: backup.json and backup_key.json (README there).

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
        chains: []const struct { path: []const u8, chainCode: []const u8, private: []const u8, xpub: []const u8 },
    },
};

/// The 74 bytes after an xpub's 4-byte version: what `extendedPublic` and `publicDerive` produce.
fn decodeXpub(xpub: []const u8) ![74]u8 {
    var raw: [78]u8 = undefined;
    try base58CheckDecode(xpub, &raw);
    try testing.expectEqualSlices(u8, &.{ 0x04, 0x88, 0xB2, 0x1E }, raw[0..4]);
    return raw[4..78].*;
}

test "BIP-32: the published xpub of every chain but the master, and every non-hardened step derived publicly" {
    const parsed = try load(Bip32, "bip32.json");
    defer parsed.deinit();
    var public_steps: usize = 0;

    for (parsed.value.vectors) |vector| {
        const seed = try hexAlloc(vector.seed);
        defer testing.allocator.free(seed);
        for (vector.chains, 0..) |chain, position| {
            const path = try engine.path.parse(chain.path);
            if (path.steps().len == 0) {
                try testing.expectError(error.InvalidPath, engine.bip32.extendedPublic(seed, &path));
                continue;
            }

            const expected = try decodeXpub(chain.xpub);
            try testing.expectEqualSlices(u8, &expected, &try engine.bip32.extendedPublic(seed, &path));

            // A chain one non-hardened step below the one before it: the same key from the parent's xpub alone.
            if (position == 0) continue;
            const step = path.steps()[path.steps().len - 1];
            const parent = try decodeXpub(vector.chains[position - 1].xpub);
            if (step >= engine.path.hardened) {
                try testing.expectError(error.InvalidPath, engine.bip32.publicChild(&parent, step));
            } else {
                try testing.expectEqualSlices(u8, &expected, &try engine.bip32.publicChild(&parent, step));
                public_steps += 1;
            }
        }
    }

    // Vectors 1 and 2 have three non-hardened steps between them (m/0'/1, m/0'/1/2'/2, m/0).
    try testing.expect(public_steps >= 3);
}

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

// --- BIP-340 and BIP-341 ---------------------------------------------------------------------------------

/// A row of BIP-340's test-vectors.csv: index, secret key, public key, aux_rand, message, signature, verification
/// result, comment. The file is the BIP's (whose CRLF line endings Git may have turned into LF; either reads), and
/// no comment holds a comma.
const Bip340 = struct {
    index: []const u8,
    secret: []const u8,
    public: []const u8,
    aux: []const u8,
    message: []const u8,
    signature: []const u8,
    valid: bool,
    comment: []const u8,
};

fn bip340Rows(rows: *[32]Bip340) ![]const Bip340 {
    var lines = std.mem.tokenizeAny(u8, @embedFile("vectors/bip340.csv"), "\r\n");
    _ = lines.next(); // the header
    var count: usize = 0;
    while (lines.next()) |line| : (count += 1) {
        var fields = std.mem.splitScalar(u8, line, ',');
        var values: [8][]const u8 = undefined;
        for (&values) |*value| value.* = fields.next() orelse return error.TestUnexpectedResult;
        if (fields.next() != null) return error.TestUnexpectedResult;
        rows[count] = .{
            .index = values[0],
            .secret = values[1],
            .public = values[2],
            .aux = values[3],
            .message = values[4],
            .signature = values[5],
            .valid = std.mem.eql(u8, values[6], "TRUE"),
            .comment = values[7],
        };
    }
    return rows[0..count];
}

test "BIP-340: every published vector, signed with its aux_rand through a handle, and verified" {
    var buffer: [32]Bip340 = undefined;
    const rows = try bip340Rows(&buffer);
    try testing.expectEqual(@as(usize, 19), rows.len);
    var vault: engine.keys.Vault = .{};
    var signed: usize = 0;

    for (rows) |row| {
        const public_key = try bytes(32, row.public);
        const signature = try bytes(64, row.signature);
        const message = try hexAlloc(row.message);
        defer testing.allocator.free(message);

        if (row.secret.len > 0) {
            const key = try engine.keys.import(&vault, .secp256k1, &try bytes(32, row.secret));
            defer vault.destroy(key) catch unreachable;
            var out: [64]u8 = undefined;
            _ = try engine.keys.xOnlyPublicKey(&vault, key, &out);
            try testing.expectEqualSlices(u8, &public_key, out[0..32]);
            _ = try engine.keys.signSchnorrWith(&vault, key, message, .none, &try bytes(32, row.aux), &out);
            try testing.expectEqualSlices(u8, &signature, &out);
            signed += 1;
        }

        const result = engine.secp256k1.verifySchnorr(&public_key, message, &signature);
        if (row.valid) {
            result catch |err| {
                std.debug.print("BIP-340 vector {s}: {s}\n", .{ row.index, @errorName(err) });
                return err;
            };
        } else if (std.mem.startsWith(u8, row.comment, "public key")) {
            try testing.expectError(error.InvalidPublicKey, result);
        } else {
            try testing.expectError(error.VerificationFailed, result);
        }
    }
    try testing.expectEqual(@as(usize, 8), signed);
    try testing.expectEqual(@as(u32, 0), vault.count());
}

const Bip341 = struct {
    scriptPubKey: []const struct {
        given: struct { internalPubkey: []const u8 },
        intermediary: struct { merkleRoot: ?[]const u8, tweakedPubkey: []const u8 },
        expected: struct { scriptPubKey: []const u8, scriptPathControlBlocks: ?[]const []const u8 = null },
    },
    keyPathSpending: []const struct {
        inputSpending: []const struct {
            given: struct { internalPrivkey: []const u8, merkleRoot: ?[]const u8 },
            intermediary: struct { internalPubkey: []const u8, tweakedPrivkey: []const u8, sigHash: []const u8 },
            expected: struct { witness: []const []const u8 },
        },
    },
};

fn merkleRoot(hex: ?[]const u8) !?[32]u8 {
    return if (hex) |root| try bytes(32, root) else null;
}

test "BIP-341: output keys and their parity from every scriptPubKey vector" {
    const parsed = try load(Bip341, "bip341.json");
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 7), parsed.value.scriptPubKey.len);

    for (parsed.value.scriptPubKey) |vector| {
        const root = try merkleRoot(vector.intermediary.merkleRoot);
        const output = try engine.secp256k1.taprootTweak(&try bytes(32, vector.given.internalPubkey), if (root) |*r| r else null);
        try testing.expectEqualSlices(u8, &try bytes(32, vector.intermediary.tweakedPubkey), output[1..33]);
        // A P2TR scriptPubKey is OP_1 OP_PUSHBYTES_32 and the output key.
        try testing.expectEqualSlices(u8, &try bytes(34, vector.expected.scriptPubKey), &([_]u8{ 0x51, 0x20 } ++ output[1..33].*));
        // A control block's first byte is the leaf version with the output key's parity in its low bit.
        for (vector.expected.scriptPathControlBlocks orelse &.{}) |block| {
            const first = try bytes(1, block[0..2]);
            try testing.expectEqual(output[0] - 2, first[0] & 1);
        }
    }
}

test "BIP-341: every key path signature, through a handle tweaked inside the engine" {
    const parsed = try load(Bip341, "bip341.json");
    defer parsed.deinit();
    var vault: engine.keys.Vault = .{};
    var inputs: usize = 0;
    // The vectors are signed with aux_rand all zero.
    const aux: [32]u8 = @splat(0);

    for (parsed.value.keyPathSpending) |spending| {
        for (spending.inputSpending) |input| {
            const root = try merkleRoot(input.given.merkleRoot);
            const root_pointer: ?*const [32]u8 = if (root) |*r| r else null;
            const internal = try bytes(32, input.intermediary.internalPubkey);
            const sighash = try bytes(32, input.intermediary.sigHash);
            const output = try engine.secp256k1.taprootTweak(&internal, root_pointer);

            const key = try engine.keys.import(&vault, .secp256k1, &try bytes(32, input.given.internalPrivkey));
            defer vault.destroy(key) catch unreachable;
            var out: [64]u8 = undefined;
            _ = try engine.keys.xOnlyPublicKey(&vault, key, &out);
            try testing.expectEqualSlices(u8, &internal, out[0..32]);
            _ = try engine.keys.signSchnorrWith(&vault, key, &sighash, .{ .taproot = root_pointer }, &aux, &out);
            // The witness is the signature, with the sighash type appended when it is not SIGHASH_DEFAULT.
            try testing.expectEqualSlices(u8, &try bytes(64, input.expected.witness[0][0..128]), &out);
            try engine.secp256k1.verifySchnorr(output[1..33], &sighash, &out);

            // The tweaked private key BIP-341 lists is the key of the output key.
            const tweaked = try engine.secp256k1.xOnlyFromPrivate(&try bytes(32, input.intermediary.tweakedPrivkey));
            try testing.expectEqualSlices(u8, output[1..33], &tweaked);
            inputs += 1;
        }
    }
    try testing.expectEqual(@as(usize, 7), inputs);
    try testing.expectEqual(@as(u32, 0), vault.count());
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

const Backup = struct {
    vectors: []const struct {
        backup: []const u8,
        entropy: []const u8,
        memory: u32,
        nonce: []const u8,
        passes: u32,
        password: []const u8,
        salt: []const u8,
    },
};

test "backups: the engine seals and opens what an independent implementation does, byte for byte" {
    const parsed = try load(Backup, "backup.json");
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 3), parsed.value.vectors.len);

    for (parsed.value.vectors) |vector| {
        const entropy = try hexAlloc(vector.entropy);
        defer testing.allocator.free(entropy);
        const expected = try hexAlloc(vector.backup);
        defer testing.allocator.free(expected);
        const salt = try bytes(16, vector.salt);
        const nonce = try bytes(24, vector.nonce);

        var sealed: [engine.backup.max_length]u8 = undefined;
        const params: engine.backup.Params = .{ .memory = vector.memory, .passes = vector.passes };
        const written = try engine.backup.sealWith(entropy, vector.password, params, &salt, &nonce, &sealed);
        try testing.expectEqualSlices(u8, expected, sealed[0..written]);

        var opened: [engine.backup.max_entropy_length]u8 = undefined;
        const length = try engine.backup.open(expected, vector.password, &opened);
        try testing.expectEqualSlices(u8, entropy, opened[0..length]);
    }
}

const BackupKey = struct {
    vectors: []const struct { backup: []const u8, entropy: []const u8, key: []const u8, nonce: []const u8, salt: []const u8 },
};

test "key-sealed backups: the engine seals and opens what an independent implementation does, byte for byte" {
    const parsed = try load(BackupKey, "backup_key.json");
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 3), parsed.value.vectors.len);

    for (parsed.value.vectors) |vector| {
        const entropy = try hexAlloc(vector.entropy);
        defer testing.allocator.free(entropy);
        const expected = try hexAlloc(vector.backup);
        defer testing.allocator.free(expected);
        const key = try bytes(32, vector.key);

        var sealed: [engine.backup.max_length]u8 = undefined;
        const written = try engine.backup.sealWithKeyWith(entropy, &key, &try bytes(16, vector.salt), &try bytes(24, vector.nonce), &sealed);
        try testing.expectEqualSlices(u8, expected, sealed[0..written]);
        try testing.expectEqual(engine.backup.kdf_key, try engine.backup.keyDerivation(expected));

        var opened: [engine.backup.max_entropy_length]u8 = undefined;
        const length = try engine.backup.openWithKey(expected, &key, &opened);
        try testing.expectEqualSlices(u8, entropy, opened[0..length]);
    }
}
