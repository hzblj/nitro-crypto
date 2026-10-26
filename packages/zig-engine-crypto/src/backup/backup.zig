//! A wallet's BIP-39 entropy sealed under a password, for a backup that leaves the device (ADR 0009). Argon2id
//! stretches the password into a key, XChaCha20-Poly1305 seals the entropy under it, and the header that names the
//! parameters is the associated data: neither can be changed without the tag failing to verify. A wrong password
//! and a tampered backup fail the same way, on purpose.
//!
//!   offset  length
//!   0       4       magic, "ncbk"
//!   4       1       version, 1
//!   5       1       key derivation, 1: Argon2id (version 0x13)
//!   6       4       memory, in KiB, big-endian
//!   10      4       passes, big-endian
//!   14      1       lanes, 1
//!   15      16      salt
//!   31      24      nonce
//!   55      n       the sealed entropy (16 to 32 bytes), then its 16-byte tag
//!
//! Nothing here keeps a secret: the key and Argon2's memory are zeroed before every return.

const builtin = @import("builtin");
const std = @import("std");

const entropy_source = @import("../os/entropy.zig");
const secure = @import("../core/secure.zig");
const Error = @import("../core/status.zig").Error;

const argon2 = std.crypto.pwhash.argon2;
const Aead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const magic = "ncbk";
pub const version: u8 = 1;
pub const kdf_argon2id: u8 = 1;

pub const salt_length = 16;
pub const nonce_length = Aead.nonce_length;
pub const tag_length = Aead.tag_length;
pub const header_length = 4 + 1 + 1 + 4 + 4 + 1 + salt_length + nonce_length;
pub const max_entropy_length = 32;
pub const max_length = header_length + max_entropy_length + tag_length;
pub const max_password_length = 1024;

pub const Params = struct {
    /// Argon2id's memory, in KiB.
    memory: u32,
    passes: u32,
};

/// What a new backup takes: 64 MiB and three passes, about half a second on a phone and costly on a GPU. They are
/// written into the header, so a later version can ask for more and still open these.
pub const default_params: Params = .{ .memory = 64 * 1024, .passes = 3 };

/// What opening accepts: from OWASP's floor for Argon2id (19 MiB) to what a phone can spare, so a crafted backup
/// can ask neither for a trivial key nor for more memory than the device has. The tests go below the floor.
const min_memory: u32 = if (builtin.is_test) 8 else 19 * 1024;
const max_memory: u32 = 256 * 1024;
const max_passes: u32 = 10;

fn checkEntropy(length: usize) Error!void {
    switch (length) {
        16, 20, 24, 28, 32 => {},
        else => return error.InvalidLength,
    }
}

fn checkParams(params: Params) Error!void {
    if (params.memory < min_memory or params.memory > max_memory) return error.InvalidArgument;
    if (params.passes < 1 or params.passes > max_passes) return error.InvalidArgument;
}

// --- Argon2's memory --------------------------------------------------------------------------------------------

/// The page allocator, zeroing every block before it goes back: Argon2's memory holds values derived from the
/// password, and the standard library frees it as it is.
const zeroing: std.mem.Allocator = .{ .ptr = undefined, .vtable = &.{
    .alloc = zeroingAlloc,
    .resize = zeroingResize,
    .remap = zeroingRemap,
    .free = zeroingFree,
} };

fn zeroingAlloc(_: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
    return std.heap.page_allocator.rawAlloc(len, alignment, ret_addr);
}

fn zeroingResize(_: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
    if (new_len < memory.len) secure.zero(memory[new_len..]);
    return std.heap.page_allocator.rawResize(memory, alignment, new_len, ret_addr);
}

/// Never moves a block in place of its caller: a move would leave the old pages unzeroed.
fn zeroingRemap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
    return null;
}

fn zeroingFree(_: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
    secure.zero(memory);
    std.heap.page_allocator.rawFree(memory, alignment, ret_addr);
}

/// The key for `password` and the header's salt and parameters. One lane: Argon2 runs on the calling thread, and
/// the single-threaded `Io` it asks for is never used.
fn deriveKey(password: []const u8, salt: *const [salt_length]u8, params: Params, key: *[Aead.key_length]u8) Error!void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    argon2.kdf(zeroing, key, password, salt, .{ .t = params.passes, .m = params.memory, .p = 1 }, .argon2id, threaded.io()) catch |err| {
        secure.zero(key);
        return switch (err) {
            error.OutOfMemory => error.Internal,
            else => error.InvalidArgument,
        };
    };
}

// --- the header -------------------------------------------------------------------------------------------------

fn writeHeader(out: *[header_length]u8, params: Params, salt: *const [salt_length]u8, nonce: *const [nonce_length]u8) void {
    @memcpy(out[0..4], magic);
    out[4] = version;
    out[5] = kdf_argon2id;
    std.mem.writeInt(u32, out[6..10], params.memory, .big);
    std.mem.writeInt(u32, out[10..14], params.passes, .big);
    out[14] = 1;
    @memcpy(out[15..31], salt);
    @memcpy(out[31..55], nonce);
}

const Header = struct {
    params: Params,
    salt: *const [salt_length]u8,
    nonce: *const [nonce_length]u8,
};

fn readHeader(backup: []const u8) Error!Header {
    if (backup.len < header_length) return error.InvalidLength;
    if (!std.mem.eql(u8, backup[0..4], magic) or backup[4] != version or backup[5] != kdf_argon2id or backup[14] != 1) {
        return error.InvalidArgument;
    }
    const params: Params = .{
        .memory = std.mem.readInt(u32, backup[6..10], .big),
        .passes = std.mem.readInt(u32, backup[10..14], .big),
    };
    try checkParams(params);
    return .{ .nonce = backup[31..55], .params = params, .salt = backup[15..31] };
}

// --- sealing and opening ----------------------------------------------------------------------------------------

/// Seals `entropy` under `password` into `out` with fresh salt and nonce; the length written.
pub fn seal(entropy: []const u8, password: []const u8, out: []u8) Error!usize {
    var salt: [salt_length]u8 = undefined;
    var nonce: [nonce_length]u8 = undefined;
    try entropy_source.fill(&salt);
    try entropy_source.fill(&nonce);
    return sealWith(entropy, password, default_params, &salt, &nonce, out);
}

/// `seal` with every input given: the published vector, and the tests' smaller parameters.
pub fn sealWith(
    entropy: []const u8,
    password: []const u8,
    params: Params,
    salt: *const [salt_length]u8,
    nonce: *const [nonce_length]u8,
    out: []u8,
) Error!usize {
    try checkEntropy(entropy.len);
    try checkParams(params);
    if (password.len > max_password_length) return error.InvalidLength;
    const length = header_length + entropy.len + tag_length;
    if (out.len < length) return error.BufferTooSmall;

    writeHeader(out[0..header_length], params, salt, nonce);
    var key: [Aead.key_length]u8 = undefined;
    defer secure.zero(&key);
    try deriveKey(password, salt, params, &key);

    const sealed = out[header_length..][0..entropy.len];
    const tag = out[header_length + entropy.len ..][0..tag_length];
    Aead.encrypt(sealed, tag, entropy, out[0..header_length], nonce.*, key);
    return length;
}

/// The entropy `backup` holds, into `out`; its length. `VerificationFailed` for a wrong password or any change to
/// the backup, header included; `out` is zeroed then.
pub fn open(backup: []const u8, password: []const u8, out: *[max_entropy_length]u8) Error!usize {
    if (backup.len > max_length) return error.InvalidLength;
    if (password.len > max_password_length) return error.InvalidLength;
    const header = try readHeader(backup);
    if (backup.len < header_length + tag_length) return error.InvalidLength;
    const entropy_length = backup.len - header_length - tag_length;
    try checkEntropy(entropy_length);

    var key: [Aead.key_length]u8 = undefined;
    defer secure.zero(&key);
    try deriveKey(password, header.salt, header.params, &key);

    const sealed = backup[header_length..][0..entropy_length];
    const tag = backup[header_length + entropy_length ..][0..tag_length];
    Aead.decrypt(out[0..entropy_length], sealed, tag.*, backup[0..header_length], header.nonce.*, key) catch {
        secure.zero(out);
        return error.VerificationFailed;
    };
    return entropy_length;
}

const testing = std.testing;

/// Small enough for Debug builds: the tests check the format and the composition, Argon2 itself has its own.
const test_params: Params = .{ .memory = 64, .passes = 1 };

fn sealForTest(entropy: []const u8, password: []const u8, out: []u8) Error!usize {
    var salt: [salt_length]u8 = undefined;
    var nonce: [nonce_length]u8 = undefined;
    try entropy_source.fill(&salt);
    try entropy_source.fill(&nonce);
    return sealWith(entropy, password, test_params, &salt, &nonce, out);
}

test "a backup opens with its password, at every entropy length, and with no other" {
    for ([_]usize{ 16, 20, 24, 28, 32 }) |length| {
        var entropy: [32]u8 = undefined;
        try entropy_source.fill(entropy[0..length]);
        var backup: [max_length]u8 = undefined;
        const written = try sealForTest(entropy[0..length], "correct horse", &backup);
        try testing.expectEqual(header_length + length + tag_length, written);

        var opened: [max_entropy_length]u8 = undefined;
        try testing.expectEqual(length, try open(backup[0..written], "correct horse", &opened));
        try testing.expectEqualSlices(u8, entropy[0..length], opened[0..length]);

        try testing.expectError(error.VerificationFailed, open(backup[0..written], "correct horse!", &opened));
        try testing.expect(std.mem.allEqual(u8, &opened, 0));
    }
}

test "any change to a backup fails, the header's included" {
    var backup: [max_length]u8 = undefined;
    const written = try sealForTest(&([_]u8{7} ** 16), "pw", &backup);
    var opened: [max_entropy_length]u8 = undefined;

    // Salt, nonce, sealed bytes and tag: the tag fails.
    for ([_]usize{ 15, 40, header_length, written - 1 }) |index| {
        var changed = backup;
        changed[index] ^= 1;
        try testing.expectError(error.VerificationFailed, open(changed[0..written], "pw", &opened));
    }
    // The parameters are associated data too: one more pass and the tag fails.
    var passes = backup;
    passes[13] += 1;
    try testing.expectError(error.VerificationFailed, open(passes[0..written], "pw", &opened));
    // What the header must say, it must say.
    for ([_]usize{ 0, 4, 5, 14 }) |index| {
        var changed = backup;
        changed[index] ^= 0xFF;
        try testing.expectError(error.InvalidArgument, open(changed[0..written], "pw", &opened));
    }
    try testing.expectError(error.InvalidLength, open(backup[0 .. written - 1], "pw", &opened));
    try testing.expectError(error.InvalidLength, open(backup[0..20], "pw", &opened));
}

test "sealing refuses what is not entropy, a short buffer, and parameters out of bounds" {
    var backup: [max_length]u8 = undefined;
    try testing.expectError(error.InvalidLength, sealForTest(&([_]u8{1} ** 17), "pw", &backup));
    try testing.expectError(error.BufferTooSmall, sealForTest(&([_]u8{1} ** 16), "pw", backup[0 .. header_length + 31]));
    const salt = [_]u8{0} ** salt_length;
    const nonce = [_]u8{0} ** nonce_length;
    try testing.expectError(
        error.InvalidArgument,
        sealWith(&([_]u8{1} ** 16), "pw", .{ .memory = max_memory + 1, .passes = 1 }, &salt, &nonce, &backup),
    );
    try testing.expectError(
        error.InvalidArgument,
        sealWith(&([_]u8{1} ** 16), "pw", .{ .memory = 64, .passes = 0 }, &salt, &nonce, &backup),
    );
}

test "Argon2id as the engine runs it: RFC 9106, section 5.3" {
    var tag: [32]u8 = undefined;
    var threaded: std.Io.Threaded = .init_single_threaded;
    try argon2.kdf(zeroing, &tag, &([_]u8{1} ** 32), &([_]u8{2} ** 16), .{
        .ad = &([_]u8{4} ** 12),
        .m = 32,
        .p = 4,
        .secret = &([_]u8{3} ** 8),
        .t = 3,
    }, .argon2id, threaded.io());
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
    try testing.expectEqualSlices(u8, &expected, &tag);
}

test "XChaCha20-Poly1305: draft-irtf-cfrg-xchacha-03, appendix A.3.1" {
    var key: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    var ad: [12]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    _ = try std.fmt.hexToBytes(&nonce, "404142434445464748494a4b4c4d4e4f5051525354555657");
    _ = try std.fmt.hexToBytes(&ad, "50515253c0c1c2c3c4c5c6c7");
    const plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, " ++
        "sunscreen would be it.";
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [tag_length]u8 = undefined;
    Aead.encrypt(&ciphertext, &tag, plaintext, &ad, nonce, key);

    var expected: [plaintext.len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e");
    var expected_tag: [tag_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_tag, "c0875924c1c7987947deafd8780acf49");
    try testing.expectEqualSlices(u8, &expected, &ciphertext);
    try testing.expectEqualSlices(u8, &expected_tag, &tag);
}

test "the default parameters are within what opening accepts" {
    try checkParams(default_params);
}
