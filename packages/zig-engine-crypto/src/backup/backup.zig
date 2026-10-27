//! A wallet's BIP-39 entropy sealed for a backup that leaves the device: under a password (ADR 0009), or under a
//! 32-byte key such as a passkey's PRF output (ADR 0010). A key derivation turns the password or the key into the
//! sealing key, XChaCha20-Poly1305 seals the entropy under it, and the header that names the derivation is the
//! associated data: neither can be changed without the tag failing to verify. A wrong password or key and a
//! tampered backup fail the same way, on purpose.
//!
//! Every backup starts with six bytes: the magic "ncbk", the version, 1, and the key derivation, which decides
//! what follows.
//!
//!   1: Argon2id (version 0x13) over a password     2: HKDF-SHA256 over a 32-byte key
//!   offset  length                                  offset  length
//!   0       4       magic, "ncbk"                   0       4       magic, "ncbk"
//!   4       1       version, 1                      4       1       version, 1
//!   5       1       key derivation, 1               5       1       key derivation, 2
//!   6       4       memory, in KiB, big-endian      6       16      salt
//!   10      4       passes, big-endian              22      24      nonce
//!   14      1       lanes, 1                        46      n       the sealed entropy, then its 16-byte tag
//!   15      16      salt
//!   31      24      nonce
//!   55      n       the sealed entropy (16 to 32 bytes), then its 16-byte tag
//!
//! Key derivation 2's sealing key is HKDF-SHA256 (RFC 5869): extracted from the 32-byte key with the salt, expanded
//! with the info "ncbk xchacha20poly1305 key" to 32 bytes.
//!
//! Nothing here keeps a secret: the keys and Argon2's memory are zeroed before every return.

const builtin = @import("builtin");
const std = @import("std");

const entropy_source = @import("../os/entropy.zig");
const hash = @import("../hash.zig");
const secure = @import("../core/secure.zig");
const Error = @import("../core/status.zig").Error;

const argon2 = std.crypto.pwhash.argon2;
const Aead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const Hkdf = std.crypto.kdf.hkdf.Hkdf(hash.HmacSha256);

pub const magic = "ncbk";
pub const version: u8 = 1;
pub const kdf_argon2id: u8 = 1;
pub const kdf_key: u8 = 2;

pub const salt_length = 16;
pub const nonce_length = Aead.nonce_length;
pub const tag_length = Aead.tag_length;
/// Magic, version and key derivation: what every backup starts with.
const prefix_length = 4 + 1 + 1;
/// A password-sealed backup's header: the prefix, Argon2id's memory, passes and lanes, the salt and the nonce.
pub const header_length = prefix_length + 4 + 4 + 1 + salt_length + nonce_length;
/// A key-sealed backup's header: the prefix, the salt and the nonce.
pub const key_header_length = prefix_length + salt_length + nonce_length;
pub const max_entropy_length = 32;
/// The longest backup of either kind (a password's header is the longer).
pub const max_length = header_length + max_entropy_length + tag_length;
pub const max_password_length = 1024;
/// What a key-sealed backup is sealed under: 32 bytes, such as a passkey's PRF output.
pub const key_length = 32;
const hkdf_info = "ncbk xchacha20poly1305 key";

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

/// The sealing key for a 32-byte key and the header's salt: HKDF-SHA256, extract then expand. No stretching: the
/// key is already uniformly random, which a password is not (ADR 0010).
fn deriveFromKey(input_key: *const [key_length]u8, salt: *const [salt_length]u8, key: *[Aead.key_length]u8) void {
    var prk = Hkdf.extract(salt, input_key);
    defer secure.zero(&prk);
    Hkdf.expand(key, hkdf_info, prk);
}

/// A 32-byte key, refused when it is all zero: what a buffer nobody filled holds, and a backup sealed under it would
/// open for anyone. One branch, on the whole key, so nothing about its bytes shows.
fn checkKey(input_key: []const u8) Error!*const [key_length]u8 {
    if (input_key.len != key_length) return error.InvalidLength;
    var bits: u8 = 0;
    for (input_key) |byte| bits |= byte;
    if (bits == 0) return error.InvalidArgument;
    return input_key[0..key_length];
}

// --- the header -------------------------------------------------------------------------------------------------

/// The key derivation a backup names, from its first six bytes, with the length a backup of that kind has (header,
/// 16 to 32 bytes of entropy, tag); it is not opened. `InvalidArgument` for a header this engine does not read,
/// `InvalidLength` for a length no backup of that kind has.
pub fn keyDerivation(backup: []const u8) Error!u8 {
    if (backup.len < prefix_length) return error.InvalidLength;
    if (!std.mem.eql(u8, backup[0..4], magic) or backup[4] != version) return error.InvalidArgument;
    const header: usize = switch (backup[5]) {
        kdf_argon2id => header_length,
        kdf_key => key_header_length,
        else => return error.InvalidArgument,
    };
    if (backup.len < header + tag_length) return error.InvalidLength;
    try checkEntropy(backup.len - header - tag_length);
    return backup[5];
}

/// The magic and version this engine reads, and the key derivation the caller opens with: a backup of the other
/// kind is `InvalidArgument`, before any key is derived.
fn expectPrefix(backup: []const u8, kdf: u8) Error!void {
    if (backup.len < prefix_length) return error.InvalidLength;
    if (!std.mem.eql(u8, backup[0..4], magic) or backup[4] != version or backup[5] != kdf) return error.InvalidArgument;
}

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
    try expectPrefix(backup, kdf_argon2id);
    if (backup.len < header_length) return error.InvalidLength;
    if (backup[14] != 1) return error.InvalidArgument;
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

// --- sealing and opening under a key ----------------------------------------------------------------------------

/// Seals `entropy` under a 32-byte key into `out` with fresh salt and nonce; the length written.
pub fn sealWithKey(entropy: []const u8, input_key: []const u8, out: []u8) Error!usize {
    var salt: [salt_length]u8 = undefined;
    var nonce: [nonce_length]u8 = undefined;
    try entropy_source.fill(&salt);
    try entropy_source.fill(&nonce);
    return sealWithKeyWith(entropy, input_key, &salt, &nonce, out);
}

/// `sealWithKey` with every input given: the published vectors.
pub fn sealWithKeyWith(
    entropy: []const u8,
    input_key: []const u8,
    salt: *const [salt_length]u8,
    nonce: *const [nonce_length]u8,
    out: []u8,
) Error!usize {
    try checkEntropy(entropy.len);
    const checked = try checkKey(input_key);
    const length = key_header_length + entropy.len + tag_length;
    if (out.len < length) return error.BufferTooSmall;

    @memcpy(out[0..4], magic);
    out[4] = version;
    out[5] = kdf_key;
    @memcpy(out[6..22], salt);
    @memcpy(out[22..46], nonce);
    var key: [Aead.key_length]u8 = undefined;
    defer secure.zero(&key);
    deriveFromKey(checked, salt, &key);

    const sealed = out[key_header_length..][0..entropy.len];
    const tag = out[key_header_length + entropy.len ..][0..tag_length];
    Aead.encrypt(sealed, tag, entropy, out[0..key_header_length], nonce.*, key);
    return length;
}

/// The entropy a key-sealed backup holds, into `out`; its length. `VerificationFailed` for a wrong key or any change
/// to the backup, header included (`out` is zeroed then); `InvalidArgument` for a backup sealed under a password.
pub fn openWithKey(backup: []const u8, input_key: []const u8, out: *[max_entropy_length]u8) Error!usize {
    const checked = try checkKey(input_key);
    try expectPrefix(backup, kdf_key);
    if (backup.len < key_header_length + tag_length) return error.InvalidLength;
    const entropy_length = backup.len - key_header_length - tag_length;
    try checkEntropy(entropy_length);

    var key: [Aead.key_length]u8 = undefined;
    defer secure.zero(&key);
    deriveFromKey(checked, backup[6..22], &key);

    const sealed = backup[key_header_length..][0..entropy_length];
    const tag = backup[key_header_length + entropy_length ..][0..tag_length];
    Aead.decrypt(out[0..entropy_length], sealed, tag.*, backup[0..key_header_length], backup[22..46].*, key) catch {
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

test "a key-sealed backup opens with its key, at every entropy length, and with no other" {
    var key: [key_length]u8 = undefined;
    try entropy_source.fill(&key);
    for ([_]usize{ 16, 20, 24, 28, 32 }) |length| {
        var entropy: [32]u8 = undefined;
        try entropy_source.fill(entropy[0..length]);
        var backup: [max_length]u8 = undefined;
        const written = try sealWithKey(entropy[0..length], &key, &backup);
        try testing.expectEqual(key_header_length + length + tag_length, written);
        try testing.expectEqual(kdf_key, try keyDerivation(backup[0..written]));

        var opened: [max_entropy_length]u8 = undefined;
        try testing.expectEqual(length, try openWithKey(backup[0..written], &key, &opened));
        try testing.expectEqualSlices(u8, entropy[0..length], opened[0..length]);

        var other = key;
        other[31] ^= 1;
        try testing.expectError(error.VerificationFailed, openWithKey(backup[0..written], &other, &opened));
        try testing.expect(std.mem.allEqual(u8, &opened, 0));
    }
}

test "any change to a key-sealed backup fails: the prefix as unreadable, the rest as unverifiable" {
    const key: [key_length]u8 = @splat(0x5c);
    var backup: [max_length]u8 = undefined;
    const written = try sealWithKey(&([_]u8{7} ** 24), &key, &backup);
    var opened: [max_entropy_length]u8 = undefined;
    for (0..written) |index| {
        var changed = backup;
        changed[index] ^= 0x01;
        const expected: Error = if (index < prefix_length) error.InvalidArgument else error.VerificationFailed;
        try testing.expectError(expected, openWithKey(changed[0..written], &key, &opened));
    }
    try testing.expectError(error.InvalidLength, openWithKey(backup[0 .. written - 1], &key, &opened));
    try testing.expectError(error.InvalidLength, openWithKey(backup[0 .. key_header_length + tag_length], &key, &opened));
    try testing.expectError(error.InvalidLength, openWithKey(backup[0..5], &key, &opened));
    try testing.expectError(error.InvalidLength, openWithKey(&.{}, &key, &opened));
}

test "a backup of one kind is refused by the other's opening, before any key is derived" {
    const key: [key_length]u8 = @splat(0x5c);
    var opened: [max_entropy_length]u8 = undefined;
    var by_key: [max_length]u8 = undefined;
    const key_written = try sealWithKeyWith(&([_]u8{1} ** 16), &key, &@as([salt_length]u8, @splat(0)), &@as([nonce_length]u8, @splat(0)), &by_key);
    var by_password: [max_length]u8 = undefined;
    const password_written = try sealForTest(&([_]u8{1} ** 16), "pw", &by_password);

    try testing.expectError(error.InvalidArgument, open(by_key[0..key_written], "pw", &opened));
    try testing.expectError(error.InvalidArgument, openWithKey(by_password[0..password_written], &key, &opened));
    try testing.expectEqual(kdf_argon2id, try keyDerivation(by_password[0..password_written]));

    // Relabelled: a key backup that says Argon2id reads its salt as parameters (zero memory, refused), and a password
    // backup that says key has a length no key backup has.
    var relabelled = by_key;
    relabelled[5] = kdf_argon2id;
    try testing.expectError(error.InvalidArgument, open(relabelled[0..key_written], "pw", &opened));
    relabelled = by_password;
    relabelled[5] = kdf_key;
    try testing.expectError(error.InvalidLength, openWithKey(relabelled[0..password_written], &key, &opened));
}

test "sealing under a key refuses other key lengths, a key of zeros, what is not entropy and a short buffer" {
    var backup: [max_length]u8 = undefined;
    var opened: [max_entropy_length]u8 = undefined;
    const key: [key_length]u8 = @splat(0x5c);
    const entropy = [_]u8{1} ** 16;
    try testing.expectError(error.InvalidLength, sealWithKey(&entropy, key[0..31], &backup));
    try testing.expectError(error.InvalidLength, sealWithKey(&entropy, &([_]u8{1} ** 33), &backup));
    try testing.expectError(error.InvalidArgument, sealWithKey(&entropy, &([_]u8{0} ** 32), &backup));
    try testing.expectError(error.InvalidLength, sealWithKey(entropy[0..15], &key, &backup));
    try testing.expectError(error.BufferTooSmall, sealWithKey(&entropy, &key, backup[0 .. key_header_length + 31]));
    const written = try sealWithKey(&entropy, &key, &backup);
    try testing.expectError(error.InvalidArgument, openWithKey(backup[0..written], &([_]u8{0} ** 32), &opened));
    try testing.expectError(error.InvalidLength, openWithKey(backup[0..written], key[0..31], &opened));
}

test "keyDerivation names each kind and refuses what is no backup" {
    try testing.expectError(error.InvalidLength, keyDerivation("ncbk"));
    try testing.expectError(error.InvalidArgument, keyDerivation("ncbx\x01\x01" ++ [_]u8{0} ** 81));
    try testing.expectError(error.InvalidArgument, keyDerivation("ncbk\x02\x01" ++ [_]u8{0} ** 81));
    try testing.expectError(error.InvalidArgument, keyDerivation("ncbk\x01\x03" ++ [_]u8{0} ** 81));
    try testing.expectEqual(kdf_argon2id, try keyDerivation("ncbk\x01\x01" ++ [_]u8{0} ** 81));
    try testing.expectError(error.InvalidLength, keyDerivation("ncbk\x01\x01" ++ [_]u8{0} ** 80));
    try testing.expectEqual(kdf_key, try keyDerivation("ncbk\x01\x02" ++ [_]u8{0} ** 72));
    try testing.expectError(error.InvalidLength, keyDerivation("ncbk\x01\x02" ++ [_]u8{0} ** 73));
}

test "HKDF-SHA256 as the engine runs it: RFC 5869, test case 1" {
    var ikm: [22]u8 = @splat(0x0b);
    var salt: [13]u8 = undefined;
    var info: [10]u8 = undefined;
    _ = try std.fmt.hexToBytes(&salt, "000102030405060708090a0b0c");
    _ = try std.fmt.hexToBytes(&info, "f0f1f2f3f4f5f6f7f8f9");
    const prk = Hkdf.extract(&salt, &ikm);
    var expected_prk: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_prk, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    try testing.expectEqualSlices(u8, &expected_prk, &prk);
    var okm: [42]u8 = undefined;
    Hkdf.expand(&okm, &info, prk);
    var expected: [42]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    try testing.expectEqualSlices(u8, &expected, &okm);
}
