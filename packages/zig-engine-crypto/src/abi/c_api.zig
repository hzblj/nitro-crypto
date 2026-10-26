//! The C ABI (include/nitro_crypto.h): pointers and lengths in, status codes out, and nothing else.
//!
//! Every function turns its pointer arguments into slices (`input`, `output`), calls the engine, and maps the
//! result with `status.of`. No cryptography here, and no engine logic beyond argument shape.

const std = @import("std");

const bip39 = @import("../derivation/bip39.zig");
const ed25519 = @import("../curves/ed25519.zig");
const entropy = @import("../os/entropy.zig");
const hash = @import("../hash.zig");
const keys = @import("../vault/keys.zig");
const secp256k1 = @import("../curves/secp256k1.zig");
const status = @import("../core/status.zig");
const version = @import("version.zig");

const Error = status.Error;
const Handle = @import("../vault/handles.zig").Handle;

/// The engine's one vault: every handle the ABI issues lives here.
var vault: keys.Vault = .{};

// --- arguments -------------------------------------------------------------------------------------------

/// An input buffer: NULL is allowed only with length 0.
fn input(pointer: ?[*]const u8, length: usize) Error![]const u8 {
    if (length == 0) return &.{};
    return (pointer orelse return error.InvalidArgument)[0..length];
}

fn output(pointer: ?[*]u8, length: usize) Error![]u8 {
    if (length == 0) return &.{};
    return (pointer orelse return error.InvalidArgument)[0..length];
}

fn exact(comptime length: usize, bytes: []const u8) Error!*const [length]u8 {
    if (bytes.len != length) return error.InvalidLength;
    return bytes[0..length];
}

fn store(comptime T: type, pointer: ?*T, value: T) Error!void {
    (pointer orelse return error.InvalidArgument).* = value;
}

fn code(result: Error!void) i32 {
    return @intFromEnum(status.of(result));
}

// --- status, version, capabilities -----------------------------------------------------------------------

export fn nc_status_name(value: i32) [*:0]const u8 {
    return status.nameOf(value);
}

export fn nc_abi_version() u32 {
    return version.abi_version;
}

export fn nc_engine_version() [*:0]const u8 {
    return version.engine_version;
}

export fn nc_build_info() [*:0]const u8 {
    return version.build_info;
}

export fn nc_capabilities() u64 {
    return version.capabilities();
}

export fn nc_capability_name(bit: u32) ?[*:0]const u8 {
    return if (version.capabilityName(bit)) |name| name.ptr else null;
}

// --- random and hashes -----------------------------------------------------------------------------------

export fn nc_random_bytes(out: ?[*]u8, out_len: usize) i32 {
    return code(randomBytes(out, out_len));
}

fn randomBytes(out: ?[*]u8, out_len: usize) Error!void {
    try entropy.fill(try output(out, out_len));
}

export fn nc_hash_length(algorithm: u32) usize {
    const known = hash.Algorithm.fromInt(algorithm) catch return 0;
    return known.length();
}

export fn nc_hash(algorithm: u32, data: ?[*]const u8, data_len: usize, out: ?[*]u8, out_len: usize) i32 {
    return code(digest(algorithm, data, data_len, out, out_len));
}

fn digest(algorithm: u32, data: ?[*]const u8, data_len: usize, out: ?[*]u8, out_len: usize) Error!void {
    try hash.digest(try hash.Algorithm.fromInt(algorithm), try input(data, data_len), try output(out, out_len));
}

export fn nc_hmac(
    algorithm: u32,
    key: ?[*]const u8,
    key_len: usize,
    data: ?[*]const u8,
    data_len: usize,
    out: ?[*]u8,
    out_len: usize,
) i32 {
    return code(hmac(algorithm, key, key_len, data, data_len, out, out_len));
}

fn hmac(algorithm: u32, key: ?[*]const u8, key_len: usize, data: ?[*]const u8, data_len: usize, out: ?[*]u8, out_len: usize) Error!void {
    try hash.hmac(try hash.Algorithm.fromInt(algorithm), try input(key, key_len), try input(data, data_len), try output(out, out_len));
}

// --- secp256k1 -------------------------------------------------------------------------------------------

export fn nc_secp256k1_public_key_convert(
    public_key: ?[*]const u8,
    public_key_len: usize,
    compressed: i32,
    out: ?[*]u8,
    out_len: usize,
    written: ?*usize,
) i32 {
    return code(convert(public_key, public_key_len, compressed, out, out_len, written));
}

fn convert(public_key: ?[*]const u8, public_key_len: usize, compressed: i32, out: ?[*]u8, out_len: usize, written: ?*usize) Error!void {
    const length = try secp256k1.convertPublicKey(try input(public_key, public_key_len), compressed != 0, try output(out, out_len));
    try store(usize, written, length);
}

export fn nc_secp256k1_verify(
    public_key: ?[*]const u8,
    public_key_len: usize,
    message_digest: ?[*]const u8,
    digest_len: usize,
    signature: ?[*]const u8,
    signature_len: usize,
) i32 {
    return code(verifySecp256k1(public_key, public_key_len, message_digest, digest_len, signature, signature_len));
}

fn verifySecp256k1(public_key: ?[*]const u8, public_key_len: usize, message_digest: ?[*]const u8, digest_len: usize, signature: ?[*]const u8, signature_len: usize) Error!void {
    try secp256k1.verify(
        try input(public_key, public_key_len),
        try exact(secp256k1.digest_length, try input(message_digest, digest_len)),
        try exact(secp256k1.signature_length, try input(signature, signature_len)),
    );
}

export fn nc_secp256k1_recover(
    message_digest: ?[*]const u8,
    digest_len: usize,
    signature: ?[*]const u8,
    signature_len: usize,
    compressed: i32,
    out: ?[*]u8,
    out_len: usize,
    written: ?*usize,
) i32 {
    return code(recover(message_digest, digest_len, signature, signature_len, compressed, out, out_len, written));
}

fn recover(message_digest: ?[*]const u8, digest_len: usize, signature: ?[*]const u8, signature_len: usize, compressed: i32, out: ?[*]u8, out_len: usize, written: ?*usize) Error!void {
    const public_key = try secp256k1.recover(
        try exact(secp256k1.digest_length, try input(message_digest, digest_len)),
        try exact(secp256k1.recoverable_signature_length, try input(signature, signature_len)),
    );
    try store(usize, written, try secp256k1.serializePublicKey(&public_key, compressed != 0, try output(out, out_len)));
}

// --- ed25519 ---------------------------------------------------------------------------------------------

export fn nc_ed25519_verify(
    public_key: ?[*]const u8,
    public_key_len: usize,
    message: ?[*]const u8,
    message_len: usize,
    signature: ?[*]const u8,
    signature_len: usize,
) i32 {
    return code(verifyEd25519(public_key, public_key_len, message, message_len, signature, signature_len));
}

fn verifyEd25519(public_key: ?[*]const u8, public_key_len: usize, message: ?[*]const u8, message_len: usize, signature: ?[*]const u8, signature_len: usize) Error!void {
    try ed25519.verify(
        try exact(ed25519.public_key_length, try input(public_key, public_key_len)),
        try input(message, message_len),
        try exact(ed25519.signature_length, try input(signature, signature_len)),
    );
}

// --- handles ---------------------------------------------------------------------------------------------

export fn nc_handle_destroy(handle: Handle) i32 {
    return code(vault.destroy(handle));
}

export fn nc_handle_kind(handle: Handle, kind: ?*u32) i32 {
    return code(handleKind(handle, kind));
}

fn handleKind(handle: Handle, kind: ?*u32) Error!void {
    try store(u32, kind, @intFromEnum(try vault.kindOf(handle)));
}

export fn nc_handle_count() u32 {
    return vault.count();
}

// --- mnemonics and seeds ---------------------------------------------------------------------------------

export fn nc_mnemonic_validate(mnemonic: ?[*]const u8, mnemonic_len: usize) i32 {
    return code(validateMnemonic(mnemonic, mnemonic_len));
}

fn validateMnemonic(mnemonic: ?[*]const u8, mnemonic_len: usize) Error!void {
    try bip39.validate(try input(mnemonic, mnemonic_len));
}

export fn nc_mnemonic_generate(word_count: u32, out: ?[*]u8, out_len: usize, written: ?*usize) i32 {
    return code(mnemonicGenerate(word_count, out, out_len, written));
}

/// The capacity is checked against the longest sentence of that many words before any entropy is drawn, so a
/// buffer is either always large enough or never, whichever words come out.
fn mnemonicGenerate(word_count: u32, out: ?[*]u8, out_len: usize, written: ?*usize) Error!void {
    _ = bip39.entropyLength(word_count) catch return error.InvalidArgument;
    if (written == null) return error.InvalidArgument;
    const buffer = try output(out, out_len);
    if (buffer.len < bip39.maxSentenceLength(word_count)) return error.BufferTooSmall;

    var sentence: bip39.Sentence = .{};
    defer sentence.zero();
    try bip39.generate(word_count, &sentence);
    @memcpy(buffer[0..sentence.len], sentence.slice());
    try store(usize, written, sentence.len);
}

export fn nc_seed_generate(word_count: u32, passphrase: ?[*]const u8, passphrase_len: usize, out: ?*Handle) i32 {
    return code(seedGenerate(word_count, passphrase, passphrase_len, out));
}

fn seedGenerate(word_count: u32, passphrase: ?[*]const u8, passphrase_len: usize, out: ?*Handle) Error!void {
    if (out == null) return error.InvalidArgument;
    try store(Handle, out, try keys.seedGenerate(&vault, word_count, try input(passphrase, passphrase_len)));
}

export fn nc_seed_from_mnemonic(
    mnemonic: ?[*]const u8,
    mnemonic_len: usize,
    passphrase: ?[*]const u8,
    passphrase_len: usize,
    out: ?*Handle,
) i32 {
    return code(seedFromMnemonic(mnemonic, mnemonic_len, passphrase, passphrase_len, out));
}

fn seedFromMnemonic(mnemonic: ?[*]const u8, mnemonic_len: usize, passphrase: ?[*]const u8, passphrase_len: usize, out: ?*Handle) Error!void {
    if (out == null) return error.InvalidArgument;
    const handle = try keys.seedFromMnemonic(&vault, try input(mnemonic, mnemonic_len), try input(passphrase, passphrase_len));
    try store(Handle, out, handle);
}

export fn nc_seed_fingerprint(seed: Handle, out: ?*u32) i32 {
    return code(seedFingerprint(seed, out));
}

fn seedFingerprint(seed: Handle, out: ?*u32) Error!void {
    if (out == null) return error.InvalidArgument;
    try store(u32, out, try keys.seedFingerprint(&vault, seed));
}

// --- keys ------------------------------------------------------------------------------------------------

export fn nc_key_derive(seed: Handle, scheme: u32, path: ?[*]const u8, path_len: usize, out: ?*Handle) i32 {
    return code(keyDerive(seed, scheme, path, path_len, out));
}

fn keyDerive(seed: Handle, scheme: u32, path: ?[*]const u8, path_len: usize, out: ?*Handle) Error!void {
    if (out == null) return error.InvalidArgument;
    try store(Handle, out, try keys.derive(&vault, seed, try keys.Scheme.fromInt(scheme), try input(path, path_len)));
}

export fn nc_key_generate(curve: u32, out: ?*Handle) i32 {
    return code(keyGenerate(curve, out));
}

fn keyGenerate(curve: u32, out: ?*Handle) Error!void {
    if (out == null) return error.InvalidArgument;
    try store(Handle, out, try keys.generate(&vault, try keys.Curve.fromInt(curve)));
}

export fn nc_key_import(curve: u32, secret: ?[*]const u8, secret_len: usize, out: ?*Handle) i32 {
    return code(keyImport(curve, secret, secret_len, out));
}

fn keyImport(curve: u32, secret: ?[*]const u8, secret_len: usize, out: ?*Handle) Error!void {
    if (out == null) return error.InvalidArgument;
    try store(Handle, out, try keys.import(&vault, try keys.Curve.fromInt(curve), try input(secret, secret_len)));
}

export fn nc_key_public(key: Handle, compressed: i32, out: ?[*]u8, out_len: usize, written: ?*usize) i32 {
    return code(keyPublic(key, compressed, out, out_len, written));
}

fn keyPublic(key: Handle, compressed: i32, out: ?[*]u8, out_len: usize, written: ?*usize) Error!void {
    if (written == null) return error.InvalidArgument;
    try store(usize, written, try keys.publicKey(&vault, key, compressed != 0, try output(out, out_len)));
}

export fn nc_key_sign(key: Handle, data: ?[*]const u8, data_len: usize, out: ?[*]u8, out_len: usize, written: ?*usize) i32 {
    return code(keySign(key, data, data_len, out, out_len, written));
}

fn keySign(key: Handle, data: ?[*]const u8, data_len: usize, out: ?[*]u8, out_len: usize, written: ?*usize) Error!void {
    if (written == null) return error.InvalidArgument;
    try store(usize, written, try keys.sign(&vault, key, try input(data, data_len), try output(out, out_len)));
}

const testing = std.testing;

fn fuzzBoundary(_: void, smith: *testing.Smith) anyerror!void {
    var data: [256]u8 = undefined;
    const data_len = smith.slice(&data);
    var out: [128]u8 = undefined;
    const out_len = smith.valueRangeAtMost(u8, 0, 128);
    var written: usize = 0;
    const data_ptr: ?[*]const u8 = if (smith.value(bool)) &data else null;
    const out_ptr: ?[*]u8 = if (smith.value(bool)) &out else null;
    const handle: Handle = smith.value(u64);
    const selector = smith.value(u32);

    // Every entry point taking buffers, with random ids, lengths, null pointers and handles: each returns a
    // status the header defines, and none crashes.
    const codes = [_]i32{
        nc_hash(selector % 6, data_ptr, data_len, out_ptr, out_len),
        nc_hmac(selector % 6, data_ptr, data_len / 2, data_ptr, data_len, out_ptr, out_len),
        nc_secp256k1_public_key_convert(data_ptr, data_len, @intCast(selector & 1), out_ptr, out_len, &written),
        nc_secp256k1_verify(data_ptr, data_len, data_ptr, @min(data_len, 32), data_ptr, @min(data_len, 64)),
        nc_secp256k1_recover(data_ptr, @min(data_len, 32), data_ptr, @min(data_len, 65), 1, out_ptr, out_len, &written),
        nc_ed25519_verify(data_ptr, @min(data_len, 32), data_ptr, data_len, data_ptr, @min(data_len, 64)),
        nc_mnemonic_validate(data_ptr, data_len),
        nc_mnemonic_generate(selector % 32, out_ptr, out_len, if (smith.value(bool)) &written else null),
        nc_key_public(handle, 1, out_ptr, out_len, &written),
        nc_key_sign(handle, data_ptr, data_len, out_ptr, out_len, &written),
        nc_handle_destroy(handle),
    };
    for (codes) |value| {
        try testing.expect(value <= 0 and value >= @intFromEnum(status.Status.internal));
    }
    try testing.expectEqual(@as(u32, 0), nc_handle_count());
}

test "property: the C ABI boundary returns defined statuses for any arguments" {
    try @import("../testing/property.zig").check(fuzzBoundary, 3000, 3);
}

test "fuzz: the C ABI boundary returns defined statuses for any arguments" {
    try testing.fuzz({}, fuzzBoundary, .{});
}

test "statuses carry through the exported functions" {
    var out: [32]u8 = undefined;
    try testing.expectEqual(@as(i32, 0), nc_hash(1, "abc", 3, &out, 32));
    try testing.expectEqual(@intFromEnum(status.Status.buffer_too_small), nc_hash(1, "abc", 3, &out, 31));
    try testing.expectEqual(@intFromEnum(status.Status.invalid_argument), nc_hash(1, null, 3, &out, 32));
    try testing.expectEqual(@intFromEnum(status.Status.invalid_handle), nc_handle_destroy(0));
}

test "a generated mnemonic comes out whole, validates, and stores nothing" {
    var out: [bip39.max_sentence_length]u8 = undefined;
    var again: [bip39.max_sentence_length]u8 = undefined;
    var written: usize = 0;
    var written_again: usize = 0;
    const count = nc_handle_count();

    try testing.expectEqual(@as(i32, 0), nc_mnemonic_generate(24, &out, out.len, &written));
    try testing.expectEqual(@as(i32, 0), nc_mnemonic_validate(&out, written));
    try testing.expectEqual(@as(usize, 24), std.mem.count(u8, out[0..written], " ") + 1);
    try testing.expectEqual(@as(i32, 0), nc_mnemonic_generate(24, &again, again.len, &written_again));
    try testing.expect(!std.mem.eql(u8, out[0..written], again[0..written_again]));
    try testing.expectEqual(@as(i32, 0), nc_mnemonic_generate(12, &out, bip39.maxSentenceLength(12), &written));
    try testing.expectEqual(@as(usize, 12), std.mem.count(u8, out[0..written], " ") + 1);
    try testing.expectEqual(count, nc_handle_count());

    const too_small = bip39.maxSentenceLength(12) - 1;
    try testing.expectEqual(@intFromEnum(status.Status.buffer_too_small), nc_mnemonic_generate(12, &out, too_small, &written));
    try testing.expectEqual(@intFromEnum(status.Status.invalid_argument), nc_mnemonic_generate(13, &out, out.len, &written));
    try testing.expectEqual(@intFromEnum(status.Status.invalid_argument), nc_mnemonic_generate(12, &out, out.len, null));
    try testing.expectEqual(@intFromEnum(status.Status.invalid_argument), nc_mnemonic_generate(12, null, out.len, &written));
}
