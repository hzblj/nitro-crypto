//! secp256k1 through bitcoin-core/libsecp256k1 (v0.8.0; recovery, extrakeys and schnorrsig modules), the
//! implementation Bitcoin Core signs with: constant-time signing, RFC 6979 nonces, lower-S signatures, public key
//! recovery, and BIP-340 Schnorr signatures with BIP-341's Taproot tweak.
//!
//! Zig's own `std.crypto.ecc.Secp256k1` has none of the last three: its ECDSA nonces are not RFC 6979, it
//! neither produces nor enforces lower S, and it cannot recover a key, so signatures from it would not match
//! Ethereum's or Bitcoin's. This file is the only one that talks to the C library.
//!
//! Policy: signatures are produced in lower-S form, and verification and recovery reject the upper-S twin of a
//! valid signature (`InvalidSignature`) instead of quietly accepting a malleable encoding.

const std = @import("std");
const c = @import("secp256k1_c");

const entropy = @import("../os/entropy.zig");
const secure = @import("../core/secure.zig");
const SpinLock = @import("../core/lock.zig").SpinLock;
const Error = @import("../core/status.zig").Error;

pub const private_key_length = 32;
pub const compressed_length = 33;
pub const uncompressed_length = 65;
pub const digest_length = 32;
pub const signature_length = 64;
pub const recoverable_signature_length = 65;
pub const x_only_length = 32;
pub const schnorr_signature_length = 64;
pub const merkle_root_length = 32;

pub const PrivateKey = [private_key_length]u8;
pub const Digest = [digest_length]u8;
pub const PublicKey = c.secp256k1_pubkey;
/// BIP-340's public key: the x coordinate of the point whose y is even.
pub const XOnly = [x_only_length]u8;
pub const MerkleRoot = [merkle_root_length]u8;

// --- context ---------------------------------------------------------------------------------------------

/// Room for a context. v0.8.0 needs a few hundred bytes (its tables are static); `signingContext` checks.
const context_capacity = 1024;

var context_memory: [context_capacity]u8 align(16) = undefined;
var context_pointer: ?*c.secp256k1_context = null;
var context_ready = std.atomic.Value(bool).init(false);
var context_lock: SpinLock = .{};

/// The context for operations on secrets (signing, public keys from private keys, tweaks), created on first
/// use and randomized with 32 bytes from the OS: libsecp256k1 blinds its scalar multiplications with them.
/// If the OS has no entropy the context is not created and the next call tries again.
fn signingContext() Error!*const c.secp256k1_context {
    if (context_ready.load(.acquire)) return context_pointer.?;

    context_lock.lock();
    defer context_lock.unlock();
    if (context_ready.load(.monotonic)) return context_pointer.?;

    if (c.nc_secp256k1_context_preallocated_size(c.SECP256K1_CONTEXT_NONE) > context_capacity) return error.Internal;
    const created = c.nc_secp256k1_context_preallocated_create(&context_memory, c.SECP256K1_CONTEXT_NONE) orelse
        return error.Internal;

    var seed: [32]u8 = undefined;
    defer secure.zero(&seed);
    entropy.fill(&seed) catch |err| {
        c.nc_secp256k1_context_preallocated_destroy(created);
        return err;
    };
    if (c.nc_secp256k1_context_randomize(created, &seed) != 1) return error.Internal;

    context_pointer = created;
    context_ready.store(true, .release);
    return created;
}

/// Operations on public data only (parsing, serializing, verifying, recovering) need no blinding.
fn publicContext() *const c.secp256k1_context {
    return c.nc_secp256k1_context_static.?;
}

/// libsecp256k1 reports misuse (a null pointer, an out-of-range argument) through this callback and then
/// returns 0, which every wrapper below turns into an error. Arguments are checked before every call, so it
/// is not expected to run; when it does, the error that follows is enough.
export fn nc_secp256k1_default_illegal_callback_fn(message: [*c]const u8, data: ?*anyopaque) callconv(.c) void {
    _ = message;
    _ = data;
}

/// An internal consistency failure inside libsecp256k1: memory corruption or a broken build. Not recoverable.
export fn nc_secp256k1_default_error_callback_fn(message: [*c]const u8, data: ?*anyopaque) callconv(.c) void {
    _ = message;
    _ = data;
    std.c.abort();
}

// --- keys ------------------------------------------------------------------------------------------------

/// A private key is valid when it is not zero and below the group order.
pub fn validatePrivateKey(key: *const PrivateKey) Error!void {
    if (c.nc_secp256k1_ec_seckey_verify(publicContext(), key) != 1) return error.InvalidPrivateKey;
}

pub fn publicKeyFromPrivate(key: *const PrivateKey) Error!PublicKey {
    var public_key: PublicKey = undefined;
    if (c.nc_secp256k1_ec_pubkey_create(try signingContext(), &public_key, key) != 1) return error.InvalidPrivateKey;
    return public_key;
}

/// Parses a SEC1 public key, compressed (33 bytes) or uncompressed (65).
pub fn parsePublicKey(bytes: []const u8) Error!PublicKey {
    if (bytes.len != compressed_length and bytes.len != uncompressed_length) return error.InvalidLength;
    var public_key: PublicKey = undefined;
    if (c.nc_secp256k1_ec_pubkey_parse(publicContext(), &public_key, bytes.ptr, bytes.len) != 1) {
        return error.InvalidPublicKey;
    }
    return public_key;
}

/// Serializes into the front of `out` and returns the length written.
pub fn serializePublicKey(public_key: *const PublicKey, compressed: bool, out: []u8) Error!usize {
    const length: usize = if (compressed) compressed_length else uncompressed_length;
    if (out.len < length) return error.BufferTooSmall;
    var written: usize = length;
    const flags: c_uint = if (compressed) c.SECP256K1_EC_COMPRESSED else c.SECP256K1_EC_UNCOMPRESSED;
    if (c.nc_secp256k1_ec_pubkey_serialize(publicContext(), out.ptr, &written, public_key, flags) != 1) {
        return error.Internal;
    }
    std.debug.assert(written == length);
    return written;
}

pub fn compressedPublicKey(public_key: *const PublicKey) [compressed_length]u8 {
    var out: [compressed_length]u8 = undefined;
    _ = serializePublicKey(public_key, true, &out) catch unreachable;
    return out;
}

/// Validates a SEC1 public key and re-encodes it.
pub fn convertPublicKey(bytes: []const u8, compressed: bool, out: []u8) Error!usize {
    const public_key = try parsePublicKey(bytes);
    return serializePublicKey(&public_key, compressed, out);
}

/// `key = key + tweak (mod n)`: the step of BIP-32 private child derivation. Fails, leaving `key` zeroed, when
/// the tweak is not below n or the sum is zero, exactly BIP-32's two invalid-child cases.
pub fn addTweak(key: *PrivateKey, tweak: *const [32]u8) Error!void {
    if (c.nc_secp256k1_ec_seckey_tweak_add(try signingContext(), key, tweak) != 1) {
        secure.zero(key);
        return error.DerivationFailed;
    }
}

/// `public_key = public_key + tweak·G`: the step of BIP-32 public child derivation. Public data only, so no
/// blinding. Fails when the tweak is not below n or the sum is the point at infinity: BIP-32's two invalid-child
/// cases.
pub fn addTweakToPublicKey(public_key: *PublicKey, tweak: *const [32]u8) Error!void {
    if (c.nc_secp256k1_ec_pubkey_tweak_add(publicContext(), public_key, tweak) != 1) return error.DerivationFailed;
}

// --- signatures ------------------------------------------------------------------------------------------

/// ECDSA over a 32-byte digest with an RFC 6979 nonce: 64 bytes `r || s` (lower S) and the recovery id.
pub fn sign(key: *const PrivateKey, digest: *const Digest) Error![recoverable_signature_length]u8 {
    var signature: c.secp256k1_ecdsa_recoverable_signature = undefined;
    defer secure.zeroValue(&signature);
    const context = try signingContext();
    if (c.nc_secp256k1_ecdsa_sign_recoverable(context, &signature, digest, key, null, null) != 1) {
        return error.InvalidPrivateKey;
    }

    var out: [recoverable_signature_length]u8 = undefined;
    var recovery_id: c_int = undefined;
    _ = c.nc_secp256k1_ecdsa_recoverable_signature_serialize_compact(publicContext(), &out, &recovery_id, &signature);
    out[signature_length] = @intCast(recovery_id);
    return out;
}

/// A compact signature, refused when malformed (r or s zero or not below n) or not in lower-S form.
fn parseSignature(bytes: *const [signature_length]u8) Error!c.secp256k1_ecdsa_signature {
    if (isZero(bytes[0..32]) or isZero(bytes[32..64])) return error.InvalidSignature;
    var signature: c.secp256k1_ecdsa_signature = undefined;
    if (c.nc_secp256k1_ecdsa_signature_parse_compact(publicContext(), &signature, bytes) != 1) {
        return error.InvalidSignature;
    }
    try requireLowerS(&signature);
    return signature;
}

fn requireLowerS(signature: *const c.secp256k1_ecdsa_signature) Error!void {
    // Returns 1 when the input was not normalized, that is, when its S is in the upper half.
    if (c.nc_secp256k1_ecdsa_signature_normalize(publicContext(), null, signature) == 1) {
        return error.InvalidSignature;
    }
}

fn isZero(bytes: []const u8) bool {
    return std.mem.allEqual(u8, bytes, 0);
}

pub fn verify(public_key_bytes: []const u8, digest: *const Digest, signature_bytes: *const [signature_length]u8) Error!void {
    const public_key = try parsePublicKey(public_key_bytes);
    const signature = try parseSignature(signature_bytes);
    if (c.nc_secp256k1_ecdsa_verify(publicContext(), &signature, digest, &public_key) != 1) {
        return error.VerificationFailed;
    }
}

/// The public key a 65-byte recoverable signature (`r || s || recovery id`) was made with.
pub fn recover(digest: *const Digest, signature_bytes: *const [recoverable_signature_length]u8) Error!PublicKey {
    const recovery_id = signature_bytes[signature_length];
    if (recovery_id > 3) return error.InvalidSignature;
    const compact = signature_bytes[0..signature_length];
    _ = try parseSignature(compact);

    var signature: c.secp256k1_ecdsa_recoverable_signature = undefined;
    if (c.nc_secp256k1_ecdsa_recoverable_signature_parse_compact(publicContext(), &signature, compact, recovery_id) != 1) {
        return error.InvalidSignature;
    }
    var public_key: PublicKey = undefined;
    if (c.nc_secp256k1_ecdsa_recover(publicContext(), &public_key, &signature, digest) != 1) {
        return error.VerificationFailed;
    }
    return public_key;
}

// --- BIP-340 Schnorr and BIP-341 Taproot --------------------------------------------------------------------

/// How a Schnorr signature's key is used: as it is, or tweaked first as BIP-341's key path spends it, by
/// TapTweak(x-only key || merkle root), or by TapTweak(x-only key) alone when there is no script tree (BIP-86).
pub const Tweak = union(enum) {
    none,
    taproot: ?*const MerkleRoot,
};

fn serializeXOnly(public_key: *const c.secp256k1_xonly_pubkey) XOnly {
    var out: XOnly = undefined;
    _ = c.nc_secp256k1_xonly_pubkey_serialize(publicContext(), &out, public_key);
    return out;
}

/// The keypair of a private key: what libsecp256k1 signs Schnorr with. The caller zeroes it.
fn keypairOf(key: *const PrivateKey, keypair: *c.secp256k1_keypair) Error!void {
    if (c.nc_secp256k1_keypair_create(try signingContext(), keypair, key) != 1) {
        secure.zeroValue(keypair);
        return error.InvalidPrivateKey;
    }
}

fn keypairXOnly(keypair: *const c.secp256k1_keypair) c.secp256k1_xonly_pubkey {
    var public_key: c.secp256k1_xonly_pubkey = undefined;
    _ = c.nc_secp256k1_keypair_xonly_pub(publicContext(), &public_key, null, keypair);
    return public_key;
}

/// BIP-341's tweak: the tagged hash "TapTweak" of the x-only internal key, followed by the merkle root of its script
/// tree when it has one.
pub fn tapTweak(internal: *const XOnly, merkle_root: ?*const MerkleRoot) [32]u8 {
    var message: [x_only_length + merkle_root_length]u8 = undefined;
    @memcpy(message[0..x_only_length], internal);
    var length: usize = x_only_length;
    if (merkle_root) |root| {
        @memcpy(message[x_only_length..], root);
        length += merkle_root_length;
    }
    var out: [32]u8 = undefined;
    const tag = "TapTweak";
    _ = c.nc_secp256k1_tagged_sha256(publicContext(), &out, tag, tag.len, &message, length);
    return out;
}

/// The x-only public key of a private key: x(d·G), whichever the parity of its y (BIP-340).
pub fn xOnlyFromPrivate(key: *const PrivateKey) Error!XOnly {
    var keypair: c.secp256k1_keypair = undefined;
    defer secure.zeroValue(&keypair);
    try keypairOf(key, &keypair);
    return serializeXOnly(&keypairXOnly(&keypair));
}

/// BIP-341's output key Q = P + t·G for an internal key P (x-only, 32 bytes, or SEC1, 33 or 65, whose y parity
/// BIP-341 drops) and the optional merkle root of its script tree, compressed (33 bytes): its x coordinate is what a
/// P2TR output commits to, its prefix (0x02 even, 0x03 odd) the parity a script path's control block carries.
/// Public data only. `DerivationFailed` when t is not below the group order (probability about 2^-128).
pub fn taprootTweak(internal_key: []const u8, merkle_root: ?*const MerkleRoot) Error![compressed_length]u8 {
    var internal: c.secp256k1_xonly_pubkey = undefined;
    switch (internal_key.len) {
        x_only_length => if (c.nc_secp256k1_xonly_pubkey_parse(publicContext(), &internal, internal_key.ptr) != 1) {
            return error.InvalidPublicKey;
        },
        compressed_length, uncompressed_length => {
            const full = try parsePublicKey(internal_key);
            _ = c.nc_secp256k1_xonly_pubkey_from_pubkey(publicContext(), &internal, null, &full);
        },
        else => return error.InvalidLength,
    }
    const tweak = tapTweak(&serializeXOnly(&internal), merkle_root);
    var output: PublicKey = undefined;
    if (c.nc_secp256k1_xonly_pubkey_tweak_add(publicContext(), &output, &internal, &tweak) != 1) {
        return error.DerivationFailed;
    }
    return compressedPublicKey(&output);
}

/// A BIP-340 signature of `message` (any length; Taproot signs a 32-byte sighash) with `aux` as the auxiliary
/// randomness, by the key itself or by its Taproot tweak. As BIP-340's signing algorithm ends, the signature is
/// verified before it is returned, so a fault in the computation cannot hand out a value that leaks the key.
pub fn signSchnorr(key: *const PrivateKey, message: []const u8, aux: *const [32]u8, tweak: Tweak) Error![schnorr_signature_length]u8 {
    const context = try signingContext();
    var keypair: c.secp256k1_keypair = undefined;
    defer secure.zeroValue(&keypair);
    try keypairOf(key, &keypair);

    switch (tweak) {
        .none => {},
        .taproot => |merkle_root| {
            const t = tapTweak(&serializeXOnly(&keypairXOnly(&keypair)), merkle_root);
            if (c.nc_secp256k1_keypair_xonly_tweak_add(context, &keypair, &t) != 1) return error.DerivationFailed;
        },
    }

    var params: c.secp256k1_schnorrsig_extraparams = .{
        .magic = .{ 0xda, 0x6f, 0xb3, 0x8c },
        .noncefp = null,
        .ndata = @ptrCast(@constCast(aux)),
    };
    var signature: [schnorr_signature_length]u8 = undefined;
    if (c.nc_secp256k1_schnorrsig_sign_custom(context, &signature, message.ptr, message.len, &keypair, &params) != 1) {
        return error.Internal;
    }
    const public_key = keypairXOnly(&keypair);
    if (c.nc_secp256k1_schnorrsig_verify(publicContext(), &signature, message.ptr, message.len, &public_key) != 1) {
        return error.Internal;
    }
    return signature;
}

/// BIP-340 verification. `InvalidPublicKey` when the key is not the x coordinate of a point on the curve;
/// `VerificationFailed` for a signature that does not verify, malformed ones (r not below p, s not below n) included.
pub fn verifySchnorr(public_key_bytes: *const XOnly, message: []const u8, signature: *const [schnorr_signature_length]u8) Error!void {
    var public_key: c.secp256k1_xonly_pubkey = undefined;
    if (c.nc_secp256k1_xonly_pubkey_parse(publicContext(), &public_key, public_key_bytes) != 1) {
        return error.InvalidPublicKey;
    }
    if (c.nc_secp256k1_schnorrsig_verify(publicContext(), signature, message.ptr, message.len, &public_key) != 1) {
        return error.VerificationFailed;
    }
}

const testing = std.testing;

fn hexArray(comptime length: usize, comptime hex: []const u8) [length]u8 {
    var out: [length]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// The group order n, and n - 1 (the largest valid private key).
const order = hexArray(32, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const order_minus_one = hexArray(32, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");

test "private key validity: zero and n are refused, 1 and n - 1 accepted" {
    const zero_key: PrivateKey = @splat(0);
    try testing.expectError(error.InvalidPrivateKey, validatePrivateKey(&zero_key));
    try testing.expectError(error.InvalidPrivateKey, validatePrivateKey(&order));
    try validatePrivateKey(&order_minus_one);
    var one: PrivateKey = @splat(0);
    one[31] = 1;
    try validatePrivateKey(&one);
}

test "the public key of 1 is the generator, in both encodings" {
    var one: PrivateKey = @splat(0);
    one[31] = 1;
    const public_key = try publicKeyFromPrivate(&one);
    var out: [65]u8 = undefined;
    try testing.expectEqual(@as(usize, 33), try serializePublicKey(&public_key, true, &out));
    try testing.expectEqualSlices(u8, &hexArray(33, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"), out[0..33]);
    try testing.expectEqual(@as(usize, 65), try serializePublicKey(&public_key, false, &out));
    try testing.expectEqualSlices(
        u8,
        &hexArray(65, "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
        &out,
    );
}

test "public key parsing rejects bad lengths, prefixes and off-curve points" {
    try testing.expectError(error.InvalidLength, parsePublicKey(&[_]u8{0x02} ** 32));
    var bad_prefix = hexArray(33, "0579be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    try testing.expectError(error.InvalidPublicKey, parsePublicKey(&bad_prefix));
    // x = 5 has no point on the curve (5^3 + 7 = 132 is not a square mod p).
    var off_curve: [33]u8 = @splat(0);
    off_curve[0] = 0x02;
    off_curve[32] = 5;
    try testing.expectError(error.InvalidPublicKey, parsePublicKey(&off_curve));
}

test "convertPublicKey round-trips between encodings" {
    const compressed = hexArray(33, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    var uncompressed: [65]u8 = undefined;
    try testing.expectEqual(@as(usize, 65), try convertPublicKey(&compressed, false, &uncompressed));
    var again: [33]u8 = undefined;
    try testing.expectEqual(@as(usize, 33), try convertPublicKey(&uncompressed, true, &again));
    try testing.expectEqualSlices(u8, &compressed, &again);
    var short: [32]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, convertPublicKey(&compressed, true, &short));
}

test "sign, verify and recover agree, and the signature is lower-S" {
    var key: PrivateKey = undefined;
    for (&key, 0..) |*byte, index| byte.* = @truncate(index * 7 + 1);
    const digest = std.mem.zeroes(Digest);
    const signature = try sign(&key, &digest);
    try testing.expect(signature[64] <= 3);

    const public_key = try publicKeyFromPrivate(&key);
    const compressed = compressedPublicKey(&public_key);
    try verify(&compressed, &digest, signature[0..64]);

    const recovered = try recover(&digest, &signature);
    try testing.expectEqualSlices(u8, &compressed, &compressedPublicKey(&recovered));

    // The top bit of a lower-S value is clear: S < n / 2 < 2^255.
    try testing.expect(signature[32] & 0x80 == 0);
}

test "signing is deterministic (RFC 6979)" {
    var key: PrivateKey = @splat(0x11);
    const digest: Digest = @splat(0x22);
    try testing.expectEqualSlices(u8, &try sign(&key, &digest), &try sign(&key, &digest));
}

/// `n - s`: the upper-S twin of a signature.
fn negateS(s: *[32]u8) void {
    var borrow: u1 = 0;
    var index: usize = 32;
    while (index > 0) {
        index -= 1;
        const difference = @subWithOverflow(order[index], s[index]);
        const with_borrow = @subWithOverflow(difference[0], borrow);
        s[index] = with_borrow[0];
        borrow = difference[1] | with_borrow[1];
    }
}

test "the upper-S twin of a valid signature is refused by verify and recover" {
    const key: PrivateKey = @splat(0x42);
    const digest: Digest = @splat(0x07);
    var signature = try sign(&key, &digest);
    const compressed = compressedPublicKey(&try publicKeyFromPrivate(&key));

    negateS(signature[32..64]);
    try testing.expectError(error.InvalidSignature, verify(&compressed, &digest, signature[0..64]));
    try testing.expectError(error.InvalidSignature, recover(&digest, &signature));
}

test "verify fails for another digest, another key, and malformed signatures" {
    const key: PrivateKey = @splat(0x42);
    const digest: Digest = @splat(0x07);
    const signature = try sign(&key, &digest);
    const compressed = compressedPublicKey(&try publicKeyFromPrivate(&key));

    var other_digest = digest;
    other_digest[0] ^= 1;
    try testing.expectError(error.VerificationFailed, verify(&compressed, &other_digest, signature[0..64]));

    const other_key: PrivateKey = @splat(0x43);
    const other_public = compressedPublicKey(&try publicKeyFromPrivate(&other_key));
    try testing.expectError(error.VerificationFailed, verify(&other_public, &digest, signature[0..64]));

    var zero_r = signature;
    @memset(zero_r[0..32], 0);
    try testing.expectError(error.InvalidSignature, verify(&compressed, &digest, zero_r[0..64]));

    var r_overflow = signature;
    r_overflow[0..32].* = order;
    try testing.expectError(error.InvalidSignature, verify(&compressed, &digest, r_overflow[0..64]));

    var bad_recovery = signature;
    bad_recovery[64] = 4;
    try testing.expectError(error.InvalidSignature, recover(&digest, &bad_recovery));
}

test "addTweak: BIP-32's invalid cases fail and zero the key" {
    var key = order_minus_one;
    var one: [32]u8 = @splat(0);
    one[31] = 1;
    // (n - 1) + 1 = n = 0 (mod n): an invalid child.
    try testing.expectError(error.DerivationFailed, addTweak(&key, &one));
    try testing.expect(isZero(&key));

    var valid: PrivateKey = @splat(0x01);
    try testing.expectError(error.DerivationFailed, addTweak(&valid, &order));
    try testing.expect(isZero(&valid));

    var base: PrivateKey = @splat(0);
    base[31] = 2;
    try addTweak(&base, &one);
    try testing.expectEqual(@as(u8, 3), base[31]);
}

test "Schnorr: BIP-340 vector 0, its public key, signature and verification" {
    var key: PrivateKey = @splat(0);
    key[31] = 3;
    const aux: [32]u8 = @splat(0);
    const message: [32]u8 = @splat(0);
    try testing.expectEqualSlices(u8, &hexArray(32, "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"), &try xOnlyFromPrivate(&key));
    const signature = try signSchnorr(&key, &message, &aux, .none);
    try testing.expectEqualSlices(u8, &hexArray(64, "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"), &signature);
    try verifySchnorr(&try xOnlyFromPrivate(&key), &message, &signature);
}

test "Schnorr: another message, another key or a changed signature fails; a key off the curve is refused" {
    const key: PrivateKey = @splat(0x42);
    const aux: [32]u8 = @splat(0x07);
    const public_key = try xOnlyFromPrivate(&key);
    const signature = try signSchnorr(&key, "hello", &aux, .none);
    try verifySchnorr(&public_key, "hello", &signature);
    try testing.expectError(error.VerificationFailed, verifySchnorr(&public_key, "hellp", &signature));
    try testing.expectError(error.VerificationFailed, verifySchnorr(&try xOnlyFromPrivate(&order_minus_one), "hello", &signature));
    var changed = signature;
    changed[63] ^= 1;
    try testing.expectError(error.VerificationFailed, verifySchnorr(&public_key, "hello", &changed));
    // x = 5 is the x coordinate of no point.
    var off_curve: XOnly = @splat(0);
    off_curve[31] = 5;
    try testing.expectError(error.InvalidPublicKey, verifySchnorr(&off_curve, "hello", &signature));
    // Fresh aux, another signature of the same message, which verifies too.
    const other = try signSchnorr(&key, "hello", &@as([32]u8, @splat(0x08)), .none);
    try testing.expect(!std.mem.eql(u8, &signature, &other));
    try verifySchnorr(&public_key, "hello", &other);
}

test "Taproot: a key path signature verifies under the output key, with and without a merkle root" {
    const key: PrivateKey = @splat(0x24);
    const aux: [32]u8 = @splat(0);
    const message: [32]u8 = @splat(0x5a);
    const internal = try xOnlyFromPrivate(&key);
    const root: MerkleRoot = @splat(0x99);
    for ([_]?*const MerkleRoot{ null, &root }) |merkle_root| {
        const output = try taprootTweak(&internal, merkle_root);
        try testing.expect(output[0] == 0x02 or output[0] == 0x03);
        const signature = try signSchnorr(&key, &message, &aux, .{ .taproot = merkle_root });
        try verifySchnorr(output[1..33], &message, &signature);
        try testing.expectError(error.VerificationFailed, verifySchnorr(&internal, &message, &signature));
        // The SEC1 encodings of the internal key, either parity, tweak the same as its x-only one.
        const full = compressedPublicKey(&try publicKeyFromPrivate(&key));
        try testing.expectEqualSlices(u8, &output, &try taprootTweak(&full, merkle_root));
        var flipped = full;
        flipped[0] ^= 1;
        try testing.expectEqualSlices(u8, &output, &try taprootTweak(&flipped, merkle_root));
    }
    try testing.expectError(error.InvalidLength, taprootTweak(internal[0..31], null));
}
