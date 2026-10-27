//! `zig build bench`: the engine's primitives in ReleaseFast on the build machine, without any bridge.
//!
//! These are the native floor the on-device numbers (the example app's Performance screen) add the Nitro
//! crossing to. Each line is the median of `rounds` timed batches; nothing here is a release gate.

const std = @import("std");
const engine = @import("engine");

const rounds = 7;

const Bench = struct {
    io: std.Io,
    out: *std.Io.Writer,

    /// Times `iterations` calls of `function(context)` per round and prints the median time per call.
    fn run(self: Bench, name: []const u8, iterations: usize, context: anytype, comptime function: anytype) !void {
        var samples: [rounds]i96 = undefined;
        for (&samples) |*sample| {
            const start = std.Io.Timestamp.now(self.io, .awake);
            for (0..iterations) |_| try function(context);
            const elapsed = start.durationTo(std.Io.Timestamp.now(self.io, .awake));
            sample.* = @divTrunc(elapsed.nanoseconds, iterations);
        }
        std.mem.sort(i96, &samples, {}, std.sort.asc(i96));
        const median = samples[rounds / 2];
        try self.out.print("{s:<40} {d:>10.2} µs\n", .{ name, @as(f64, @floatFromInt(median)) / 1000.0 });
    }
};

const Payload = struct { data: []const u8, algorithm: engine.hash.Algorithm };

fn hashOnce(payload: Payload) !void {
    var out: [64]u8 = undefined;
    try engine.hash.digest(payload.algorithm, payload.data, &out);
    std.mem.doNotOptimizeAway(&out);
}

const Signing = struct {
    key: engine.secp256k1.PrivateKey,
    digest: engine.secp256k1.Digest,
    signature: [65]u8,
    public_key: [33]u8,
};

fn secpSign(s: *const Signing) !void {
    std.mem.doNotOptimizeAway(try engine.secp256k1.sign(&s.key, &s.digest));
}

fn secpVerify(s: *const Signing) !void {
    try engine.secp256k1.verify(&s.public_key, &s.digest, s.signature[0..64]);
}

fn secpRecover(s: *const Signing) !void {
    std.mem.doNotOptimizeAway(try engine.secp256k1.recover(&s.digest, &s.signature));
}

fn secpPublic(s: *const Signing) !void {
    std.mem.doNotOptimizeAway(try engine.secp256k1.publicKeyFromPrivate(&s.key));
}

const Schnorr = struct {
    key: engine.secp256k1.PrivateKey,
    digest: engine.secp256k1.Digest,
    signature: [64]u8,
    public_key: engine.secp256k1.XOnly,
};

/// The aux randomness is fixed here: the engine draws it from the OS, a cost the hash benchmarks do not include either.
fn schnorrSign(s: *const Schnorr) !void {
    std.mem.doNotOptimizeAway(try engine.secp256k1.signSchnorr(&s.key, &s.digest, &s.digest, .none));
}

fn taprootSign(s: *const Schnorr) !void {
    std.mem.doNotOptimizeAway(try engine.secp256k1.signSchnorr(&s.key, &s.digest, &s.digest, .{ .taproot = null }));
}

fn schnorrVerify(s: *const Schnorr) !void {
    try engine.secp256k1.verifySchnorr(&s.public_key, &s.digest, &s.signature);
}

const Edwards = struct { pair: engine.ed25519.KeyPair, public_key: [32]u8, signature: [64]u8, message: []const u8 };

fn edSign(e: *const Edwards) !void {
    std.mem.doNotOptimizeAway(try engine.ed25519.sign(&e.pair, e.message));
}

fn edVerify(e: *const Edwards) !void {
    try engine.ed25519.verify(&e.public_key, e.message, &e.signature);
}

const abandon = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn mnemonicSeed(_: void) !void {
    var seed: [64]u8 = undefined;
    try engine.bip39.toSeed(abandon, "", &seed);
    std.mem.doNotOptimizeAway(&seed);
}

const Derivation = struct { seed: [64]u8, path: engine.path.Path };

fn bip32Derive(d: *const Derivation) !void {
    var key = try engine.bip32.derive(&d.seed, &d.path);
    std.mem.doNotOptimizeAway(&key);
}

fn slip10Derive(d: *const Derivation) !void {
    var key = try engine.slip10.derive(&d.seed, &d.path);
    std.mem.doNotOptimizeAway(&key);
}

fn implementation(instructions: bool) []const u8 {
    return if (instructions) "on the processor's instructions" else "in software";
}

pub fn main(init: std.process.Init) !void {
    var buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(init.io, &buffer);
    const bench: Bench = .{ .io = init.io, .out = &stdout.interface };

    try bench.out.print("nitro-crypto engine {s}, ecmult window {d}\n", .{
        engine.version.engine_version,
        engine.version.ecmult_window,
    });
    try bench.out.print("SHA-256 {s}, SHA-512 {s}\n\n", .{
        implementation(engine.sha2.usesInstructions(.sha256)),
        implementation(engine.sha2.usesInstructions(.sha512)),
    });

    const small = [_]u8{0x61} ** 32;
    const kilobyte = [_]u8{0x61} ** 1024;
    const megabyte = try init.gpa.alloc(u8, 1 << 20);
    defer init.gpa.free(megabyte);
    @memset(megabyte, 0x61);

    inline for (.{ .sha256, .sha512, .keccak256, .ripemd160 }) |algorithm| {
        try bench.run(@tagName(algorithm) ++ " 32 B", 20_000, Payload{ .data = &small, .algorithm = algorithm }, hashOnce);
        try bench.run(@tagName(algorithm) ++ " 1 KiB", 5_000, Payload{ .data = &kilobyte, .algorithm = algorithm }, hashOnce);
        try bench.run(@tagName(algorithm) ++ " 1 MiB", 10, Payload{ .data = megabyte, .algorithm = algorithm }, hashOnce);
    }

    var signing: Signing = .{ .key = @splat(0x42), .digest = @splat(0x07), .signature = undefined, .public_key = undefined };
    signing.signature = try engine.secp256k1.sign(&signing.key, &signing.digest);
    signing.public_key = engine.secp256k1.compressedPublicKey(&try engine.secp256k1.publicKeyFromPrivate(&signing.key));
    try bench.out.writeAll("\n");
    try bench.run("secp256k1 public key", 2_000, &signing, secpPublic);
    try bench.run("secp256k1 sign (RFC 6979)", 2_000, &signing, secpSign);
    try bench.run("secp256k1 verify", 2_000, &signing, secpVerify);
    try bench.run("secp256k1 recover", 2_000, &signing, secpRecover);

    var schnorr: Schnorr = .{ .key = signing.key, .digest = signing.digest, .signature = undefined, .public_key = undefined };
    schnorr.signature = try engine.secp256k1.signSchnorr(&schnorr.key, &schnorr.digest, &schnorr.digest, .none);
    schnorr.public_key = try engine.secp256k1.xOnlyFromPrivate(&schnorr.key);
    try bench.run("schnorr sign (BIP-340, verified)", 2_000, &schnorr, schnorrSign);
    try bench.run("schnorr sign, taproot tweak", 2_000, &schnorr, taprootSign);
    try bench.run("schnorr verify", 2_000, &schnorr, schnorrVerify);

    var edwards: Edwards = .{
        .pair = try engine.ed25519.keyPair(&@as(engine.ed25519.Seed, @splat(9))),
        .public_key = undefined,
        .signature = undefined,
        .message = &kilobyte,
    };
    edwards.public_key = engine.ed25519.publicKey(&edwards.pair);
    edwards.signature = try engine.ed25519.sign(&edwards.pair, edwards.message);
    try bench.run("ed25519 sign 1 KiB", 2_000, &edwards, edSign);
    try bench.run("ed25519 verify 1 KiB", 2_000, &edwards, edVerify);

    var derivation: Derivation = .{ .seed = undefined, .path = try engine.path.parse("m/44'/60'/0'/0/0") };
    try engine.bip39.toSeed(abandon, "", &derivation.seed);
    try bench.out.writeAll("\n");
    try bench.run("bip39 seed (PBKDF2, 2048 rounds)", 20, {}, mnemonicSeed);
    try bench.run("bip32 m/44'/60'/0'/0/0", 500, &derivation, bip32Derive);
    derivation.path = try engine.path.parse("m/44'/501'/0'/0'");
    try bench.run("slip10 m/44'/501'/0'/0'", 2_000, &derivation, slip10Derive);

    try bench.out.flush();
}
