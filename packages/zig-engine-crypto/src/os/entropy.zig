//! Random bytes from the operating system's CSPRNG, and nothing else.
//!
//! No userspace generator, no seeding, no fallback: every request is a call into the kernel (`getentropy` on
//! Apple platforms, the `getrandom` system call on Linux and Android, `random_get` under WASI). Fails closed:
//! when the OS does not deliver, the output is zeroed and the caller gets `EntropyUnavailable`, never a guess.

const std = @import("std");
const builtin = @import("builtin");

const secure = @import("../core/secure.zig");
const Error = @import("../core/status.zig").Error;

/// A source of randomness: fills the whole buffer or fails. The OS is the only one outside of tests.
pub const Source = *const fn (out: []u8) Error!void;

pub const os: Source = switch (builtin.os.tag) {
    .macos, .ios, .tvos, .watchos, .visionos => darwin,
    .linux => linux,
    .wasi => wasi,
    else => @compileError("nitro-crypto has no entropy source for " ++ @tagName(builtin.os.tag)),
};

/// Fills `out` from the OS CSPRNG, or zeroes it and fails.
pub fn fill(out: []u8) Error!void {
    return fillFrom(os, out);
}

/// `fill` with an explicit source: the fail-closed contract, testable without breaking the OS.
pub fn fillFrom(source: Source, out: []u8) Error!void {
    source(out) catch |err| {
        secure.zero(out);
        return err;
    };
}

extern "c" fn getentropy(buffer: [*]u8, size: usize) c_int;

/// `getentropy` delivers at most 256 bytes per call.
const darwin_chunk = 256;

fn darwin(out: []u8) Error!void {
    var offset: usize = 0;
    while (offset < out.len) {
        const length = @min(darwin_chunk, out.len - offset);
        if (getentropy(out[offset..].ptr, length) != 0) return error.EntropyUnavailable;
        offset += length;
    }
}

fn linux(out: []u8) Error!void {
    var offset: usize = 0;
    while (offset < out.len) {
        const rc = std.os.linux.getrandom(out[offset..].ptr, out.len - offset, 0);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => offset += rc,
            .INTR => continue,
            else => return error.EntropyUnavailable,
        }
    }
}

fn wasi(out: []u8) Error!void {
    if (out.len == 0) return;
    if (std.os.wasi.random_get(out.ptr, out.len) != .SUCCESS) return error.EntropyUnavailable;
}

const testing = std.testing;

test "fill produces bytes that differ between calls" {
    var a: [64]u8 = undefined;
    var b: [64]u8 = undefined;
    try fill(&a);
    try fill(&b);
    try testing.expect(!std.mem.eql(u8, &a, &b));
}

test "fill handles empty and large buffers" {
    try fill(&.{});
    var large: [4096]u8 = @splat(0);
    try fill(&large);
    // 4096 random bytes with no non-zero byte would mean the source wrote nothing.
    try testing.expect(!std.mem.allEqual(u8, &large, 0));
}

fn failing(out: []u8) Error!void {
    @memset(out, 0x5A);
    return error.EntropyUnavailable;
}

test "a failing source fails closed: the output is zeroed" {
    var out: [32]u8 = @splat(0xFF);
    try testing.expectError(error.EntropyUnavailable, fillFrom(failing, &out));
    try testing.expect(std.mem.allEqual(u8, &out, 0));
}
