//! Which SHA-2 instructions the processor has, where the build cannot know.
//!
//! The engine is built for each platform's oldest processor: ARMv8.0 for Android (arm64-v8a's baseline), the A7 for
//! iOS 15.1, x86-64's baseline for Android's x86_64 ABI. Most processors running it have more. `has` answers at
//! compile time where the target settles it, and otherwise asks the system once and keeps the answer: the kernel's
//! hardware capabilities on Linux and Android (`getauxval`), `sysctlbyname` on Apple platforms, `cpuid` on x86-64.

const std = @import("std");
const builtin = @import("builtin");

pub const Feature = enum {
    /// ARMv8's SHA-2 extension (`sha256h`), or x86's SHA extensions (`sha256rnds2`).
    sha256,
    /// ARMv8.2's SHA-512 extension (`sha512h`). x86 has no equivalent before 2024's processors: never asked there.
    sha512,
};

pub const Availability = enum {
    /// The target guarantees the instructions: they are compiled in unconditionally.
    promised,
    /// The target may or may not have them: `has` asks the system.
    detected,
    /// Not on this target, or nothing to ask.
    absent,
};

/// Settled at compile time, so callers choose their types with it.
pub fn availability(comptime feature: Feature) Availability {
    return switch (builtin.cpu.arch) {
        .aarch64 => if (promisedOnArm(feature)) .promised else if (asksOnArm()) .detected else .absent,
        .x86_64 => switch (feature) {
            .sha256 => if (builtin.cpu.has(.x86, .sha)) .promised else .detected,
            .sha512 => .absent,
        },
        else => .absent,
    };
}

fn promisedOnArm(comptime feature: Feature) bool {
    return switch (feature) {
        .sha256 => builtin.cpu.has(.aarch64, .sha2),
        // LLVM's `sha3` feature is FEAT_SHA3 and FEAT_SHA512 together.
        .sha512 => builtin.cpu.has(.aarch64, .sha3),
    };
}

fn asksOnArm() bool {
    return (builtin.os.tag == .linux and builtin.link_libc) or builtin.os.tag.isDarwin();
}

/// Whether the processor running this has the instructions for `feature`.
pub inline fn has(comptime feature: Feature) bool {
    return switch (comptime availability(feature)) {
        .promised => true,
        .absent => false,
        .detected => detected().contains(feature),
    };
}

const Detected = packed struct(u8) {
    /// False until the system has been asked: the zero value means "not yet".
    asked: bool = true,
    sha256: bool,
    sha512: bool,
    _: u5 = 0,

    fn contains(self: Detected, feature: Feature) bool {
        return switch (feature) {
            .sha256 => self.sha256,
            .sha512 => self.sha512,
        };
    }
};

/// Asked once, by whichever thread hashes first. Threads that race ask too and store the same answer.
var cache = std.atomic.Value(u8).init(0);

fn detected() Detected {
    const cached: Detected = @bitCast(cache.load(.monotonic));
    if (cached.asked) return cached;
    const answer = ask();
    cache.store(@bitCast(answer), .monotonic);
    return answer;
}

fn ask() Detected {
    return switch (builtin.cpu.arch) {
        .aarch64 => if (builtin.os.tag.isDarwin()) askApple() else askLinux(),
        .x86_64 => askX86(),
        else => comptime unreachable,
    };
}

// Linux's arch/arm64/include/uapi/asm/hwcap.h.
const hwcap_sha2 = 1 << 6;
const hwcap_sha512 = 1 << 21;

/// libc's `getauxval`, not `std.os.linux.getauxval`: the auxiliary vector that one reads is filled by Zig's own
/// startup code, which a library linked into an app never runs, so there it answers 0.
fn askLinux() Detected {
    const hwcap = std.c.getauxval(std.elf.AT_HWCAP);
    return .{ .sha256 = hwcap & hwcap_sha2 != 0, .sha512 = hwcap & hwcap_sha512 != 0 };
}

/// Every Apple arm64 processor has SHA-256 (the A7 does). SHA-512 arrived with the A13 and M1; older systems name it
/// `hw.optional.armv8_2_sha512` rather than `hw.optional.arm.FEAT_SHA512`.
fn askApple() Detected {
    const sha512 = sysctlFlag("hw.optional.arm.FEAT_SHA512") orelse
        sysctlFlag("hw.optional.armv8_2_sha512") orelse
        false;
    return .{ .sha256 = true, .sha512 = sha512 };
}

/// A boolean `hw.optional` value, or null when the system does not have that name.
fn sysctlFlag(name: [*:0]const u8) ?bool {
    var value: c_int = 0;
    var length: usize = @sizeOf(c_int);
    if (std.c.sysctlbyname(name, &value, &length, null, 0) != 0) return null;
    return value != 0;
}

/// CPUID leaf 7, EBX bit 29: the SHA extensions. Leaf 0 says how many leaves there are.
fn askX86() Detected {
    const highest_leaf = cpuid(0, 0)[0];
    const sha = highest_leaf >= 7 and cpuid(7, 0)[1] & (1 << 29) != 0;
    return .{ .sha256 = sha, .sha512 = false };
}

/// EAX, EBX, ECX, EDX.
fn cpuid(leaf: u32, subleaf: u32) [4]u32 {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [_] "={eax}" (eax),
          [_] "={ebx}" (ebx),
          [_] "={ecx}" (ecx),
          [_] "={edx}" (edx),
        : [_] "{eax}" (leaf),
          [_] "{ecx}" (subleaf),
    );
    return .{ eax, ebx, ecx, edx };
}

const testing = std.testing;

test "a promise is a yes, and absence a no, without asking" {
    inline for (comptime std.enums.values(Feature)) |feature| {
        switch (comptime availability(feature)) {
            .promised => try testing.expect(has(feature)),
            .absent => try testing.expect(!has(feature)),
            .detected => {},
        }
    }
}

test "the system is asked once, and the answer kept" {
    if (comptime (availability(.sha256) != .detected and availability(.sha512) != .detected)) return error.SkipZigTest;
    const first = detected();
    try testing.expect(first.asked);
    try testing.expectEqual(@as(u8, @bitCast(first)), cache.load(.monotonic));
    try testing.expectEqual(first, detected());
}

test "an Apple processor answers what the build would promise" {
    // The Mac running the tests is an M1 or later: both, which its build also promises.
    if (comptime !(builtin.cpu.arch == .aarch64 and builtin.os.tag.isDarwin())) return error.SkipZigTest;
    const answer = askApple();
    try testing.expect(answer.sha256);
    try testing.expectEqual(builtin.cpu.has(.aarch64, .sha3), answer.sha512);
}
