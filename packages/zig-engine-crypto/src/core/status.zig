//! The engine's errors and the C ABI's status codes, and the one mapping between them.
//!
//! Engine code returns `Error!T`; only `abi/c_api.zig` turns an error into a `Status`. The numbers and names are
//! part of the ABI (`include/nitro_crypto.h`): never renumber one, only add.

const std = @import("std");

pub const Error = error{
    InvalidArgument,
    BufferTooSmall,
    InvalidLength,
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidSignature,
    VerificationFailed,
    InvalidPath,
    InvalidMnemonic,
    MnemonicChecksum,
    InvalidHandle,
    HandleLimit,
    EntropyUnavailable,
    DerivationFailed,
    Internal,
};

pub const Status = enum(i32) {
    ok = 0,
    invalid_argument = -1,
    buffer_too_small = -2,
    invalid_length = -3,
    invalid_private_key = -4,
    invalid_public_key = -5,
    invalid_signature = -6,
    verification_failed = -7,
    invalid_path = -8,
    invalid_mnemonic = -9,
    mnemonic_checksum = -10,
    invalid_handle = -11,
    handle_limit = -12,
    entropy_unavailable = -13,
    derivation_failed = -14,
    internal = -15,

    /// The stable identifier of a status, as the header spells it: `NC_OK`, `NC_ERR_INVALID_LENGTH`.
    pub fn name(status: Status) [:0]const u8 {
        return switch (status) {
            inline else => |tag| comptime identifier(tag),
        };
    }

    fn identifier(comptime tag: Status) [:0]const u8 {
        if (tag == .ok) return "NC_OK";
        const lower = @tagName(tag);
        var upper: [lower.len:0]u8 = undefined;
        for (lower, 0..) |char, index| upper[index] = std.ascii.toUpper(char);
        const result = "NC_ERR_" ++ upper;
        return result;
    }
};

pub fn fromError(err: Error) Status {
    return switch (err) {
        error.InvalidArgument => .invalid_argument,
        error.BufferTooSmall => .buffer_too_small,
        error.InvalidLength => .invalid_length,
        error.InvalidPrivateKey => .invalid_private_key,
        error.InvalidPublicKey => .invalid_public_key,
        error.InvalidSignature => .invalid_signature,
        error.VerificationFailed => .verification_failed,
        error.InvalidPath => .invalid_path,
        error.InvalidMnemonic => .invalid_mnemonic,
        error.MnemonicChecksum => .mnemonic_checksum,
        error.InvalidHandle => .invalid_handle,
        error.HandleLimit => .handle_limit,
        error.EntropyUnavailable => .entropy_unavailable,
        error.DerivationFailed => .derivation_failed,
        error.Internal => .internal,
    };
}

/// A status for a result: `ok`, or its error's code.
pub fn of(result: Error!void) Status {
    result catch |err| return fromError(err);
    return .ok;
}

/// The name of a raw status code as a host passed it, including codes this build does not know.
pub fn nameOf(code: i32) [:0]const u8 {
    const status = std.enums.fromInt(Status, code) orelse return "NC_ERR_UNKNOWN";
    return status.name();
}

const testing = std.testing;

test "every error maps to a distinct negative status" {
    var seen = std.EnumSet(Status).initEmpty();
    inline for (@typeInfo(Error).error_set.?) |field| {
        const status = fromError(@field(Error, field.name));
        try testing.expect(@intFromEnum(status) < 0);
        try testing.expect(!seen.contains(status));
        seen.insert(status);
    }
    // Every status except `ok` is reachable from an error.
    try testing.expectEqual(@typeInfo(Status).@"enum".fields.len - 1, seen.count());
}

test "names match the header's identifiers" {
    try testing.expectEqualStrings("NC_OK", Status.ok.name());
    try testing.expectEqualStrings("NC_ERR_INVALID_LENGTH", Status.invalid_length.name());
    try testing.expectEqualStrings("NC_ERR_MNEMONIC_CHECKSUM", Status.mnemonic_checksum.name());
    try testing.expectEqualStrings("NC_ERR_UNKNOWN", nameOf(-999));
    try testing.expectEqualStrings("NC_ERR_UNKNOWN", nameOf(1));
    try testing.expectEqualStrings("NC_ERR_INTERNAL", nameOf(-15));
}

test "of maps results" {
    try testing.expectEqual(Status.ok, of({}));
    try testing.expectEqual(Status.handle_limit, of(error.HandleLimit));
}
