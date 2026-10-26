//! Derivation paths: "m/44'/60'/0'/0/0".
//!
//! Strict and canonical, because a path that parses two ways is two different keys: "m", then steps of a
//! decimal index below 2^31 with no leading zeros, hardened when followed by ' or h. No whitespace, no empty
//! steps, no trailing slash, at most `max_depth` steps.

const std = @import("std");

const Error = @import("../core/status.zig").Error;

pub const hardened: u32 = 0x8000_0000;
pub const max_depth = 32;

pub const Path = struct {
    indices: [max_depth]u32 = undefined,
    depth: usize = 0,

    pub fn steps(self: *const Path) []const u32 {
        return self.indices[0..self.depth];
    }

    /// Whether every step is hardened, as SLIP-0010 requires for Ed25519.
    pub fn allHardened(self: *const Path) bool {
        for (self.steps()) |index| {
            if (index < hardened) return false;
        }
        return true;
    }

    /// The canonical text of the path, with ' for hardened steps.
    pub fn format(self: *const Path, out: []u8) Error![]const u8 {
        var writer = std.Io.Writer.fixed(out);
        writer.writeByte('m') catch return error.BufferTooSmall;
        for (self.steps()) |index| {
            const marker: []const u8 = if (index >= hardened) "'" else "";
            writer.print("/{d}{s}", .{ index & ~hardened, marker }) catch return error.BufferTooSmall;
        }
        return writer.buffered();
    }
};

pub fn parse(text: []const u8) Error!Path {
    if (text.len == 0 or text[0] != 'm') return error.InvalidPath;
    var path: Path = .{};
    var rest = text[1..];
    while (rest.len > 0) {
        if (rest[0] != '/') return error.InvalidPath;
        rest = rest[1..];
        if (path.depth == max_depth) return error.InvalidPath;
        path.indices[path.depth] = try parseStep(&rest);
        path.depth += 1;
    }
    return path;
}

/// One step at the front of `rest`: digits, then an optional hardened marker. Advances `rest` past it.
fn parseStep(rest: *[]const u8) Error!u32 {
    const text = rest.*;
    var length: usize = 0;
    while (length < text.len and std.ascii.isDigit(text[length])) length += 1;
    if (length == 0) return error.InvalidPath;
    if (length > 1 and text[0] == '0') return error.InvalidPath;
    // Ten digits are enough for 2^31 - 1; more would also overflow the parse below.
    if (length > 10) return error.InvalidPath;

    const index = std.fmt.parseInt(u32, text[0..length], 10) catch return error.InvalidPath;
    if (index >= hardened) return error.InvalidPath;

    var consumed = length;
    var result = index;
    if (consumed < text.len and (text[consumed] == '\'' or text[consumed] == 'h')) {
        result |= hardened;
        consumed += 1;
    }
    rest.* = text[consumed..];
    return result;
}

const testing = std.testing;

fn expectSteps(text: []const u8, expected: []const u32) !void {
    const path = try parse(text);
    try testing.expectEqualSlices(u32, expected, path.steps());
}

test "parses the paths the adapters use" {
    try expectSteps("m", &.{});
    try expectSteps("m/44'/60'/0'/0/0", &.{ 44 | hardened, 60 | hardened, hardened, 0, 0 });
    try expectSteps("m/84h/0h/0h/1/7", &.{ 84 | hardened, hardened, hardened, 1, 7 });
    try expectSteps("m/44'/501'/0'/0'", &.{ 44 | hardened, 501 | hardened, hardened, hardened });
    try expectSteps("m/2147483647'", &.{0xFFFF_FFFF});
    try expectSteps("m/0/1000000000", &.{ 0, 1_000_000_000 });
}

test "refuses everything that is not canonical" {
    const invalid = [_][]const u8{
        "",     "M",      "m/",    "/0",           "0",            "m//0",
        "m/0/", "m/01",   "m/00",  "m/-1",         "m/+1",         "m/ 1",
        "m/1 ", "m/1''",  "m/1H'", "m/2147483648", "m/4294967296", "m/99999999999",
        "m/1x", "m/0'/a", "mm/0",  "m0",           "m/0\x00",
    };
    for (invalid) |text| {
        if (parse(text)) |_| {
            std.debug.print("accepted: \"{s}\"\n", .{text});
            return error.TestUnexpectedResult;
        } else |err| try testing.expectEqual(error.InvalidPath, err);
    }
}

test "depth is bounded" {
    try testing.expectEqual(@as(usize, max_depth), (try parse("m" ++ "/0" ** max_depth)).depth);
    try testing.expectError(error.InvalidPath, parse("m" ++ "/0" ** (max_depth + 1)));
}

test "format writes the canonical text" {
    var buffer: [64]u8 = undefined;
    const path = try parse("m/84h/0h/0h/1/7");
    try testing.expectEqualStrings("m/84'/0'/0'/1/7", try path.format(&buffer));
    var tiny: [4]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, path.format(&tiny));
}

test "allHardened" {
    try testing.expect((try parse("m/44'/501'/0'/0'")).allHardened());
    try testing.expect(!(try parse("m/44'/501'/0'/0")).allHardened());
    try testing.expect((try parse("m")).allHardened());
}

fn fuzzParse(_: void, smith: *testing.Smith) anyerror!void {
    var input: [96]u8 = undefined;
    const length = smith.slice(&input);
    const text = input[0..length];
    const path = parse(text) catch return;
    // Whatever parses formats back to an equivalent canonical text that parses to the same steps.
    var buffer: [max_depth * 13 + 1]u8 = undefined;
    const canonical = try path.format(&buffer);
    const again = try parse(canonical);
    try testing.expectEqualSlices(u32, path.steps(), again.steps());
}

test "property: parse never crashes, and what it accepts round-trips" {
    try @import("../testing/property.zig").check(fuzzParse, 20000, 1);
}

test "fuzz: parse never crashes, and what it accepts round-trips" {
    try testing.fuzz({}, fuzzParse, .{ .corpus = &.{ "m/44'/60'/0'/0/0", "m/0h/1/2h", "m", "m/2147483647'" } });
}
