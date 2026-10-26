//! The engine as a WebAssembly reactor, for hosts without a native build (the TypeScript tests in Node).
//!
//! The C ABI, unchanged, plus the two functions a JavaScript host needs to move bytes in and out of linear
//! memory. Every buffer the host allocates it frees, zeroed, with `nc_wasm_free`.

const std = @import("std");

const secure = @import("core/secure.zig");

comptime {
    _ = @import("abi/c_api.zig");
}

const allocator = std.heap.wasm_allocator;

export fn nc_wasm_alloc(length: usize) ?[*]u8 {
    const memory = allocator.alloc(u8, @max(length, 1)) catch return null;
    return memory.ptr;
}

/// Zeroes and frees what `nc_wasm_alloc` returned; `length` must be the length it was asked for.
export fn nc_wasm_free(pointer: ?[*]u8, length: usize) void {
    const memory = (pointer orelse return)[0..@max(length, 1)];
    secure.zero(memory);
    allocator.free(memory);
}
