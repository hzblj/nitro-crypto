//! The engine as a WebAssembly reactor, for hosts without a native build (the TypeScript tests in Node).
//!
//! The C ABI, unchanged, plus the two functions a JavaScript host needs to move bytes in and out of linear
//! memory. Every buffer the host allocates it frees, zeroed, with `nc_wasm_free`. And one test hook the native
//! libraries do not have: Schnorr signing with the auxiliary randomness given, for the published vectors.

const std = @import("std");

const c_api = @import("abi/c_api.zig");
const secure = @import("core/secure.zig");

comptime {
    _ = c_api;
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

/// For tests only: `nc_key_sign_schnorr` (`taproot` 0) or `nc_key_sign_taproot` (otherwise) with the 32 bytes of
/// auxiliary randomness given rather than drawn, so BIP-340's and BIP-341's published signatures can be reproduced
/// through this build. A chosen aux weakens nothing BIP-340 relies on (its nonce still hashes the key and the
/// message), but it is not what a wallet should sign with, so the native libraries do not export it.
export fn nc_wasm_test_sign_schnorr(
    key: u64,
    message: ?[*]const u8,
    message_len: usize,
    taproot: i32,
    merkle_root: ?[*]const u8,
    merkle_root_len: usize,
    aux: ?[*]const u8,
    aux_len: usize,
    out: ?[*]u8,
    out_len: usize,
    written: ?*usize,
) i32 {
    return c_api.signSchnorrWithAux(key, message, message_len, taproot, merkle_root, merkle_root_len, aux, aux_len, out, out_len, written);
}
