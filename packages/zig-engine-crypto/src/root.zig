//! The engine: the static library's root, and the Zig module the tests and the benchmark import.
//!
//! The library is the C ABI (abi/c_api.zig), exported below; nothing else leaves it. The module is every part,
//! by folder: what the vector tests and the benchmark reach into.

// The ABI: `nc_*`, and what it says about itself.
pub const c_api = @import("abi/c_api.zig");
pub const version = @import("abi/version.zig");

// What every other part uses: errors and statuses, zeroization, a lock.
pub const lock = @import("core/lock.zig");
pub const secure = @import("core/secure.zig");
pub const status = @import("core/status.zig");

// What the engine asks of the system: randomness, and what the processor can do.
pub const cpu = @import("os/cpu.zig");
pub const entropy = @import("os/entropy.zig");

// Hashes by id, and the ones Zig's library lacks or runs without the processor's instructions.
pub const hash = @import("hash.zig");
pub const ripemd160 = @import("hash/ripemd160.zig");
pub const sha2 = @import("hash/sha2.zig");

// The curves.
pub const ed25519 = @import("curves/ed25519.zig");
pub const secp256k1 = @import("curves/secp256k1.zig");

// From words to seeds to keys.
pub const bip32 = @import("derivation/bip32.zig");
pub const bip39 = @import("derivation/bip39.zig");
pub const path = @import("derivation/path.zig");
pub const slip10 = @import("derivation/slip10.zig");

// Secrets behind handles, and what can be done with them.
pub const handles = @import("vault/handles.zig");
pub const keys = @import("vault/keys.zig");

// A wallet's entropy under a password, for a backup that leaves the device.
pub const backup = @import("backup/backup.zig");

// Seeded random input for the fuzz targets.
pub const property = @import("testing/property.zig");

comptime {
    _ = c_api;
}

test {
    @import("std").testing.refAllDecls(@This());
}
