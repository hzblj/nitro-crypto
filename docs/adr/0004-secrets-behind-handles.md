# 4. Secrets behind generation-checked handles in a fixed table

Accepted.

## Context

Seeds and private keys must stay inside the engine. The C ABI needs a way to name them across calls, from several
threads (Nitro's thread pool derives seeds while the JS thread signs), that survives a careless or hostile caller.

## Decision

- **A fixed table of 1024 slots**, never an allocator: a secret lives in exactly one place, which release zeroes,
  instead of wherever a heap moved or copied it. Exhausting it is `NC_ERR_HANDLE_LIMIT`, not a crash.
- **Handles are `generation << 32 | (slot + 1)`.** Every reuse of a slot bumps its generation, so a destroyed handle, a
  forged one or one from an earlier life of the slot is refused (`NC_ERR_INVALID_HANDLE`) instead of reaching
  whichever secret lives there now. 0 is never a handle.
- **Copy out, then work.** An operation copies the one secret it needs onto its stack under the lock, releases the
  lock, works, and zeroes the copy. The lock is held for a lookup and a 64-byte copy, never for a PBKDF2, so
  derivation and signing never wait on each other for long, and nothing deadlocks (no operation takes the lock twice).
- **A spin lock that yields.** Zig 0.16 moved its blocking mutex onto `std.Io`, which a C library called from foreign
  threads has no instance of; critical sections are microseconds, so spinning briefly, then yielding, is enough.
- **No export.** No ABI function returns a secret. Raw import exists (`nc_key_import`) for test vectors; a generated
  mnemonic exists only on the stack of the call that turns it into a seed.
- **Ownership above the ABI**: the C++ bridge owns a handle per Hybrid Object and releases it on `dispose()` or
  destruction (an atomic exchange, so the two cannot double-free); the facade tracks disposal itself, because Nitro
  detaches a disposed object from JavaScript, and a wallet disposes every key it handed out.

## Consequences

- An app can hold at most 1024 seeds and keys at once; a demo holds a handful.
- Every path is tested: lifecycle, stale and forged handles, exhaustion, 8 threads at once (C harness and Zig), and
  disposal leaving `nc_handle_count()` where it started (the TypeScript tests and the example check it after every
  run).
