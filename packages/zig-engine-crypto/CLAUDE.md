# zig-engine-crypto

The engine: every cryptographic operation and every secret. Zig 0.16.0, libsecp256k1 v0.8.0 (pinned by hash in
`build.zig.zon`), and nothing else. Private: its artifacts ship inside `@hzblj/nitro-crypto` (`scripts/build-native`
writes them into `packages/nitro-crypto/engine/`).

Hosts reach it through one C ABI, `include/nitro_crypto.h`, which documents itself: status codes, ownership,
threading, the compatibility policy.

`src/` is a folder per concern. Zig resolves imports within the root's directory, so the two roots sit at the top:
`root.zig` (the static library, which exports the ABI, and the module the tests and the bench import) and `wasm.zig`.

| Path | What it is |
| --- | --- |
| `src/root.zig` | The library's root (its `comptime` block exports `abi/c_api.zig`) and the module, every part by folder. |
| `src/wasm.zig` | The WebAssembly root: the ABI plus `nc_wasm_alloc`/`nc_wasm_free`. |
| `src/abi/c_api.zig` | The ABI's functions: pointers and lengths to slices, the engine call, `status.of`. No logic beyond argument shape. |
| `src/abi/version.zig` | ABI version, engine version, build info, capability bits and names. |
| `src/core/status.zig` | `Error` (what engine code returns) and `Status` (what the ABI returns); the one mapping between them. |
| `src/core/secure.zig`, `src/core/lock.zig` | Zeroization and constant-time helpers; a spin lock that yields. |
| `src/os/entropy.zig` | OS randomness, fail-closed. |
| `src/os/cpu.zig` | Which SHA-2 instructions the processor has, where the build cannot know: `getauxval` (Linux, Android), `sysctlbyname` (Apple), `cpuid` (x86-64), asked once. |
| `src/hash.zig` | Hashes and HMAC by id, as the ABI addresses them. |
| `src/hash/sha2.zig` | The engine's SHA-256 and SHA-512: Zig's, or the same algorithm on the processor's instructions, chosen at compile time where the target settles it and at run time where it does not. |
| `src/hash/sha2/armv8.zig`, `src/hash/sha2/x86.zig` | The compression functions on ARMv8's SHA-2 and SHA-512 extensions, and on x86's SHA extensions. |
| `src/hash/ripemd160.zig` | RIPEMD-160, which Zig's library lacks. |
| `src/curves/secp256k1.zig`, `.h`, `_prefix.h` | The only file that calls libsecp256k1; its bindings; every libsecp256k1 symbol renamed `nc_secp256k1_*`. |
| `src/curves/ed25519.zig` | Zig's Ed25519, with errors mapped. |
| `src/derivation/bip39.zig`, `bip39_english.txt` | Mnemonics: generation from OS entropy, validation, seeds; word lookups scan all 2048 entries with masks. The list is pinned by SHA-256. |
| `src/derivation/path.zig`, `bip32.zig`, `slip10.zig` | Derivation paths (strict, canonical), BIP-32 for secp256k1, SLIP-0010 for Ed25519. |
| `src/vault/handles.zig` | The vault: a fixed table of generation-checked handles, zeroed on release (docs/adr/0004). |
| `src/vault/keys.zig` | Operations on handles: seeds, derivation, generation, import, public keys, signing. |
| `src/backup/backup.zig` | A wallet's entropy under a password: Argon2id, XChaCha20-Poly1305, the versioned format (docs/adr/0009). |
| `src/testing/property.zig` | Runs the fuzz targets over seeded random input (Zig 0.16.0's `--fuzz` mode does not build). |
| `test/vectors.zig`, `test/vectors/` | Every published vector and both Wycheproof suites (README there says where each came from). |
| `test/c_abi_test.c` | The ABI as C sees it: errors, ownership, 64 MiB inputs, handle exhaustion, 8 threads. |
| `bench/main.zig` | `zig build bench`: each primitive, ReleaseFast, no bridge. |

## Rules

- **No chain here.** Curves, hashes, derivation schemes: yes. Addresses, message formats, networks: never. A chain
  that needs something new gets a new primitive with its own capability bit (docs/adding-an-adapter.md).
- **No secret leaves.** No function returns a seed or a private key. A secret is copied out of the vault onto the
  stack for one operation and zeroed before it returns (`defer secure.zero(...)`), on every path, errors included.
  The exceptions are `nc_mnemonic_generate` (a fresh mnemonic, handed out once for backup and never kept,
  docs/adr/0005) and what only native callers may use: entropy in and out for a vault (docs/adr/0008), and a backup
  opened back into entropy (docs/adr/0009). Nothing else joins them without an ADR of its own. Chain codes are not
  secrets but are not free either: `nc_seed_extended_public` hands out an account's, never the master's
  (docs/adr/0007).
- **No allocator for secrets.** The vault is a fixed table; buffers are stack arrays. The one exception is Argon2id's
  memory for a backup (docs/adr/0009): 64 MiB no stack holds, from the page allocator through one that zeroes every
  block before it goes back, freed before the call returns.
- **No secret-dependent branches in code of ours** (word lookups, comparisons). libsecp256k1 and Zig's Ed25519 make
  their own claims.
- **The ABI is additive.** New functions, statuses and capability bits are fine; changing a signature or a meaning
  bumps `NC_ABI_VERSION` here, in `abi/version.zig`, and `SUPPORTED_ABI_VERSION` in the facade. The bridge
  (`packages/nitro-crypto/cpp`) and the WebAssembly host (`packages/nitro-crypto/src/host/wasm.ts`) follow every
  change.
- **Every primitive has its published vectors** in `test/vectors.zig`, and a parity test against an independent
  implementation in the TypeScript tests.

## Commands

```bash
zig build test --summary all     # units, vectors, Wycheproof, property tests, the C harness (yarn engine:test)
zig build bench                  # timings; -Decmult-window=15 to compare tables (docs/adr/0002)
zig build wasm                   # zig-out/bin/nitro_crypto.wasm
zig fmt build.zig build.zig.zon src test bench

# The tests and the benchmark on an Android device or emulator, at arm64-v8a's baseline (ARMv8.0)
zig build test-exe bench-exe -Dtarget=aarch64-linux-musl -Dcpu=baseline
adb push zig-out/bin/. /data/local/tmp/nc/ && adb shell 'cd /data/local/tmp/nc && ./engine_test && ./vectors_test && ./c_abi_test'

# The same at x86-64's baseline, under QEMU with every extension it emulates (SHA included), in an arm64 container
zig build test-exe bench-exe -Dtarget=x86_64-linux-musl -p zig-out/x86_64
docker run --rm -v "$PWD/zig-out/x86_64/bin:/t:ro" debian:trixie sh -c \
  'apt-get update -qq && apt-get install -y -qq qemu-user && qemu-x86_64 -cpu max /t/engine_test'
```

A Mac never takes the run-time branch in `src/hash/sha2.zig` and `src/os/cpu.zig`: its build knows its processor
has the instructions. Change either, run the tests on the emulator and under QEMU too. (Docker's own amd64 emulation
is Rosetta, which has no SHA extensions and cannot load the larger test binaries.)

Cross-compiling for iOS and Android is `yarn engine` at the root: it writes a `--libc` file per target, strips,
repacks Apple archives with `libtool` (Zig 0.16 archives are not 8-byte aligned for ld64), and records digests. The
results are reproducible; `yarn engine:verify` checks them.
