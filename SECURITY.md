# Security

> [!WARNING]
> **Not security audited. Do not use with real funds.** nitro-crypto is a foundation and a demonstration of an
> architecture. Its keys are real cryptography, but nothing about their storage, backup or review makes them fit for
> anything of value, and no independent party has reviewed this code.

## Reporting a vulnerability

Please report privately, through GitHub's [private vulnerability reporting](https://github.com/hzblj/nitro-crypto/security/advisories/new)
on this repository, not in a public issue. Include what you found, how to reproduce it, and which version. You will get
an acknowledgement, and a fix or an explanation, as soon as it can be worked out; a confirmed issue is disclosed in the
changelog and a GitHub advisory once a fixed version is published.

## What this protects, and from whom

**Assets.** Private keys and BIP-39 seeds, created or imported in an app, for as long as the app holds them.

**In scope:**

- JavaScript never holding key material in ordinary use. Seeds and private keys live in the engine's native memory,
  behind opaque handles; JavaScript holds objects, public keys, addresses and signatures. A leak through the JS heap,
  a debugger attached to JavaScript, a crash report of JS state or a log line does not carry a key. The exception is
  a mnemonic the app asks for (`crypto.mnemonic.generate`) or passes in to restore a wallet: that string is the app's.
- Secrets not outliving their use inside the engine: a disposed key or seed is zeroized, its slot reused only under a
  new generation, so a stale handle never reaches another secret.
- Errors never carrying inputs: native errors are status names (`NC_ERR_INVALID_LENGTH`), and the facade drops any
  other native message rather than pass it on.
- Signatures that do not leak the key through their nonce (RFC 6979 for ECDSA, BIP-340's nonce with fresh auxiliary
  randomness for Schnorr, and libsecp256k1's constant-time signing with blinding), and verification that refuses
  malleable (upper-S) and non-canonical encodings. A Taproot key is tweaked inside the engine (BIP-341), and the tweaked
  key never leaves the stack of the call that signs with it.
- Randomness only from the operating system, failing closed.

**Out of scope:**

- An attacker with code execution in the app's process, or a compromised or rooted device: they can read native
  memory as easily as JavaScript's.
- Hardware isolation. These keys are **not** in Secure Enclave or StrongBox: neither holds secp256k1 or Ed25519 keys
  for general signing, and nothing here pretends otherwise.
- Persistence and secure storage: there is none (see below). Backup is the user's: the engine can hand out a fresh
  mnemonic once, and restore a wallet from one.
- Side channels beyond what the underlying implementations claim (see "Primitives").
- Physical and fault attacks.

## Key lifecycle

1. **Created** inside the engine: from 16 to 32 bytes of OS entropy turned into a BIP-39 mnemonic and its seed
   (`createEphemeralWallet()`), from a mnemonic the user wrote down, one `crypto.mnemonic.generate()` returned or a
   test vector (`createEphemeralWallet({mnemonic})`), from BIP-39 entropy another native module in the app holds,
   such as a vault that unsealed it (`nc_seed_from_entropy` through `cpp/NitroCryptoInterop.hpp`, never from
   JavaScript, docs/adr/0008), from fresh entropy for a lone key (`keys.generate`), or from raw bytes for
   interoperability (`keys.importRawSecret`, which is absent from every ordinary flow and named to say so).
2. **Held** in a fixed table inside the engine (1024 slots, no allocator), addressed by a 64-bit handle that encodes a
   slot and a generation. Each operation copies the one secret it needs onto the stack, uses it and zeroes the copy.
3. **Used**: derivation (BIP-32, SLIP-0010) creates new key handles; signing returns a signature. No operation returns
   a seed or a private key. The mnemonic behind `createEphemeralWallet()` exists only on the stack of the call that
   turns it into a seed; `crypto.mnemonic.generate()` is the one call that hands a mnemonic out, once, for the user to
   write down (docs/adr/0005). The engine keeps no copy of it, the bridge zeroes its stack buffer, and the facade
   overwrites its bytes after decoding them; the string it returns is the app's. `wallet.extendedPublicKey(path)`
   hands out an account's public key and chain code, never the master's (docs/adr/0007): public, but with any one
   private key below it in a non-hardened step, it would give the account's private key away, and it shows every
   address of the account to whoever holds it.
4. **Destroyed** by `dispose()` on a key or a wallet (a wallet disposes every key derived from it), or when the
   native object is garbage-collected: the slot is zeroized and freed. A reload, a restart or an uninstall ends the
   process and the memory with it. **Nothing is ever persisted.**

## Known limitations

- **Best-effort zeroization.** The engine zeroes what it owns, through volatile writes the optimizer cannot remove.
  Copies made elsewhere are beyond its reach: a mnemonic or passphrase typed into a text field lives in JavaScript
  strings and native UI buffers before the facade encodes it; the facade overwrites its own byte copies after use,
  and the C++ bridge zeroes its copies, but the JS engine may have made others. Swap and core dumps are the
  operating system's.
- **No secure storage.** Persistence, biometric authorization, passkeys and encrypted backup each need their own design
  and review, and are deliberately absent from the library. An app that keeps a mnemonic decides where: the platform's
  keychain, behind its biometric prompt, is the least it should do. Better is a vault that keeps the entropy sealed by
  the Secure Enclave or StrongBox and hands the engine a seed natively (docs/adr/0008), so no word or byte of it
  reaches JavaScript.
- **A generated or restored mnemonic is a JavaScript string.** `crypto.mnemonic.generate()` returns one, and
  `createEphemeralWallet({mnemonic})` takes one across the bridge as bytes it overwrites afterwards. Strings cannot be
  wiped: the one the app holds, and any copies the JS engine made, are outside the library's control.
- **Spin lock, not a mutex.** Handle-table operations are microseconds long; under heavy contention a thread spins,
  then yields.
- **Chains: what is not implemented is refused, not imitated.** The adapters build and sign Ethereum transactions
  of types 0 (EIP-155), 1, 2 and 4 and EIP-712 typed data, Bitcoin P2WPKH payments and PSBTs, and Solana legacy and v0
  transactions (SOL and SPL transfers, and a slot of any transaction others sign too) and off-chain messages. Bitcoin
  accounts have no `signMessage`; Ethereum's blob transactions (EIP-4844), Bitcoin's BIP-322, Taproot and PSBT
  version 2, and Solana's v1 transactions are not implemented.
- **Ethereum signs nothing it cannot show.** No account signs a bare hash (`eth_sign`), directly or through the viem
  account. Every transaction, typed data domain and EIP-7702 authorization is bound to the adapter's chain id
  (`CHAIN_MISMATCH` otherwise); a legacy transaction always carries EIP-155 replay protection, and an authorization
  for chain id 0, valid on every chain, needs an explicit `allowAllChains`. What a delegate contract does with an
  account, and what a dApp's typed data means, is for the app to show before it asks for the signature.
- **The example wallet is a testnet demo.** `apps/example` keeps its recovery phrase in the platform keychain
  (`expo-secure-store`, this device only, behind Face ID or the passcode), reads it into JavaScript to unlock, and
  wipes the engine's seed and keys after a minute in the background. That is the least a wallet should do, not an
  audited design; it talks to Sepolia, Bitcoin testnet4 and Solana devnet only.

## Air-gapped signing

The air-gap packages (`@hzblj/crypto-airgap` and its chain packages) live in
[hzblj/crypto-airgap](https://github.com/hzblj/crypto-airgap), with their own
[security policy](https://github.com/hzblj/crypto-airgap/blob/main/SECURITY.md): what they treat as hostile, what they
check before a signer signs and before a watch-only wallet broadcasts, and what they leave to the app. What they share
to pair comes from here: public keys with their paths, or an account's extended public key, never the master's and
never a private one (docs/adr/0007).

## Primitives and dependencies

| Primitive | Implementation | Notes |
| --- | --- | --- |
| secp256k1 ECDSA, recovery, key tweaks, BIP-340 Schnorr | [bitcoin-core/libsecp256k1](https://github.com/bitcoin-core/secp256k1) v0.8.0, with the recovery, extrakeys and schnorrsig modules | Bitcoin Core's: constant-time signing, context blinding, RFC 6979, lower S; BIP-340 signatures verified before they are returned. Symbols renamed `nc_secp256k1_*` so an app may link another copy. MIT. |
| Ed25519 | Zig 0.16 standard library | RFC 8032, deterministic; strict verification (rejects non-canonical S, invalid R, small-order keys). MIT. |
| SHA-256, SHA-512, HMAC, PBKDF2 | Zig 0.16 standard library | MIT. Where the processor has instructions Zig does not use, the next row's. |
| SHA-256 and SHA-512 on the processor's instructions | This repository (`packages/zig-engine-crypto/src/hash/sha2.zig`, `sha2/armv8.zig`, `sha2/x86.zig`) | Used where Zig's library would hash in software though the processor has the instructions: SHA-256 on Android (ARMv8 SHA-2, x86 SHA extensions), SHA-512 everywhere it has ARMv8.2's. The system is asked once (`getauxval`, `sysctlbyname`, `cpuid`); otherwise Zig's software. SHA-256's sequences are Zig's own; SHA-512's follows the instructions' definitions, as the Linux kernel's does. Branches on lengths only. Checked against the FIPS 180-4 examples and Zig's implementation at every length, split and random input, on a Mac, the Android emulator and QEMU's x86-64. Ed25519 keeps Zig's own SHA-512. |
| Keccak-256 | Zig 0.16 standard library | Ethereum's Keccak (padding 0x01), not SHA3-256. MIT. |
| RIPEMD-160 | This repository (`packages/zig-engine-crypto/src/hash/ripemd160.zig`) | Zig's library lacks it. A transcription of the reference, for public data only (HASH160 of public keys). Checked against the reference vectors and `@noble/hashes`. |
| BIP-39 | This repository, English list from bitcoin/bips | Word lookups in both directions scan the whole list with masks, so timing does not depend on the words. The list is pinned by its SHA-256. |
| BIP-32, SLIP-0010 | This repository, over the primitives above | BIP-32's invalid-child case fails (`DERIVATION_FAILED`) rather than silently moving to the next index. |
| Randomness | The OS: `getentropy` (Apple), `getrandom` (Linux, Android) | No user-space generator. Failure is `ENTROPY_UNAVAILABLE` and a zeroed buffer. |

Zig's memory safety is not a constant-time guarantee: the engine relies on libsecp256k1's and Zig's own claims for
their primitives, and keeps its own code (word lookups, comparisons) free of secret-dependent branches.

**Dependency audit strategy.** Every native dependency is pinned by content: libsecp256k1 by the hash in
`build.zig.zon`, Zig by version (`0.16.0`, which the build scripts refuse to differ from), the NDK by version. Release
artifacts are built reproducibly (two clean builds produce the same bytes; `engine/manifest.json` records each
artifact's SHA-256 and `yarn engine:verify` checks them, and that nothing but `nc_*` is exported). Updating a
dependency means: read its changelog and security advisories, update the pin, rerun the published vectors, the
Wycheproof suites and the parity tests against independent libraries, and record the change in the changelog.
JavaScript dependencies of the published packages: none at runtime besides the `react-native-nitro-modules` peer.

## Verification

- Published vectors: FIPS 180-4, RFC 4231, RFC 8032, the RIPEMD-160 reference, BIP-39 (Trezor), BIP-32 vectors 1 to 4,
  SLIP-0010, BIP-84, BIP-86, BIP-173, BIP-340, BIP-341's wallet vectors and BIP-350.
- Google's Wycheproof suites for secp256k1 ECDSA and Ed25519 (462 cases).
- Parity on random inputs with `@noble/hashes`, `@noble/curves`, `@scure/bip32`, `@scure/bip39`, `@scure/btc-signer`,
  viem and `@solana/kit`, run against the engine itself (compiled to WebAssembly).
- The air-gap packages: Blockchain Commons' bc-ur test vectors and BCR-2020-015's example, every multipart part
  compared both ways with `@ngraveio/bc-ur`, and every UR type's CBOR compared with Keystone's registries.
- A C program exercising the ABI: errors, ownership, 64 MiB inputs, handle exhaustion, 8 threads at once.
- Fuzz targets for the path parser, the mnemonic parser and the whole ABI boundary, run over seeded random inputs.
