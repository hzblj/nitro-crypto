# 8. Other native modules make seeds from entropy, and hand them over without JavaScript

Accepted. Amends [0004](0004-secrets-behind-handles.md) and [0005](0005-mnemonic-generation-for-backup.md).

## Context

The engine persists nothing (SECURITY.md): an app that keeps a wallet decides where. The example keeps its recovery
phrase in the Keychain behind Face ID, and to unlock reads it into JavaScript as a string, which no one can wipe, and
passes it to `createEphemeralWallet({mnemonic})`. That is the least a wallet should do.

A wallet can do better on a phone with a Secure Enclave or a StrongBox. Neither holds secp256k1 or Ed25519 keys, and
BIP-32 needs the seed, so signing stays in the engine; but either can seal the seed at rest under a key that never
leaves the chip and opens only for the person whose face or finger enrolled it. That is a separate package with
native code of its own on each platform (`@hzblj/crypto-vault`). What it unseals must reach the engine without
passing through JavaScript, or sealing it in hardware buys little.

Two Nitro modules in one app share one process and one engine: nitro-crypto links the engine into its native
library, and another module can link against that library. Nitro passes a Hybrid Object one module made through
another module's spec (external Hybrid Objects), as long as the first module's iOS module name and Android library
name agree, as nitro-crypto's do (`NitroCrypto`).

## Decision

- **What a vault keeps is BIP-39 entropy,** 16 to 32 bytes, not the seed and not the words. From it come both the
  seed (through the mnemonic, so it is the one a wallet restored from those words has) and the words themselves, when
  the user asks to see them for backup. Three functions, for native callers:
  - `nc_seed_from_entropy(entropy, passphrase)`: a seed handle; the mnemonic exists only on that call's stack.
  - `nc_mnemonic_to_entropy(mnemonic)`: what a vault seals when the user restores from words.
  - `nc_mnemonic_from_entropy(entropy)`: the words, written into the caller's buffer. Like `nc_mnemonic_generate`
    (ADR 0005), a secret handed out, for the one moment a user writes their words down.
- **JavaScript gets none of them.** The spec, the facade and the WebAssembly host stay as they are: no JavaScript call
  takes or returns entropy. A vault calls them natively through `cpp/NitroCryptoInterop.hpp`, which turns a seed
  handle into the `HybridNitroSeed` JavaScript receives, and the facade takes that object over:
  `createEphemeralWallet({seed, words})` wraps it as any other wallet, and disposing the wallet disposes it.
- **The bridge is exported.** The C header, the bridge's headers and the generated specs are CocoaPods public headers
  (`<NitroCrypto/NitroCryptoInterop.hpp>`) and the Android prefab module `NitroCrypto`, in the package Gradle names
  after the autolinked project (`hzblj_nitro-crypto::NitroCrypto`). `EngineBridge.hpp` includes the C header by a
  quoted name, so it is found beside the bridge in either layout.
- **Additive:** three functions and one capability bit, `bip39-entropy` (bit 16). The ABI version stays 1.
  `interop::supported()` checks both, so a module built against an older engine refuses to start rather than fail
  midway.
- **Held to the reference.** Trezor's BIP-39 vectors already check entropy to words and back; the C harness checks the
  seed from entropy against the seed from its words, and every refusal (lengths, buffers, checksums).

## Consequences

- A vault seals a wallet's entropy under a key the hardware holds, unseals it after the system's biometric prompt,
  and hands the engine a seed without JavaScript seeing a byte of it. What JavaScript holds is the same opaque
  `NitroSeed` `createEphemeralWallet` always returned.
- Another native module in the app can now make seeds: the engine trusts the process it lives in, as before (an
  attacker with code execution in it is out of scope).
- A passphrase (BIP-39's "25th word") goes through `nc_seed_from_entropy` but not yet through the interop helper,
  which makes seeds without one. A vault that wants one adds it to what it seals. (Amended: `interop::seedFromEntropy`
  now has an overload that takes one, UTF-8 and NFKD-normalized by the caller, as the facade normalizes its own.)
