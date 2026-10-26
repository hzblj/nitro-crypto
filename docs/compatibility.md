# Compatibility

## Supported

| | Version | Notes |
| --- | --- | --- |
| Expo SDK | 57 | Development builds only: Expo Go does not contain this native module. |
| React Native | 0.86 (New Architecture) | Nitro Modules require React Native 0.75 or newer; this repository builds and tests 0.86.3. |
| Nitro Modules | 0.37.1 (`^0.37.1`) | A peer dependency. The generated bindings are checked in, made with nitrogen 0.37.1. |
| iOS | 15.1 and later | React Native's own floor. Device arm64; simulator arm64 and x86_64. |
| Android | API 24 and later | arm64-v8a, armeabi-v7a, x86 and x86_64, aligned for 16 KB pages. |
| Xcode | 16.4 or later | Built and run here with Xcode 27.1. |
| Android NDK | 27.1.12297006 | React Native 0.86's. The engine archives are built against it; an app's own NDK links them. |
| Node.js | 22 | For the tooling and `@hzblj/nitro-crypto/testing` (which needs `WebAssembly` and `crypto.getRandomValues`). |
| Web, macOS, Windows | No | React Native and Expo on iOS and Android only. |

## Air-gapped signing

What `@hzblj/crypto-airgap` and its chain packages were tested against, and what they were not. A row says
"fixture" when the evidence is an independent implementation's output, and "device" only for a physical device.

| Type | Evidence | Kind |
| --- | --- | --- |
| UR, Bytewords, multipart (fountain codes) | Blockchain Commons' bc-ur (C++) test vectors: CRC-32, Bytewords, Xoshiro256**, sampler, shuffle, degrees, fragments, parts, single-part and multipart URs. `@ngraveio/bc-ur` 1.1.13: the same part strings, both ways, on random payloads, with lost parts. | Fixture |
| `crypto-hdkey`, `crypto-keypath`, `crypto-coin-info`, `crypto-eckey`, `crypto-multi-accounts` | `@keystonehq/bc-ur-registry` 0.8.1: the same CBOR both ways; its master and private keys refused. | Fixture |
| `crypto-account`, `crypto-output` | BCR-2020-015's example (seven descriptors) decodes key for key and re-encodes to the same UR. Keystone's form (descriptors without `#6.308`) reads; Keystone's registry reads neither the specification's form nor `tr` and `cosigner`. | Fixture |
| `crypto-psbt` | `@keystonehq/bc-ur-registry`'s `CryptoPSBT`: the same CBOR and UR. The PSBTs: `@scure/btc-signer` 2.4.1 reads ours, finalizes what we sign, and its signatures finalize here. | Fixture |
| `eth-sign-request`, `eth-signature` (ERC-4527) | `@keystonehq/bc-ur-registry-eth` 0.22.1: the same CBOR and URs both ways; a request it writes is answered here. viem 2.57.11 recovers the signers and reads the transactions. | Fixture |
| `sol-sign-request`, `sol-signature` | `@keystonehq/bc-ur-registry-sol` 0.9.5: the same CBOR and URs both ways, for transactions and messages. `@solana/kit` 8.5.0 decodes the messages the same way. | Fixture |
| Extended public keys | BIP-32's published xpubs at every depth, and `@scure/bip32` 2.4.0 on random paths: the engine's account keys and public derivation. Keystone's registry reads our `crypto-account` and `crypto-hdkey` as the same xpubs; viem's `mnemonicToAccount` agrees on MetaMask's. | Fixture |
| Keystone 3 (firmware codec) | `keystone-sdk-rust`'s own test payloads: `crypto-hdkey` (and the xpub it reads it as), `crypto-account` with single keys and a multisig written without `#6.308`, `crypto-multi-accounts` with an Ethereum account key and Solana keys, `eth-sign-request` (legacy and EIP-1559), `eth-signature`, a 0.1 SOL `sol-sign-request`, `sol-signature`. Each reads, writes back byte for byte where the codec does, and the keys are watched at the addresses `@scure/bip32` derives. | Fixture |
| Keystone (device) | Its developer documentation's `crypto-hdkey` for MetaMask decodes to the xpub it documents, and its `eth-signature` reads. | Fixture |
| OneKey | Its QR wallet gallery's EVM account key is watched; its master key, whole and in two parts, is refused (`PRIVATE_KEY_MATERIAL`). | Fixture |
| Sparrow | The `crypto-account` it imports (BCR-2020-015's form, with `#6.308`), and PSBTs it would send: three inputs at different addresses of the account with change, signed and finalized against `@scure/btc-signer`. | Fixture |
| MetaMask | The `crypto-hdkey` its QR keyring reads (children `0/*`, the note `account.standard`, read through Keystone's registry as its keyring does), and requests for any address below it. | Fixture |
| Any of these on a physical device or app | Not tested: no hardware wallet, Sparrow or MetaMask was paired while building this. | None |

The example wallet pairs and signs with itself (two phones, or one in the Debug tab's loopback), and shows pairing
codes for Sparrow and MetaMask. Fixtures are the formats these wallets write, taken from their own sources and test
suites (each `test/vectors` file says where); a device or app may still differ from its own fixtures, and that is
what the rows marked "None" leave open.

## Building the engine from source

Only contributors need this: the package ships the engine prebuilt.

| Tool | Version | Pinned where |
| --- | --- | --- |
| Zig | 0.16.0 exactly | `scripts/build-native/shared.mjs` refuses another, `build.zig.zon` (`minimum_zig_version`) |
| libsecp256k1 | v0.8.0 | `packages/zig-engine-crypto/build.zig.zon`, by URL and content hash |
| Android NDK | 27.1.12297006 | `scripts/build-native/android.mjs` |
| Xcode (iOS only) | any with the iOS SDK | Its SDK headers, `libtool`, `lipo` and `xcodebuild -create-xcframework` |

```sh
yarn engine            # every platform this machine can build: wasm, Android, and iOS on macOS
yarn engine:verify     # the artifacts: present, matching their digests, the whole ABI and nothing else exported
yarn engine:test       # the Zig tests, the published vectors, Wycheproof and the C ABI harness
```

The artifacts are reproducible: two builds from clean caches produce the same bytes (`engine/manifest.json` records
each artifact's SHA-256). What it took, for anyone changing the build:

- **Stripped artifacts.** Debug information carries the build machine's paths and a randomized cache path.
- **Repacked iOS archives.** Apple's linker ignores members of a Zig 0.16 archive that are not 8-byte aligned (and so
  drops libsecp256k1's tables); the build extracts the objects (making them readable: Zig writes mode 000) and
  re-archives them with `libtool`, with `ZERO_AR_DATE` set.
- **A canonical XCFramework `Info.plist`.** `xcodebuild` lists the libraries in no fixed order; the build sorts them.
- **A `--libc` file per target.** Zig finds the iOS SDK's and the NDK's headers through it; `--sysroot` alone is not
  enough.

## What the platforms bring

| | iOS | Android |
| --- | --- | --- |
| Randomness | `getentropy` | The `getrandom` system call (no libc version requirement) |
| Linking | The XCFramework, vendored by CocoaPods; the C++ bridge compiles with the app | `libnitro_crypto.a` for the ABI being built, linked into `libNitroCrypto.so` by CMake |
| 16 KB pages | n/a | The module is built with `ANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES`; Android 15 and later devices with 16 KB pages, and Google Play, require it. The emulator here runs a 16 KB image. |

## Verified on

| Platform | Where | What ran |
| --- | --- | --- |
| iOS 27.0 | iPhone 18 Pro simulator (arm64), Xcode 27.1 | The example, debug and release builds: the self-test, every screen, the Maestro smoke and tour flows, and the release benchmarks ([benchmarks](./benchmarks.md)) |
| Android 17 (API 37, 16 KB pages) | Pixel 9 Pro emulator (arm64-v8a) | The same |
| Android armeabi-v7a, x86, x86_64 | Built and linked into the example's APK | Not run: the Apple Silicon emulator runs arm64 only |
| macOS (arm64), Node 22 | The engine natively (Zig tests, C harness), and as WebAssembly (all TypeScript tests) | Everything but the bridge |

Physical devices were not available while building this version: the matrix above is what was actually run.
