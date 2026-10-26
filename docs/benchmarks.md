# Benchmarks

Two sets of numbers: the engine on its own, and the engine through Nitro in a release build of the example app,
beside @noble's audited JavaScript doing the same work. Both were measured on one Mac (Apple M1 Max, macOS 27.0), the
second on its iOS simulator and its Android emulator.

> [!IMPORTANT]
> **No physical device was measured.** The simulator and the emulator run on the Mac's cores, which are faster than a
> phone's: read the absolute numbers as a lower bound, and the ratios between native and JavaScript as the finding.
> A Mac does not throttle the way a phone does either.

## The engine on its own

`zig build bench` in `packages/zig-engine-crypto` (`yarn workspace @hzblj/zig-engine-crypto bench`): each primitive
called directly, ReleaseFast, on macOS arm64. Each figure is the median of seven timed batches. This is the floor every
number in the app adds the Nitro call to.

| Operation | 32 B | 1 KiB | 1 MiB |
| --- | --- | --- | --- |
| SHA-256 | 0.06 µs | 0.54 µs | 501 µs |
| SHA-512 | 0.11 µs | 0.82 µs | 762 µs |
| Keccak-256 | 0.22 µs | 1.78 µs | 1.71 ms |
| RIPEMD-160 | 0.19 µs | 3.12 µs | 3.00 ms |

| Operation | Time |
| --- | --- |
| secp256k1 public key from a private key | 14.4 µs |
| secp256k1 sign (RFC 6979 nonce, lower S) | 21.5 µs |
| secp256k1 verify | 30.8 µs |
| secp256k1 recover | 31.3 µs |
| Ed25519 sign, 1 KiB message | 53.3 µs |
| Ed25519 verify, 1 KiB message | 56.9 µs |
| BIP-39 seed (PBKDF2-HMAC-SHA512, 2048 rounds) | 1.02 ms |
| BIP-32 `m/44'/60'/0'/0/0` from the seed | 32.0 µs |
| SLIP-0010 `m/44'/501'/0'/0'` from the seed | 2.5 µs |

secp256k1 is libsecp256k1 with an 8-bit precomputation window, not upstream's 15: about 7% slower verification for a
megabyte less in every binary. [ADR 0002](./adr/0002-secp256k1-from-libsecp256k1.md) has the measurements for each
window, and `-Decmult-window=15` builds the upstream default.

An Ed25519 key is kept with its public key beside the seed, computed once when the key enters the vault: a signature
then costs one scalar multiplication rather than two. Before that change, signing 1 KiB took 98 µs here.

### SHA-2 on the processor's instructions

Zig's library uses the SHA-2 instructions only for SHA-256, and only when the build promises them. The engine is built
for each platform's oldest processor, so it now asks the system which instructions there are (`src/os/cpu.zig`) and
runs SHA-256 and SHA-512 on them (`src/hash/sha2.zig`). What changed, here and on the Android emulator, which runs the
same bench built for arm64-v8a's baseline (`zig build bench-exe`, below):

| Operation | macOS, before | macOS, now | Android emulator, before | Android emulator, now |
| --- | --- | --- | --- | --- |
| SHA-256, 1 MiB | 481 µs | 501 µs | 4.73 ms | 509 µs |
| SHA-512, 1 MiB | 3.07 ms | 762 µs | 3.16 ms | 780 µs |
| BIP-39 seed | 3.46 ms | 1.02 ms | 3.57 ms | 1.12 ms |
| BIP-32 path | 38.4 µs | 32.0 µs | 40.2 µs | 33.4 µs |
| SLIP-0010 path | 8.3 µs | 2.5 µs | 8.6 µs | 2.4 µs |

On the Mac, SHA-256 is Zig's in both columns (the build promises the instructions, and Zig uses them): the two figures
differ by a run. SHA-512 is four times faster on both, and with it HMAC-SHA512, under BIP-32, SLIP-0010 and the
2048 rounds of PBKDF2 that make a BIP-39 seed. Ed25519 hashes with the SHA-512 inside Zig's Ed25519, which the engine
does not replace, so its figures are unchanged. On Android's x86_64 ABI, SHA-256 runs on the SHA extensions where the
processor has them; no x86 figures here, as the only x86-64 with them at hand was QEMU's.

## Through Nitro, in the example app

The example's Performance screen (Lab, then Performance) runs each operation natively through the facade and, where one
exists, the same operation in `@noble/hashes` and `@noble/curves` on the same keys and inputs, after a short warm-up,
one call at a time. The figures are time per call, from release builds (Hermes, the bundle embedded), photographed by
the `release-benchmarks` Maestro flow.

- iOS: iPhone 18 Pro simulator, iOS 27.0, arm64. One run.
- Android: Pixel 9 Pro emulator, Android 17 (API 37, 16 KB pages), arm64-v8a. The median of three runs, figure by
  figure: the emulator is noisy (below).

**32-byte payload, 1000 calls**

| Operation | iOS, native | iOS, @noble | Android, native | Android, @noble |
| --- | --- | --- | --- | --- |
| Bridge crossing (SHA-256 of nothing) | 1.39 µs | 27.8 µs | 1.90 µs | 29.8 µs |
| SHA-256 | 1.03 µs | 28.4 µs | 1.33 µs | 31.0 µs |
| Keccak-256 | 1.27 µs | 165 µs | 1.40 µs | 126 µs |
| SHA-256, async (awaited) | 22.2 µs | | 312 µs | |
| secp256k1 sign | 23.8 µs | 5.88 ms | 28.3 µs | 7.67 ms |
| secp256k1 verify | 34.5 µs | 19.8 ms | 45.0 µs | 26.6 ms |
| Ed25519 sign | 51.3 µs | 5.21 ms | 60.4 µs | 6.70 ms |
| Ed25519 verify | 57.1 µs | 17.1 ms | 76.4 µs | 23.9 ms |
| Wallet from a mnemonic (awaited) | 1.26 ms | | 1.71 ms | |

**64 KiB payload, 100 calls** (the operations whose cost grows with the input)

| Operation | iOS, native | iOS, @noble | Android, native | Android, @noble |
| --- | --- | --- | --- | --- |
| SHA-256 | 32.3 µs | 26.7 ms | 38.4 µs | 29.2 ms |
| Keccak-256 | 109 µs | 77.3 ms | 136 µs | 58.0 ms |
| SHA-256, async (awaited) | 57.9 µs | | 463 µs | |
| Ed25519 sign | 498 µs | 189 ms | 494 µs | 192 ms |
| Ed25519 verify | 255 µs | 108 ms | 305 µs | 116 ms |

## Reading the numbers

**A call costs about 1.4 µs on iOS and 1.9 µs on Android.** SHA-256 of nothing is almost all crossing: the JSI call,
the C++ bridge, the `ArrayBuffer` native code allocates for the result, and the `Uint8Array` the facade wraps around
it. Below a few microseconds of work, the crossing is the cost.

**The JavaScript side is Hermes, and the ratios are Hermes's.** Hermes interprets bytecode without a JIT, and @noble's
curves do their arithmetic in `BigInt`, which it runs slowly: signing and verifying are 100 to 600 times slower there
than in the engine, hashing small inputs 20 to 130 times. The same @noble code under a JIT (Node, a browser) is far
faster than these figures. The comparison answers one question: what moving this work out of Hermes buys an app.

**Awaiting costs a thread hop: about 20 µs on iOS, 0.3 ms on Android.** The async calls run on Nitro's thread pool and
resolve on the JavaScript thread through React Native's call invoker, which is slower to wake on Android. That is
worth paying when the work takes milliseconds (a wallet, which runs PBKDF2; hashing a megabyte), not for a digest of a
few bytes. `digestAsync` is documented that way.

**SHA-2 runs on the processor's instructions, chosen at run time.** The engine is built for each platform's oldest
processor, and Zig's library chooses its SHA-2 when it compiles, so it hashed in software wherever the build could not
promise the instructions: SHA-256 on Android, SHA-512 everywhere. The engine now asks the system once (`getauxval`,
`sysctlbyname`, `cpuid`, in `src/os/cpu.zig`) and uses the instructions when they are there (the engine section above
has the figures alone). In the app, SHA-256 of 64 KiB on Android went from 353 µs to 38.4 µs, against 32.3 µs on iOS,
and a wallet from a mnemonic, whose 2048 rounds of PBKDF2 are HMAC-SHA512, from 3.72 ms to 1.26 ms on iOS and from
4.70 ms to 1.71 ms on Android.

**Ed25519 signs in one scalar multiplication.** Keeping the public key beside the seed in the vault halved the cost of
a signature in the app: 98.9 µs to 51.3 µs on iOS, 117.7 µs to about 60 µs on Android (32 bytes).

**The emulator is noisier than the simulator.** Its figures move between runs, sometimes a whole phase at once: over the
three runs above, SHA-256, awaited, of 64 KiB measured 744 µs, 463 µs and 418 µs, and secp256k1 verify 45.0 µs,
57.4 µs and 41.8 µs, where the simulator gave 1.03 µs, 1.02 µs and 1.03 µs for SHA-256 of 32 bytes in three runs.
Hence the medians; ratios within one run are steadier than absolute figures across runs.

**Debug builds are not benchmarks.** In a development build, Hermes runs unoptimized JavaScript and the bridge crossing
measured about 3 µs on iOS: the screen says so when it runs in one.

## Running them

```sh
yarn workspace @hzblj/zig-engine-crypto bench   # the engine alone, ReleaseFast
yarn workspace @hzblj/zig-engine-crypto bench -Decmult-window=15   # with upstream's secp256k1 tables

# The engine alone on an Android device or emulator, at arm64-v8a's baseline
cd packages/zig-engine-crypto
zig build bench-exe -Dtarget=aarch64-linux-musl -Dcpu=baseline
adb push zig-out/bin/nitro_crypto_bench /data/local/tmp/ && adb shell /data/local/tmp/nitro_crypto_bench
```

In the app, build a release (`yarn example expo run:ios --configuration Release`, or
`yarn example expo run:android --variant release`), open Lab, then Performance, and run. With the release build
installed on a booted simulator or a running emulator, `yarn example e2e ios release-benchmarks --release` (or
`android`) runs it at 32 bytes and at 64 KiB and saves the screenshots to `apps/example/e2e/output/`.
