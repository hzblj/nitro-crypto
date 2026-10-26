# 6. Air-gapped signing is data, in packages of its own

Accepted. The packages have since moved to their own repository,
[hzblj/crypto-airgap](https://github.com/hzblj/crypto-airgap), where this decision continues as its ADR 0001.

## Context

A watch-only wallet and an offline signer (a hardware wallet, or a second phone that never goes online) exchange
signing requests, public accounts and signatures as QR codes. The industry's format for that is Blockchain Commons'
Uniform Resources (BC-UR v2): typed CBOR, Bytewords text with a checksum, and fountain-coded multipart parts for
payloads larger than one code. Keystone, OneKey, Sparrow and others speak it, with each chain's types on top
(`crypto-psbt`, ERC-4527's `eth-sign-request`, Keystone's `sol-sign-request`).

Three questions had to be answered: whether to depend on an existing UR implementation, where the code lives, and
what it may know about the app around it.

## Decision

- **Our own codec, held to the reference.** `@ngraveio/bc-ur`, the JavaScript implementation most wallets use, needs
  Node's `Buffer` and `assert`, `sha.js`, `crc`, `jsbi` and `bignumber.js`: polyfills in every React Native app, and
  a large surface to audit for a few hundred lines of protocol. `@hzblj/crypto-airgap` implements Bytewords, the CBOR
  subset UR types use, and the fountain code in TypeScript over `Uint8Array`, with no dependencies. The one
  cryptographic function it needs, the SHA-256 that seeds the fountain code's generator, is the caller's: the
  engine's `crypto.hash.sha256` in an app, so an app has one SHA-256, the engine's, and the package installs alone. Its tests run Blockchain Commons' own C++ test vectors and
  compare every part, both ways, with `@ngraveio/bc-ur`; the type packages compare their CBOR with Keystone's
  registries. A part that differs by a bit from the reference's is a part no other wallet reads, so the parity tests
  are the specification here.
- **Headless.** The packages turn values into strings and strings into values. Drawing QR codes, the camera, its
  permission, and the timing of an animated QR are the app's; nothing here has a timer, a component or a native
  module. The example app shows one way to do the rest (`qrcode-generator`, `expo-camera`).
- **A core and a package per chain.** `@hzblj/crypto-airgap` knows no chain: the codec, the registry, the public key
  types every chain shares (`crypto-hdkey`, `crypto-keypath`, `crypto-multi-accounts`), and the requester and
  responder shapes. `@hzblj/crypto-airgap-bitcoin`, `-ethereum` and `-solana` each add their types and an adapter
  bound to the chain client (`bitcoinAirgap(crypto.chains.bitcoin)`), so they decode, sign and verify through the
  existing adapters and the engine, and contain no cryptography of their own. A new chain is a new package.
- **The chain adapters grew what signing elsewhere needs,** and nothing else: PSBTs and watch-only accounts for
  Bitcoin (BIP-174 had been listed as a later capability), strict parsing, signer recovery and assembly for
  Ethereum, message decoding and assembly for Solana. Each is useful without QR codes, and tested against the same
  independent libraries as before.
- **Hostile input, checked answers.** Decoders take allowlists and bounds; seed and private key types are refused
  whatever an allowlist says; a response is checked against the request it answers (its id, its transaction, its
  signer, verified by the engine) before anything is broadcast. Decoding a request is never consent: the signer shows
  it and asks.

## Consequences

- Interoperability is claimed only where a test shows it: the reference vectors, `@ngraveio/bc-ur`, Keystone's
  registries, `@scure/btc-signer`, viem and `@solana/kit`. No hardware wallet was available while building this
  version; [compatibility](../compatibility.md) lists what was and was not tried.
- The engine still exports no chain code, so this wallet shares single public keys, not extended ones, and a
  watch-only wallet cannot yet derive addresses from an extended key a hardware wallet shares (public BIP-32
  derivation is not in the engine). Pairing with wallets that require an extended key (MetaMask's QR hardware
  wallets, Sparrow) waits for that.
- Keystone's JavaScript registry writes `crypto-account` descriptors without the `#6.308` tag the specification's
  example has. The packages write what the specification shows and read both.
