# Architecture

nitro-crypto is a cryptography engine in Zig, a thin native bridge, a TypeScript facade, and one package per chain.
Dependencies point one way, down; nothing below the adapters knows a chain exists.

```text
apps/example                      Expo Router + Kara UI: every screen runs on the real engine
        │
        ├──────────────▶ @hzblj/crypto-airgap-{bitcoin,ethereum,solana}    air-gapped signing: requests and
        │                        │  answers as URs, checked through the     answers over QR codes, no UI
        │                        ▼  chain clients they are bound to
        │                @hzblj/crypto-airgap      UR codec, multipart, registry, public key types (no native code)
        ▼
@hzblj/crypto-ethereum   @hzblj/crypto-bitcoin   @hzblj/crypto-solana      (and any chain written elsewhere)
        │  plain TypeScript over @hzblj/nitro-crypto/adapter; no native code, no chain imports another
        ▼
@hzblj/nitro-crypto       facade: primitives, keys, wallets, the typed adapter registry, errors
        │  host: NitroCrypto, NitroSeed, NitroKey (src/specs/nitro-crypto.nitro.ts)
        ▼
Nitro Modules (JSI)       generated bindings (nitrogen/generated); buffers cross without copies
        │
        ▼
C++ bridge (cpp/)         three Hybrid Objects; argument views, status → exception, handle ownership
        │  nitro_crypto.h: a versioned C ABI
        ▼
Zig engine                packages/zig-engine-crypto: libsecp256k1, Zig std, BIP-39/32, SLIP-0010, handle vault
```

## The layers

**The engine** (`packages/zig-engine-crypto`) owns every cryptographic operation and every secret. It exports a C
ABI (`include/nitro_crypto.h`) of plain types: pointers with lengths in, status codes out, outputs into buffers the
caller owns. Secrets never cross it; seeds and private keys are 64-bit handles into a fixed table the engine zeroes on
release. It knows curves, hashes and derivation schemes, and no chain: there is no "Ethereum" anywhere in it.

It builds as a static library for iOS (an XCFramework), Android (four ABIs) and the host, and as a WebAssembly
reactor. Every artifact is reproducible and checked (`yarn engine`, `yarn engine:verify`).

**The bridge** (`packages/nitro-crypto/cpp`) is the C++ half of three Nitro Hybrid Objects, generated from
`src/specs/nitro-crypto.nitro.ts`:

- `NitroCrypto`, the engine: version and capabilities, randomness, hashes, HMAC, the stateless curve operations,
  mnemonic generation and validation, and the factories for seeds and keys.
- `NitroSeed`, a BIP-39 seed: its fingerprint, and `deriveKey(scheme, path)`.
- `NitroKey`, a private key: its curve, its public key, `sign`.

It contains no cryptography. Each method views its buffers, calls the ABI, and throws the status name on failure. Seed
and key objects own their handle (`EngineHandle`) and release it on `dispose()` or destruction. Two methods run on
Nitro's thread pool, because they take milliseconds: deriving a seed from a mnemonic (PBKDF2, 2048 rounds) and
hashing large payloads (`hashAsync`); both copy their inputs first, since a JS-owned buffer is only readable during
the synchronous call.

**The facade** (`packages/nitro-crypto/src`) is what applications use. It is written against the host interface,
not against Nitro: `createCryptoEngine` passes it the native module, and `@hzblj/nitro-crypto/testing` passes it the
same engine compiled to WebAssembly. Everything above the host, adapters included, is one code path in both.

- `engine/primitives.ts`: bytes in, bytes out; the verify policy (a malformed or upper-S signature is `false`, a
  malformed key throws).
- `engine/keys.ts`: native keys as `Secp256k1Key` / `Ed25519Key`, which track their own disposal.
- `engine/wallet.ts`: the ephemeral wallet, which owns its seed and every key derived from it.
- `adapters/`: the adapter contract and the registry.
- `core/errors.ts`: one `CryptoError` with a stable `code`; native status names map to codes, native messages are
  dropped.
- `encoding/`: hex, UTF-8, Base58, Base58Check and Bech32/Bech32m, pure, for every adapter to share.

**Adapters** are TypeScript packages that import only `@hzblj/nitro-crypto/adapter`, which loads no native code.
Each declares the engine capabilities it needs, binds to an engine once (`create`), and returns a client with
`deriveAccount` and `validateAddress` plus whatever its chain offers. See [adding-an-adapter.md](adding-an-adapter.md).

**Air-gap packages** sit beside the app, not under the engine. `@hzblj/crypto-airgap` is the payload protocol
(BC-UR v2: Bytewords, CBOR, fountain-coded multipart, a typed registry) and depends on nothing in this repository;
each chain's air-gap package binds to that chain's client (`bitcoinAirgap(crypto.chains.bitcoin)`) and uses it to
read, sign and verify what travels. They draw no QR code and open no camera: strings in, strings out
([ADR 0006](adr/0006-air-gap-as-data.md)).

## The adapter registry

```ts
const crypto = createCryptoEngine({adapters: [ethereumAdapter(), bitcoinAdapter(), solanaAdapter()]})
const wallet = await crypto.createEphemeralWallet()
const eth = await wallet.deriveAccount({chain: 'ethereum', index: 0}) // EthereumAccount
crypto.chains.bitcoin.validateAddress('bc1q…') // BitcoinAddressValidation
```

The adapters list is a `const` type parameter, so the registry's type is a map from each literal id to its client
type, with no `any` and no switch over chains: `deriveAccount({chain: 'ethereum', …})` takes Ethereum's request and
returns Ethereum's account. At runtime the registry validates every adapter before binding any (shape, unique id,
capabilities the engine has), so a bad list fails whole, naming the adapter and the problem.

## Where secrets are

| Secret | Where it lives | How long |
| --- | --- | --- |
| A mnemonic `createEphemeralWallet()` generates | The stack of the native call that turns it into a seed | That call |
| A mnemonic `crypto.mnemonic.generate()` returns | The engine's stack, then the bridge's stack buffer, then a JS string | The engine and the bridge zero theirs before returning, the facade overwrites its bytes; the string is the app's |
| A seed, a private key | One slot of the engine's handle table | Until `dispose()`, garbage collection, or the process ends |
| A copy for one operation | The engine's stack | That operation, zeroed before it returns |
| A mnemonic or passphrase the app passes in | The app's strings; the facade's UTF-8 bytes; the bridge's copy | The facade and the bridge overwrite theirs; the app's are the app's |

JavaScript holds `NitroSeed` and `NitroKey` objects, never key bytes. The one secret that reaches it is a mnemonic the
app asked for, to show the user once ([ADR 0005](adr/0005-mnemonic-generation-for-backup.md)). Account-level extended
public keys reach it too, for watch-only wallets to derive addresses from; the master's never does
([ADR 0007](adr/0007-extended-public-keys.md)). See [SECURITY.md](../SECURITY.md).

## Packaging

`@hzblj/nitro-crypto` ships the prebuilt engine (`engine/`), the bridge's C++, the generated Nitro code, the podspec
and the Android library. CocoaPods vendors the XCFramework; CMake links the archive for the ABI being built. An app
installs it like any Nitro module and needs no Zig. It is autolinked as a React Native module; there is no Expo module
wrapper and no config plugin, because nothing in the native build needs configuring.

## How this layout maps to the plan

The implementation plan sketched a layout; where the repositories' conventions differ, they win:

| Plan | Here | Why |
| --- | --- | --- |
| `apps/example-expo/` | `apps/example/` | Every library repository names its example `apps/example`. |
| `native/zig-crypto/` | `packages/zig-engine-crypto/` | A workspace like the others (zyplot keeps its Zig engine in `packages/` too); private, never published. Its artifacts ship inside `@hzblj/nitro-crypto`. |
| `packages/crypto-adapter-core/` | `@hzblj/nitro-crypto/adapter` | A subpath, not a package: the contract has no dependency boundary of its own to justify one, and a subpath loads no native code just the same. |
| `scripts/build-native/`, `scripts/verify-artifacts/` | The same | |
| `docs/security.md` | `SECURITY.md` | Where GitHub looks for it. |
