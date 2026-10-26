# nitro-crypto

[![npm](https://img.shields.io/npm/v/@hzblj/nitro-crypto.svg)](https://www.npmjs.com/package/@hzblj/nitro-crypto)
[![license](https://img.shields.io/npm/l/@hzblj/nitro-crypto.svg)](./LICENSE)

Native cryptography for React Native and Expo: a Zig engine behind Nitro Modules hashes, signs and derives keys, and
holds every seed and private key in native memory. Chains are adapters, each its own package, on a typed registry:
Ethereum, Bitcoin and Solana here, any other chain whose primitives the engine has in a few dozen lines.

> [!WARNING]
> **Not security audited. Never use with real funds.** See [SECURITY.md](./SECURITY.md).

<p>
  <img alt="The example wallet on iOS: Sepolia, Bitcoin testnet4 and Solana devnet from one phrase, its keys and signatures in the native engine" height="560" src="media/ios-wallet.png" />
  <img alt="The same on Android" height="560" src="media/android-wallet.png" />
</p>

```sh
npx expo install @hzblj/nitro-crypto @hzblj/crypto-ethereum react-native-nitro-modules
```

```ts
import {ethereumAdapter} from '@hzblj/crypto-ethereum'
import {createCryptoEngine} from '@hzblj/nitro-crypto'

const crypto = createCryptoEngine({adapters: [ethereumAdapter()]})
const wallet = await crypto.createEphemeralWallet()
const account = await wallet.deriveAccount({chain: 'ethereum', index: 0})
const signature = await account.signMessage({message: 'Hello from Expo'})
```

**[Documentation](./packages/nitro-crypto/README.md)**: install, the API, supported algorithms, chains and platforms,
and what is not in this version.

## This repository

| Path | What lives there |
| --- | --- |
| `packages/nitro-crypto/` | `@hzblj/nitro-crypto`: the TypeScript facade and adapter registry, the Nitro specs and C++ bridge, the prebuilt engine |
| `packages/crypto-ethereum/`, `crypto-bitcoin/`, `crypto-solana/` | The chain adapters, each published on its own |
| `packages/zig-engine-crypto/` | The engine in Zig: its C ABI, tests, published vectors and benchmark (private; it ships inside `@hzblj/nitro-crypto`) |
| `apps/example/` | The example app: a testnet wallet (Sepolia, Bitcoin testnet4, Solana devnet) that sends and receives on the engine, and a Debug tab with the self-test, accounts on four chains, signing, primitives, benchmarks, security |
| `scripts/` | The engine's reproducible builds and their verification, the pack check, version sync |
| `docs/` | [Architecture](./docs/architecture.md), [adding an adapter](./docs/adding-an-adapter.md), [compatibility](./docs/compatibility.md), [benchmarks](./docs/benchmarks.md), [decisions](./docs/adr) |

```sh
yarn                 # install
yarn engine          # build the engine for every platform this machine can (needs Zig 0.16.0)
yarn prebuild        # build the engine, then a clean `expo prebuild` of the example
yarn ios             # run the example on iOS (dev client); `yarn android` for Android
yarn test            # the Zig tests, vectors and C harness, and every TypeScript test on the engine as WebAssembly
yarn lint            # Biome and TypeScript
yarn engine:verify   # the prebuilt artifacts: digests, architectures, exported symbols
yarn pack:check      # pack every package as npm gets it and type-check a consumer
yarn changeset       # describe a change for the next release
```

## More libraries

The other libraries from the same author are at **[libraries.janblazej.dev](https://www.libraries.janblazej.dev)**.
