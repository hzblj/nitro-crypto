# @hzblj/nitro-crypto

[![npm](https://img.shields.io/npm/v/@hzblj/nitro-crypto.svg)](https://www.npmjs.com/package/@hzblj/nitro-crypto)
[![license](https://img.shields.io/npm/l/@hzblj/nitro-crypto.svg)](https://github.com/hzblj/nitro-crypto/blob/main/LICENSE)

Native cryptography for React Native and Expo. A Zig engine, behind Nitro Modules, does the hashing, the signing and
the key derivation, and holds every seed and private key in native memory: JavaScript gets objects, public keys and
signatures, never key bytes. Chains are separate packages that plug into a typed registry.

> [!WARNING]
> **Not security audited. Never use with real funds.** Keys are ephemeral and live in memory only. See
> [SECURITY.md](https://github.com/hzblj/nitro-crypto/blob/main/SECURITY.md).

<p>
  <img alt="An Ethereum account derived from one seed by the native engine, in the example on iOS" height="560" src="https://raw.githubusercontent.com/hzblj/nitro-crypto/main/media/ios-accounts.png" />
  <img alt="The same on Android" height="560" src="https://raw.githubusercontent.com/hzblj/nitro-crypto/main/media/android-accounts.png" />
</p>

- SHA-256, SHA-512, Keccak-256, RIPEMD-160, HMAC, and OS randomness that fails closed
- secp256k1 from Bitcoin Core's libsecp256k1: RFC 6979, lower S, public key recovery
- Ed25519 (RFC 8032), strict verification
- BIP-39 seeds, BIP-32 and SLIP-0010 derivation, all inside the engine
- Chain adapters: [Ethereum](https://www.npmjs.com/package/@hzblj/crypto-ethereum), [Bitcoin](https://www.npmjs.com/package/@hzblj/crypto-bitcoin),
  [Solana](https://www.npmjs.com/package/@hzblj/crypto-solana), or your own
- Prebuilt for iOS and Android: no Zig needed
- `@hzblj/nitro-crypto/testing`: the same engine as WebAssembly, for tests in Node, Jest and Vitest

## Install

```sh
npx expo install @hzblj/nitro-crypto react-native-nitro-modules
npx expo install @hzblj/crypto-ethereum @hzblj/crypto-bitcoin @hzblj/crypto-solana   # the chains you need
```

Requires Expo SDK 57 (React Native 0.86) or newer and a [development build](https://docs.expo.dev/develop/development-builds/introduction/):
Expo Go doesn't include this native module. No config plugin: run `npx expo prebuild` (or rebuild) after installing.

## Usage

```ts
import {bitcoinAdapter} from '@hzblj/crypto-bitcoin'
import {ethereumAdapter} from '@hzblj/crypto-ethereum'
import {solanaAdapter} from '@hzblj/crypto-solana'
import {createCryptoEngine} from '@hzblj/nitro-crypto'

const crypto = createCryptoEngine({adapters: [ethereumAdapter(), bitcoinAdapter(), solanaAdapter()]})

// A wallet in memory only: a fresh BIP-39 seed the engine generates and keeps.
const wallet = await crypto.createEphemeralWallet()
const eth = await wallet.deriveAccount({chain: 'ethereum', index: 0})
const btc = await wallet.deriveAccount({chain: 'bitcoin', index: 0})
const sol = await wallet.deriveAccount({chain: 'solana', account: 0})

const signature = await eth.signMessage({message: 'Hello from Expo'}) // EIP-191
await eth.verifyMessage({message: 'Hello from Expo', signature}) // true

wallet.dispose() // zeroizes the seed and every key derived from it
```

Every account, request and chain is typed by its adapter: `deriveAccount({chain: 'ethereum', …})` returns an
`EthereumAccount`, and `crypto.chains.bitcoin` is Bitcoin's client.

### Primitives

```ts
import {hex, utf8} from '@hzblj/nitro-crypto'

crypto.hash.sha256(utf8.encode('abc'))
crypto.hash.keccak256(bytes)
await crypto.hash.digestAsync('sha256', largePayload) // off the JS thread
crypto.hmac.sha512(key, data)
crypto.random(32)

crypto.secp256k1.verify(publicKey, digest, signature) // false for a mismatch or an upper-S signature
crypto.secp256k1.recover(digest, {signature, recovery})
crypto.ed25519.verify(publicKey, message, signature)

const key = crypto.keys.generate('ed25519') // held by the engine
key.sign(message)
key.dispose()
```

Inputs and outputs are `Uint8Array`. `hex`, `utf8`, `base58`, `base58check` and `bech32` are exported for the text
around them.

### Wallets

| | |
| --- | --- |
| `createEphemeralWallet({words?, passphrase?})` | A fresh 12 to 24 word mnemonic, generated inside the engine and never readable |
| `createEphemeralWallet({mnemonic, passphrase?})` | A known mnemonic, for published test vectors. Never type a real seed phrase into a demo. |
| `wallet.deriveAccount({chain, …})` | An account by a registered adapter |
| `wallet.deriveKey('bip32' \| 'slip10', path)` | A key at any path |
| `wallet.fingerprint` | The BIP-32 fingerprint: a public name for the seed |
| `wallet.dispose()` | Zeroizes the seed and every key derived from it |

Nothing is persisted: a reload or a restart loses every wallet. There is no mnemonic export in this version.

### Errors

Every failure is a `CryptoError` with a stable `code` (`INVALID_LENGTH`, `INVALID_MNEMONIC`, `DISPOSED`,
`MISSING_CAPABILITY`…). Messages never contain the inputs.

```ts
import {isCryptoError} from '@hzblj/nitro-crypto'

try {
  await crypto.createEphemeralWallet({mnemonic})
} catch (error) {
  if (isCryptoError(error, 'MNEMONIC_CHECKSUM')) {
    // a word is wrong
  }
}
```

### Testing

```ts
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'

const crypto = createTestCryptoEngine({adapters: [ethereumAdapter()]})
```

The same engine compiled to WebAssembly, behind the same API, for tests in Node, Jest or Vitest: no simulator, no
mocks. Not for production (WebAssembly memory is readable from JavaScript).

### Your own chain

A chain whose curves and hashes the engine has is one adapter, written against `@hzblj/nitro-crypto/adapter`. See
[Adding an adapter](https://github.com/hzblj/nitro-crypto/blob/main/docs/adding-an-adapter.md).

## Supported

| Algorithm | Standard | Implementation |
| --- | --- | --- |
| SHA-256, SHA-512, HMAC, PBKDF2 | FIPS 180-4, RFC 2104 | Zig standard library |
| Keccak-256 | Keccak (Ethereum) | Zig standard library |
| RIPEMD-160 | RIPEMD-160 | This package, against the reference vectors |
| secp256k1 ECDSA, recovery | SEC 2, RFC 6979 | libsecp256k1 0.8.0 |
| Ed25519 | RFC 8032 | Zig standard library |
| Mnemonics, seeds | BIP-39 (English) | This package |
| HD keys | BIP-32 (secp256k1), SLIP-0010 (Ed25519) | This package |

| Chain | Package | Accounts | Signing |
| --- | --- | --- | --- |
| Ethereum and EVM | `@hzblj/crypto-ethereum` | BIP-44, EIP-55 addresses, per-network chain ids | EIP-191 messages, signer recovery |
| Bitcoin | `@hzblj/crypto-bitcoin` | BIP-84 native SegWit (P2WPKH), mainnet, testnet, signet, regtest | None yet |
| Solana | `@hzblj/crypto-solana` | SLIP-0010, Base58 addresses | Ed25519 over message bytes |

| Platform | Minimum |
| --- | --- |
| Expo SDK | 57 |
| React Native | 0.86, New Architecture |
| react-native-nitro-modules | 0.37.1 |
| iOS | 15.1 |
| Android | API 24 (arm64-v8a, armeabi-v7a, x86, x86_64; 16 KB pages) |

## Not in this version

EIP-712 typed data and transaction signing; Bitcoin message signing (BIP-322), PSBT and Taproot; Solana transactions;
persistent or hardware-backed storage, backup and recovery. The adapters' `features` say so at runtime.

## More

[Architecture](https://github.com/hzblj/nitro-crypto/blob/main/docs/architecture.md) ·
[Security](https://github.com/hzblj/nitro-crypto/blob/main/SECURITY.md) ·
[Compatibility](https://github.com/hzblj/nitro-crypto/blob/main/docs/compatibility.md) ·
[Benchmarks](https://github.com/hzblj/nitro-crypto/blob/main/docs/benchmarks.md) ·
[Example app](https://github.com/hzblj/nitro-crypto/tree/main/apps/example)

The other libraries from the same author are at **[libraries.janblazej.dev](https://www.libraries.janblazej.dev)**.
