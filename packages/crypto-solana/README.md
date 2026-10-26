# @hzblj/crypto-solana

[![npm](https://img.shields.io/npm/v/@hzblj/crypto-solana.svg)](https://www.npmjs.com/package/@hzblj/crypto-solana)
[![license](https://img.shields.io/npm/l/@hzblj/crypto-solana.svg)](https://github.com/hzblj/nitro-crypto/blob/main/LICENSE)

Solana for [`@hzblj/nitro-crypto`](https://www.npmjs.com/package/@hzblj/nitro-crypto): Ed25519 accounts derived with
SLIP-0010, Base58 addresses, and signatures of message bytes. The keys stay in the native engine; this package is
TypeScript over it.

> [!WARNING]
> **Not security audited. Never use with real funds.**

```sh
npx expo install @hzblj/nitro-crypto @hzblj/crypto-solana react-native-nitro-modules
```

```ts
import {base58} from '@hzblj/nitro-crypto'
import {solanaAdapter} from '@hzblj/crypto-solana'
import {createCryptoEngine} from '@hzblj/nitro-crypto'

const crypto = createCryptoEngine({adapters: [solanaAdapter()]})
const wallet = await crypto.createEphemeralWallet()

const account = await wallet.deriveAccount({chain: 'solana', account: 0}) // m/44'/501'/0'/0'
account.address // Base58 of the 32-byte public key
const signature = await account.signMessage({message: 'Hello from Expo'}) // 64 bytes
base58.encode(signature) // as Solana tools print it
await account.verifyMessage({message: 'Hello from Expo', signature}) // true
```

| Request | Path |
| --- | --- |
| `{account}` (0 by default) | `m/44'/501'/{account}'/0'`, as Phantom, Solflare and `solana-keygen` derive |
| `{path}` | Any SLIP-0010 path; every step hardened |

`signMessage` signs the message bytes exactly as given, like a wallet's `signMessage`: it is not a transaction
signature and adds no off-chain message header. Addresses and signatures match `@solana/kit` for the same key.
`validateAddress` accepts the canonical Base58 of any 32 bytes, including program-derived addresses, which are off
the curve.

**Not in this version:** transaction serialization and signing, and off-chain message headers.

[Documentation](https://github.com/hzblj/nitro-crypto#readme) · [Security](https://github.com/hzblj/nitro-crypto/blob/main/SECURITY.md)
