# @hzblj/crypto-ethereum

[![npm](https://img.shields.io/npm/v/@hzblj/crypto-ethereum.svg)](https://www.npmjs.com/package/@hzblj/crypto-ethereum)
[![license](https://img.shields.io/npm/l/@hzblj/crypto-ethereum.svg)](https://github.com/hzblj/nitro-crypto/blob/main/LICENSE)

Ethereum and every EVM chain for [`@hzblj/nitro-crypto`](https://www.npmjs.com/package/@hzblj/nitro-crypto):
secp256k1 accounts at BIP-44 paths, EIP-55 addresses, EIP-191 message signatures and signer recovery. The keys stay in
the native engine; this package is TypeScript over it.

> [!WARNING]
> **Not security audited. Never use with real funds.**

```sh
npx expo install @hzblj/nitro-crypto @hzblj/crypto-ethereum react-native-nitro-modules
```

```ts
import {ethereumAdapter} from '@hzblj/crypto-ethereum'
import {createCryptoEngine} from '@hzblj/nitro-crypto'

const crypto = createCryptoEngine({adapters: [ethereumAdapter(), ethereumAdapter({id: 'base', chainId: 8453, name: 'Base'})]})
const wallet = await crypto.createEphemeralWallet()

const account = await wallet.deriveAccount({chain: 'ethereum', index: 0}) // m/44'/60'/0'/0/0
account.address // 0x… (EIP-55)
const signature = await account.signMessage({message: 'Hello from Expo'}) // EIP-191 personal_sign, 0x… (65 bytes)
await account.verifyMessage({message: 'Hello from Expo', signature}) // true

crypto.chains.ethereum.recoverMessageAddress({message: 'Hello from Expo', signature}) // the signer
crypto.chains.ethereum.validateAddress('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed') // {valid, checksum: 'valid', normalized}
```

| Request | Path |
| --- | --- |
| `{index}` (and `account`, both 0 by default) | `m/44'/60'/{account}'/0/{index}`, MetaMask's |
| `{path}` | Any BIP-32 path (Ledger Live: `m/44'/60'/{account}'/0/0`) |

| Configuration | |
| --- | --- |
| `id` | The id it registers under. One per EVM network: `ethereum`, `base`, `sepolia`. |
| `chainId` | The EIP-155 chain id, 1 by default. The address is the same on every network; the account carries the network. |
| `name` | For people, "Ethereum" by default. |

Signatures are byte-for-byte viem's for the same key and message (RFC 6979, lower S), and both libraries verify each
other's. Messages are text (signed as UTF-8) or raw bytes. `verifyMessage` is `false` for any signature that does not
recover to the account, including a malformed one.

**Not in this version:** EIP-712 typed data, and transaction signing. The adapter's `features` say so.

[Documentation](https://github.com/hzblj/nitro-crypto#readme) · [Security](https://github.com/hzblj/nitro-crypto/blob/main/SECURITY.md)
