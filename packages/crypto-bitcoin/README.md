# @hzblj/crypto-bitcoin

[![npm](https://img.shields.io/npm/v/@hzblj/crypto-bitcoin.svg)](https://www.npmjs.com/package/@hzblj/crypto-bitcoin)
[![license](https://img.shields.io/npm/l/@hzblj/crypto-bitcoin.svg)](https://github.com/hzblj/nitro-crypto/blob/main/LICENSE)

Bitcoin for [`@hzblj/nitro-crypto`](https://www.npmjs.com/package/@hzblj/nitro-crypto): native SegWit (P2WPKH)
accounts at BIP-84 paths on mainnet, testnet, signet or regtest, and validation of every address type. The keys stay
in the native engine; this package is TypeScript over it.

> [!WARNING]
> **Not security audited. Never use with real funds.**

```sh
npx expo install @hzblj/nitro-crypto @hzblj/crypto-bitcoin react-native-nitro-modules
```

```ts
import {bitcoinAdapter} from '@hzblj/crypto-bitcoin'
import {createCryptoEngine} from '@hzblj/nitro-crypto'

const crypto = createCryptoEngine({adapters: [bitcoinAdapter(), bitcoinAdapter({id: 'bitcoin-testnet', network: 'testnet'})]})
const wallet = await crypto.createEphemeralWallet()

const account = await wallet.deriveAccount({chain: 'bitcoin', index: 0}) // m/84'/0'/0'/0/0
account.address // bc1q…
account.scriptPubKey // OP_0 <20-byte key hash>

crypto.chains.bitcoin.validateAddress('bc1p…') // {valid, type: 'p2tr', scriptPubKey, normalized}
```

| Request | Path |
| --- | --- |
| `{account, change, index}` (each 0 by default; `change` is 0 or 1) | BIP-84, `m/84'/{coin}'/{account}'/{change}/{index}`; coin 0 on mainnet, 1 on test networks |
| `{path}` | Any BIP-32 path; the address is still P2WPKH |

| Network | SegWit prefix | Legacy prefixes |
| --- | --- | --- |
| `mainnet` (default) | `bc1` | `1`, `3` |
| `testnet`, `signet` | `tb1` | `m`/`n`, `2` |
| `regtest` | `bcrt1` | `m`/`n`, `2` |

`validateAddress` accepts SegWit of every version, Bech32 for version 0 and Bech32m from version 1 (BIP-350), and
legacy Base58Check, on the adapter's network only; an address of another network is invalid, with a reason that says
so. Addresses match BIP-84's test vectors and `@scure/btc-signer`.

**Not in this version:** signing of any kind. Bitcoin message signing (BIP-137, BIP-322) differs from Ethereum's and is
not implemented, nor are PSBT and Taproot (BIP-86, Schnorr); accounts have no `signMessage`, and the adapter's
`features` say so.

[Documentation](https://github.com/hzblj/nitro-crypto#readme) · [Security](https://github.com/hzblj/nitro-crypto/blob/main/SECURITY.md)
