# @hzblj/crypto-bitcoin

[![npm](https://img.shields.io/npm/v/@hzblj/crypto-bitcoin.svg)](https://www.npmjs.com/package/@hzblj/crypto-bitcoin)
[![license](https://img.shields.io/npm/l/@hzblj/crypto-bitcoin.svg)](https://github.com/hzblj/nitro-crypto/blob/main/LICENSE)

Bitcoin for [`@hzblj/nitro-crypto`](https://www.npmjs.com/package/@hzblj/nitro-crypto): native SegWit (P2WPKH)
accounts at BIP-84 paths on mainnet, testnet, signet or regtest, validation of every address type, and payments from
an account: coin selection, fees and BIP-143 signatures. The keys stay in the native engine; this package is
TypeScript over it.

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

## Payments

An account spends the coins its address holds. `createTransaction` plans a payment and `signTransaction` signs and
serializes it; fetching coins and broadcasting are the app's (any Esplora or Bitcoin Core node).

```ts
const utxos = (await (await fetch(`${esplora}/address/${account.address}/utxo`)).json()).map(
  ({txid, vout, value}) => ({txid, value: BigInt(value), vout})
)

const plan = account.createTransaction({amount: 25_000n, feeRate: 2, to: 'tb1q…', utxos})
plan.fee // satoshis, for the estimated plan.vsize
plan.outputs // the recipient, then change back to the account when it is worth an output

const {hex, txid} = await account.signTransaction(plan)
await fetch(`${esplora}/tx`, {body: hex, method: 'POST'})
```

| | |
| --- | --- |
| Coin selection | Largest coins first, until they cover the amount and the fee. `amount: 'max'` spends every coin, less the fee, with no change. |
| Fee | `ceil(vsize × feeRate)`, from an estimate that assumes the longest signatures, so the real rate is never lower. |
| Change | Back to the account's address, or `changeAddress`. Change under the dust limit (294 sats for P2WPKH) joins the fee. |
| Checks | A recipient of another network is `INVALID_ADDRESS`; an amount under the recipient's dust limit, or more than the coins cover (saying by how much), is `INVALID_ARGUMENT`. `signTransaction` refuses a plan whose outputs or fee were changed after it was made. |
| Signing | Version 2, lock time 0, every input replaceable (BIP-125), SIGHASH_ALL over BIP-143, strict DER with a low S. Every input must pay the account's own address. |

`crypto.chains.bitcoin.dustThreshold(address)` says the smallest amount an address can be paid. Transactions match
BIP-143's published example and `@scure/btc-signer`, byte for byte.

**Not in this version:** message signing. Bitcoin's (BIP-137, BIP-322) differs from Ethereum's and is not
implemented, nor are PSBT, Taproot (BIP-86, Schnorr), spending from several addresses at once, or inputs of any type
but P2WPKH; accounts have no `signMessage`, and the adapter's `features` say so.

[Documentation](https://github.com/hzblj/nitro-crypto#readme) · [Security](https://github.com/hzblj/nitro-crypto/blob/main/SECURITY.md)
