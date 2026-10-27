# @hzblj/crypto-bitcoin

[![npm](https://img.shields.io/npm/v/@hzblj/crypto-bitcoin.svg)](https://www.npmjs.com/package/@hzblj/crypto-bitcoin)
[![license](https://img.shields.io/npm/l/@hzblj/crypto-bitcoin.svg)](https://github.com/hzblj/nitro-crypto/blob/main/LICENSE)

Bitcoin for [`@hzblj/nitro-crypto`](https://www.npmjs.com/package/@hzblj/nitro-crypto): native SegWit (P2WPKH,
BIP-84) and Taproot (P2TR, BIP-86) accounts on mainnet, testnet, signet or regtest, validation of every address type,
payments from an account (coin selection, fees, BIP-143 and BIP-341 signatures), PSBTs (BIP-174, with BIP-371's
Taproot fields) for keys held elsewhere, and message signatures (BIP-322, and the legacy "Bitcoin Signed Message").
The keys stay in the native engine; this package is TypeScript over it.

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

const taproot = await wallet.deriveAccount({addressType: 'p2tr', chain: 'bitcoin'}) // m/86'/0'/0'/0/0
taproot.address // bc1p…
taproot.scriptPubKey // OP_1 <32-byte output key>

crypto.chains.bitcoin.validateAddress('bc1p…') // {valid, type: 'p2tr', scriptPubKey, normalized}
```

| Request | Path |
| --- | --- |
| `{account, change, index}` (each 0 by default; `change` is 0 or 1) | BIP-84, `m/84'/{coin}'/{account}'/{change}/{index}`; coin 0 on mainnet, 1 on test networks |
| `{addressType: 'p2tr', account, change, index}` | BIP-86, `m/86'/{coin}'/{account}'/{change}/{index}` |
| `{path}`, `{addressType: 'p2tr', path}` | Any BIP-32 path; the address is P2WPKH unless `addressType` says `p2tr` |

| Network | SegWit prefix | Legacy prefixes |
| --- | --- | --- |
| `mainnet` (default) | `bc1` | `1`, `3` |
| `testnet`, `signet` | `tb1` | `m`/`n`, `2` |
| `regtest` | `bcrt1` | `m`/`n`, `2` |

`validateAddress` accepts SegWit of every version, Bech32 for version 0 and Bech32m from version 1 (BIP-350), and
legacy Base58Check, on the adapter's network only; an address of another network is invalid, with a reason that says
so. Any account pays any of them, Taproot outputs included. Addresses match BIP-84's and BIP-86's test vectors and
`@scure/btc-signer`.

## Taproot

A Taproot account is BIP-86's: the key at its path is the internal key, tweaked by BIP-341's TapTweak of itself (no
script tree) into the output key its address pays, and it spends by the key path. The tweak happens inside the engine,
for signing too: the tweaked private key never exists in JavaScript.

```ts
const taproot = await wallet.deriveAccount({account: 0, addressType: 'p2tr', chain: 'bitcoin', index: 3})
taproot.publicKey // 33 bytes, compressed; the internal key is its x coordinate, publicKey.subarray(1)

// Watch-only, from the account's extended public key (m/86'/0'/0') or one key:
const xpub = wallet.extendedPublicKey("m/86'/0'/0'")
crypto.chains.bitcoin.watchAccount({addressType: 'p2tr', extendedKey: xpub, fingerprint, index: 3, path: "m/86'/0'/0'"})
crypto.chains.bitcoin.addressFromPublicKey(publicKey, 'p2tr') // a SEC1 key or a 32-byte x-only one
```

Taproot needs an engine with the capabilities `secp256k1-schnorr` and `taproot-tweak`. The adapter does not list them
in `requires`, which is all or nothing: an app whose JavaScript was updated over the air but whose native engine is
older would lose its whole Bitcoin adapter, P2WPKH included. Instead it registers on any engine, P2WPKH works as
before, and what needs them (a Taproot account, address or watch-only account, finalizing a Taproot input, verifying
a Taproot message) throws `UNSUPPORTED` there, naming what is missing. `crypto.info.has('taproot-tweak')` says which
engine an app has.

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
| Fee | `ceil(vsize × feeRate)`, from an estimate that assumes the longest signatures, so the real rate is never lower: 68 vB a P2WPKH input, 57.5 a Taproot one (its 64-byte signature makes that exact). |
| Change | Back to the account's address, or `changeAddress`. Change under the dust limit (294 sats for P2WPKH, 330 for P2TR) joins the fee. |
| Checks | A recipient of another network is `INVALID_ADDRESS`; an amount under the recipient's dust limit, or more than the coins cover (saying by how much), is `INVALID_ARGUMENT`. `signTransaction` refuses a plan whose outputs or fee were changed after it was made. |
| Signing | Version 2, lock time 0, every input replaceable (BIP-125). P2WPKH: SIGHASH_ALL over BIP-143, strict DER with a low S. Taproot: SIGHASH_DEFAULT over BIP-341, a 64-byte BIP-340 signature by the tweaked key. Every input must pay the account's own address. |

`crypto.chains.bitcoin.dustThreshold(address)` says the smallest amount an address can be paid. Transactions match
BIP-143's published example and `@scure/btc-signer` byte for byte, Taproot ones too when both sign with the same
auxiliary randomness; BIP-341's signature hashes match its wallet vectors and btc-signer's for every hash type.

## PSBTs

A key held elsewhere (an air-gapped signer, a hardware wallet) is a watch-only account: its address, payments planned
from it, and PSBTs (BIP-174, version 0) for its signer. Every account is one too, and signs them.

```ts
const watch = crypto.chains.bitcoin.watchAccount({publicKey, path: "m/84'/1'/0'/0/0", fingerprint})
const plan = watch.createTransaction({amount: 25_000n, feeRate: 2, to, utxos})
const psbt = watch.createPsbt(plan, {previousTransactions}) // by txid, hex or bytes: optional, lets a signer check values

// The signer, with the key:
crypto.chains.bitcoin.decodePsbt(psbt) // inputs (with addresses and values), outputs, fee: what to show first
const {psbt: signed} = await account.signPsbt(psbt)

// Back online:
const {hex, txid} = crypto.chains.bitcoin.finalizePsbt(signed)
```

| | |
| --- | --- |
| `createPsbt` | The unsigned transaction (as `signTransaction` would make it), each input's witness UTXO and key origin, the origin on change back to the account, and each coin's previous transaction when given (checked against the coin). P2WPKH's origin is `PSBT_IN_BIP32_DERIVATION`; Taproot's is BIP-371's `PSBT_IN_TAP_INTERNAL_KEY` and `PSBT_IN_TAP_BIP32_DERIVATION`, and on change `PSBT_OUT_TAP_INTERNAL_KEY` and `PSBT_OUT_TAP_BIP32_DERIVATION`. |
| `decodePsbt` | Strict BIP-174 version 0: the magic, canonical sizes, no repeated keys, a map per input and output, an unsigned transaction with empty scripts. Each input's coin, from its previous transaction when there is one (`verifiedValue`), its address, derivations, partial signatures, and its Taproot fields (`taprootInternalKey`, `taprootMerkleRoot`, `taprootDerivations`, `taprootKeySignature`), which are checked too. |
| `signPsbt` | Signs the inputs that spend this account's coins and leaves the rest: P2WPKH with SIGHASH_ALL only, Taproot with SIGHASH_DEFAULT (or SIGHASH_ALL when the PSBT asks) as `PSBT_IN_TAP_KEY_SIG`. A Taproot account also signs the key path of a coin of its key under a script tree whose `PSBT_IN_TAP_MERKLE_ROOT` the PSBT gives. A PSBT with nothing for the account is refused, and so is a Taproot input in a PSBT that does not say every coin it spends: BIP-341 signs them all. |
| `finalizePsbt` | Every input a P2WPKH or Taproot key path coin with its signature, or finalized already by its signer: each signature verified by the engine (P2WPKH's strict DER, lower S, by the key it pays; Taproot's under the coin's output key, for the sighash type it carries) before it becomes a witness. |

A PSBT may spend coins of several accounts, of both types: each account signs its own inputs in turn, and
`finalizePsbt` finalizes them together. A Taproot signature commits to the value and script of every coin the
transaction spends, so a coordinator that lies about one makes it invalid; a P2WPKH signature commits to its own coin's
value only, which is what `previousTransactions` and `verifiedValue` are for.

PSBTs written here are read by `@scure/btc-signer`, byte for byte the PSBTs it writes for the same fields; what this
package signs, btc-signer finalizes to the same transaction, and what btc-signer signs (or finalizes), `finalizePsbt`
finalizes. `@hzblj/crypto-airgap-bitcoin` carries them over QR codes.

## Messages

Accounts sign messages for their own address, and the chain verifies anyone's.

```ts
const signature = await account.signMessage({message: 'Hello from Expo'}) // 'smpAkcwRAIg…', BIP-322
await account.verifyMessage({message: 'Hello from Expo', signature}) // true

await account.signMessage({format: 'legacy', message}) // 65 bytes in Base64, BIP-137, P2WPKH only
crypto.chains.bitcoin.verifyMessage({address, message, signature}) // BIP-322 or legacy, whichever it is
```

| Format | What it is |
| --- | --- |
| `bip322` (the default) | BIP-322's simple signature: the witness that would spend a coin of the address in a virtual transaction committing to the message, Base64, prefixed `smp` as BIP-322 has required since it was finalized. P2WPKH signs with SIGHASH_ALL, Taproot with SIGHASH_DEFAULT. |
| `bip322-unprefixed` | The same witness without `smp`, for verifiers written before BIP-322 was finalized. |
| `legacy` | "Bitcoin Signed Message" (BIP-137): a recoverable ECDSA signature of the message, Base64, its header byte 39 to 42 (native SegWit). P2WPKH only: BIP-137 has no form for Taproot, and BIP-322 asks new proofs to use its own format, but many services still ask for this one. |

`verifyMessage` reads BIP-322's simple form with or without `smp`, for P2WPKH and Taproot key path addresses, and
legacy signatures as Electrum reads them: headers 27 to 30 for an uncompressed key's P2PKH, 31 to 34 for a compressed
key's P2PKH, P2SH-P2WPKH or P2WPKH (what Electrum and Bitcoin Core write), 35 to 38 for P2SH-P2WPKH, 39 to 42 for
P2WPKH. A malformed or wrong signature is `false`; what it cannot decide is `UNSUPPORTED`, never `true`: BIP-322's full
and proof-of-funds forms, and a script (a P2WSH witness of the address's own script, a Taproot script path that commits
to the address). Signatures match BIP-322's published vectors (P2WPKH ones byte for byte, being deterministic), Bitcoin
Core's `signmessagewithprivkey` vector, and `@noble/curves` on random keys.

**Not in this version:** Taproot script path spends (signing or finalizing a script leaf, `PSBT_IN_TAP_SCRIPT_SIG` and
`PSBT_IN_TAP_LEAF_SCRIPT` are kept as they came but not used), MuSig2 and other multi-party keys, BIP-322's full and
proof-of-funds signatures and its PSBT-based signing, BIP-137 signatures for P2PKH or P2SH-P2WPKH accounts (which this
package does not derive), sighash types other than SIGHASH_ALL (P2WPKH) and SIGHASH_DEFAULT or SIGHASH_ALL (Taproot)
when signing, PSBT version 2, spending from several addresses in one `signTransaction` (a PSBT does it), inputs of any
type but P2WPKH and Taproot key paths, and watching an extended public key's every address at once (one address per
watch-only account).

[Documentation](https://github.com/hzblj/nitro-crypto#readme) · [Security](https://github.com/hzblj/nitro-crypto/blob/main/SECURITY.md)
