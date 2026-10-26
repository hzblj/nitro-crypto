# @hzblj/crypto-bitcoin

Bitcoin: BIP-84 native SegWit accounts on four networks, validation of every address type, P2WPKH payments (coin
selection, fees, BIP-143 signing), PSBTs (BIP-174 v0) and watch-only accounts. No message signing. Parity: BIP-84
and BIP-143 vectors, @scure/btc-signer.

TypeScript over `@hzblj/nitro-crypto/adapter` and nothing else: no native code, no other adapter. Keys come from the
`KeySource` a wallet hands `deriveAccount`; the primitives from the `AdapterContext` `create` receives.

| Path | What it is |
| --- | --- |
| `src/adapter.ts` | The factory: configuration, `defineAdapter`, the chain client. Returns `ChainAdapter<NoInfer<Id>, …>`, so a configured id keeps its literal type in the registry. |
| `src/networks.ts` | The four networks: Bech32 prefix, coin type, legacy version bytes. |
| `src/segwit.ts` | Witness programs to and from addresses, BIP-173 and BIP-350 rules, output scripts. |
| `src/address.ts` | P2WPKH from a public key; validation of SegWit and legacy addresses; the address of a standard script. |
| `src/account.ts` | `BitcoinWatchAccount` (address, plans, `createPsbt`) and `BitcoinAccount` on top of it (`signTransaction`, `signPsbt`); no `signMessage`, on purpose. |
| `src/psbt.ts` | BIP-174 version 0: strict parsing (previous transactions checked against their inputs), `createPsbt`, `signPsbt` (SIGHASH_ALL only), `finalizePsbt` (every signature verified by the engine). Unknown fields are kept. |
| `src/transaction.ts` | Payments: coin selection, the vsize estimate and dust limits, BIP-143 digests, serialization (BIP-144), signing. The plan is rechecked before signing. |
| `src/der.ts` | A 64-byte `r \|\| s` signature to and from strict DER (BIP-66). |
| `src/path.ts` | The account request and its derivation path. |
| `src/version.ts` | `VERSION`, synced from package.json by `scripts/sync-versions.mjs`; a test holds them equal. |
| `test/` | Published vectors, and parity on many keys with an independent library, all on the real engine (WebAssembly). |

What the adapter does not do it says in `features` (`false`), and its README lists. Docs copy has no em dashes.
