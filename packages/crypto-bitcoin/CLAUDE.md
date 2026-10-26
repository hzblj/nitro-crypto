# @hzblj/crypto-bitcoin

Bitcoin: BIP-84 native SegWit accounts on four networks, validation of every address type. Signs nothing. Parity: BIP-84 vectors, @scure/btc-signer.

TypeScript over `@hzblj/nitro-crypto/adapter` and nothing else: no native code, no other adapter. Keys come from the
`KeySource` a wallet hands `deriveAccount`; the primitives from the `AdapterContext` `create` receives.

| Path | What it is |
| --- | --- |
| `src/adapter.ts` | The factory: configuration, `defineAdapter`, the chain client. Returns `ChainAdapter<NoInfer<Id>, …>`, so a configured id keeps its literal type in the registry. |
| `src/networks.ts` | The four networks: Bech32 prefix, coin type, legacy version bytes. |
| `src/segwit.ts` | Witness programs to and from addresses, BIP-173 and BIP-350 rules, output scripts. |
| `src/address.ts` | P2WPKH from a public key; validation of SegWit and legacy addresses. |
| `src/account.ts` | `BitcoinAccount`: no `signMessage`, on purpose. |
| `src/path.ts` | The account request and its derivation path. |
| `src/version.ts` | `VERSION`, synced from package.json by `scripts/sync-versions.mjs`; a test holds them equal. |
| `test/` | Published vectors, and parity on many keys with an independent library, all on the real engine (WebAssembly). |

What the adapter does not do it says in `features` (`false`), and its README lists. Docs copy has no em dashes.
