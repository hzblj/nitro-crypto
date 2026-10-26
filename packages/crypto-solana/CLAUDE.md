# @hzblj/crypto-solana

Solana: SLIP-0010 Ed25519 accounts, Base58 addresses, signatures of raw message bytes. Parity: @solana/kit.

TypeScript over `@hzblj/nitro-crypto/adapter` and nothing else: no native code, no other adapter. Keys come from the
`KeySource` a wallet hands `deriveAccount`; the primitives from the `AdapterContext` `create` receives.

| Path | What it is |
| --- | --- |
| `src/adapter.ts` | The factory: configuration, `defineAdapter`, the chain client. Returns `ChainAdapter<NoInfer<Id>, …>`, so a configured id keeps its literal type in the registry. |
| `src/address.ts` | Base58 addresses; validation (canonical, 32 bytes, off-curve allowed). |
| `src/account.ts` | `SolanaAccount`, verification by address. |
| `src/path.ts` | The account request and its derivation path. |
| `src/version.ts` | `VERSION`, synced from package.json by `scripts/sync-versions.mjs`; a test holds them equal. |
| `test/` | Published vectors, and parity on many keys with an independent library, all on the real engine (WebAssembly). |

What the adapter does not do it says in `features` (`false`), and its README lists. Docs copy has no em dashes.
