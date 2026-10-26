# @hzblj/crypto-solana

Solana: SLIP-0010 Ed25519 accounts, Base58 addresses, signatures of raw message bytes, legacy transactions (SOL and
SPL token transfers). Parity: @solana/kit.

TypeScript over `@hzblj/nitro-crypto/adapter` and nothing else: no native code, no other adapter. Keys come from the
`KeySource` a wallet hands `deriveAccount`; the primitives from the `AdapterContext` `create` receives.

| Path | What it is |
| --- | --- |
| `src/adapter.ts` | The factory: configuration, `defineAdapter`, the chain client. Returns `ChainAdapter<NoInfer<Id>, …>`, so a configured id keeps its literal type in the registry. |
| `src/address.ts` | Base58 addresses; validation (canonical, 32 bytes, off-curve allowed). |
| `src/account.ts` | `SolanaAccount`: verification by address, `signTransaction` (fee payer and only signer), `signTransactionMessage` (a compiled message made elsewhere, read first). |
| `src/message.ts` | Legacy messages read back, strictly, with a summary of each instruction a wallet sends; v0 refused. |
| `src/instructions.ts` | System transfer, Token `TransferChecked`, ATA `CreateIdempotent`, and `transferToken` built from them. |
| `src/transaction.ts` | Legacy messages: account merging and ordering (kit's collator, written without `Intl`), compact-u16, the wire format. |
| `src/pda.ts`, `src/curve.ts` | Program-derived and associated token addresses; the Ed25519 on-curve check in BigInt, decided as kit decides. |
| `src/programs.ts` | The program ids this package builds instructions for. |
| `src/path.ts` | The account request and its derivation path. |
| `src/version.ts` | `VERSION`, synced from package.json by `scripts/sync-versions.mjs`; a test holds them equal. |
| `test/` | Published vectors, and parity on many keys with an independent library, all on the real engine (WebAssembly). |

What the adapter does not do it says in `features` (`false`), and its README lists. Docs copy has no em dashes.
