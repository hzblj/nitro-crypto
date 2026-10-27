# @hzblj/crypto-solana

Solana: SLIP-0010 Ed25519 accounts, Base58 addresses, signatures of raw message bytes and of off-chain messages,
transactions legacy and v0 with address lookup tables (SOL and SPL token transfers built; any transaction read and
signed, a slot at a time), and a @solana/kit signer. Parity: @solana/kit 8.5.0, byte for byte.

TypeScript over `@hzblj/nitro-crypto/adapter` and nothing else: no native code, no other adapter. Keys come from the
`KeySource` a wallet hands `deriveAccount`; the primitives from the `AdapterContext` `create` receives. The one
exception is `src/kit.ts`, the `./kit` entry: it imports @solana/kit's *types* only (`import type`), kit being an
optional peer dependency; nothing else in `src/` names kit, a test holds that, and `yarn pack:check` refuses published
JavaScript that loads an optional peer.

| Path | What it is |
| --- | --- |
| `src/adapter.ts` | The factory: configuration, `defineAdapter`, the chain client. Returns `ChainAdapter<NoInfer<Id>, …>`, so a configured id keeps its literal type in the registry. |
| `src/address.ts` | Base58 addresses; validation (canonical, 32 bytes, off-curve allowed). |
| `src/account.ts` | `SolanaAccount`: verification by address, `signTransaction` (fee payer and only signer, legacy or v0), `signTransactionMessage` (a compiled message made elsewhere, read first), `partiallySignTransaction` (its own slot of a wire transaction), `signOffchainMessage`. |
| `src/message.ts` | Messages read back, legacy and v0, strictly, with a summary of each instruction a wallet sends; looked-up accounts named from tables the caller gives, or left `undefined`. `decodeTransaction` reads the wire format. |
| `src/offchain.ts` | Off-chain messages, versions 0 and 1 as kit encodes them: encode, decode (stricter than kit: no duplicate v0 signers, text must be UTF-8), and the bytes plus signers an account checks before signing. |
| `src/kit.ts` | `toKitSigner`: an account as kit's `TransactionPartialSigner` and `MessagePartialSigner`. Types only from kit. |
| `src/instructions.ts` | System transfer, Token `TransferChecked`, ATA `CreateIdempotent`, and `transferToken` built from them. |
| `src/transaction.ts` | Compiling, legacy and v0: account merging and ordering (kit's collator, written without `Intl`), which accounts a v0 message looks up and in what order (kit's compression and compiler: not a signer, the fee payer or an invoked program; first table given, first index; lookups writable first, then by table, then by address), kit's limits (64 accounts, 12 signers, 64 instructions), compact-u16, the wire format. |
| `src/pda.ts`, `src/curve.ts` | Program-derived and associated token addresses; the Ed25519 on-curve check in BigInt, decided as kit decides. |
| `src/programs.ts` | The program ids this package builds instructions for. |
| `src/path.ts` | The account request and its derivation path. |
| `src/version.ts` | `VERSION`, synced from package.json by `scripts/sync-versions.mjs`; a test holds them equal. |
| `test/` | Published vectors, and parity on many keys and random inputs with @solana/kit, all on the real engine (WebAssembly): `transaction` (legacy), `versioned` (v0, lookup tables, partial signing), `offchain`, `kit` (the bridge against kit's own key pair signers), `support.ts` (shared helpers, not a test). |

Kit decides parity: when kit 8.5's behaviour and the runtime's differ (account limits, lookup selection), this package
does what kit does, and the tests compare against kit, not prose. kit also reads v1 transactions; this package refuses
them. What the adapter does not do it says in `features` (`false`), and its README lists under "Not in this version".
Docs copy has no em dashes.
