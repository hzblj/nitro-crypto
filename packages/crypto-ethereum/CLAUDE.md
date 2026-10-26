# @hzblj/crypto-ethereum

Ethereum and EVM: BIP-44 accounts, EIP-55 addresses, EIP-191 signatures and signer recovery. Parity: viem.

TypeScript over `@hzblj/nitro-crypto/adapter` and nothing else: no native code, no other adapter. Keys come from the
`KeySource` a wallet hands `deriveAccount`; the primitives from the `AdapterContext` `create` receives.

| Path | What it is |
| --- | --- |
| `src/adapter.ts` | The factory: configuration, `defineAdapter`, the chain client. Returns `ChainAdapter<NoInfer<Id>, …>`, so a configured id keeps its literal type in the registry. |
| `src/address.ts` | EIP-55 checksums, validation, address from a public key. |
| `src/message.ts` | The EIP-191 digest. |
| `src/signature.ts` | 65-byte `r || s || v` hex, v as 27/28 or 0/1. |
| `src/account.ts` | `EthereumAccount`, and verification as recovery. |
| `src/path.ts` | The account request and its derivation path. |
| `src/version.ts` | `VERSION`, synced from package.json by `scripts/sync-versions.mjs`; a test holds them equal. |
| `test/` | Published vectors, and parity on many keys with an independent library, all on the real engine (WebAssembly). |

What the adapter does not do it says in `features` (`false`), and its README lists. Docs copy has no em dashes.
