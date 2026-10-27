# @hzblj/crypto-ethereum

Ethereum and EVM: BIP-44 accounts, EIP-55 addresses, EIP-191 messages and EIP-712 typed data with signer recovery,
transactions of types 0 (EIP-155), 1, 2 and 4 with access lists and contract creation, EIP-7702 authorizations,
ERC-20 call data, and a viem account (`/viem`). Parity: viem.

TypeScript over `@hzblj/nitro-crypto/adapter` and nothing else: no native code, no other adapter. Keys come from the
`KeySource` a wallet hands `deriveAccount`; the primitives from the `AdapterContext` `create` receives. The one
exception is `src/viem.ts`, the `@hzblj/crypto-ethereum/viem` entry: it imports viem, an optional peer dependency,
and nothing else in `src/` may (a test and `pack:check` hold that).

| Path | What it is |
| --- | --- |
| `src/adapter.ts` | The factory: configuration, `defineAdapter`, features, the chain client. Returns `ChainAdapter<NoInfer<Id>, …>`, so a configured id keeps its literal type in the registry. |
| `src/config.ts` | The configuration, and `networkChainId`: a request's chain id bound to the adapter's, `CHAIN_MISMATCH` otherwise. |
| `src/address.ts` | EIP-55 checksums, validation, address from a public key. |
| `src/message.ts` | The EIP-191 digest. |
| `src/typed-data.ts` | EIP-712: the types checked once (identifiers, unknown and recursive types, `EIP712Domain` declared or derived), `encodeType`, `hashStruct`, the domain separator and the digest, with the domain's chain id bound. Messages name structs and members, never values. |
| `src/signature.ts` | 65-byte `r || s || v` hex, v as 27/28 or 0/1; a signature as RLP fields. |
| `src/account.ts` | `EthereumAccount` (`signMessage`, `signTypedData`, `signTransaction`, `signAuthorization`), and verification as recovery. No raw-hash signing, on purpose. |
| `src/transaction.ts` | Legacy (EIP-155 only), EIP-2930, EIP-1559 and EIP-7702: the request union, its checks (chain id, no mixed types, `to: null` for creation with init code), the unsigned and signed forms, the hash; strict parsing of an unsigned transaction of every type, its digest, and assembly with a signature made elsewhere. Blob transactions are `UNSUPPORTED`. |
| `src/authorization.ts` | EIP-7702 authorizations: the request (chain id 0 only with `allowAllChains`), the digest, signing, and the `[chainId, address, nonce, yParity, r, s]` tuples a type 4 transaction lists. |
| `src/viem.ts` | `toViemAccount`: a viem `LocalAccount` over an account, viem's `TransactionSerializable` mapped onto the requests, a chain's custom serializer accepted only when it writes the same bytes, no `sign`. |
| `src/rlp.ts` | RLP encoding, and strict decoding (canonical forms only). |
| `src/erc20.ts` | `transfer` and `balanceOf` call data, and a `uint256` result. |
| `src/integer.ts` | Range checks, integer text, minimal big-endian bytes, 32-byte ABI words. |
| `src/path.ts` | The account request and its derivation path. |
| `src/version.ts` | `VERSION`, synced from package.json by `scripts/sync-versions.mjs`; a test holds them equal. |
| `test/` | Published vectors (EIP-712's Mail, EIP-155's example, RLP), and parity on many keys and random inputs with viem (typed data, every transaction type, authorizations, the viem account through a wallet client), all on the real engine (WebAssembly). `support.ts` is shared. |

What the adapter does not do it says in `features` (`false`), and its README lists. Docs copy has no em dashes.
