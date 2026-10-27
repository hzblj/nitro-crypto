# @hzblj/crypto-bitcoin

Bitcoin: BIP-84 native SegWit and BIP-86 Taproot (key path) accounts on four networks, validation of every address
type, payments (coin selection, fees, BIP-143 and BIP-341 signing), PSBTs (BIP-174 v0 with BIP-371's Taproot fields),
watch-only accounts, and message signatures (BIP-322 simple, legacy BIP-137). Parity: BIP-84, BIP-86, BIP-143,
BIP-341 and BIP-322 vectors, Bitcoin Core's message vector, @scure/btc-signer, @noble/curves. A second entry, `/sync`
(`src/sync/`), keeps a watch-only account in step with the chain over Esplora (ADR 0011).

TypeScript over `@hzblj/nitro-crypto/adapter` and nothing else: no native code, no other adapter. Keys come from the
`KeySource` a wallet hands `deriveAccount`; the primitives from the `AdapterContext` `create` receives.

| Path | What it is |
| --- | --- |
| `src/adapter.ts` | The factory: configuration, `defineAdapter`, the chain client. Returns `ChainAdapter<NoInfer<Id>, …>`, so a configured id keeps its literal type in the registry. Taproot's capabilities are checked when used (`UNSUPPORTED`), not in `requires`. |
| `src/networks.ts` | The four networks: Bech32 prefix, coin type, legacy version bytes. |
| `src/segwit.ts` | Witness programs to and from addresses, BIP-173 and BIP-350 rules, output scripts. |
| `src/address.ts` | P2WPKH and P2TR (BIP-86, the engine's tweak) from a public key; validation of SegWit and legacy addresses; the address of a standard script. |
| `src/account.ts` | `BitcoinWatchAccount` (type, address, plans, `createPsbt`) and `BitcoinAccount` on top of it (`signTransaction`, `signPsbt`, `signMessage`, `verifyMessage`), either type. |
| `src/psbt.ts` | BIP-174 version 0: strict parsing (previous transactions checked against their inputs, BIP-371's fields checked), `createPsbt`, `signPsbt` (P2WPKH SIGHASH_ALL; Taproot key path SIGHASH_DEFAULT or ALL, merkle root when given), `finalizePsbt` (both types, finalized inputs too; every signature verified by the engine). Unknown fields are kept. |
| `src/transaction.ts` | Payments: coin selection, the vsize estimate per input type and dust limits, BIP-143 digests, BIP-341 signature hashes (every type, key path), tagged hashes, serialization (BIP-144), signing. The plan is rechecked before signing. |
| `src/message.ts` | BIP-322 simple (`smp`, with or without) and legacy BIP-137 signing and verification; `UNSUPPORTED` for what needs a script interpreter. |
| `src/base64.ts` | Strict Base64: not every runtime has `atob`. |
| `src/der.ts` | A 64-byte `r \|\| s` signature to and from strict DER (BIP-66). |
| `src/path.ts` | The account request (`addressType`), its derivation path (purpose 84 or 86). |
| `src/version.ts` | `VERSION`, synced from package.json by `scripts/sync-versions.mjs`; a test holds them equal. |
| `src/sync/` | `@hzblj/crypto-bitcoin/sync`, its own entry (`index.ts`): `createBitcoinSync` (`sync.ts`: discovery, incremental resync, reorganizations, payments, fee bumps, broadcast), the backend contract (`backend.ts`) and Esplora over `fetch` (`esplora.ts`, `http.ts`: timeouts, abort, retries, concurrency, pacing, the pause on an unreachable server), the account's view (`accounting.ts`), the snapshot (`state.ts`), extended key text (`extended-key.ts`), the script types (`script-types.ts`), the PSBT combiner (`psbt.ts`), `SyncError` (`errors.ts`). |
| `test/` | Published vectors, and parity on many keys with independent libraries, all on the real engine (WebAssembly). `support.ts` reaches the WebAssembly build's Schnorr test hook (`../nitro-crypto/test/abi.ts`) to sign with given aux randomness, so Taproot transactions compare with btc-signer byte for byte. `test/sync/`: a fake Esplora over an in-memory chain (`fake-esplora.ts`: real transaction bytes, reorganizations, drops, replacements), parity with @scure/bip32 and btc-signer, and `live.test.ts` against a real Esplora (`BITCOIN_SYNC_LIVE_URL`, mempool.space's testnet4 by default), skipped unless `BITCOIN_SYNC_LIVE=1`. |

## The sync's rules

- **The main entry has no network code.** Nothing outside `src/sync/` imports from it or calls `fetch`; a test holds
  that. The subpath is in `exports` (with `source`), `publishConfig.exports`, the example's `tsconfig.json` paths and
  the pack check's required files.
- **The adapter plans and writes; the sync combines.** Coin selection is `createTransaction`'s and PSBT fields are
  `createPsbt`'s, one watch-only account per key; `sync/psbt.ts` only picks which PSBT each map comes from. A new
  script type is a `ScriptSupport` in `script-types.ts` (P2TR is reserved there): nothing else in `src/sync/` knows a
  script's fields.
- **Addresses come from the key, never from storage.** A snapshot holds what the backend said; the receiving and change
  addresses are derived again on every load.
- **The backend is read strictly and trusted only for chain data.** Every Esplora answer is parsed field by field
  (`INVALID_RESPONSE`); previous transactions are checked against their coins before a PSBT carries them.
- **Public servers are asked politely.** `PUBLIC_PACING` (two requests a second, two at once) applies to
  mempool.space and blockstream.info whatever the call; repeated connection failures pause every request
  (`UNREACHABLE`). Never loosen these defaults for a public host, and never point a test at one: an unpaced sync of a
  large account got this machine's IP address blocked by mempool.space. Tests use the fake; the live test is opt-in.
- **Every failure is a `SyncError`;** a `CryptoError` from the adapter is mapped (`fromCrypto`). Messages never quote
  an address or a key.

What the adapter does not do it says in `features` (`false`), and its README lists. Docs copy has no em dashes.
