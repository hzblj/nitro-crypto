# @hzblj/crypto-solana

[![npm](https://img.shields.io/npm/v/@hzblj/crypto-solana.svg)](https://www.npmjs.com/package/@hzblj/crypto-solana)
[![license](https://img.shields.io/npm/l/@hzblj/crypto-solana.svg)](https://github.com/hzblj/nitro-crypto/blob/main/LICENSE)

Solana for [`@hzblj/nitro-crypto`](https://www.npmjs.com/package/@hzblj/nitro-crypto): Ed25519 accounts derived with
SLIP-0010, Base58 addresses, signatures of message bytes, and legacy transactions for SOL and SPL token transfers.
The keys stay in the native engine; this package is TypeScript over it.

```sh
npx expo install @hzblj/nitro-crypto @hzblj/crypto-solana react-native-nitro-modules
```

```ts
import {base58} from '@hzblj/nitro-crypto'
import {solanaAdapter} from '@hzblj/crypto-solana'
import {createCryptoEngine} from '@hzblj/nitro-crypto'

const crypto = createCryptoEngine({adapters: [solanaAdapter()]})
const wallet = await crypto.createEphemeralWallet()

const account = await wallet.deriveAccount({chain: 'solana', account: 0}) // m/44'/501'/0'/0'
account.address // Base58 of the 32-byte public key
const signature = await account.signMessage({message: 'Hello from Expo'}) // 64 bytes
base58.encode(signature) // as Solana tools print it
await account.verifyMessage({message: 'Hello from Expo', signature}) // true
```

| Request | Path |
| --- | --- |
| `{account}` (0 by default) | `m/44'/501'/{account}'/0'`, as Phantom, Solflare and `solana-keygen` derive |
| `{path}` | Any SLIP-0010 path; every step hardened |

`signMessage` signs the message bytes exactly as given, like a wallet's `signMessage`: it is not a transaction
signature and adds no off-chain message header. Addresses and signatures match `@solana/kit` for the same key.
`validateAddress` accepts the canonical Base58 of any 32 bytes, including program-derived addresses, which are off
the curve.

## Transactions

The chain builds instructions; the account compiles them into a legacy message with itself as the fee payer, signs it
and returns the wire bytes. Fetching a blockhash and sending are the app's, over any RPC client.

```ts
const solana = crypto.chains.solana
const {value} = await rpc('getLatestBlockhash') // {blockhash, lastValidBlockHeight}

// SOL
const sol = await account.signTransaction({
  instructions: [solana.instructions.transfer({from: account.address, lamports: 10_000_000n, to: recipient})],
  recentBlockhash: value.blockhash,
})

// An SPL token, to the recipient's associated token account (created, idempotently, when it does not exist)
const usdc = await account.signTransaction({
  instructions: solana.instructions.transferToken({amount: 1_500_000n, decimals: 6, from: account.address, mint, to: recipient}),
  recentBlockhash: value.blockhash,
})

usdc.signature // Base58: the transaction id
await rpc('sendTransaction', [Buffer.from(usdc.serialized).toString('base64'), {encoding: 'base64'}])
```

| On the chain | What it is |
| --- | --- |
| `instructions.transfer` | System Program `Transfer` |
| `instructions.transferChecked` | Token program `TransferChecked`, between two token accounts |
| `instructions.createAssociatedTokenAccountIdempotent` | Associated Token Account `CreateIdempotent` |
| `instructions.transferToken` | Wallet to wallet: their associated token accounts, the recipient's created if needed |
| `associatedTokenAddress`, `findProgramAddress`, `isOnCurve` | Program-derived addresses, in TypeScript over the engine's SHA-256 |
| `compileMessage` | The legacy message bytes, for `getFeeForMessage` |

`SYSTEM_PROGRAM`, `TOKEN_PROGRAM`, `TOKEN_2022_PROGRAM` and `ASSOCIATED_TOKEN_PROGRAM` are exported. Accounts are
merged and ordered as the runtime requires and in `@solana/kit`'s order within each role, so the message and the
signed transaction are byte for byte what kit produces for the same instructions and key. The account signs alone:
an instruction that needs another signer is refused, and so is a transaction over 1232 bytes.

## Signing elsewhere

For a key the app does not hold (an air-gapped signer, a hardware wallet), the chain reads and assembles what
travels between the two:

```ts
const message = solana.compileMessage({feePayer: address, instructions, recentBlockhash})

// The signer, with the key: read it, show it, sign it.
const decoded = solana.decodeMessage(message) // fee payer, signers, accounts and roles, blockhash, instructions
decoded.instructions[0].summary // {type: 'transfer', from, to, lamports}, 'token-transfer', 'create-token-account', …
const signature = await account.signTransactionMessage(message) // refused unless the account is a signer

// Back online: each signature verified by the engine against its signer, then the wire bytes.
const {serialized, signature: id} = solana.assembleTransaction({message, signatures: [signature]})
```

`decodeMessage` is strict (canonical compact-u16 lengths, indexes in range, no account twice, nothing after the last
instruction) and reads what `@solana/kit` compiles, back to the same bytes. It summarizes System transfers, Token and
Token-2022 `TransferChecked`, associated token account creation, and compute budget limits and prices; anything else
is `unknown`, with its program. `@hzblj/crypto-airgap-solana` carries these over QR codes.

**Not in this version:** versioned (v0) transactions and address lookup tables, durable nonces, compute budget
instructions (add them yourself with any program's instruction), and off-chain message headers.

[Documentation](https://github.com/hzblj/nitro-crypto#readme) · [Security](https://github.com/hzblj/nitro-crypto/blob/main/SECURITY.md)
