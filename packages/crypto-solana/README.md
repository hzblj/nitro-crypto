# @hzblj/crypto-solana

[![npm](https://img.shields.io/npm/v/@hzblj/crypto-solana.svg)](https://www.npmjs.com/package/@hzblj/crypto-solana)
[![license](https://img.shields.io/npm/l/@hzblj/crypto-solana.svg)](https://github.com/hzblj/nitro-crypto/blob/main/LICENSE)

Solana for [`@hzblj/nitro-crypto`](https://www.npmjs.com/package/@hzblj/nitro-crypto): Ed25519 accounts derived with
SLIP-0010, Base58 addresses, signatures of message bytes and of off-chain messages, and transactions, legacy and v0
with address lookup tables: SOL and SPL token transfers built here, and any dApp's transaction read and signed, a slot
at a time when several sign. A [`@solana/kit`](https://www.npmjs.com/package/@solana/kit) signer is one call away. The
keys stay in the native engine; this package is TypeScript over it.

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

`signMessage` signs the message bytes exactly as given, as a wallet's `signMessage` does for Phantom's API and Sign In
With Solana: no prefix, no header, so show the text before signing it. Addresses and signatures match `@solana/kit`
for the same key.
`validateAddress` accepts the canonical Base58 of any 32 bytes, including program-derived addresses, which are off
the curve.

## Transactions

The chain builds instructions; the account compiles them into a message with itself as the fee payer, signs it and
returns the wire bytes. Fetching a blockhash and sending are the app's, over any RPC client.

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
| `compileMessage` | The message bytes, legacy or v0, for `getFeeForMessage` |

`SYSTEM_PROGRAM`, `TOKEN_PROGRAM`, `TOKEN_2022_PROGRAM` and `ASSOCIATED_TOKEN_PROGRAM` are exported. Accounts are
merged and ordered as the runtime requires and in `@solana/kit`'s order within each role, so the message and the
signed transaction are byte for byte what kit produces for the same instructions and key. The account signs alone:
an instruction that needs another signer is refused, and so is a transaction over 1232 bytes. What kit refuses to
compile is refused too: more than 64 accounts, 12 signers or 64 instructions.

### Versioned transactions and address lookup tables

A v0 message names accounts held in an address lookup table by one byte instead of 32, so a transaction with many
accounts fits. Give the tables' addresses (the table accounts, read with `jsonParsed`, or kit's
`fetchAddressesForLookupTables`):

```ts
const signed = await account.signTransaction({
  addressLookupTables: {[tableAddress]: tableAddresses}, // each table's address, and the addresses it holds in order
  instructions,
  recentBlockhash: value.blockhash,
  version: 0,
})
```

The message loads every account it can from the tables: one that is not a signer, the fee payer or an invoked program
(the runtime requires those in full). Where an address is in several tables, the first table given that holds it is
used, at its first index. That is `@solana/kit`'s `compressTransactionMessageUsingAddressLookupTables` and compiler,
byte for byte, tested on random instructions and tables. Without tables, `version: 0` is a v0 message that names
every account in full.

## Signing a dApp's transaction

A dApp hands a wallet a wire transaction (Base64-decoded), legacy or v0, often built for several signers. Read it,
show it, and sign the account's own slot; every other slot stays as it is:

```ts
const transaction = solana.decodeTransaction(bytes, {addressLookupTables}) // tables optional
transaction.instructions // as decodeMessage reads them (below), each with a summary
transaction.signatures // one per signer, in order: 64 bytes, or undefined while unsigned

const {serialized, complete, signature} = await account.partiallySignTransaction(bytes)
// serialized: back to the dApp, or on to the next signer; complete: every slot signed; signature: the fee payer's
// signature in Base58 (the transaction id) once it has signed
```

`partiallySignTransaction` refuses a transaction that does not read strictly or does not name the account as a
signer. Without the tables, a v0 transaction's looked-up accounts are listed by table and index, their `address`
`undefined`, and an instruction whose summary needs one is `unknown`: the tables are what a review screen needs to say
who receives what. Addresses from tables are taken as given; a signer offline cannot check them against the chain.

## Signing elsewhere

For a key the app does not hold (an air-gapped signer, a hardware wallet), the chain reads and assembles what
travels between the two, legacy or v0:

```ts
const message = solana.compileMessage({feePayer: address, instructions, recentBlockhash})

// The signer, with the key: read it, show it, sign it.
const decoded = solana.decodeMessage(message) // version, fee payer, signers, accounts and roles, blockhash, instructions
decoded.instructions[0].summary // {type: 'transfer', from, to, lamports}, 'token-transfer', 'create-token-account', …
const signature = await account.signTransactionMessage(message) // refused unless the account is a signer

// Back online: each signature verified by the engine against its signer, then the wire bytes.
const {serialized, signature: id} = solana.assembleTransaction({message, signatures: [signature]})
```

`decodeMessage` is strict (canonical compact-u16 lengths, indexes in range, programs never loaded from a table, no
account twice, nothing after the end) and reads what `@solana/kit` compiles, back to the same bytes; a version after
v0 is refused. It summarizes System transfers, Token and Token-2022 `TransferChecked`, associated token account
creation, and compute budget limits and prices; anything else is `unknown`, with its program. Given
`{addressLookupTables}`, it names a v0 message's looked-up accounts as kit's `decompileTransactionMessage` does.
`@hzblj/crypto-airgap-solana` carries these over QR codes.

## Off-chain messages

Solana's off-chain message format starts with `\xffsolana offchain`, which no transaction can, so a signature of one
can never be replayed as a transaction signature. Both versions `@solana/kit` reads are here, encoded as kit encodes
them:

```ts
// Version 1: the signers and the text, of any length.
const {message, signature} = await account.signOffchainMessage({signers: [account.address], text: 'Hello', version: 1})

// Version 0: the application that asks, a format (chosen from the text when left out), the signers, the text.
await account.signOffchainMessage({applicationDomain, signers: [account.address], text: 'Approve', version: 0})

solana.decodeOffchainMessage(message) // what to show; also how bytes a dApp sent are read before signing them
solana.verifyOffchainMessage({address: account.address, message, signature}) // true
```

`signOffchainMessage` also takes the encoded bytes, which it reads first: it refuses anything that is not an
off-chain message naming the account as a signer. Version 0 formats are `restricted-ascii` and `limited-utf8` (within
1232 bytes with the header, what a hardware wallet can show) and `extended-utf8` (up to 65535 bytes). Decoding is
stricter than kit's in one place: a version 0 message that names a signer twice is refused. Version 0 here is the
spec's and kit's, with the application domain and the signers; the `solana sign-offchain-message` CLI (solana-sdk's
`offchain-message` crate) writes an older version 0 without them, so their signatures do not verify each other's.

## @solana/kit

`@hzblj/crypto-solana/kit` turns an account into a kit `TransactionPartialSigner` and `MessagePartialSigner`, its key
still in the engine. `@solana/kit` is an optional peer dependency: only this entry names it, for its types, and the
main entry never imports it.

```ts
import {toKitSigner} from '@hzblj/crypto-solana/kit'

const signer = toKitSigner(account)
const message = pipe(
  createTransactionMessage({version: 0}),
  message => setTransactionMessageFeePayerSigner(signer, message),
  message => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, message),
  message => appendTransactionMessageInstructions(instructions, message)
)
const transaction = await signTransactionMessageWithSigners(message)
```

Ed25519 is deterministic, so `signTransactionMessageWithSigners`, `partiallySignTransactionMessageWithSigners` and
`signOffchainMessageWithSigners` make with it exactly the signatures they make with a kit key pair signer of the same
key. `signTransactions` reads each message first (legacy or v0) and refuses one the account does not sign;
`signMessages` signs each message's bytes as given, as kit's key pair signers do.

**Not in this version:** v1 transactions (kit 8.5 compiles them; `decodeMessage` refuses them), durable nonces (a
nonce message is signed and read, but not built here or summarized), compute budget instructions (add them yourself
with any program's instruction), lookup table instructions (create, extend), decoding a lookup table account's raw
data, off-chain message envelopes (several signatures in one payload), and the older version 0 off-chain messages of
the `solana` CLI.

[Documentation](https://github.com/hzblj/nitro-crypto#readme) · [Security](https://github.com/hzblj/nitro-crypto/blob/main/SECURITY.md)
