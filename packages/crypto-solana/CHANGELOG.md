# @hzblj/crypto-solana

## 0.3.0

### Minor Changes

- [#12](https://github.com/hzblj/nitro-crypto/pull/12) [`05bc44f`](https://github.com/hzblj/nitro-crypto/commit/05bc44f1dfe64aee0c0bca3e060e081bd5bc24c9) Thanks [@hzblj](https://github.com/hzblj)! - Versioned transactions, off-chain messages and a @solana/kit signer, so a wallet can sign what modern Solana dApps send. `account.signTransaction` and `chain.compileMessage` take `version: 0` and `addressLookupTables`, and compile a v0 message that loads accounts from the tables as kit's `compressTransactionMessageUsingAddressLookupTables` and compiler do, byte for byte. `decodeMessage` reads legacy and v0 messages and names looked-up accounts from the tables' addresses when given (`{addressLookupTables}`), `decodeTransaction` reads a wire transaction with its signature slots, and `account.partiallySignTransaction` signs the account's own slot of a transaction others sign too. `account.signOffchainMessage`, `chain.encodeOffchainMessage`, `decodeOffchainMessage` and `verifyOffchainMessage` handle Solana's off-chain messages, versions 0 and 1, encoded as kit encodes them. `@hzblj/crypto-solana/kit` exports `toKitSigner(account)`, a kit `TransactionPartialSigner` and `MessagePartialSigner`; `@solana/kit` is an optional peer dependency that only this entry names, for its types. `features.versionedTransactions` and `features.offchainMessages` are now `true`. Changed: a decoded account's `address` is `undefined` for a v0 account loaded from a table that was not supplied (`DecodedSolanaAccount`, `DecodedSolanaInstruction`), decoded messages say their `version` and `addressTableLookups`, and compiling refuses what kit refuses (more than 64 accounts, 12 signers or 64 instructions) for legacy messages too.

### Patch Changes

- Updated dependencies [[`315484b`](https://github.com/hzblj/nitro-crypto/commit/315484b5ec891b6b45f38c2415d323841243df8a), [`dc6062d`](https://github.com/hzblj/nitro-crypto/commit/dc6062d9d700ddf9e33e7cc4ff43836c658f65f6), [`c1ceb75`](https://github.com/hzblj/nitro-crypto/commit/c1ceb759f9c3b840153933d6c288d6c887f28a2d), [`fbd3720`](https://github.com/hzblj/nitro-crypto/commit/fbd37205d4c57696f91e988b513d04cef29b2cb8), [`b8ee6b2`](https://github.com/hzblj/nitro-crypto/commit/b8ee6b24c3fb198ad25b4e7baa8854fb856dba46)]:
  - @hzblj/nitro-crypto@0.1.5

## 0.2.0

### Minor Changes

- [#4](https://github.com/hzblj/nitro-crypto/pull/4) [`219ccf7`](https://github.com/hzblj/nitro-crypto/commit/219ccf7ef493c3a89854d4fdc500568e578cfabc) Thanks [@hzblj](https://github.com/hzblj)! - Messages signed elsewhere. `crypto.chains.solana.decodeMessage(message)` reads a legacy message back (fee payer, signers, accounts and their roles, blockhash, instructions), strictly, with a summary of each transfer, token transfer, token account creation and compute budget instruction. `account.signTransactionMessage(message)` signs a compiled message made elsewhere once it has read it and found the account among its signers, and `assembleTransaction({message, signatures})` verifies each signature on the engine before it returns the wire bytes. Parity with `@solana/kit`.

### Patch Changes

- [#4](https://github.com/hzblj/nitro-crypto/pull/4) [`65f53ca`](https://github.com/hzblj/nitro-crypto/commit/65f53ca5723969fea2d7f6184b52217831da58ba) Thanks [@hzblj](https://github.com/hzblj)! - The published `exports` no longer name a `source` condition. It pointed at `src/`, which the package does not ship, so a project that resolves with that condition (a monorepo's own tests often do) found nothing; the published map now has only `types` and `default`.

- Updated dependencies [[`185dac9`](https://github.com/hzblj/nitro-crypto/commit/185dac9c5f27a932e0ad0160fb8cb2c31efdd0b3), [`65f53ca`](https://github.com/hzblj/nitro-crypto/commit/65f53ca5723969fea2d7f6184b52217831da58ba)]:
  - @hzblj/nitro-crypto@0.1.2

## 0.1.1

### Patch Changes

- [`c5e3660`](https://github.com/hzblj/nitro-crypto/commit/c5e3660f85de65016e63d533128a28459356b4e8) Thanks [@hzblj](https://github.com/hzblj)! - The README no longer opens with a warning banner. What the library keeps in memory and what it leaves to the app is in SECURITY.md.

- Updated dependencies [[`c5e3660`](https://github.com/hzblj/nitro-crypto/commit/c5e3660f85de65016e63d533128a28459356b4e8)]:
  - @hzblj/nitro-crypto@0.1.1
