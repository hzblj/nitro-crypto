# @hzblj/crypto-ethereum

## 0.3.0

### Minor Changes

- [#11](https://github.com/hzblj/nitro-crypto/pull/11) [`315484b`](https://github.com/hzblj/nitro-crypto/commit/315484b5ec891b6b45f38c2415d323841243df8a) Thanks [@hzblj](https://github.com/hzblj)! - EIP-712 typed data, every transaction type a wallet signs, EIP-7702, and a viem account. `account.signTypedData({domain, types, primaryType, message})` signs viem's shape (and `eth_signTypedData_v4`'s), with the whole of EIP-712: nested structs, arrays of any dimension, every `intN`, `uintN` and `bytesN` checked, `EIP712Domain` declared or derived; malformed typed data is refused with messages that never repeat a value. The chain adds `hashTypedData`, `hashDomain`, `hashStruct`, `recoverTypedDataAddress` and `verifyTypedData`. Transactions: legacy (type 0, always with EIP-155), EIP-2930 (type 1), access lists on types 1, 2 and 4, contract creation (`to: null`, init code in `data`) on types 0 to 2, and EIP-7702 (type 4) with its authorization list; `account.signAuthorization({address, nonce})` signs an authorization, with chain id 0 (every chain) refused unless `allowAllChains` is set, and the chain adds `hashAuthorization` and `recoverAuthorizationAddress`. `parseTransaction` reads every type it signs and returns its `type`. A request for another network (a transaction, a typed data domain, an authorization, a parsed transaction) is now `CHAIN_MISMATCH` instead of `INVALID_ARGUMENT`. `@hzblj/crypto-ethereum/viem` exports `toViemAccount(account)`, a viem `LocalAccount` that signs byte for byte as `privateKeyToAccount` does, with no raw-hash `sign`; viem is an optional peer dependency. `features` gain `typedData`, `legacyTransactions`, `accessLists`, `contractCreation` and `setCodeTransactions` (true), and `blobTransactions` and `hashSigning` (false). Parity with viem.

### Patch Changes

- Updated dependencies [[`315484b`](https://github.com/hzblj/nitro-crypto/commit/315484b5ec891b6b45f38c2415d323841243df8a), [`dc6062d`](https://github.com/hzblj/nitro-crypto/commit/dc6062d9d700ddf9e33e7cc4ff43836c658f65f6), [`c1ceb75`](https://github.com/hzblj/nitro-crypto/commit/c1ceb759f9c3b840153933d6c288d6c887f28a2d), [`fbd3720`](https://github.com/hzblj/nitro-crypto/commit/fbd37205d4c57696f91e988b513d04cef29b2cb8), [`b8ee6b2`](https://github.com/hzblj/nitro-crypto/commit/b8ee6b24c3fb198ad25b4e7baa8854fb856dba46)]:
  - @hzblj/nitro-crypto@0.1.5

## 0.2.0

### Minor Changes

- [#4](https://github.com/hzblj/nitro-crypto/pull/4) [`219ccf7`](https://github.com/hzblj/nitro-crypto/commit/219ccf7ef493c3a89854d4fdc500568e578cfabc) Thanks [@hzblj](https://github.com/hzblj)! - Transactions signed elsewhere. `crypto.chains.ethereum.parseTransaction(unsigned)` reads an unsigned EIP-1559 envelope back into its request, strictly and bound to the adapter's chain id; `recoverTransactionAddress({transaction, signature})` names its signer; `assembleTransaction(request, signature)` makes the transaction to broadcast; `addressFromPublicKey` takes a compressed or uncompressed key; `derivePublic(extendedKey, path)` derives an account's addresses from its extended public key, on an engine with public derivation. A signed transaction now also carries its `signature` (`r || s` and the y parity). RLP decoding accepts only canonical encodings. Parity with viem.

### Patch Changes

- [#4](https://github.com/hzblj/nitro-crypto/pull/4) [`65f53ca`](https://github.com/hzblj/nitro-crypto/commit/65f53ca5723969fea2d7f6184b52217831da58ba) Thanks [@hzblj](https://github.com/hzblj)! - The published `exports` no longer name a `source` condition. It pointed at `src/`, which the package does not ship, so a project that resolves with that condition (a monorepo's own tests often do) found nothing; the published map now has only `types` and `default`.

- Updated dependencies [[`185dac9`](https://github.com/hzblj/nitro-crypto/commit/185dac9c5f27a932e0ad0160fb8cb2c31efdd0b3), [`65f53ca`](https://github.com/hzblj/nitro-crypto/commit/65f53ca5723969fea2d7f6184b52217831da58ba)]:
  - @hzblj/nitro-crypto@0.1.2

## 0.1.1

### Patch Changes

- [`c5e3660`](https://github.com/hzblj/nitro-crypto/commit/c5e3660f85de65016e63d533128a28459356b4e8) Thanks [@hzblj](https://github.com/hzblj)! - The README no longer opens with a warning banner. What the library keeps in memory and what it leaves to the app is in SECURITY.md.

- Updated dependencies [[`c5e3660`](https://github.com/hzblj/nitro-crypto/commit/c5e3660f85de65016e63d533128a28459356b4e8)]:
  - @hzblj/nitro-crypto@0.1.1
