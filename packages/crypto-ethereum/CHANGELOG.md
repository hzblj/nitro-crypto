# @hzblj/crypto-ethereum

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
