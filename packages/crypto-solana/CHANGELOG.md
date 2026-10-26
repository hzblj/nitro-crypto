# @hzblj/crypto-solana

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
