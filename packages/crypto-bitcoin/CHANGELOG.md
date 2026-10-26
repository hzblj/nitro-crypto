# @hzblj/crypto-bitcoin

## 0.2.0

### Minor Changes

- [#4](https://github.com/hzblj/nitro-crypto/pull/4) [`219ccf7`](https://github.com/hzblj/nitro-crypto/commit/219ccf7ef493c3a89854d4fdc500568e578cfabc) Thanks [@hzblj](https://github.com/hzblj)! - PSBTs (BIP-174, version 0) and watch-only accounts. `crypto.chains.bitcoin.watchAccount({publicKey, path, fingerprint})` is an account of a key held elsewhere, and `watchAccount({extendedKey, path, fingerprint, change?, index?})` any address of an account whose extended public key a signer shared (`derivePublic`, on an engine with public derivation): its address, `createTransaction`, and `createPsbt(plan, {previousTransactions?})`, which writes each input's coin and BIP-32 derivation, the derivation on change, and each coin's previous transaction when given. Every account is one too, now with its wallet's `fingerprint`, and signs with `signPsbt(psbt)` (the inputs that spend its coins, SIGHASH_ALL only). `decodePsbt` reads a PSBT strictly, with each input's address, value and whether that value can be checked, and the fee; `finalizePsbt` verifies every signature on the engine before it extracts the transaction. The adapter now states `psbt: true`. Parity with `@scure/btc-signer` both ways.

### Patch Changes

- [#4](https://github.com/hzblj/nitro-crypto/pull/4) [`65f53ca`](https://github.com/hzblj/nitro-crypto/commit/65f53ca5723969fea2d7f6184b52217831da58ba) Thanks [@hzblj](https://github.com/hzblj)! - The published `exports` no longer name a `source` condition. It pointed at `src/`, which the package does not ship, so a project that resolves with that condition (a monorepo's own tests often do) found nothing; the published map now has only `types` and `default`.

- Updated dependencies [[`185dac9`](https://github.com/hzblj/nitro-crypto/commit/185dac9c5f27a932e0ad0160fb8cb2c31efdd0b3), [`65f53ca`](https://github.com/hzblj/nitro-crypto/commit/65f53ca5723969fea2d7f6184b52217831da58ba)]:
  - @hzblj/nitro-crypto@0.1.2

## 0.1.1

### Patch Changes

- [`c5e3660`](https://github.com/hzblj/nitro-crypto/commit/c5e3660f85de65016e63d533128a28459356b4e8) Thanks [@hzblj](https://github.com/hzblj)! - The README no longer opens with a warning banner. What the library keeps in memory and what it leaves to the app is in SECURITY.md.

- Updated dependencies [[`c5e3660`](https://github.com/hzblj/nitro-crypto/commit/c5e3660f85de65016e63d533128a28459356b4e8)]:
  - @hzblj/nitro-crypto@0.1.1
