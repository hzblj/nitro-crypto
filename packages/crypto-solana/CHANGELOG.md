# @hzblj/crypto-solana

## 1.0.0

### Minor Changes

- [`bd06ced`](https://github.com/hzblj/nitro-crypto/commit/bd06cedc3a7b64967c23e0d163db9926e79e5473) Thanks [@hzblj](https://github.com/hzblj)! - Legacy transactions: `account.signTransaction({instructions, recentBlockhash})` compiles the instructions with the account as fee payer, signs the message and returns the wire bytes and the Base58 signature. The chain gains instruction builders for SOL (`transfer`) and SPL tokens (`transferChecked`, `createAssociatedTokenAccountIdempotent`, `transferToken`), `associatedTokenAddress`, `findProgramAddress`, `isOnCurve` and `compileMessage`. Messages and signed transactions equal `@solana/kit`'s byte for byte. `features.transactionSigning` is now `true`, and the adapter requires `sha256`.

### Patch Changes

- Updated dependencies [[`bd06ced`](https://github.com/hzblj/nitro-crypto/commit/bd06cedc3a7b64967c23e0d163db9926e79e5473)]:
  - @hzblj/nitro-crypto@0.2.0
