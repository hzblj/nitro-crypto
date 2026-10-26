---
"@hzblj/crypto-solana": minor
---

Legacy transactions: `account.signTransaction({instructions, recentBlockhash})` compiles the instructions with the account as fee payer, signs the message and returns the wire bytes and the Base58 signature. The chain gains instruction builders for SOL (`transfer`) and SPL tokens (`transferChecked`, `createAssociatedTokenAccountIdempotent`, `transferToken`), `associatedTokenAddress`, `findProgramAddress`, `isOnCurve` and `compileMessage`. Messages and signed transactions equal `@solana/kit`'s byte for byte. `features.transactionSigning` is now `true`, and the adapter requires `sha256`.
