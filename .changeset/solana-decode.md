---
'@hzblj/crypto-solana': minor
---

Messages signed elsewhere. `crypto.chains.solana.decodeMessage(message)` reads a legacy message back (fee payer, signers, accounts and their roles, blockhash, instructions), strictly, with a summary of each transfer, token transfer, token account creation and compute budget instruction. `account.signTransactionMessage(message)` signs a compiled message made elsewhere once it has read it and found the account among its signers, and `assembleTransaction({message, signatures})` verifies each signature on the engine before it returns the wire bytes. Parity with `@solana/kit`.
