---
'@hzblj/crypto-bitcoin': minor
---

Payments from an account. `account.createTransaction({utxos, to, amount, feeRate, changeAddress?})` selects coins (largest first), estimates the size and fee, and adds change back to the account when it is above the dust limit; `amount: 'max'` spends every coin. `account.signTransaction(plan)` signs every P2WPKH input over BIP-143 with the engine's key and returns the serialized transaction, its txid, size and fee, ready for any Esplora or Bitcoin Core node. `crypto.chains.bitcoin.dustThreshold(address)` gives the smallest amount an address can be paid. The adapter now states `transactionSigning: true` and the `p2wpkh-bip143` signature format; message signing, PSBT and Taproot are still not implemented. Transactions match BIP-143's published example and `@scure/btc-signer` byte for byte.
