---
'@hzblj/crypto-ethereum': minor
---

Transactions signed elsewhere. `crypto.chains.ethereum.parseTransaction(unsigned)` reads an unsigned EIP-1559 envelope back into its request, strictly and bound to the adapter's chain id; `recoverTransactionAddress({transaction, signature})` names its signer; `assembleTransaction(request, signature)` makes the transaction to broadcast; `addressFromPublicKey` takes a compressed or uncompressed key; `derivePublic(extendedKey, path)` derives an account's addresses from its extended public key, on an engine with public derivation. A signed transaction now also carries its `signature` (`r || s` and the y parity). RLP decoding accepts only canonical encodings. Parity with viem.
