---
'@hzblj/crypto-ethereum': minor
---

EIP-1559 transactions: `account.signTransaction(request)` signs a type 2 transaction for the adapter's chain id and returns the serialized envelope for `eth_sendRawTransaction` and its hash, byte for byte what viem produces. `chain.serializeTransaction` gives the unsigned or signed envelope, and `chain.erc20` the `transfer` and `balanceOf` call data and the `uint256` result. A request for another chain id is refused. `features.transactionSigning` is now `true`, and `formats.signature` lists `eip1559`.
