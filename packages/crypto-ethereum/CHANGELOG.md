# @hzblj/crypto-ethereum

## 1.0.0

### Minor Changes

- [`bd06ced`](https://github.com/hzblj/nitro-crypto/commit/bd06cedc3a7b64967c23e0d163db9926e79e5473) Thanks [@hzblj](https://github.com/hzblj)! - EIP-1559 transactions: `account.signTransaction(request)` signs a type 2 transaction for the adapter's chain id and returns the serialized envelope for `eth_sendRawTransaction` and its hash, byte for byte what viem produces. `chain.serializeTransaction` gives the unsigned or signed envelope, and `chain.erc20` the `transfer` and `balanceOf` call data and the `uint256` result. A request for another chain id is refused. `features.transactionSigning` is now `true`, and `formats.signature` lists `eip1559`.

### Patch Changes

- Updated dependencies [[`bd06ced`](https://github.com/hzblj/nitro-crypto/commit/bd06cedc3a7b64967c23e0d163db9926e79e5473)]:
  - @hzblj/nitro-crypto@0.2.0
