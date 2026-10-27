---
'@hzblj/nitro-crypto': patch
---

A new error code, `CHAIN_MISMATCH`: a request is for another network than the one the adapter signs for. `@hzblj/crypto-ethereum` uses it for a transaction, typed data domain or EIP-7702 authorization naming another chain id, so a wallet can tell a dApp asking for another network from a malformed request.
