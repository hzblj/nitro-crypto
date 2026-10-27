---
'@hzblj/nitro-crypto': minor
---

`interop::seedFromEntropy` takes a BIP-39 passphrase, for a vault whose wallet has one: an overload with `passphrase` and its length, UTF-8 and NFKD-normalized by the caller (as the facade normalizes `createEphemeralWallet`'s), at most 1024 bytes. The two-argument form still makes a seed with no passphrase.
