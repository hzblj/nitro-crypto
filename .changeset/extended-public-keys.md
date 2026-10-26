---
'@hzblj/nitro-crypto': patch
---

Extended public keys. `wallet.extendedPublicKey(path)` returns an account's BIP-32 extended public key (its public key, chain code, depth, parent fingerprint and child number), for a watch-only wallet to derive the account's addresses from; the master's is refused, and no private key leaves (ADR 0007). `crypto.bip32.derivePublic(key, path)` is public derivation from one, non-hardened steps only. Two engine functions (`nc_seed_extended_public`, `nc_bip32_public_derive`) and two capability bits (`bip32-extended-public`, `bip32-public-derivation`); the ABI version stays 1. Adapters reach them through `keys.extendedPublicKey` and `bip32.derivePublic`. Parity with BIP-32's published vectors and `@scure/bip32`.
