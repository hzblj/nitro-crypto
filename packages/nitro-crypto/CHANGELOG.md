# @hzblj/nitro-crypto

## 0.1.2

### Patch Changes

- [#4](https://github.com/hzblj/nitro-crypto/pull/4) [`185dac9`](https://github.com/hzblj/nitro-crypto/commit/185dac9c5f27a932e0ad0160fb8cb2c31efdd0b3) Thanks [@hzblj](https://github.com/hzblj)! - Extended public keys. `wallet.extendedPublicKey(path)` returns an account's BIP-32 extended public key (its public key, chain code, depth, parent fingerprint and child number), for a watch-only wallet to derive the account's addresses from; the master's is refused, and no private key leaves (ADR 0007). `crypto.bip32.derivePublic(key, path)` is public derivation from one, non-hardened steps only. Two engine functions (`nc_seed_extended_public`, `nc_bip32_public_derive`) and two capability bits (`bip32-extended-public`, `bip32-public-derivation`); the ABI version stays 1. Adapters reach them through `keys.extendedPublicKey` and `bip32.derivePublic`. Parity with BIP-32's published vectors and `@scure/bip32`.

- [#4](https://github.com/hzblj/nitro-crypto/pull/4) [`65f53ca`](https://github.com/hzblj/nitro-crypto/commit/65f53ca5723969fea2d7f6184b52217831da58ba) Thanks [@hzblj](https://github.com/hzblj)! - The published `exports` no longer name a `source` condition. It pointed at `src/`, which the package does not ship, so a project that resolves with that condition (a monorepo's own tests often do) found nothing; the published map now has only `types` and `default`.

## 0.1.1

### Patch Changes

- [`c5e3660`](https://github.com/hzblj/nitro-crypto/commit/c5e3660f85de65016e63d533128a28459356b4e8) Thanks [@hzblj](https://github.com/hzblj)! - The README no longer opens with a warning banner. What the library keeps in memory and what it leaves to the app is in SECURITY.md.
