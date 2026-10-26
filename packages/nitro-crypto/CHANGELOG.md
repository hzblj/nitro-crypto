# @hzblj/nitro-crypto

## 0.1.4

### Patch Changes

- [#9](https://github.com/hzblj/nitro-crypto/pull/9) [`6f18481`](https://github.com/hzblj/nitro-crypto/commit/6f18481e41e43a650a9f9968017068d2d17a8d2a) Thanks [@hzblj](https://github.com/hzblj)! - Backups sealed under a password, for native callers. `nc_backup_seal` turns BIP-39 entropy into a backup that is safe to store anywhere: Argon2id over the password (64 MiB, 3 passes, one lane) and XChaCha20-Poly1305, the versioned header as associated data. `nc_backup_open` turns it back into entropy, and fails alike for a wrong password and a changed backup. Both reach another native module as `backupSeal` and `backupOpen` in `cpp/NitroCryptoInterop.hpp`, behind the capability bit `backup-argon2id`; no JavaScript call takes or returns entropy, and the ABI version stays 1 (ADR 0009). Held to RFC 9106's and draft-irtf-cfrg-xchacha's vectors and to backups sealed by @noble.

## 0.1.3

### Patch Changes

- [#7](https://github.com/hzblj/nitro-crypto/pull/7) [`772d739`](https://github.com/hzblj/nitro-crypto/commit/772d7394af433122d0c90d43c1801f1da5e4af68) Thanks [@hzblj](https://github.com/hzblj)! - Seeds another native module hands over, without JavaScript. A vault that keeps a wallet's BIP-39 entropy sealed by the Secure Enclave or StrongBox makes the seed natively through `cpp/NitroCryptoInterop.hpp` (`<NitroCrypto/NitroCryptoInterop.hpp>` on iOS, the prefab module `NitroCrypto` (package `hzblj_nitro-crypto`) on Android) and returns it as a `NitroSeed`; `crypto.createEphemeralWallet({seed, words})` takes it over, and disposing the wallet disposes it. Three engine functions for native callers only (`nc_seed_from_entropy`, `nc_mnemonic_to_entropy`, `nc_mnemonic_from_entropy`) and the capability bit `bip39-entropy`; no JavaScript call takes or returns entropy, and the ABI version stays 1 (ADR 0008). `NitroSeed` is exported as a type.

## 0.1.2

### Patch Changes

- [#4](https://github.com/hzblj/nitro-crypto/pull/4) [`185dac9`](https://github.com/hzblj/nitro-crypto/commit/185dac9c5f27a932e0ad0160fb8cb2c31efdd0b3) Thanks [@hzblj](https://github.com/hzblj)! - Extended public keys. `wallet.extendedPublicKey(path)` returns an account's BIP-32 extended public key (its public key, chain code, depth, parent fingerprint and child number), for a watch-only wallet to derive the account's addresses from; the master's is refused, and no private key leaves (ADR 0007). `crypto.bip32.derivePublic(key, path)` is public derivation from one, non-hardened steps only. Two engine functions (`nc_seed_extended_public`, `nc_bip32_public_derive`) and two capability bits (`bip32-extended-public`, `bip32-public-derivation`); the ABI version stays 1. Adapters reach them through `keys.extendedPublicKey` and `bip32.derivePublic`. Parity with BIP-32's published vectors and `@scure/bip32`.

- [#4](https://github.com/hzblj/nitro-crypto/pull/4) [`65f53ca`](https://github.com/hzblj/nitro-crypto/commit/65f53ca5723969fea2d7f6184b52217831da58ba) Thanks [@hzblj](https://github.com/hzblj)! - The published `exports` no longer name a `source` condition. It pointed at `src/`, which the package does not ship, so a project that resolves with that condition (a monorepo's own tests often do) found nothing; the published map now has only `types` and `default`.

## 0.1.1

### Patch Changes

- [`c5e3660`](https://github.com/hzblj/nitro-crypto/commit/c5e3660f85de65016e63d533128a28459356b4e8) Thanks [@hzblj](https://github.com/hzblj)! - The README no longer opens with a warning banner. What the library keeps in memory and what it leaves to the app is in SECURITY.md.
