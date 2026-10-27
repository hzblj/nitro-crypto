# @hzblj/nitro-crypto

## 0.1.5

### Patch Changes

- [#11](https://github.com/hzblj/nitro-crypto/pull/11) [`315484b`](https://github.com/hzblj/nitro-crypto/commit/315484b5ec891b6b45f38c2415d323841243df8a) Thanks [@hzblj](https://github.com/hzblj)! - A new error code, `CHAIN_MISMATCH`: a request is for another network than the one the adapter signs for. `@hzblj/crypto-ethereum` uses it for a transaction, typed data domain or EIP-7702 authorization naming another chain id, so a wallet can tell a dApp asking for another network from a malformed request.

- [#16](https://github.com/hzblj/nitro-crypto/pull/16) [`dc6062d`](https://github.com/hzblj/nitro-crypto/commit/dc6062d9d700ddf9e33e7cc4ff43836c658f65f6) Thanks [@hzblj](https://github.com/hzblj)! - A disposed key's `publicKey()` now throws `DISPOSED` like every other member, also when the public key was read before the key was disposed (it used to hand out the cached copy). The README's chains table and "Not in this version" now say what the adapters sign, with the `/viem`, `/kit` and `/sync` entries and the vault, recovery and air-gap packages beside them.

- [#14](https://github.com/hzblj/nitro-crypto/pull/14) [`c1ceb75`](https://github.com/hzblj/nitro-crypto/commit/c1ceb759f9c3b840153933d6c288d6c887f28a2d) Thanks [@hzblj](https://github.com/hzblj)! - `interop::seedFromEntropy` takes a BIP-39 passphrase, for a vault whose wallet has one: an overload with `passphrase` and its length, UTF-8 and NFKD-normalized by the caller (as the facade normalizes `createEphemeralWallet`'s), at most 1024 bytes. The two-argument form still makes a seed with no passphrase.

- [#14](https://github.com/hzblj/nitro-crypto/pull/14) [`fbd3720`](https://github.com/hzblj/nitro-crypto/commit/fbd37205d4c57696f91e988b513d04cef29b2cb8) Thanks [@hzblj](https://github.com/hzblj)! - Backups sealed under a 32-byte key, such as a passkey's PRF output, for native callers. The `ncbk` format gains key derivation 2: HKDF-SHA256 over the key with a fresh salt, then XChaCha20-Poly1305 as before, in a 46-byte header at version 1, so a backup is 78 to 94 bytes and password backups open as they did. `nc_backup_seal_with_key` and `nc_backup_open_with_key` seal and open it, and `nc_backup_kdf` says whether a backup needs a password or a key without opening it; each kind is refused by the other's opening. All three reach another native module as `backupSealWithKey`, `backupOpenWithKey` and `backupKeyDerivation` in `cpp/NitroCryptoInterop.hpp`, behind the capability bit `backup-hkdf-sha256` (`backupWithKeySupported()`); no JavaScript call takes the key or the entropy, and the ABI version stays 1 (ADR 0010). Held to RFC 5869's vector and to backups sealed and opened by @noble.

- [#14](https://github.com/hzblj/nitro-crypto/pull/14) [`b8ee6b2`](https://github.com/hzblj/nitro-crypto/commit/b8ee6b24c3fb198ad25b4e7baa8854fb856dba46) Thanks [@hzblj](https://github.com/hzblj)! - BIP-340 Schnorr signatures and BIP-341 Taproot tweaks, from libsecp256k1's extrakeys and schnorrsig modules. A secp256k1 key gains `xOnlyPublicKey()`, `signSchnorr(message)` (any length, with fresh auxiliary randomness from the OS) and `signTaproot(sighash, merkleRoot?)`, which signs a key path spend with the key tweaked inside the engine (no merkle root: BIP-86). `crypto.schnorr.verify(publicKey, message, signature)` verifies, and `crypto.schnorr.taprootTweak(internalKey, merkleRoot?)` returns the output key and its parity. Adapters declare them as the capabilities `secp256k1-schnorr` and `taproot-tweak`; in the C ABI they are `nc_secp256k1_schnorr_verify`, `nc_secp256k1_taproot_tweak`, `nc_key_public_xonly`, `nc_key_sign_schnorr` and `nc_key_sign_taproot`, and the ABI version stays 1. Held to every BIP-340 vector, BIP-341's wallet vectors and BIP-86's, and to @noble/curves.

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
