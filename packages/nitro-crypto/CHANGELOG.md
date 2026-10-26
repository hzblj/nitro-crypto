# @hzblj/nitro-crypto

## 0.2.0

### Minor Changes

- [`bd06ced`](https://github.com/hzblj/nitro-crypto/commit/bd06cedc3a7b64967c23e0d163db9926e79e5473) Thanks [@hzblj](https://github.com/hzblj)! - `crypto.mnemonic.generate(words?)` returns a fresh BIP-39 English mnemonic (12 words by default, or 15, 18, 21 or 24) from the operating system's CSPRNG, for a wallet the user can back up and restore: show it once, then pass it to `createEphemeralWallet({mnemonic})`. It is the one secret the engine hands out, through the new `nc_mnemonic_generate` in the C ABI; the engine keeps no copy, and the facade and the bridge overwrite their byte copies. The engine reports it as the `mnemonic-generate` capability. The C ABI version is unchanged: the function and the capability bit are additive.
