---
'@hzblj/nitro-crypto': patch
---

Seeds another native module hands over, without JavaScript. A vault that keeps a wallet's BIP-39 entropy sealed by the Secure Enclave or StrongBox makes the seed natively through `cpp/NitroCryptoInterop.hpp` (`<NitroCrypto/NitroCryptoInterop.hpp>` on iOS, the prefab module `NitroCrypto` (package `hzblj_nitro-crypto`) on Android) and returns it as a `NitroSeed`; `crypto.createEphemeralWallet({seed, words})` takes it over, and disposing the wallet disposes it. Three engine functions for native callers only (`nc_seed_from_entropy`, `nc_mnemonic_to_entropy`, `nc_mnemonic_from_entropy`) and the capability bit `bip39-entropy`; no JavaScript call takes or returns entropy, and the ABI version stays 1 (ADR 0008). `NitroSeed` is exported as a type.
