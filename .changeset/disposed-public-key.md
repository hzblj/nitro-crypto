---
'@hzblj/nitro-crypto': patch
---

A disposed key's `publicKey()` now throws `DISPOSED` like every other member, also when the public key was read before the key was disposed (it used to hand out the cached copy). The README's chains table and "Not in this version" now say what the adapters sign, with the `/viem`, `/kit` and `/sync` entries and the vault, recovery and air-gap packages beside them.
