# 5. A generated mnemonic leaves the engine once, for backup

Accepted. Amends [0004](0004-secrets-behind-handles.md) ("No export").

## Context

Until now a generated mnemonic existed only on the stack of the call that turned it into a seed
(`nc_seed_generate`): a wallet nobody could back up, and so nothing an app could restore after a reinstall or offer
on a second device. The example app is becoming a testnet wallet with onboarding, which needs what every wallet does:
twelve words the user writes down once and can restore from.

The words could have been made in JavaScript, from `crypto.random()` and a word list bundled with the app. That moves
mnemonic generation out of the reviewed code path into every app that wants it, with its own copy of the list, its
own checksum code and its own mistakes, while the engine already holds the pinned list, the checksum and the OS
entropy source.

## Decision

- **One function hands one secret out:** `nc_mnemonic_generate(word_count, out, out_len, written)` draws 16 to 32
  bytes of OS entropy and writes the English mnemonic into the caller's buffer. The entropy and the engine's copy of
  the sentence are zeroed before it returns; the engine keeps nothing, and no handle is created.
- **Its capacity check is deterministic.** `out_len` must fit the longest sentence of that many words
  (`word_count * 9 - 1`, `NC_MNEMONIC_MAX_LENGTH` for 24), checked before any entropy is drawn, so a buffer is either
  always large enough or never, whatever words come out.
- **Bytes across the bridge, wiped on the way.** The C++ bridge writes the sentence into a stack buffer it zeroes on
  every path and hands JavaScript a copy; the facade decodes that copy into the string it returns and overwrites the
  bytes. `crypto.mnemonic.generate(words?)` is the only API that produces it.
- **The string is the app's.** What the app does with it (show it once, verify the user wrote it down, store it where
  the platform protects it) is the app's design, as is restoring with `createEphemeralWallet({mnemonic})`.
- **Additive:** a new function and a new capability bit (`mnemonic-generate`, bit 13). The ABI version stays 1.
- Seeds and private keys still never leave: no function returns one, and `nc_seed_generate` still keeps its mnemonic
  to itself, for apps that want a wallet nobody can export.

## Consequences

- JavaScript holds a secret it never held before: the mnemonic string, in the JS heap, for as long as the app keeps
  it. The facade can overwrite its bytes but not the string; the JS engine may copy it. SECURITY.md says so.
- Restoring a wallet goes through `createEphemeralWallet({mnemonic})`, which is no longer only for test vectors.
- Persistence stays outside the library: the engine still writes nothing anywhere.
