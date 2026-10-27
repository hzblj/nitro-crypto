---
'@hzblj/nitro-crypto': patch
---

Backups sealed under a 32-byte key, such as a passkey's PRF output, for native callers. The `ncbk` format gains key derivation 2: HKDF-SHA256 over the key with a fresh salt, then XChaCha20-Poly1305 as before, in a 46-byte header at version 1, so a backup is 78 to 94 bytes and password backups open as they did. `nc_backup_seal_with_key` and `nc_backup_open_with_key` seal and open it, and `nc_backup_kdf` says whether a backup needs a password or a key without opening it; each kind is refused by the other's opening. All three reach another native module as `backupSealWithKey`, `backupOpenWithKey` and `backupKeyDerivation` in `cpp/NitroCryptoInterop.hpp`, behind the capability bit `backup-hkdf-sha256` (`backupWithKeySupported()`); no JavaScript call takes the key or the entropy, and the ABI version stays 1 (ADR 0010). Held to RFC 5869's vector and to backups sealed and opened by @noble.
