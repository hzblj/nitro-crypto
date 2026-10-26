---
'@hzblj/nitro-crypto': patch
---

Backups sealed under a password, for native callers. `nc_backup_seal` turns BIP-39 entropy into a backup that is safe to store anywhere: Argon2id over the password (64 MiB, 3 passes, one lane) and XChaCha20-Poly1305, the versioned header as associated data. `nc_backup_open` turns it back into entropy, and fails alike for a wrong password and a changed backup. Both reach another native module as `backupSeal` and `backupOpen` in `cpp/NitroCryptoInterop.hpp`, behind the capability bit `backup-argon2id`; no JavaScript call takes or returns entropy, and the ABI version stays 1 (ADR 0009). Held to RFC 9106's and draft-irtf-cfrg-xchacha's vectors and to backups sealed by @noble.
