# 10. A wallet's entropy sealed under a 32-byte key, for passkeys

Accepted. Amends [0009](0009-password-sealed-backup.md).

## Context

A backup sealed under a password (ADR 0009) is as good as the password, and the user has to keep it for years. A
passkey can take its place. WebAuthn's PRF extension (built on CTAP2's `hmac-secret`) evaluates a pseudo-random
function inside the authenticator, keyed by a secret bound to the credential, over a salt the relying party supplies,
and returns 32 bytes. The same credential and salt give the same 32 bytes on every device the passkey syncs to, behind
the platform's own biometric prompt. A vault can seal a wallet's entropy under that output and keep the backup
anywhere, with nothing for the user to remember: the passkey is the key.

That output is a key, not a password: 256 uniformly random bits. It comes from the platform's passkey API, natively,
and must not pass through JavaScript any more than the entropy may.

## Decision

- **A second key derivation in the `ncbk` format, 2: HKDF-SHA256 over a 32-byte key.** The header keeps the magic
  `ncbk`, the version 1 and the key derivation byte, and after them what this key derivation needs: a 16-byte salt and
  the 24-byte nonce. 46 bytes of header; with the sealed entropy and its 16-byte tag, 78 to 94 bytes in all, within
  `NC_BACKUP_MAX_LENGTH` (103), so a buffer sized for any backup still fits both kinds.

  ```text
  offset  length
  0       4       magic, "ncbk"
  4       1       version, 1
  5       1       key derivation, 2: HKDF-SHA256
  6       16      salt
  22      24      nonce
  46      n       the sealed entropy (16 to 32 bytes), then its 16-byte tag
  ```

- **HKDF, not Argon2id.** Stretching makes guessing a secret of little entropy costly; 256 random bits cannot be
  guessed, so Argon2id would cost half a second and 64 MiB for nothing. HKDF-SHA256 (RFC 5869) extracts with the
  backup's salt and expands with the info `ncbk xchacha20poly1305 key` into the 32-byte sealing key: every backup has
  a key of its own though the PRF output is the same, and the PRF output itself never keys a cipher. The SHA-256
  underneath is the engine's.
- **The same seal.** XChaCha20-Poly1305 with a fresh random nonce, the whole header as associated data, as ADR 0009
  seals: changing any byte of it fails the tag.
- **The version stays 1.** The version says how the format is read; the key derivation byte was put in it to choose
  what follows (ADR 0009 left that room). The first six bytes are shared, so a reader knows from them which layout
  follows and which secret to ask for. Key derivation 2 carries no Argon2id fields set to zero: a field that means
  nothing is one more thing for every reader to check or get wrong.
- **The kinds do not cross.** `nc_backup_open` refuses a key-sealed backup and `nc_backup_open_with_key` a
  password-sealed one, both `NC_ERR_INVALID_ARGUMENT`, before any key is derived. `nc_backup_kdf` reads which kind a
  backup is without opening it, so a vault asks for the password or for the passkey, never tries both. An engine from
  before this decision reads a key-sealed backup as a header it does not know: `NC_ERR_INVALID_ARGUMENT` as well. A
  wrong key and a changed backup fail alike, `NC_ERR_VERIFICATION_FAILED`, with nothing written.
- **A key of 32 zero bytes is refused** (`NC_ERR_INVALID_ARGUMENT`): it is what a buffer nobody filled holds, and a
  backup sealed under it would open for anyone.
- **Three functions, for native callers.** `nc_backup_seal_with_key(entropy, key)`, `nc_backup_open_with_key(backup,
  key)` and `nc_backup_kdf(backup)`, in `cpp/NitroCryptoInterop.hpp` as `backupSealWithKey`, `backupOpenWithKey` and
  `backupKeyDerivation`, with the capability bit `backup-hkdf-sha256` (bit 20) and `interop::backupWithKeySupported()`.
  JavaScript calls none of them, as with ADR 0009: a vault takes the PRF output from the platform and the entropy from
  its own store, seals natively, and hands JavaScript the sealed backup, which is safe anywhere. The ABI version stays
  1.
- **Held to the reference.** RFC 5869's first HKDF vector as the engine runs it; backups sealed by an independent
  implementation (@noble/hashes' HKDF and @noble/ciphers' XChaCha20-Poly1305, composed as above) that the engine must
  seal byte for byte and open (`test/vectors/backup_key.json`), and backups the engine seals that @noble opens; every
  changed byte, both kinds refused by the other's opening, every length, in Zig, in the C harness and through the
  WebAssembly build.

## Consequences

- A vault can offer a backup with nothing to remember: the entropy sealed under a passkey's PRF output, kept in the
  platform's end-to-end encrypted store or anywhere else, and opened on a new device after the passkey's prompt.
- The backup is as safe as the passkey: whoever can use the passkey (a synced device, the account of the passkey's
  provider) can open it, and losing the passkey loses the backup. A vault offers the words, or a password-sealed backup,
  beside it.
- The credential and the PRF salt are the vault's to choose and keep; neither is secret, and the engine sees neither,
  only the 32 bytes. A vault evaluates the PRF with a salt it uses for this alone.
- Shamir shares (SLIP-39) remain a later format, behind another key derivation byte or version.
