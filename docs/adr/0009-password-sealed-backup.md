# 9. A wallet's entropy sealed under a password, for a backup that leaves the device

Accepted. Amends [0004](0004-secrets-behind-handles.md) and [0008](0008-native-secret-handoff.md).

## Context

A vault that keeps a wallet's entropy sealed by the Secure Enclave or StrongBox (ADR 0008) keeps it on that device
only: a new phone, a lost one or a reset is the end of it. The BIP-39 words are one way back, and every wallet offers
them. The other, which most wallets offer beside the words, is an encrypted backup the platform keeps in its own
end-to-end encrypted store (iCloud Keychain, Android Block Store), restored on a new device with a password.

What a backup holds must be useless without the password: the platform's own encryption is a second layer, not the
first. So the entropy is sealed under a key stretched from the password, and that sealing is cryptography, which is
this engine's and nowhere else's. The entropy is native when the vault holds it, and must stay native on its way into
the backup and back out of it.

## Decision

- **Argon2id stretches the password, XChaCha20-Poly1305 seals the entropy.** Argon2id (RFC 9106) at 64 MiB, three
  passes and one lane: about half a second on a phone, and memory-hard against GPUs and ASICs. XChaCha20-Poly1305,
  whose 24-byte nonce is random with no risk of collision. Both are Zig's standard library.
- **A versioned format with its parameters in it.** Magic `ncbk`, version 1, the key derivation (1: Argon2id), the
  memory and passes, one lane, a 16-byte salt and a 24-byte nonce: 55 bytes of header, the associated data of the seal,
  so changing any of it fails the tag. Then the sealed entropy and its 16-byte tag: 87 to 103 bytes in all. Opening
  accepts 19 to 256 MiB and 1 to 10 passes, so a crafted backup can ask neither for a trivial key nor for more memory
  than a phone has; a later version can raise the defaults and still open these.
- **A wrong password and a changed backup fail alike,** `NC_ERR_VERIFICATION_FAILED`, with nothing written.
- **Two functions, for native callers.** `nc_backup_seal(entropy, password)` and `nc_backup_open(backup, password)`, in
  `cpp/NitroCryptoInterop.hpp` as `backupSeal` and `backupOpen`, with the capability bit `backup-argon2id` (bit 17).
  JavaScript calls neither: a vault opens an entry and seals it into a backup natively, and opens a backup straight
  into a new entry. What JavaScript sees is the sealed backup, which is safe anywhere. The ABI version stays 1.
- **Argon2id's memory is the one allocation for a secret.** 64 MiB holds values derived from the password and fits no
  stack: it comes from the page allocator through one that zeroes every block before it goes back, and is freed before
  the call returns. The key and the decrypted entropy stay on the stack, zeroed on every path.
- **Held to the reference.** RFC 9106's Argon2id vector and draft-irtf-cfrg-xchacha's XChaCha20-Poly1305 vector, as
  the engine runs them; backups sealed by an independent implementation (@noble/hashes and @noble/ciphers, composed as
  above) that the engine must seal byte for byte and open (`test/vectors/backup.json`); tampering with every part of
  the format, and the C harness at the real parameters.

## Consequences

- A vault can offer a backup that survives the device: the entropy sealed under a password the user keeps, stored in
  the platform's end-to-end encrypted store or anywhere else.
- The password is as strong as the person makes it, and is a string in JavaScript on its way in (as typed words are,
  ADR 0005): the facade asks for a long one and turns it into bytes it overwrites. Argon2id makes guessing costly, not
  impossible.
- Passkeys (WebAuthn's PRF) in place of a password, and Shamir shares (SLIP-39), are later formats: the header's key
  derivation byte and version leave room for them.
