//
// NitroCryptoInterop.hpp
// For another native module in the same app, such as a vault that keeps a wallet's BIP-39 entropy sealed by the
// device's hardware key: the engine's seed functions for bytes that module holds natively, and the seed handed to
// JavaScript as a NitroSeed, so the secret never crosses into JavaScript (docs/adr/0008-native-secret-handoff.md).
//
// Header-only, over the C ABI and HybridNitroSeed, which this package exports to other modules: CocoaPods public
// headers (`#include <NitroCrypto/NitroCryptoInterop.hpp>`) and the Android prefab module `NitroCrypto`, in the package
// Gradle names after the project autolinking makes of @hzblj/nitro-crypto (`find_package(hzblj_nitro-crypto REQUIRED
// CONFIG)`, `target_link_libraries(... hzblj_nitro-crypto::NitroCrypto)`). The engine is one per process: a seed made
// here lives in the same table as every other the app holds.
//

#pragma once

#include "EngineBridge.hpp"
#include "HybridNitroSeed.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>

namespace margelo::nitro::nitrocrypto::interop {

/// Whether the linked engine has what this header calls: false on an engine older than the `bip39-entropy`
/// capability. A module checks it once, before anything else, and refuses to work rather than fail midway.
inline bool supported() {
  return nc_abi_version() == NC_ABI_VERSION && (nc_capabilities() & NC_CAP_BIP39_ENTROPY) != 0;
}

/// Whether the linked engine seals backups (`backup-argon2id`, docs/adr/0009): a module that offers backups checks it
/// as `supported()` above.
inline bool backupSupported() {
  return supported() && (nc_capabilities() & NC_CAP_BACKUP_ARGON2ID) != 0;
}

/// Whether the linked engine seals backups under a 32-byte key, such as a passkey's PRF output, and reads which kind a
/// backup is (`backup-hkdf-sha256`, docs/adr/0010): `backupSealWithKey`, `backupOpenWithKey` and
/// `backupKeyDerivation` below. Checked as `supported()` above.
inline bool backupWithKeySupported() {
  return supported() && (nc_capabilities() & NC_CAP_BACKUP_HKDF_SHA256) != 0;
}

/// `length` bytes from the operating system's CSPRNG, through the engine, which fails closed: fresh entropy is
/// 16 bytes for 12 words, 32 for 24.
inline void randomBytes(uint8_t* out, size_t length) {
  bridge::check(nc_random_bytes(out, length));
}

/// A seed from BIP-39 entropy (16, 20, 24, 28 or 32 bytes), as the NitroSeed JavaScript receives: the seed the words
/// behind that entropy make, with no passphrase. Runs PBKDF2, so call it off the JS thread. The entropy stays the
/// caller's to zero.
inline std::shared_ptr<HybridNitroSeedSpec> seedFromEntropy(const uint8_t* entropy, size_t length) {
  nc_handle handle = 0;
  bridge::check(nc_seed_from_entropy(entropy, length, nullptr, 0, &handle));
  return std::make_shared<HybridNitroSeed>(handle);
}

/// The entropy `mnemonic` encodes (NFKD-normalized UTF-8, single spaces) into `out`, which holds at least
/// NC_ENTROPY_MAX_LENGTH bytes; its length. Throws NC_ERR_INVALID_MNEMONIC or NC_ERR_MNEMONIC_CHECKSUM. For a vault
/// sealing the words a user restores from; `out` is the caller's to zero.
inline size_t entropyFromMnemonic(const char* mnemonic, size_t length, uint8_t* out, size_t capacity) {
  size_t written = 0;
  bridge::check(nc_mnemonic_to_entropy(mnemonic, length, out, capacity, &written));
  return written;
}

/// The mnemonic `entropy` encodes into `out`, which holds at least NC_MNEMONIC_MAX_LENGTH bytes; its length. The one
/// moment a vault's words leave it, for the user to write down; `out` is the caller's to zero.
inline size_t mnemonicFromEntropy(const uint8_t* entropy, size_t length, char* out, size_t capacity) {
  size_t written = 0;
  bridge::check(nc_mnemonic_from_entropy(entropy, length, out, capacity, &written));
  return written;
}

/// Entropy sealed under a password into `out` (at least NC_BACKUP_MAX_LENGTH bytes): a backup that is safe to store
/// anywhere, as the password keeps it; its length. Runs Argon2id over 64 MiB, about half a second: never on the JS or
/// UI thread. The entropy and the password stay the caller's to zero.
inline size_t backupSeal(const uint8_t* entropy, size_t length, const char* password, size_t passwordLength, uint8_t* out,
                         size_t capacity) {
  size_t written = 0;
  bridge::check(nc_backup_seal(entropy, length, password, passwordLength, out, capacity, &written));
  return written;
}

/// The entropy a backup holds, into `out` (at least NC_ENTROPY_MAX_LENGTH bytes); its length. Throws
/// NC_ERR_VERIFICATION_FAILED for a wrong password and for a changed backup alike, and NC_ERR_INVALID_ARGUMENT for a
/// backup sealed under a key (`backupKeyDerivation` tells them apart). `out` is the caller's to zero.
inline size_t backupOpen(const uint8_t* backup, size_t length, const char* password, size_t passwordLength, uint8_t* out,
                         size_t capacity) {
  size_t written = 0;
  bridge::check(nc_backup_open(backup, length, password, passwordLength, out, capacity, &written));
  return written;
}

/// Entropy sealed under a 32-byte key (NC_BACKUP_KEY_LENGTH) into `out` (at least NC_BACKUP_MAX_LENGTH bytes): the key a
/// passkey's PRF extension returns for a salt the vault keeps, so the user has nothing to remember. HKDF-SHA256 and
/// XChaCha20-Poly1305, microseconds; the key comes from the platform's passkey API natively and never reaches
/// JavaScript. Throws NC_ERR_INVALID_ARGUMENT for a key of 32 zero bytes. The entropy and the key stay the caller's to
/// zero.
inline size_t backupSealWithKey(const uint8_t* entropy, size_t length, const uint8_t* key, size_t keyLength, uint8_t* out,
                                size_t capacity) {
  size_t written = 0;
  bridge::check(nc_backup_seal_with_key(entropy, length, key, keyLength, out, capacity, &written));
  return written;
}

/// The entropy a key-sealed backup holds, into `out` (at least NC_ENTROPY_MAX_LENGTH bytes); its length. Throws
/// NC_ERR_VERIFICATION_FAILED for a wrong key and for a changed backup alike, and NC_ERR_INVALID_ARGUMENT for a backup
/// sealed under a password. `out` is the caller's to zero.
inline size_t backupOpenWithKey(const uint8_t* backup, size_t length, const uint8_t* key, size_t keyLength, uint8_t* out,
                                size_t capacity) {
  size_t written = 0;
  bridge::check(nc_backup_open_with_key(backup, length, key, keyLength, out, capacity, &written));
  return written;
}

/// Which key a backup was sealed under, without opening it: NC_BACKUP_KDF_ARGON2ID (ask for the password) or
/// NC_BACKUP_KDF_KEY (ask the passkey). Throws NC_ERR_INVALID_ARGUMENT for a header this engine does not read and
/// NC_ERR_INVALID_LENGTH for a length no backup has; says nothing of whether it opens.
inline uint32_t backupKeyDerivation(const uint8_t* backup, size_t length) {
  uint32_t kdf = 0;
  bridge::check(nc_backup_kdf(backup, length, &kdf));
  return kdf;
}

} // namespace margelo::nitro::nitrocrypto::interop
