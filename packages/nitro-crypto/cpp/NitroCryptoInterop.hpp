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

} // namespace margelo::nitro::nitrocrypto::interop
