//
// HybridNitroCrypto.cpp
//

#include "HybridNitroCrypto.hpp"
#include "EngineBridge.hpp"
#include "HybridNitroKey.hpp"
#include "HybridNitroSeed.hpp"

#include <cmath>
#include <limits>

namespace margelo::nitro::nitrocrypto {

using namespace bridge;

namespace {

  /// A length JS passed as a number: a non-negative integer, or NC_ERR_INVALID_ARGUMENT.
  size_t lengthOf(double value) {
    if (!(value >= 0) || std::floor(value) != value || value > static_cast<double>(std::numeric_limits<uint32_t>::max())) {
      throw std::runtime_error(nc_status_name(NC_ERR_INVALID_ARGUMENT));
    }
    return static_cast<size_t>(value);
  }

  /// The C ABI's verify contract as a boolean: OK is true, a well-formed mismatch is false, anything else throws.
  bool verified(nc_status status) {
    if (status == NC_ERR_VERIFICATION_FAILED) {
      return false;
    }
    check(status);
    return true;
  }

  std::shared_ptr<ArrayBuffer> digest(uint32_t algorithm, ByteView data) {
    auto out = allocate(nc_hash_length(algorithm));
    check(nc_hash(algorithm, data.data, data.size, out->data(), out->size()));
    return out;
  }

} // namespace

HybridNitroCrypto::HybridNitroCrypto() : HybridObject(TAG) {
  if (nc_abi_version() != NC_ABI_VERSION) {
    throw std::runtime_error("nitro-crypto: the linked engine implements ABI " + std::to_string(nc_abi_version()) +
                             ", this bridge was built for ABI " + std::to_string(NC_ABI_VERSION));
  }
}

// --- version and capabilities ---------------------------------------------------------------------------------------

double HybridNitroCrypto::getAbiVersion() {
  return nc_abi_version();
}

std::string HybridNitroCrypto::getEngineVersion() {
  return nc_engine_version();
}

std::string HybridNitroCrypto::getBuildInfo() {
  return nc_build_info();
}

std::vector<std::string> HybridNitroCrypto::getCapabilities() {
  const uint64_t capabilities = nc_capabilities();
  std::vector<std::string> names;
  for (uint32_t bit = 0; bit < 64; bit++) {
    const char* name = nc_capability_name(bit);
    if (name != nullptr && (capabilities & (1ull << bit)) != 0) {
      names.emplace_back(name);
    }
  }
  return names;
}

double HybridNitroCrypto::getLiveHandles() {
  return nc_handle_count();
}

// --- random, hashes -------------------------------------------------------------------------------------------------

std::shared_ptr<ArrayBuffer> HybridNitroCrypto::randomBytes(double length) {
  auto out = allocate(lengthOf(length));
  check(nc_random_bytes(out->data(), out->size()));
  return out;
}

std::shared_ptr<ArrayBuffer> HybridNitroCrypto::hash(HashAlgorithm algorithm, const std::shared_ptr<ArrayBuffer>& data) {
  return digest(toEngine(algorithm), view(data));
}

std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> HybridNitroCrypto::hashAsync(HashAlgorithm algorithm,
                                                                                    const std::shared_ptr<ArrayBuffer>& data) {
  // A buffer JS owns is only readable during this call: hash an owned copy on the pool thread.
  auto owned = data->isOwner() ? data : ArrayBuffer::copy(data);
  const uint32_t engineAlgorithm = toEngine(algorithm);
  return Promise<std::shared_ptr<ArrayBuffer>>::async([owned, engineAlgorithm]() { return digest(engineAlgorithm, view(owned)); });
}

std::shared_ptr<ArrayBuffer> HybridNitroCrypto::hmac(HmacAlgorithm algorithm, const std::shared_ptr<ArrayBuffer>& key,
                                                     const std::shared_ptr<ArrayBuffer>& data) {
  const uint32_t engineAlgorithm = toEngine(algorithm);
  const ByteView keyView = view(key);
  const ByteView dataView = view(data);
  auto out = allocate(nc_hash_length(engineAlgorithm));
  check(nc_hmac(engineAlgorithm, keyView.data, keyView.size, dataView.data, dataView.size, out->data(), out->size()));
  return out;
}

// --- curves ---------------------------------------------------------------------------------------------------------

std::shared_ptr<ArrayBuffer> HybridNitroCrypto::secp256k1ConvertPublicKey(const std::shared_ptr<ArrayBuffer>& publicKey,
                                                                          bool compressed) {
  const ByteView input = view(publicKey);
  auto out = allocate(NC_SECP256K1_UNCOMPRESSED_LENGTH);
  size_t written = 0;
  check(nc_secp256k1_public_key_convert(input.data, input.size, compressed ? 1 : 0, out->data(), out->size(), &written));
  return truncated(out, written);
}

std::shared_ptr<ArrayBuffer> HybridNitroCrypto::bip32DerivePublic(const std::shared_ptr<ArrayBuffer>& extendedPublicKey,
                                                                  const std::string& path) {
  const ByteView input = view(extendedPublicKey);
  auto out = allocate(NC_EXTENDED_PUBLIC_KEY_LENGTH);
  size_t written = 0;
  check(nc_bip32_public_derive(input.data, input.size, path.data(), path.size(), out->data(), out->size(), &written));
  return truncated(out, written);
}

bool HybridNitroCrypto::secp256k1Verify(const std::shared_ptr<ArrayBuffer>& publicKey,
                                        const std::shared_ptr<ArrayBuffer>& digest,
                                        const std::shared_ptr<ArrayBuffer>& signature) {
  const ByteView key = view(publicKey);
  const ByteView message = view(digest);
  const ByteView sig = view(signature);
  return verified(nc_secp256k1_verify(key.data, key.size, message.data, message.size, sig.data, sig.size));
}

std::shared_ptr<ArrayBuffer> HybridNitroCrypto::secp256k1Recover(const std::shared_ptr<ArrayBuffer>& digest,
                                                                 const std::shared_ptr<ArrayBuffer>& signature,
                                                                 bool compressed) {
  const ByteView message = view(digest);
  const ByteView sig = view(signature);
  auto out = allocate(NC_SECP256K1_UNCOMPRESSED_LENGTH);
  size_t written = 0;
  check(nc_secp256k1_recover(message.data, message.size, sig.data, sig.size, compressed ? 1 : 0, out->data(),
                             out->size(), &written));
  return truncated(out, written);
}

bool HybridNitroCrypto::secp256k1SchnorrVerify(const std::shared_ptr<ArrayBuffer>& publicKey,
                                               const std::shared_ptr<ArrayBuffer>& message,
                                               const std::shared_ptr<ArrayBuffer>& signature) {
  const ByteView key = view(publicKey);
  const ByteView data = view(message);
  const ByteView sig = view(signature);
  return verified(nc_secp256k1_schnorr_verify(key.data, key.size, data.data, data.size, sig.data, sig.size));
}

std::shared_ptr<ArrayBuffer> HybridNitroCrypto::secp256k1TaprootTweak(const std::shared_ptr<ArrayBuffer>& publicKey,
                                                                      const std::shared_ptr<ArrayBuffer>& merkleRoot) {
  const ByteView key = view(publicKey);
  const ByteView root = view(merkleRoot);
  auto out = allocate(NC_SECP256K1_COMPRESSED_LENGTH);
  size_t written = 0;
  check(nc_secp256k1_taproot_tweak(key.data, key.size, root.data, root.size, out->data(), out->size(), &written));
  return truncated(out, written);
}

bool HybridNitroCrypto::ed25519Verify(const std::shared_ptr<ArrayBuffer>& publicKey,
                                      const std::shared_ptr<ArrayBuffer>& message,
                                      const std::shared_ptr<ArrayBuffer>& signature) {
  const ByteView key = view(publicKey);
  const ByteView data = view(message);
  const ByteView sig = view(signature);
  return verified(nc_ed25519_verify(key.data, key.size, data.data, data.size, sig.data, sig.size));
}

// --- seeds ----------------------------------------------------------------------------------------------------------

void HybridNitroCrypto::validateMnemonic(const std::shared_ptr<ArrayBuffer>& mnemonic) {
  const ByteView text = view(mnemonic);
  check(nc_mnemonic_validate(reinterpret_cast<const char*>(text.data), text.size));
}

std::shared_ptr<ArrayBuffer> HybridNitroCrypto::generateMnemonic(double wordCount) {
  const uint32_t words = static_cast<uint32_t>(lengthOf(wordCount));
  // The sentence lands on this stack, which is zeroized however the call leaves; JS receives its own copy, which the
  // facade overwrites once it has decoded it.
  StackSecret<NC_MNEMONIC_MAX_LENGTH> sentence;
  size_t written = 0;
  check(nc_mnemonic_generate(words, reinterpret_cast<char*>(sentence.bytes), NC_MNEMONIC_MAX_LENGTH, &written));
  return ArrayBuffer::copy(sentence.bytes, written);
}

std::shared_ptr<Promise<std::shared_ptr<HybridNitroSeedSpec>>>
HybridNitroCrypto::generateSeed(double wordCount, const std::shared_ptr<ArrayBuffer>& passphrase) {
  const uint32_t words = static_cast<uint32_t>(lengthOf(wordCount));
  auto secret = std::make_shared<SecretBytes>(passphrase);
  return Promise<std::shared_ptr<HybridNitroSeedSpec>>::async([words, secret]() -> std::shared_ptr<HybridNitroSeedSpec> {
    nc_handle seed = 0;
    check(nc_seed_generate(words, secret->chars(), secret->size(), &seed));
    return std::make_shared<HybridNitroSeed>(seed);
  });
}

std::shared_ptr<Promise<std::shared_ptr<HybridNitroSeedSpec>>>
HybridNitroCrypto::seedFromMnemonic(const std::shared_ptr<ArrayBuffer>& mnemonic, const std::shared_ptr<ArrayBuffer>& passphrase) {
  // Copied while the call still owns the JS buffers; zeroized when the last copy goes, after the pool thread is done.
  auto words = std::make_shared<SecretBytes>(mnemonic);
  auto secret = std::make_shared<SecretBytes>(passphrase);
  return Promise<std::shared_ptr<HybridNitroSeedSpec>>::async([words, secret]() -> std::shared_ptr<HybridNitroSeedSpec> {
    nc_handle seed = 0;
    check(nc_seed_from_mnemonic(words->chars(), words->size(), secret->chars(), secret->size(), &seed));
    return std::make_shared<HybridNitroSeed>(seed);
  });
}

// --- keys -----------------------------------------------------------------------------------------------------------

std::shared_ptr<HybridNitroKeySpec> HybridNitroCrypto::generateKey(Curve curve) {
  nc_handle key = 0;
  check(nc_key_generate(toEngine(curve), &key));
  return std::make_shared<HybridNitroKey>(key);
}

std::shared_ptr<HybridNitroKeySpec> HybridNitroCrypto::importKey(Curve curve, const std::shared_ptr<ArrayBuffer>& secret) {
  const ByteView bytes = view(secret);
  nc_handle key = 0;
  check(nc_key_import(toEngine(curve), bytes.data, bytes.size, &key));
  return std::make_shared<HybridNitroKey>(key);
}

} // namespace margelo::nitro::nitrocrypto
