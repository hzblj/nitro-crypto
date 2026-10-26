//
// HybridNitroSeed.cpp
//

#include "HybridNitroSeed.hpp"
#include "HybridNitroKey.hpp"

namespace margelo::nitro::nitrocrypto {

using namespace bridge;

HybridNitroSeed::HybridNitroSeed(nc_handle handle) : HybridObject(TAG), _handle(handle) {
  // Computed once: it is public, and every read would otherwise redo a scalar multiplication.
  check(nc_seed_fingerprint(handle, &_fingerprint));
}

double HybridNitroSeed::getFingerprint() {
  return static_cast<double>(_fingerprint);
}

std::shared_ptr<HybridNitroKeySpec> HybridNitroSeed::deriveKey(DerivationScheme scheme, const std::string& path) {
  nc_handle key = 0;
  check(nc_key_derive(_handle.get(), toEngine(scheme), path.data(), path.size(), &key));
  return std::make_shared<HybridNitroKey>(key);
}

std::shared_ptr<ArrayBuffer> HybridNitroSeed::extendedPublicKey(const std::string& path) {
  auto out = allocate(NC_EXTENDED_PUBLIC_KEY_LENGTH);
  size_t written = 0;
  check(nc_seed_extended_public(_handle.get(), path.data(), path.size(), out->data(), out->size(), &written));
  return truncated(out, written);
}

void HybridNitroSeed::dispose() {
  _handle.release();
}

} // namespace margelo::nitro::nitrocrypto
