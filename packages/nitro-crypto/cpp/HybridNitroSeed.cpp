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

void HybridNitroSeed::dispose() {
  _handle.release();
}

} // namespace margelo::nitro::nitrocrypto
