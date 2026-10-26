//
// HybridNitroSeed.hpp
// A BIP-39 seed held by the engine. It derives keys; the seed itself never crosses the bridge.
//

#pragma once

#include "EngineHandle.hpp"
#include "HybridNitroSeedSpec.hpp"

namespace margelo::nitro::nitrocrypto {

class HybridNitroSeed : public HybridNitroSeedSpec {
public:
  /// Takes ownership of a seed handle the engine just issued.
  explicit HybridNitroSeed(nc_handle handle);

  double getFingerprint() override;
  std::shared_ptr<HybridNitroKeySpec> deriveKey(DerivationScheme scheme, const std::string& path) override;
  std::shared_ptr<ArrayBuffer> extendedPublicKey(const std::string& path) override;

  void dispose() override;

private:
  bridge::EngineHandle _handle;
  uint32_t _fingerprint = 0;
};

} // namespace margelo::nitro::nitrocrypto
