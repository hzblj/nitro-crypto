//
// HybridNitroKey.hpp
// A private key held by the engine. JS sees this object; the key's bytes never cross the bridge.
//

#pragma once

#include "EngineHandle.hpp"
#include "HybridNitroKeySpec.hpp"

namespace margelo::nitro::nitrocrypto {

class HybridNitroKey : public HybridNitroKeySpec {
public:
  /// Takes ownership of a key handle the engine just issued.
  explicit HybridNitroKey(nc_handle handle);

  Curve getCurve() override;
  std::shared_ptr<ArrayBuffer> getPublicKey(bool compressed) override;
  std::shared_ptr<ArrayBuffer> sign(const std::shared_ptr<ArrayBuffer>& data) override;

  void dispose() override;

private:
  bridge::EngineHandle _handle;
  Curve _curve;
};

} // namespace margelo::nitro::nitrocrypto
