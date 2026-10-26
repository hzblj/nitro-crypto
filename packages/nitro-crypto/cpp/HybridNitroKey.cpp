//
// HybridNitroKey.cpp
//

#include "HybridNitroKey.hpp"

namespace margelo::nitro::nitrocrypto {

using namespace bridge;

HybridNitroKey::HybridNitroKey(nc_handle handle) : HybridObject(TAG), _handle(handle), _curve(curveOf(handle)) {}

Curve HybridNitroKey::getCurve() {
  return _curve;
}

std::shared_ptr<ArrayBuffer> HybridNitroKey::getPublicKey(bool compressed) {
  auto out = allocate(NC_SECP256K1_UNCOMPRESSED_LENGTH);
  size_t written = 0;
  check(nc_key_public(_handle.get(), compressed ? 1 : 0, out->data(), out->size(), &written));
  return truncated(out, written);
}

std::shared_ptr<ArrayBuffer> HybridNitroKey::sign(const std::shared_ptr<ArrayBuffer>& data) {
  const ByteView input = view(data);
  auto out = allocate(NC_SECP256K1_RECOVERABLE_SIGNATURE_LENGTH);
  size_t written = 0;
  check(nc_key_sign(_handle.get(), input.data, input.size, out->data(), out->size(), &written));
  return truncated(out, written);
}

void HybridNitroKey::dispose() {
  _handle.release();
}

} // namespace margelo::nitro::nitrocrypto
