//
// EngineBridge.hpp
// The few things every Hybrid Object needs to talk to the engine's C ABI: a status check that throws the status's
// stable name, views of Nitro buffers, owned copies that zeroize themselves, and enum mappings.
//

#pragma once

#include "Curve.hpp"
#include "DerivationScheme.hpp"
#include "HashAlgorithm.hpp"
#include "HmacAlgorithm.hpp"

#include <NitroModules/ArrayBuffer.hpp>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <nitro_crypto.h>

namespace margelo::nitro::nitrocrypto::bridge {

/// Throws the status's name ("NC_ERR_INVALID_LENGTH") for anything but NC_OK. The TypeScript facade maps the name to
/// a `CryptoError` code; nothing else goes into the message, so no input or secret can reach a log through it.
inline void check(nc_status status) {
  if (status != NC_OK) {
    throw std::runtime_error(nc_status_name(status));
  }
}

/// A read-only view of a buffer for the duration of a synchronous call.
struct ByteView {
  const uint8_t* data;
  size_t size;
};

/// A JS-owned buffer is readable only while the call that received it runs; `data()` is null once the JS side has
/// let it go (and may be null for an empty buffer, which the C ABI accepts).
inline ByteView view(const std::shared_ptr<ArrayBuffer>& buffer) {
  const size_t size = buffer->size();
  const uint8_t* data = buffer->data();
  if (data == nullptr && size > 0) {
    throw std::runtime_error(nc_status_name(NC_ERR_INVALID_ARGUMENT));
  }
  return ByteView{data, size};
}

/// Bytes the bridge owns, zeroized when they go: a mnemonic or passphrase on its way to a background thread.
class SecretBytes {
public:
  explicit SecretBytes(const std::shared_ptr<ArrayBuffer>& buffer) {
    const ByteView source = view(buffer);
    _bytes.assign(source.data, source.data + source.size);
  }
  SecretBytes(const SecretBytes&) = delete;
  SecretBytes& operator=(const SecretBytes&) = delete;
  ~SecretBytes() {
    // Through a volatile pointer, so the stores are not optimized away as dead.
    volatile uint8_t* bytes = _bytes.data();
    for (size_t index = 0; index < _bytes.size(); index++) {
      bytes[index] = 0;
    }
  }

  const char* chars() const noexcept {
    return reinterpret_cast<const char*>(_bytes.data());
  }
  size_t size() const noexcept {
    return _bytes.size();
  }

private:
  std::vector<uint8_t> _bytes;
};

/// The engine writes into native memory the bridge then hands to JS without a copy.
inline std::shared_ptr<ArrayBuffer> allocate(size_t size) {
  return ArrayBuffer::allocate(size);
}

/// Shrinks a result to the length the engine reported (a public key whose encoding was chosen at runtime).
inline std::shared_ptr<ArrayBuffer> truncated(const std::shared_ptr<ArrayBuffer>& buffer, size_t written) {
  return written == buffer->size() ? buffer : ArrayBuffer::copy(buffer->data(), written);
}

inline uint32_t toEngine(HashAlgorithm algorithm) {
  switch (algorithm) {
    case HashAlgorithm::SHA256:
      return NC_HASH_SHA256;
    case HashAlgorithm::SHA512:
      return NC_HASH_SHA512;
    case HashAlgorithm::KECCAK256:
      return NC_HASH_KECCAK256;
    case HashAlgorithm::RIPEMD160:
      return NC_HASH_RIPEMD160;
  }
  throw std::runtime_error(nc_status_name(NC_ERR_INVALID_ARGUMENT));
}

inline uint32_t toEngine(HmacAlgorithm algorithm) {
  switch (algorithm) {
    case HmacAlgorithm::SHA256:
      return NC_HASH_SHA256;
    case HmacAlgorithm::SHA512:
      return NC_HASH_SHA512;
  }
  throw std::runtime_error(nc_status_name(NC_ERR_INVALID_ARGUMENT));
}

inline uint32_t toEngine(Curve curve) {
  switch (curve) {
    case Curve::SECP256K1:
      return NC_CURVE_SECP256K1;
    case Curve::ED25519:
      return NC_CURVE_ED25519;
  }
  throw std::runtime_error(nc_status_name(NC_ERR_INVALID_ARGUMENT));
}

inline uint32_t toEngine(DerivationScheme scheme) {
  switch (scheme) {
    case DerivationScheme::BIP32:
      return NC_SCHEME_BIP32_SECP256K1;
    case DerivationScheme::SLIP10:
      return NC_SCHEME_SLIP10_ED25519;
  }
  throw std::runtime_error(nc_status_name(NC_ERR_INVALID_ARGUMENT));
}

/// The curve of a key handle, as the engine reports its kind.
inline Curve curveOf(nc_handle key) {
  uint32_t kind = 0;
  check(nc_handle_kind(key, &kind));
  switch (kind) {
    case NC_KIND_SECP256K1_KEY:
      return Curve::SECP256K1;
    case NC_KIND_ED25519_KEY:
      return Curve::ED25519;
    default:
      throw std::runtime_error(nc_status_name(NC_ERR_INVALID_HANDLE));
  }
}

} // namespace margelo::nitro::nitrocrypto::bridge
