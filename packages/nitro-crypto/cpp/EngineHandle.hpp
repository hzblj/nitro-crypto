//
// EngineHandle.hpp
// Owns one engine handle (a seed or a key). Releasing it asks the engine to zeroize the secret and free the slot;
// that happens on `dispose()` from JS, or when the Hybrid Object is destroyed, whichever comes first.
//

#pragma once

#include "EngineBridge.hpp"

#include <atomic>

namespace margelo::nitro::nitrocrypto::bridge {

class EngineHandle {
public:
  explicit EngineHandle(nc_handle handle) : _handle(handle) {}
  EngineHandle(const EngineHandle&) = delete;
  EngineHandle& operator=(const EngineHandle&) = delete;
  ~EngineHandle() {
    release();
  }

  /// The live handle, or NC_ERR_INVALID_HANDLE once released, so a disposed object fails like a forged one.
  nc_handle get() const {
    const nc_handle handle = _handle.load();
    if (handle == 0) {
      throw std::runtime_error(nc_status_name(NC_ERR_INVALID_HANDLE));
    }
    return handle;
  }

  /// Idempotent and safe from any thread: only the first caller gets the handle to destroy.
  void release() noexcept {
    const nc_handle handle = _handle.exchange(0);
    if (handle != 0) {
      nc_handle_destroy(handle);
    }
  }

private:
  std::atomic<nc_handle> _handle;
};

} // namespace margelo::nitro::nitrocrypto::bridge
