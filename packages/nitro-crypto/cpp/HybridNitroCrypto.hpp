//
// HybridNitroCrypto.hpp
// The engine as a Hybrid Object: stateless primitives, and the factories for seeds and keys.
//

#pragma once

#include "HybridNitroCryptoSpec.hpp"

namespace margelo::nitro::nitrocrypto {

class HybridNitroCrypto : public HybridNitroCryptoSpec {
public:
  /// Refuses an engine whose C ABI is not the one this bridge was compiled against.
  HybridNitroCrypto();

  double getAbiVersion() override;
  std::string getEngineVersion() override;
  std::string getBuildInfo() override;
  std::vector<std::string> getCapabilities() override;
  double getLiveHandles() override;

  std::shared_ptr<ArrayBuffer> randomBytes(double length) override;
  std::shared_ptr<ArrayBuffer> hash(HashAlgorithm algorithm, const std::shared_ptr<ArrayBuffer>& data) override;
  std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> hashAsync(HashAlgorithm algorithm,
                                                                   const std::shared_ptr<ArrayBuffer>& data) override;
  std::shared_ptr<ArrayBuffer> hmac(HmacAlgorithm algorithm, const std::shared_ptr<ArrayBuffer>& key,
                                    const std::shared_ptr<ArrayBuffer>& data) override;

  std::shared_ptr<ArrayBuffer> secp256k1ConvertPublicKey(const std::shared_ptr<ArrayBuffer>& publicKey,
                                                         bool compressed) override;
  bool secp256k1Verify(const std::shared_ptr<ArrayBuffer>& publicKey, const std::shared_ptr<ArrayBuffer>& digest,
                       const std::shared_ptr<ArrayBuffer>& signature) override;
  std::shared_ptr<ArrayBuffer> secp256k1Recover(const std::shared_ptr<ArrayBuffer>& digest,
                                                const std::shared_ptr<ArrayBuffer>& signature, bool compressed) override;
  bool ed25519Verify(const std::shared_ptr<ArrayBuffer>& publicKey, const std::shared_ptr<ArrayBuffer>& message,
                     const std::shared_ptr<ArrayBuffer>& signature) override;

  void validateMnemonic(const std::shared_ptr<ArrayBuffer>& mnemonic) override;
  std::shared_ptr<ArrayBuffer> generateMnemonic(double wordCount) override;
  std::shared_ptr<Promise<std::shared_ptr<HybridNitroSeedSpec>>>
  generateSeed(double wordCount, const std::shared_ptr<ArrayBuffer>& passphrase) override;
  std::shared_ptr<Promise<std::shared_ptr<HybridNitroSeedSpec>>>
  seedFromMnemonic(const std::shared_ptr<ArrayBuffer>& mnemonic, const std::shared_ptr<ArrayBuffer>& passphrase) override;

  std::shared_ptr<HybridNitroKeySpec> generateKey(Curve curve) override;
  std::shared_ptr<HybridNitroKeySpec> importKey(Curve curve, const std::shared_ptr<ArrayBuffer>& secret) override;
};

} // namespace margelo::nitro::nitrocrypto
