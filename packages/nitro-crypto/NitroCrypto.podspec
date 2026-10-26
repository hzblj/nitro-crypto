require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "NitroCrypto"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]
  s.platforms    = { :ios => min_ios_version_supported }
  s.source       = { :git => "https://github.com/hzblj/nitro-crypto.git", :tag => "#{s.version}" }

  # The bridge: C++ Hybrid Objects over the engine's C ABI. No cryptography here.
  s.source_files = ["cpp/**/*.{hpp,cpp}"]

  # The engine, prebuilt (`yarn engine`), so an app never needs Zig: static archives for the device and the
  # simulator, and the C header beside them.
  s.vendored_frameworks = "engine/ios/NitroCryptoEngine.xcframework"
  s.pod_target_xcconfig = {
    "HEADER_SEARCH_PATHS" => "\"$(PODS_TARGET_SRCROOT)/engine/include\"",
  }

  load "nitrogen/generated/ios/NitroCrypto+autolinking.rb"
  add_nitrogen_files(s)

  s.dependency "React-jsi"
  s.dependency "React-callinvoker"
  install_modules_dependencies(s)
end
