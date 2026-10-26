project(NitroCrypto)
cmake_minimum_required(VERSION 3.9.0)

set(PACKAGE_NAME NitroCrypto)
set(CMAKE_CXX_STANDARD 20)

# The bridge: C++ Hybrid Objects over the engine's C ABI, shared with iOS.
add_library(${PACKAGE_NAME} SHARED
  src/main/cpp/cpp-adapter.cpp
  ../cpp/HybridNitroCrypto.cpp
  ../cpp/HybridNitroKey.cpp
  ../cpp/HybridNitroSeed.cpp
)

include(${CMAKE_SOURCE_DIR}/../nitrogen/generated/android/NitroCrypto+autolinking.cmake)

include_directories(
  "src/main/cpp"
  "../cpp"
  "../engine/include"
)

# The engine, prebuilt per ABI by `yarn engine` (position-independent, so it links into this .so). An ABI the
# package does not ship fails here, by name, rather than at a missing symbol.
set(ENGINE_ARCHIVE ${CMAKE_SOURCE_DIR}/../engine/android/${ANDROID_ABI}/libnitro_crypto.a)
if(NOT EXISTS ${ENGINE_ARCHIVE})
  message(FATAL_ERROR "nitro-crypto ships no engine for ${ANDROID_ABI} (arm64-v8a, armeabi-v7a, x86, x86_64): ${ENGINE_ARCHIVE}")
endif()
add_library(nitro_crypto_engine STATIC IMPORTED)
set_target_properties(nitro_crypto_engine PROPERTIES IMPORTED_LOCATION ${ENGINE_ARCHIVE})

find_library(LOG_LIB log)

target_link_libraries(
  ${PACKAGE_NAME}
  nitro_crypto_engine
  ${LOG_LIB}
  android
)
