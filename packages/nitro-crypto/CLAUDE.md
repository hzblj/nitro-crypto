# @hzblj/nitro-crypto

The published package: the TypeScript facade and adapter registry, the Nitro specs and the C++ bridge, the iOS and
Android packaging, and the prebuilt engine. Three entry points:

| Entry | What | Loads native code |
| --- | --- | --- |
| `.` (`src/index.ts`) | `createCryptoEngine`, types, errors, encodings | Yes, on first `createCryptoEngine` |
| `./adapter` (`src/adapter.ts`) | The adapter contract, encodings, errors: what adapters import | No |
| `./testing` (`src/testing.ts`) | `createTestCryptoEngine`: the engine as WebAssembly | No (WebAssembly) |

| Path | What it is |
| --- | --- |
| `src/specs/nitro-crypto.nitro.ts` | The Nitro spec: `NitroCrypto`, `NitroSeed`, `NitroKey`. `yarn codegen` regenerates `nitrogen/generated`, which is checked in. |
| `cpp/` | The bridge: `HybridNitroCrypto`, `HybridNitroSeed`, `HybridNitroKey`; `EngineBridge.hpp` (views, `check`, `SecretBytes`, enum mappings); `EngineHandle.hpp` (owns one handle). No cryptography. |
| `src/host/nitro.ts`, `src/host/wasm.ts` | The two hosts: the native module, and the engine compiled to WebAssembly (`wasm-binary.generated.ts`, written by `yarn engine:wasm`). |
| `src/engine/` | The facade over a host: `info` (ABI check, capabilities), `primitives` (and the verify policy), `keys`, `mnemonic`, `wallet`, `extended-key` (extended public keys and public derivation, ADR 0007), `create-engine`. |
| `src/adapters/` | `contract.ts` (the types and `defineAdapter`), `registry.ts` (validation, binding, `chains`). |
| `src/core/` | `errors.ts` (codes, native status mapping), `bytes.ts`. |
| `src/encoding/` | hex, UTF-8, Base58, Base58Check, Bech32/Bech32m. Pure. |
| `NitroCrypto.podspec` | Vendors `engine/ios/NitroCryptoEngine.xcframework`, adds `engine/include` to header search. |
| `android/` | Nitro's template library; `CMakeLists.txt` links `engine/android/<abi>/libnitro_crypto.a` and fails by name for an ABI it lacks. |
| `test/` | node:test on the WebAssembly engine: encodings, primitives against `@noble`, wallets against `@scure`, the registry and its type inference, errors. |

## Rules

- **Bytes stay bytes.** `Uint8Array` in and out; `toArrayBuffer` passes a view's buffer without a copy when the view
  covers it. Secrets cross only as bytes the facade overwrites afterwards (`withSecretBytes` going in; going out,
  only `mnemonic.generate`, which decodes and then wipes the buffer the host returned).
- **The facade is host-agnostic.** Nothing in `src/engine` or `src/adapters` imports Nitro; only `src/host/nitro.ts`
  and `src/index.ts` do. That is what lets every test run on WebAssembly.
- **Errors are `CryptoError`.** Native calls go through `native()`/`nativeAsync()`; a native message is never passed
  on (it could hold an input), only the status name is read.
- **Disposal is tracked in JavaScript.** Nitro detaches a disposed Hybrid Object; never read one to ask.
- **Async only where it pays:** PBKDF2 (`generateSeed`, `seedFromMnemonic`) and `hashAsync`. The bridge copies a
  JS-owned buffer before leaving the JS thread.
- **Adding to the ABI** means the spec, `yarn codegen`, `cpp/`, `src/host/wasm.ts`, and the facade, in one change.

## Commands

```bash
yarn test         # node:test with the source condition (needs `yarn engine:wasm` once; turbo does it)
yarn tsc:check
yarn codegen      # nitrogen, after editing the spec
yarn build        # build/ for npm
```
