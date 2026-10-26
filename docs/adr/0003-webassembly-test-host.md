# 3. The engine compiled to WebAssembly as the test host

Accepted.

## Context

The TypeScript layers (the facade, the registry, three adapters) need tests that run in CI and on a laptop, without a
simulator. Mocking the native module would test the mocks: the point of parity tests against viem or
`@solana/kit` is that they exercise the engine that ships.

## Decision

Build the same Zig engine as a `wasm32-wasi` reactor, and implement the Nitro host interface (`NitroCrypto`,
`NitroSeed`, `NitroKey`) over its C ABI exports in TypeScript (`src/host/wasm.ts`), call for call what the C++ bridge
does. The facade takes a host; `createCryptoEngine` gives it the native module, `createTestCryptoEngine` (the public
`@hzblj/nitro-crypto/testing` entry) the WebAssembly one.

- The binary is embedded in the package as base64 (`src/host/wasm-binary.generated.ts`, written by
  `yarn engine:wasm`), so the entry needs no file system, no `import.meta` and no bundler support: it loads alike
  under Node's test runner, Jest's CommonJS transform and Vitest.
- It imports one function, WASI's `random_get`, which the host serves from `crypto.getRandomValues`, so the engine's
  fail-closed randomness is exercised too.
- Every buffer a call allocates in linear memory is zeroed and freed when the call returns; handles are released on
  `dispose()` and by a `FinalizationRegistry`, as the bridge's destructors do.

## Consequences

- Every TypeScript test runs on the shipped engine: 89 tests across four packages and the example, with parity on
  random inputs against `@noble`, `@scure`, viem and `@solana/kit`.
- Third-party adapters get the same: a chain written elsewhere is tested against the real engine in Node.
- What WebAssembly cannot test is the bridge itself (Nitro conversions, the thread pool, handle ownership in C++);
  the C ABI harness, the example app's self-test and the Maestro flows cover that, on both platforms.
- The testing entry adds about 400 KB of base64 to the package; apps never bundle it (it is a separate subpath).
- It is not for production: WebAssembly memory is readable from JavaScript, which defeats the point of the engine.
