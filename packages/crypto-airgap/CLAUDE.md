# @hzblj/crypto-airgap

The air-gap payload protocol: BC-UR v2 (Bytewords, deterministic CBOR, fountain-coded multipart), a typed registry, and
the chain-agnostic public account types. Headless: no UI, no camera, no QR rendering, no timers, no native code, no
React, and no dependencies. The SHA-256 the fountain code seeds its PRNG with is the caller's (`sha256` in the multipart
options: the engine's `crypto.hash.sha256` in an app, the WebAssembly engine's in the tests); it does not depend on
`@hzblj/nitro-crypto`, so it installs alone and runs anywhere a JS engine does. Parity: Blockchain Commons' reference
vectors (bc-ur, C++), `@ngraveio/bc-ur`, `@keystonehq/bc-ur-registry`.

| Path | What it is |
| --- | --- |
| `src/errors.ts` | `AirgapError` and its codes. Messages never quote input. |
| `src/bytes.ts` | Byte helpers and strict UTF-8 (no `TextEncoder`: not every RN runtime has it). Internal. |
| `src/crc32.ts`, `src/bytewords.ts` | CRC-32 and Bytewords (BCR-2020-012): standard, URI and minimal styles. |
| `src/cbor.ts` | The CBOR subset UR types use: encode deterministically (sorted keys, shortest heads), decode with limits. Byte strings decode to plain `Uint8Array` copies, never Buffer views. |
| `src/fountain.ts` | Xoshiro256**, the alias sampler, degree and fragment choice, the encoder, and a bounded decoder. Must match the reference bit for bit: `test/vectors/bc-ur.json`. |
| `src/ur.ts` | UR strings: parse, `encodeUR`, `decodeUR`, the secret-type denylist and the allowlist check. |
| `src/multipart.ts` | `createMultipartEncoder` (strings, no timer), `createMultipartDecoder` (any order, duplicates, sessions, limits, `reset`). |
| `src/registry.ts` | `defineURType`, `toUR`, `fromUR`, `createURRegistry` (a union by `type`, nothing global). |
| `src/schema.ts` | Field readers for writing types (`readMap`, `readBytes`, `required`, `optional`, `compact`, …); the chain packages use them. |
| `src/types/` | `crypto-keypath`, `crypto-coin-info`, `crypto-hdkey` (public only), `crypto-eckey`, `crypto-multi-accounts`, request ids (`#6.37`). |
| `src/adapter.ts` | `AirgapRequester` and `AirgapResponder`: the shape of a chain's air-gap adapter. |
| `test/` | The reference vectors, parity with ngraveio and Keystone, hardware wallets' own keys (`vectors/hardware.json`: Keystone's firmware codec, OneKey's master key refused), CBOR edge cases and fuzzing, multipart loss, order, sessions and limits. |

## Rules

- **Strings in, strings out.** Nothing here draws, scans or schedules. A new feature that needs a timer or a camera
  belongs in the app.
- **Hostile by default.** Every decoder takes an allowlist; secret types are refused whatever it says. Lengths are
  checked against the bytes left before allocating. Every new type's `fromCbor` checks every field it reads and
  refuses private key material.
- **Decoded values are frozen and `compact`:** an absent field is absent, not `undefined`.
- **The fountain code is the reference's.** Any change to `fountain.ts` must keep `test/reference.test.ts` and the
  ngraveio parity green: a part that differs by a bit is a part no other wallet reads.
- **Write what the specification shows; read what implementations write.** (`crypto-account` wraps descriptors in
  `#6.308`; Keystone's JS registry does not, and both read.)

Docs copy has no em dashes.
