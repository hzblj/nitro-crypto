# nitro-crypto

Turborepo + Yarn 4 workspaces for **`@hzblj/nitro-crypto`** and its chain adapters: native cryptography for React
Native and Expo, a Zig engine behind Nitro Modules, chains as TypeScript adapters. React Native and Expo only, no web.

Every package has its own `CLAUDE.md`: read that one before touching it.

| Path | Package | What lives there |
| --- | --- | --- |
| `packages/zig-engine-crypto/` | `@hzblj/zig-engine-crypto` (private) | The engine in Zig: `include/nitro_crypto.h` (the C ABI), `src/`, the published vectors and the C harness in `test/`, `bench/`. libsecp256k1 is a pinned dependency. |
| `packages/nitro-crypto/` | `@hzblj/nitro-crypto` | The facade (`src/`), the Nitro specs and C++ bridge (`src/specs`, `cpp/`, `nitrogen/generated`), the iOS and Android packaging, and the prebuilt engine (`engine/`, build output). Subpaths `/adapter` (the contract, no native code) and `/testing` (the engine as WebAssembly). |
| `packages/crypto-ethereum/`, `crypto-bitcoin/`, `crypto-solana/` | `@hzblj/crypto-*` | The adapters: TypeScript over `@hzblj/nitro-crypto/adapter` only. |
| `apps/example/` | `nitro-crypto-example` (private) | Expo Router app built with `@hzblj/kara-ui`, running every package of this repository from **source** (and the air-gap packages from npm): a testnet wallet (onboarding, Keychain and Face ID, balances, send, receive, history, and offline signing over QR codes: pair, scan, review, sign) and a Debug tab with the self-test, demo wallet, accounts, signing, the air-gap loopback and a watch-only wallet, primitives, benchmarks, about. TRON lives here (`src/features/debug/chains/tron.ts`), the proof that a chain needs no package edits. Maestro flows in `e2e/`. See its `CLAUDE.md`. |
| `scripts/` | | `build-native/` (the engine for iOS, Android and WebAssembly, reproducibly), `verify-artifacts/`, `pack-check.mjs`, `sync-versions.mjs`. |
| `docs/` | | Architecture, adding an adapter, compatibility, benchmarks, and the decisions (`adr/`). `SECURITY.md` is at the root. |

Dependencies point down: example → adapters → `@hzblj/nitro-crypto` → Nitro → C++ bridge → C ABI → Zig. The engine
knows no chain; the bridge holds no cryptography; adapters import no native code and no other adapter. Beside them:
example → `@hzblj/crypto-airgap-<chain>` (npm) → (`@hzblj/crypto-airgap`, that chain's adapter). The air-gap packages
live in [hzblj/crypto-airgap](https://github.com/hzblj/crypto-airgap) and take this repository's packages from npm: a
change they need here is a release here first.

## Commands

```bash
yarn engine                  # the engine for every platform here (Zig 0.16.0; NDK 27.1 for Android, Xcode for iOS)
yarn engine:ios / :android / :wasm
yarn engine:test             # zig build test: units, vectors, Wycheproof, property tests, the C harness
yarn engine:verify           # the artifacts: digests, slices, platforms, exported symbols
yarn ios / yarn android      # build the platform's engine, then run the example (dev client)
yarn prebuild                # the engine, then a clean `expo prebuild` of the example
yarn test                    # every workspace's tests (turbo builds the WebAssembly engine first)
yarn typecheck / yarn lint   # tsc, Biome
yarn pack:check              # what npm receives (the engine must be built), and a consumer type-check
yarn example e2e ios|android # Maestro: smoke and tour on the booted simulator or the emulator, Metro running
                             # (--release: the installed release build; release-benchmarks runs only by name)
yarn changeset               # describe a change for the next release
```

## Conventions that bite

**The engine is build output.** `packages/nitro-crypto/engine/` and `src/host/wasm-binary.generated.ts` are written
by `yarn engine` and gitignored. The TypeScript tests need the WebAssembly one (turbo builds it); the example needs
the platform's (`yarn ios` builds it); a release builds all of them on macOS. Change the engine, rebuild it.

**One C ABI, four hosts that must agree.** `include/nitro_crypto.h`, `src/abi/c_api.zig`, the C++ bridge (`cpp/`) and
the WebAssembly host (`src/host/wasm.ts`) say the same thing four ways. A new function goes into all four, plus the
Nitro spec and `yarn codegen`. Incompatible change: bump `NC_ABI_VERSION`, `abi/version.zig`'s `abi_version` and
`SUPPORTED_ABI_VERSION` together.

**Nitro detaches a disposed Hybrid Object.** After `dispose()` from JavaScript, reading anything on it throws; the
facade tracks disposal itself. Never read a native object to learn whether it is disposed.

**The example runs the packages' source; the world runs `build/`.** Every package's `exports` names a `source` entry,
which the example's `metro.config.js` maps and its `tsconfig.json` mirrors with `paths`. The adapters type-check with
the `source` condition (their tsconfig); the example cannot (kara-ui ships a `source` of its own).

**Native views need a native parent.** Kara's native atoms (`LabeledContent`, `Button`, `TextField`) live in an
`Island`, and inside a native stack only native children or Fragments: an RN `Box` there breaks the Compose tree on
Android.

**Adapter factories with a configurable id return `ChainAdapter<NoInfer<Id>, …>`,** or the registry's contextual type
widens the id to `string` (docs/adding-an-adapter.md).

**Publish through Yarn, tag through changesets.** `yarn release` builds the engine, verifies it, builds, runs
`yarn npm publish` in every public workspace and then `changeset tag`. Never `changeset publish`: its npm call would
ship `workspace:` ranges verbatim. `changeset:version` also syncs each package's `src/version.ts`.

**Docs copy has no em dashes.** Not in the READMEs, the JSDoc in `src/` (it is the API reference), changesets or the
example's captions. Rewrite with a comma, a colon, parentheses or a second sentence. Code comments are exempt.

**Commits are Jan's alone.** Author `Jan Blazej <hello@janblazej.dev>` (set locally in this repo), no co-author or
generated-by lines.

Code style is Biome-enforced (`@hzblj/biome-config`): 2 spaces, 120 cols, single quotes, no semicolons, sorted imports
and object keys. Named exports and `const` arrow functions; `type` over `interface` (the Nitro specs excepted: nitrogen
reads interfaces). Zig is `zig fmt`'s.
