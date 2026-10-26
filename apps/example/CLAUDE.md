# example

The example app for `@hzblj/nitro-crypto` and its adapters: a testnet wallet whose keys, addresses, transactions and
signatures all come from the engine, and a Debug tab with the library on its own. Built from `@hzblj/kara-ui` like
every hzblj example. Private; never published.

| Path | What it is |
| --- | --- |
| `app/(tabs)/` | Native tabs (`Tabs` from `@hzblj/kara-ui/router`), each a stack with a large title: Wallet (`(home)`: home, network, send, receive, sign, transaction), Activity, Settings, Debug. Route files only re-export a screen from `src/`. |
| `app/onboarding/` | A modal stack: create (the engine generates the phrase), import, protect. The phrase travels between steps in `OnboardingProvider`, never in route params. |
| `src/features/` | One folder per area, each a screen and the components only it uses, behind an `index.ts`: `home`, `network`, `send`, `receive`, `sign-message`, `transaction`, `activity`, `settings`, `lock`, `onboarding`, and `debug` (the library on its own: overview and self-test, demo wallet, accounts, sign and verify, primitives, performance, about, with its own engine in `debug/crypto`, the mainnet adapters and TRON in `debug/chains`, the published vectors in `debug/vectors`). |
| `src/components/` | Shared UI: `Page`, `Section`, `Rows`, `Card`, `Value`, `Pill`, `Notice`, `ActionButton`, `TokenBadge`, `PhraseGrid`, `QrCode` (views over `qrcode-generator`), `Hairline`, `TabStack`, `CopyProvider`. |
| `src/core/` | The wallet core, the only code that holds the seed: `chains.ts` (the adapters on Sepolia, testnet4 and devnet, the account paths), `engine.ts` (the engine and services, once per run), `keychain.ts` (the phrase in `expo-secure-store` behind Face ID or the passcode), `session.ts` (start-up, unlock, lock, create, remove). |
| `src/store/` | Zustand stores in the `core-store` pattern: `persist(immer(...))`, a slice per concern, selectors from `auto-zustand-selectors-hook` (`useWalletStore.use.record()`). `wallet` (persisted: the record, auto-lock, pending sends), `session` (not persisted: locked or not, the accounts, the app state), `cache` (persisted: balances, histories, prices). `storage.ts` is MMKV with AES-256; its key is 24 bytes from the engine's CSPRNG, kept in the Keychain (`storage-key.ts`). `serialize.ts` keeps `bigint`, `Date`, `Map` and `Set` through JSON. |
| `src/hooks/` | `use-wallet.ts` (start-up and auto-lock, the selector hooks: status, accounts, record), `use-chain-data.ts` (holdings, histories, prices, the portfolio), `use-remote.ts` (network reads through the cache store). |
| `src/services/` | Each chain's network: JSON-RPC (Sepolia, devnet), Esplora (testnet4), Blockscout (Ethereum history), CoinGecko (prices). Balances, histories, quotes, broadcast, status. Nothing secret goes through here. |
| `src/config/` | `networks.ts` (endpoints, explorers, faucets, tokens), `theme.ts` (the emerald accent). |
| `src/utils/` | `units.ts`: amounts between the smallest unit and text, dollars, short addresses, relative times. |
| `src/providers.tsx` | The root providers: kara, navigation theme, safe area, the debug engine, copying. |
| `assets/icons/` | Material Symbols SVGs, turned into native assets by kara's plugin at prebuild; `native-icons.d.ts` is written from them. |
| `assets/app.icon`, `assets/icon.png`, `assets/adaptive-icon.png` | The app icon: an Icon Composer document (a wallet with a bolt, Liquid Glass) for iOS; the same shapes on an emerald gradient as the fallback, and alone on `ICON_BACKGROUND` for Android. |

**Folders are layers, and imports point down.** `features` may use every other folder; `hooks` use `core`,
`services`, `store`, `config` and `utils`; `core` uses `services` and `store`; `services` use `config` and `utils`;
`components`, `config` and `utils` use nothing of the app's (types aside). Nothing imports a feature but its route and,
for the debug engine's provider, `providers.tsx`. Across folders, import a folder's `index.ts`; inside one, the sibling
file. The one exception is `store/storage-key.ts`, which takes `core/engine` directly: `core`'s index imports the
stores back.

**State lives in the stores, not in context.** Read narrowly (`useSessionStore.use.status()`), never the whole store;
change it through the slices' actions or `session.ts`. Bump a store's `*_STORE_VERSION` when its persisted shape
changes. Network answers are public data but are persisted encrypted all the same, so the wallet opens on its last
balances while fresh ones load.

**Long lists are Legend List.** The Activity tab is a `SectionList` from `@legendapp/list/section-list`, grouped by
day, with recycled, memoized rows that draw their own part of the card; the home and network screens show at most
ten rows and map them. Loading shows skeletons in the shape of what comes, never a bare spinner.

**Testnets only.** Sepolia (chain id 11155111), Bitcoin testnet4 and Solana devnet, through public endpoints without
keys (`src/config/networks.ts`). Balances are priced at mainnet prices and the screens say so.

**Two engines, one native module.** The wallet's engine registers the adapters on test networks under the plain ids;
the Debug tab's (`features/debug/crypto`) keeps mainnet adapters and TRON. Both count in `liveHandles`.

**The adapters build and sign, the services talk to the network.** A quote reads the network's state (nonce and fees,
coins and fee rate, blockhash and rent), the adapter builds the transaction, `confirmWithUser()` asks for Face ID, the
key in the engine signs, the service broadcasts. Nothing secret goes through `services/`.

**Native changes need a rebuild**: `yarn prebuild` (engine first), then a native run. Face ID on the simulator:
Features → Face ID → Enrolled, then Matching Face when the prompt is up.
