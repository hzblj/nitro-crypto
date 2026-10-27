# 11. A watch-only Bitcoin sync over Esplora, as a subpath of the adapter

Accepted.

## Context

`@hzblj/crypto-bitcoin` derives addresses, plans payments and writes and signs PSBTs, and leaves the network to the
app. Every app then writes the same code to make a wallet of it: find the account's addresses, read their coins and
history, tell a payment in from one out, keep it all across launches and fix it when a block is replaced or a payment
is dropped. The example did it by hand for one address (`apps/example/src/services/bitcoin.ts`). For Ethereum, viem is
that layer; for Bitcoin in React Native there was none to use:

- **BDK** (`bdk-rn`) is a Rust library behind a native binding: megabytes of native code per platform, a second
  cryptography stack beside the engine, and a wallet that wants to hold the keys (descriptors with private keys, its
  own signer). Keys here never leave the engine (ADR 0004).
- **BDK as WebAssembly** (MetaMask's build) needs a WebAssembly runtime, which Hermes does not have.
- **Light clients** (Neutrino, compact block filters) download headers and filters for the whole chain: right for a
  desktop wallet, heavy for a phone app that opens for a minute.

## Decision

- **Watch-only, with PSBTs out.** The sync holds no key. It follows an account by its extended public key
  (`wallet.extendedPublicKey`, or the xpub, tpub, zpub or vpub a signer shares), one key's address, or an address
  alone. Payments leave it as one PSBT with every coin's key origin, which the engine signs (`sync.signPsbt`, each key
  derived and checked against the PSBT) or an air-gapped signer does (`@hzblj/crypto-airgap-bitcoin`). Hot wallets,
  watch-only phones and hardware wallets take the same path.
- **Esplora first, behind an interface.** Esplora's HTTP API is what mempool.space and blockstream.info serve, and
  what anyone can run (electrs): plain `fetch`, JSON, no sockets, nothing native. The sync asks a `BitcoinBackend`
  (tip, block hashes, address summaries and history pages, transactions, their hex and status, fees, broadcast);
  `esploraBackend` is one, an Electrum or Bitcoin Core one is another, later. The HTTP layer is a wallet's: a timeout
  per attempt, the caller's `AbortSignal`, retries with backoff on 429 and 5xx (honouring `Retry-After`), bounded
  concurrency, every answer parsed strictly, every failure a `SyncError` with a stable code.
- **Polite to public servers by default.** Esplora has no batch, so the first sync of a large account is hundreds of
  requests; done unpaced at two at a time while this was written, it got the machine's IP address blocked by every
  mempool.space address. Every request of a backend (retries included) now starts no faster than a rate, after a
  small burst: two a second, five at once, two in flight for mempool.space and blockstream.info, whose limits are
  unpublished; fifty a second for any other `url`, taken to be the app's own server. Repeated connection failures
  (refused, timed out) mean the server is unreachable or refusing this address: every request then fails at once
  (`UNREACHABLE`) and none goes out for a pause that doubles up to ten minutes. The README tells a wallet with real
  users to run or rent its own Esplora.
- **Incremental, from a JSON snapshot.** The state is the tip, each used address's summary as Esplora counts it, and
  each transaction as the account needs it; `snapshot()` is plain JSON (bigints as strings) for MMKV and the like. A
  sync reads the tip, compares the blocks of the account's confirmed transactions with the best chain (newest first,
  until one agrees) to catch reorganizations, looks up every pending transaction (dropped and replaced ones go), reads
  every address's summary up to the gap limit (20), and reads history only where a summary changed, until the
  transactions add up to it; when they do not, the whole history is read and what the backend no longer lists is
  forgotten. The addresses the app shows are derived again from the key, never read from the snapshot.
- **The adapter plans and writes; the sync combines.** Coin selection is the adapter's (`createTransaction`, largest
  first) over the coins the sync allows (confirmed, and the account's own unconfirmed change); the PSBT is the
  adapter's `createPsbt`, once per key, each input's fields taken from its own key's (BIP-174's combiner, which
  `sync/psbt.ts` is). Fee bumps are payments of the same coins at a higher rate, held to BIP-125's rules. A script type
  is a `ScriptSupport` (an address from a key, a watch-only account of one key): P2WPKH (BIP-84) and Taproot key
  paths (BIP-86), whose watch-only accounts size Taproot inputs and write BIP-371's fields; nothing else in the sync
  knows a script's fields. Taproot has no SLIP-132 prefix, so its account is an xpub or tpub at `m/86'/…` with
  `scriptType: 'p2tr'`, and a snapshot is tied to the type as well as the key.
- **A subpath of the adapter, `@hzblj/crypto-bitcoin/sync`.** It needs the adapter's internals (the PSBT maps, the
  plan's checks) and moves with them, so it ships with them; a separate package would pin one adapter version against
  another for every change. The main entry stays network-free: nothing in it imports `sync/` or calls `fetch` (a test
  holds that), so an app that only signs, or a signer that must never go online, does not load it.

## Consequences

- An app syncs a Bitcoin account in a few lines and keeps it across launches, and the example's hand-written Esplora
  code is gone: its wallet and its watch-only tab run on the sync.
- The backend sees every address of the account, links them, and is trusted for balances and history. The README and
  `SECURITY.md` say so, and recommend running one's own. Previous transactions in a PSBT are checked against their
  coins, so a lying backend cannot misstate the values a signer verifies.
- Esplora has no batch and no push: a sync asks once per address and polls. On a public server, paced, a fresh
  account's first sync takes some 20 seconds; on the app's own, under one. An Electrum backend (one connection,
  scripthash subscriptions) is the next step for large accounts.
- A wallet with keys and network in one package would be simpler to call and harder to audit; this keeps the line
  ADR 0004 drew: keys in the engine, everything else outside it.
