# @hzblj/crypto-airgap-bitcoin

Bitcoin's air-gap types and adapter: `crypto-psbt` both ways, `crypto-output` and `crypto-account` for accounts. Parity:
BCR-2020-015's example, `@keystonehq/bc-ur-registry`, `@scure/btc-signer` through crypto-bitcoin.

TypeScript over `@hzblj/crypto-airgap` (a dependency) and the chain client of `@hzblj/crypto-bitcoin` (a dependency for
its types: the client itself is passed to `bitcoinAirgap(chain)`). `@hzblj/nitro-crypto` is a peer, as everywhere: one
native module per app. A dependency rather than a peer so that a minor release of the chain package does not force a
major one here (changesets' rule for peers). It imports no native code and no other chain: decoding, signing and
verification are the chain's and the engine's; this package packages, correlates and checks.

| Path | What it is |
| --- | --- |
| `src/types.ts` | The UR types, `defineURType` over the core's schema readers. `fromCbor` checks every field. |
| `src/airgap.ts` | `bitcoinAirgap(chain)`: the requester side (`encodeSignRequest`, `decodeSignResponse`), the responder side (`decodeSignRequest` for one account or every address of one, `signRequest`, `encodeSignResponse`), `watchAccount` (single keys and account keys), `pairingKey`, `accountKey`, `encodeAccount`, `decodeAccount`. |
| `src/version.ts` | `VERSION`, synced from package.json by `scripts/sync-versions.mjs`; a test holds them equal. |
| `test/` | Parity with the independent registry, both sides of a signing round trip through lossy multipart, and every mismatch. `vectors/`: BCR-2020-015's example, Keystone's firmware codec. |

## Rules

- **A response is checked against its request, never trusted for arriving:** the same unsigned transaction and coins
  (else `REQUEST_MISMATCH`), then every signature verified by the engine as the chain finalizes (else
  `INVALID_PROTOCOL_DATA`).
- **A request is checked against the signer's account** (path, fingerprint, address, coins) before anything is shown,
  and decoding is never consent.
- **Chain errors become protocol errors:** a `CryptoError` from the chain on scanned bytes is rethrown as
  `INVALID_PROTOCOL_DATA`, with the original as its `cause`.

Docs copy has no em dashes.
