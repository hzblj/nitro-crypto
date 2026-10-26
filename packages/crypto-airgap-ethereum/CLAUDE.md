# @hzblj/crypto-airgap-ethereum

Ethereum's air-gap types and adapter: ERC-4527 `eth-sign-request` and `eth-signature`, for EIP-1559 transactions and
personal messages. Parity: `@keystonehq/bc-ur-registry-eth`, viem.

TypeScript over `@hzblj/crypto-airgap` (a dependency) and the chain client of `@hzblj/crypto-ethereum` (a dependency for
its types: the client itself is passed to `ethereumAirgap(chain)`). `@hzblj/nitro-crypto` is a peer, as everywhere: one
native module per app. A dependency rather than a peer so that a minor release of the chain package does not force a
major one here (changesets' rule for peers). It imports no native code and no other chain: decoding, signing and
verification are the chain's and the engine's; this package packages, correlates and checks.

| Path | What it is |
| --- | --- |
| `src/types.ts` | The UR types, `defineURType` over the core's schema readers. `fromCbor` checks every field. |
| `src/airgap.ts` | `ethereumAirgap(chain)`: the requester side (`encodeSignRequest`, `decodeSignResponse`), the responder side (`decodeSignRequest` for one account or every address of one, `signRequest`, `encodeSignResponse`), `watchAccount` (single keys and account keys), `pairingKey`, `accountKey`. |
| `src/version.ts` | `VERSION`, synced from package.json by `scripts/sync-versions.mjs`; a test holds them equal. |
| `test/` | Parity with the independent registry, both sides of a signing round trip through lossy multipart, and every mismatch. `vectors/hardware.json`: Keystone's and OneKey's own payloads, with their sources. |

## Rules

- **A response is checked against its request, never trusted for arriving:** the request id, then the signer recovered
  by the engine and compared with the account. Anything else is `REQUEST_MISMATCH`.
- **A request is checked against the signer's account** (path, fingerprint, address, chain id) before anything is shown,
  and decoding is never consent.
- **Chain errors become protocol errors:** a `CryptoError` from the chain on scanned bytes is rethrown as
  `INVALID_PROTOCOL_DATA`, with the original as its `cause`.

Docs copy has no em dashes.
