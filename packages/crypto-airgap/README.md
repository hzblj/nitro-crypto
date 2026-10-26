# @hzblj/crypto-airgap

[![npm](https://img.shields.io/npm/v/@hzblj/crypto-airgap.svg)](https://www.npmjs.com/package/@hzblj/crypto-airgap)
[![license](https://img.shields.io/npm/l/@hzblj/crypto-airgap.svg)](https://github.com/hzblj/nitro-crypto/blob/main/LICENSE)

Air-gapped signing as data: the **payload protocol** a watch-only wallet and an offline signer (a hardware wallet,
or a second phone with no network) exchange as QR codes. Uniform Resources (BC-UR v2) with Bytewords and their
checksums, deterministic CBOR, fountain-coded multipart transport, a typed registry, and the public account types.
Pure TypeScript with no dependencies; it runs in Node and in React Native alike. The one cryptographic function it
needs, SHA-256 (the fountain code seeds its generator with it, over public data), is the caller's: in an app, the
`@hzblj/nitro-crypto` engine's `crypto.hash.sha256`, so the app keeps one SHA-256 and this package installs alone.

```sh
npm install @hzblj/crypto-airgap
```

<p>
  <img alt="Pairing: the wallet's Ethereum account key as MetaMask reads it, an animated QR code" height="480" src="https://raw.githubusercontent.com/hzblj/nitro-crypto/main/media/ios-airgap-pair.png" />
  <img alt="A request for the account's fourth address as MetaMask sends one, read from the bytes to be signed: amount, recipient, fee, chain id, nonce and the key that signs" height="480" src="https://raw.githubusercontent.com/hzblj/nitro-crypto/main/media/ios-airgap-review.png" />
  <img alt="The signature, as a QR code for the watch-only wallet to scan back" height="480" src="https://raw.githubusercontent.com/hzblj/nitro-crypto/main/media/ios-airgap-signed.png" />
</p>

The example wallet as an offline signer: its account key for MetaMask, a request as MetaMask sends one, the signature.

It is the protocol and nothing around it. These are the app's, and stay out of this package:

| Not here | Whose |
| --- | --- |
| Drawing a QR code, scanning one, the camera and its permission | The app (the example uses `qrcode-generator` and `expo-camera`) |
| When to show the next part of an animated QR | The app's timer: it calls `nextPart()` |
| Keys: generating, storing, signing | `@hzblj/nitro-crypto` and its engine |
| What a transaction is, and checking its signature | The chain adapters, through `@hzblj/crypto-airgap-bitcoin`, `-ethereum` and `-solana` |
| Broadcasting, fees, nonces, balances | The app's network code |

## A UR, whole or in parts

```ts
import {createMultipartDecoder, createMultipartEncoder, decodeUR, encodeUR} from '@hzblj/crypto-airgap'

const text = encodeUR({type: 'crypto-psbt', cbor}) // "ur:crypto-psbt/hdosjo…", lowercase
qr.show(text.toUpperCase()) // uppercase makes a smaller QR code (its alphanumeric mode)

const ur = decodeUR(scanned, {allowedTypes: ['crypto-psbt']}) // {type, cbor}
```

A payload too large for one code goes out in parts. The encoder is a function the app calls; it holds no timer:

```ts
const {sha256} = crypto.hash // the engine's; any SHA-256 of bytes to 32 bytes will do, as in Node's tests
const sender = createMultipartEncoder(ur, {maxFragmentLength: 200, sha256})
sender.fragmentCount // 1 when it fits one code: then every call returns the same single-part UR
setInterval(() => qr.show(sender.nextPart().toUpperCase()), 200) // the app's own animation

const receiver = createMultipartDecoder({allowedTypes: ['crypto-psbt'], maxMessageBytes: 1_000_000, sha256})
camera.onScan(text => {
  receiver.receivePart(text) // any order, duplicates, a single-part UR too
  progress.set(receiver.progress.fraction) // recovered fragments over expected
  if (receiver.isComplete()) done(receiver.result())
})
receiver.reset() // to read another, or to forget this one
```

After the first `fragmentCount` parts, each part mixes several fragments (fountain codes): a receiver that missed
some catches up from any of the parts after them, so a camera that reads every third frame still completes. Parts
are byte-for-byte those of the reference implementation (Blockchain Commons' bc-ur) and of `@ngraveio/bc-ur`, and
each implementation reads the other's.

## Typed values

A UR's CBOR is a value of its type. Types are defined with `defineURType` and read with `fromUR`, or several at once
with a registry, which decodes to a union discriminated by `type`:

```ts
import {CRYPTO_HDKEY, CRYPTO_MULTI_ACCOUNTS, createURRegistry, fromUR, toUR} from '@hzblj/crypto-airgap'

const accounts = fromUR(CRYPTO_MULTI_ACCOUNTS, ur) // {masterFingerprint, keys: HDKey[], device?}
const registry = createURRegistry([CRYPTO_HDKEY, CRYPTO_MULTI_ACCOUNTS])
const decoder = createMultipartDecoder({allowedTypes: registry.types, sha256})
const scanned = registry.decode(decoder.result())
if (scanned.type === 'crypto-hdkey') scanned.value.keyData // typed by the branch
```

| Type | Tag | What |
| --- | --- | --- |
| `crypto-hdkey` | 303 | A public key, extended (with its chain code) or single, its origin and children paths, coin info, names |
| `crypto-keypath` | 304 | A derivation path and the fingerprint of the key it starts from; `parseKeypath`, `formatKeypath` |
| `crypto-coin-info` | 305 | SLIP-44 coin type and network |
| `crypto-eckey` | 306 | A single public key |
| `crypto-multi-accounts` | 1103 | One signer's accounts on several chains (Keystone's registry) |
| Request ids | `#6.37` | `createRequestId(random)`: a UUID from the random bytes the app passes, `readRequestId`, `writeRequestId` |

The chain packages add theirs: `crypto-psbt`, `crypto-output` and `crypto-account` (Bitcoin), `eth-sign-request` and
`eth-signature` (ERC-4527), `sol-sign-request` and `sol-signature`. A new chain is a new package of types and an
adapter; nothing here changes. `AirgapRequester` and `AirgapResponder` are the shape each chain's adapter takes.

## Hostile input

Everything scanned is treated as hostile, and refused before it costs much:

- **Allowlists, always.** Every decoder takes the types it accepts; any other is `UNSUPPORTED_UR_TYPE`. Seed and
  private key types (`crypto-seed`, `crypto-bip39`, `crypto-sskr` and the rest) are `PRIVATE_KEY_MATERIAL` whatever
  the list says, and so is a master or private `crypto-hdkey`, a private `crypto-eckey`, or key data that is a
  private key's.
- **Bounds.** Message size (1 MB by default), fragment count (2,048), parts per message (10,000), pending mixed parts
  (512), CBOR nesting (16) and items (100,000). A length is checked against the bytes left before anything is
  allocated.
- **Strict CBOR.** Definite lengths only, no floats, no simple values but booleans, null and undefined, strict UTF-8,
  no repeated map keys, nothing after the item.
- **Sessions.** A part of another message (another type, length, checksum or fragment size) is `SESSION_MISMATCH`, and
  the decoder keeps what it had. A message whose fragments do not produce its checksum is `INVALID_UR`.
- **Errors without data.** An `AirgapError` has a stable `code` and a message that never quotes the input: no PSBT,
  key or signature reaches a log through one. Nothing here logs anything.

A checksum protects against misreading, not against forgery: a UR that decodes is not therefore trustworthy. Whether a
response answers its request, and is signed by the right key, is the chain adapters' check.

| Code | When |
| --- | --- |
| `INVALID_UR` | Not a UR: scheme, type, sequence, Bytewords, or a checksum (of the text or of a reassembled message) |
| `UNSUPPORTED_UR_TYPE` | A type the caller did not allow |
| `INVALID_CBOR` | Malformed, indefinite-length or float CBOR |
| `PAYLOAD_TOO_LARGE` | Past a configured limit |
| `SESSION_MISMATCH` | A part of another message |
| `REQUEST_MISMATCH` | A response that does not answer its request (the chain packages) |
| `INVALID_PROTOCOL_DATA` | Valid CBOR that breaks its type's schema |
| `PRIVATE_KEY_MATERIAL` | A seed or private key |
| `INVALID_ARGUMENT` | A caller's mistake: a limit, a fragment length, a value that cannot be written |

**Not in this version:** the newer BC-UR type names (`psbt`, `hdkey` and their 40000-range tags), Gordian Envelope,
output descriptors as text, and anything that carries a secret.

[Documentation](https://github.com/hzblj/nitro-crypto#readme) · [Security](https://github.com/hzblj/nitro-crypto/blob/main/SECURITY.md)
