# @hzblj/crypto-airgap-solana

[![npm](https://img.shields.io/npm/v/@hzblj/crypto-airgap-solana.svg)](https://www.npmjs.com/package/@hzblj/crypto-airgap-solana)
[![license](https://img.shields.io/npm/l/@hzblj/crypto-airgap-solana.svg)](https://github.com/hzblj/nitro-crypto/blob/main/LICENSE)

Solana air-gapped signing for [`@hzblj/crypto-airgap`](https://www.npmjs.com/package/@hzblj/crypto-airgap):
`sol-sign-request` and `sol-signature` (Keystone's registry, the schema OneKey documents too), for legacy
transactions and messages. Every answer is verified against its signer by
[`@hzblj/crypto-solana`](https://www.npmjs.com/package/@hzblj/crypto-solana), on the engine.

```sh
npx expo install @hzblj/crypto-airgap @hzblj/crypto-airgap-solana @hzblj/crypto-solana @hzblj/nitro-crypto react-native-nitro-modules
```

## The watch-only wallet (online)

```ts
import {createRequestId} from '@hzblj/crypto-airgap'
import {solanaAirgap} from '@hzblj/crypto-airgap-solana'

const airgap = solanaAirgap(crypto.chains.solana)
const account = airgap.watchAccount(key) // {address, path, fingerprint}

const request = {
  account,
  requestId: createRequestId(crypto.random),
  transaction: {instructions: [crypto.chains.solana.instructions.transfer({from: account.address, lamports, to})], recentBlockhash},
}
show(airgap.encodeSignRequest(request)) // the compiled message, with the account as fee payer

const answer = airgap.decodeSignResponse(scanned, {request})
if (answer.kind === 'transaction') await rpc('sendTransaction', [base64(answer.transaction.serialized), {encoding: 'base64'}])
```

The answer's signature is verified by the engine over the message before the transaction is assembled: one by
another key, or of another message, is `REQUEST_MISMATCH`, as is an answer to another request id.

## The signer (offline)

```ts
const request = airgap.decodeSignRequest(scanned, {account: {address, path, fingerprint}})

if (request.kind === 'transaction') {
  request.decoded.instructions // each with a summary: transfer, token-transfer, create-token-account, compute budget, unknown
  request.lamports // what the account's own transfers send
  request.warnings // ['UNKNOWN_INSTRUCTIONS', 'NOT_FEE_PAYER', 'OTHER_SIGNERS']
  const signature = await account.signTransactionMessage(request.message)
  show(airgap.encodeSignResponse({requestId: request.requestId, signature}))
}
```

A transaction this account is not a signer of, or a request for another path, wallet or address, is
`REQUEST_MISMATCH`. A "message" whose bytes are a transaction this account would sign is refused
(`INVALID_PROTOCOL_DATA`): it is a transaction in disguise.

| Interoperability | Evidence |
| --- | --- |
| `sol-sign-request`, `sol-signature` | Byte for byte `@keystonehq/bc-ur-registry-sol` 0.9.5 both ways, for transactions and messages, as CBOR and as URs. |
| Messages | Decoded as `@solana/kit` decodes them, and compiled back to the same bytes. |
| Keystone 3 (firmware codec) | `keystone-sdk-rust`'s own payloads: its `sol-sign-request` (a 0.1 SOL transfer) and `sol-signature` byte for byte, the transfer shown to its fee payer; its `crypto-multi-accounts` watched account by account. |
| Hardware wallets, Solflare, Backpack | Not tested on a device or in the app. Solana keys (SLIP-0010, hardened only) have no extended public key: they pair one account at a time. |

**Not in this version:** versioned (v0) transactions and lookup tables, requests for transactions with several signers,
off-chain message signing (its `\xffsolana offchain` header), and pairing types other than `crypto-hdkey` and
`crypto-multi-accounts`.

[Documentation](https://github.com/hzblj/nitro-crypto#readme) · [Security](https://github.com/hzblj/nitro-crypto/blob/main/SECURITY.md)
