# @hzblj/crypto-airgap-ethereum

[![npm](https://img.shields.io/npm/v/@hzblj/crypto-airgap-ethereum.svg)](https://www.npmjs.com/package/@hzblj/crypto-airgap-ethereum)
[![license](https://img.shields.io/npm/l/@hzblj/crypto-airgap-ethereum.svg)](https://github.com/hzblj/nitro-crypto/blob/main/LICENSE)

Ethereum and EVM air-gapped signing for [`@hzblj/crypto-airgap`](https://www.npmjs.com/package/@hzblj/crypto-airgap):
ERC-4527's `eth-sign-request` and `eth-signature`, for EIP-1559 transactions and `personal_sign` messages. Every
answer is checked by recovering its signer with
[`@hzblj/crypto-ethereum`](https://www.npmjs.com/package/@hzblj/crypto-ethereum), on the engine.

```sh
npx expo install @hzblj/crypto-airgap @hzblj/crypto-airgap-ethereum @hzblj/crypto-ethereum @hzblj/nitro-crypto react-native-nitro-modules
```

## The watch-only wallet (online)

```ts
import {createRequestId} from '@hzblj/crypto-airgap'
import {ethereumAirgap} from '@hzblj/crypto-airgap-ethereum'

const airgap = ethereumAirgap(crypto.chains.sepolia)
const account = airgap.watchAccount(key) // {address, path, fingerprint}, from the key the signer shared
airgap.watchAccount(key, undefined, 5) // an account's extended key (m/44'/60'/0'): its sixth address, m/…/0/5

const request = {
  account,
  origin: 'My Wallet',
  requestId: createRequestId(crypto.random), // fresh for every request
  transaction: {to, value, nonce, gas, maxFeePerGas, maxPriorityFeePerGas},
}
show(airgap.encodeSignRequest(request)) // eth-sign-request, data type 4 (a typed transaction)

const answer = airgap.decodeSignResponse(scanned, {request})
if (answer.kind === 'transaction') await rpc('eth_sendRawTransaction', [answer.transaction.serialized])
```

A message goes the same way with `message` in place of `transaction` (data type 3), and comes back as a 65-byte
signature, v as 27 or 28. An answer with another request id, or whose signature recovers to another address than the
account's (a signature by another key, or of another transaction), is `REQUEST_MISMATCH`.

## The signer (offline)

```ts
// Any address of the account (m/44'/60'/0'/0/i), as MetaMask asks: or {account: {address, path, fingerprint}} for one.
const request = airgap.decodeSignRequest(scanned, {fingerprint: wallet.fingerprint, accountPath: "m/44'/60'/0'"})
request.path // m/44'/60'/0'/0/3
request.address // when the request names one, or the account's

if (request.kind === 'transaction') {
  request.transaction // to, value, data, nonce, fees, chainId: parsed from the envelope that will be signed
  request.erc20Transfer // {recipient, amount} when the call data is an ERC-20 transfer
  request.maxFee // gas × maxFeePerGas, in wei
} else {
  request.text // the message as text, when it is readable
}

if (await userConfirms(request)) {
  // The key at request.path signs, once its address is checked against any the request names.
  const answer = await airgap.signRequest(request, path => wallet.deriveAccount({chain: 'ethereum', path}))
  show(airgap.encodeSignResponse(answer))
}
```

A request for another path (outside the account, or a change address), another wallet's fingerprint, another
address or another chain id than the adapter's is `REQUEST_MISMATCH`. The transaction is parsed strictly (canonical RLP, an empty access list, a recipient, this
chain's id), so what is shown is exactly what is signed.

| Data type | Here |
| --- | --- |
| 4, typed transaction | EIP-1559 (type 2) only |
| 3, personal message | Yes |
| 1, legacy transaction | Refused: the Ethereum adapter does not sign them |
| 2, EIP-712 typed data | Refused, for the same reason |

## Pairing

```ts
// What MetaMask's QR hardware wallets and others read, as Keystone and OneKey write it: children 0/*, account.standard.
const path = "m/44'/60'/0'"
const key = airgap.accountKey({extendedKey: wallet.extendedPublicKey(path), fingerprint, name: 'My Wallet', path})
show(toUR(CRYPTO_HDKEY, key))
```

`watchAccount` takes an account's extended key (`m/44'/60'/a'` with a chain code; its addresses below the children
it names, `0/*` unless it names others, derived by the engine's public derivation, ADR 0007) or a key at a full path
(`m/44'/60'/0'/0/0`). `pairingKey(account, fingerprint)` is one address's key, for `crypto-multi-accounts`.

| Interoperability | Evidence |
| --- | --- |
| `eth-sign-request`, `eth-signature` | Byte for byte `@keystonehq/bc-ur-registry-eth` 0.22.1 both ways, as CBOR and as URs. A request its `constructETHRequest` writes is read and answered here. Keystone 3's firmware codec (`keystone-sdk-rust`): its requests and signature read and write back byte for byte. |
| Account keys | Keystone's registry reads `accountKey` as the xpub viem derives, with MetaMask's children and note. Keystone's documented `crypto-hdkey`, a OneKey's, and a Keystone 3 Pro's `crypto-multi-accounts` are watched at the addresses `@scure/bip32` derives. |
| Transactions | Parsed, assembled and recovered as viem does, byte for byte. |
| Hardware wallets, MetaMask | Not tested on a device or in the app. |

**Not in this version:** legacy and EIP-2930 transactions, EIP-712, and batch requests (`eth-batch-sign-request`).

[Documentation](https://github.com/hzblj/nitro-crypto#readme) · [Security](https://github.com/hzblj/nitro-crypto/blob/main/SECURITY.md)
