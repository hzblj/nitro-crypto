import {
  createMultipartDecoder,
  createMultipartEncoder,
  createRequestId,
  type Sha256,
  type UR,
} from '@hzblj/crypto-airgap'
import {bitcoinAirgap} from '@hzblj/crypto-airgap-bitcoin'
import {ethereumAirgap} from '@hzblj/crypto-airgap-ethereum'
import {solanaAirgap} from '@hzblj/crypto-airgap-solana'
// The encodings without the native module, so the loopback runs in the tests too.
import {base58, hex} from '@hzblj/nitro-crypto/adapter'

import type {AppAccount, AppCrypto} from '../crypto'

/** The chains the loopback runs: the three with an air-gap package (TRON has none). */
export const LOOPBACK_CHAINS = ['ethereum', 'bitcoin', 'solana'] as const

export type LoopbackChain = (typeof LOOPBACK_CHAINS)[number]

/** One message's trip between the phones, as a camera that misses every third code would make it. */
export type Transmission = {
  readonly ur: UR
  readonly fragments: number
  /** Codes shown before the reader had the whole message. */
  readonly shown: number
  /** Codes the reader actually read. */
  readonly read: number
}

export type LoopbackRun = {
  readonly chain: LoopbackChain
  readonly request: Transmission
  readonly answer: Transmission
  /** What the signer read from the request, line by line: what it would show before asking. */
  readonly review: readonly {readonly label: string; readonly value: string}[]
  /** What the watch-only side checked the answer against, and what it ends with. */
  readonly verified: readonly {readonly label: string; readonly value: string}[]
  readonly milliseconds: number
}

/** Bytes per part: small, so even a short transaction shows the multipart path. */
const FRAGMENT = 60

/**
 * A UR shown as an animated QR code and read by a camera that misses every third code: the encoder and decoder the
 * two phones would use, with nothing between them but strings.
 */
export const transmit = (ur: UR, allowedTypes: readonly string[], sha256: Sha256): Transmission => {
  const encoder = createMultipartEncoder(ur, {maxFragmentLength: FRAGMENT, sha256})
  const decoder = createMultipartDecoder({allowedTypes, sha256})
  let shown = 0
  let read = 0

  while (!decoder.isComplete()) {
    const part = encoder.nextPart().toUpperCase()
    shown++

    if (shown % 3 !== 2 || encoder.isSinglePart) {
      decoder.receivePart(part)
      read++
    }
  }

  return {fragments: encoder.fragmentCount, read, shown, ur: decoder.result()}
}

type Accounts<Id extends LoopbackChain> = {readonly signer: AppAccount<Id>; readonly recipient: AppAccount<Id>}

const shortHex = (text: string) => (text.length > 20 ? `${text.slice(0, 10)}…${text.slice(-8)}` : text)

const ethereum = async (crypto: AppCrypto, fingerprint: number, {recipient, signer}: Accounts<'ethereum'>) => {
  const airgap = ethereumAirgap(crypto.chains.ethereum)
  const request = {
    account: {address: signer.address, fingerprint, path: signer.path},
    origin: 'Debug loopback',
    requestId: createRequestId(crypto.random),
    transaction: {
      gas: 21_000n,
      maxFeePerGas: 30_000_000_000n,
      maxPriorityFeePerGas: 1_000_000_000n,
      nonce: 0,
      to: recipient.address,
      value: 10_000_000_000_000_000n,
    },
  }
  const sent = transmit(airgap.encodeSignRequest(request), airgap.requestTypes, crypto.hash.sha256)
  const review = airgap.decodeSignRequest(sent.ur, {account: request.account})

  if (review.kind !== 'transaction') {
    throw new Error('The signer read a message, not the transaction sent.')
  }

  const signed = await signer.signTransaction(review.transaction)
  const answer = transmit(
    airgap.encodeSignResponse({requestId: review.requestId, signature: signed.signature}),
    airgap.responseTypes,
    crypto.hash.sha256
  )
  const result = airgap.decodeSignResponse(answer.ur, {request})

  if (result.kind !== 'transaction') {
    throw new Error('The answer is not a transaction.')
  }

  return {
    answer,
    request: sent,
    review: [
      {label: 'To', value: shortHex(review.transaction.to)},
      {label: 'Value', value: '0.01 ETH'},
      {label: 'Chain id', value: String(review.transaction.chainId)},
      {label: 'Request id', value: review.requestId ?? 'None'},
    ],
    verified: [
      {label: 'Request id', value: 'Matches'},
      {label: 'Signer recovered', value: shortHex(signer.address)},
      {label: 'Transaction hash', value: shortHex(result.transaction.hash)},
    ],
  }
}

const bitcoin = async (crypto: AppCrypto, fingerprint: number, {recipient, signer}: Accounts<'bitcoin'>) => {
  const airgap = bitcoinAirgap(crypto.chains.bitcoin)
  const watch = crypto.chains.bitcoin.watchAccount({fingerprint, path: signer.path, publicKey: signer.publicKey})
  // Coins no network has: the loopback never broadcasts, and a signature commits only to what the PSBT says.
  const utxos = [
    {txid: hex.encode(crypto.random(32)), value: 90_000n, vout: 0},
    {txid: hex.encode(crypto.random(32)), value: 60_000n, vout: 1},
  ]
  const psbt = watch.createPsbt(watch.createTransaction({amount: 100_000n, feeRate: 4, to: recipient.address, utxos}))
  const sent = transmit(airgap.encodeSignRequest({psbt}), airgap.requestTypes, crypto.hash.sha256)
  const review = airgap.decodeSignRequest(sent.ur, {account: signer})
  const signed = await signer.signPsbt(review.psbt)
  const answer = transmit(airgap.encodeSignResponse({psbt: signed.psbt}), airgap.responseTypes, crypto.hash.sha256)
  const {transaction} = airgap.decodeSignResponse(answer.ur, {request: psbt})

  return {
    answer,
    request: sent,
    review: [
      {label: 'Sending', value: `${review.sending} sats`},
      {label: 'Fee', value: `${review.fee ?? 0n} sats`},
      {label: 'Coins', value: `${review.inputs.length}, all this account's`},
      {label: 'Warnings', value: review.warnings.join(', ') || 'None'},
    ],
    verified: [
      {label: 'Same transaction', value: shortHex(review.txid)},
      {label: 'Signatures', value: `${review.inputs.length} verified by the engine`},
      {label: 'Ready to broadcast', value: `${transaction.vsize} vB`},
    ],
  }
}

const solana = async (crypto: AppCrypto, fingerprint: number, {recipient, signer}: Accounts<'solana'>) => {
  const airgap = solanaAirgap(crypto.chains.solana)
  const request = {
    account: {address: signer.address, fingerprint, path: signer.path},
    origin: 'Debug loopback',
    requestId: createRequestId(crypto.random),
    transaction: {
      instructions: [
        crypto.chains.solana.instructions.transfer({
          from: signer.address,
          lamports: 100_000_000n,
          to: recipient.address,
        }),
      ],
      recentBlockhash: base58.encode(crypto.random(32)),
    },
  }
  const sent = transmit(airgap.encodeSignRequest(request), airgap.requestTypes, crypto.hash.sha256)
  const review = airgap.decodeSignRequest(sent.ur, {account: request.account})

  if (review.kind !== 'transaction') {
    throw new Error('The signer read a message, not the transaction sent.')
  }

  const signature = await signer.signTransactionMessage(review.message)
  const answer = transmit(
    airgap.encodeSignResponse({requestId: review.requestId, signature}),
    airgap.responseTypes,
    crypto.hash.sha256
  )
  const result = airgap.decodeSignResponse(answer.ur, {request})

  if (result.kind !== 'transaction') {
    throw new Error('The answer is not a transaction.')
  }

  return {
    answer,
    request: sent,
    review: [
      {label: 'Instruction', value: review.decoded.instructions[0]?.summary.type ?? 'None'},
      {label: 'Sending', value: '0.1 SOL'},
      {label: 'Fee payer', value: shortHex(review.decoded.feePayer)},
      {label: 'Warnings', value: review.warnings.join(', ') || 'None'},
    ],
    verified: [
      {label: 'Request id', value: 'Matches'},
      {label: 'Signature', value: 'Verified by the engine'},
      {label: 'Transaction id', value: shortHex(result.transaction.signature)},
    ],
  }
}

/**
 * Both sides of air-gapped signing in one process, with the demo wallet's keys: the watch-only side builds a request,
 * it travels as QR parts to the signer, which reads, checks and signs it, and the answer travels back to be checked.
 * Nothing is broadcast, and nothing is mocked but the camera.
 */
export const runLoopback = async (
  crypto: AppCrypto,
  chain: LoopbackChain,
  fingerprint: number,
  account: <Id extends LoopbackChain>(chain: Id, n: number) => Promise<AppAccount<Id>>
): Promise<LoopbackRun> => {
  const started = Date.now()
  const run =
    chain === 'ethereum'
      ? await ethereum(crypto, fingerprint, {
          recipient: await account('ethereum', 1),
          signer: await account('ethereum', 0),
        })
      : chain === 'bitcoin'
        ? await bitcoin(crypto, fingerprint, {
            recipient: await account('bitcoin', 1),
            signer: await account('bitcoin', 0),
          })
        : await solana(crypto, fingerprint, {recipient: await account('solana', 1), signer: await account('solana', 0)})

  return {...run, chain, milliseconds: Date.now() - started}
}
