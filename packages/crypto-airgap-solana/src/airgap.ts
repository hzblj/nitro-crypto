import {
  AirgapError,
  type AirgapRequester,
  type AirgapResponder,
  formatKeypath,
  fromUR,
  type HDKey,
  parseKeypath,
  type RequestId,
  toUR,
  type UR,
} from '@hzblj/crypto-airgap'
import type {
  DecodedSolanaMessage,
  SignedSolanaTransaction,
  SolanaAddress,
  SolanaChain,
  SolanaInstruction,
} from '@hzblj/crypto-solana'
import {base58, bytes, isCryptoError, utf8} from '@hzblj/nitro-crypto/adapter'

import {SOL_SIGN_REQUEST, SOL_SIGNATURE, type SolSignRequest} from './types'

/** An account by its address and where its key is: all a watch-only wallet knows, and all a request names. */
export type SolanaAirgapAccount = {
  readonly address: SolanaAddress
  /** `m/44'/501'/0'/0'`. */
  readonly path: string
  /** The BIP-32 fingerprint of the signer's master key. */
  readonly fingerprint: number
}

/**
 * What a watch-only wallet asks to be signed: a legacy transaction the account pays for and signs alone (its
 * instructions and a recent blockhash, compiled here with the account as fee payer), or a message.
 */
export type SolanaAirgapRequest = {
  /** A fresh id per request (`createRequestId`): the answer must repeat it. */
  readonly requestId: RequestId
  readonly account: SolanaAirgapAccount
  readonly origin?: string
} & (
  | {readonly transaction: {readonly instructions: readonly SolanaInstruction[]; readonly recentBlockhash: string}}
  | {readonly message: Uint8Array | string}
)

/** The answer, checked: a transaction ready to send, or a message signature, each verified for the account asked. */
export type SolanaAirgapResponse =
  | {readonly kind: 'transaction'; readonly transaction: SignedSolanaTransaction}
  | {readonly kind: 'message'; readonly signature: Uint8Array}

/**
 * Something a signer should say before it signs:
 * - `UNKNOWN_INSTRUCTIONS`: an instruction calls a program, or does a thing, this package does not describe.
 * - `NOT_FEE_PAYER`: the account signs, but another account pays the fee.
 * - `OTHER_SIGNERS`: other accounts must sign too, which this signer cannot do for them.
 */
export type SolanaSignWarning = 'UNKNOWN_INSTRUCTIONS' | 'NOT_FEE_PAYER' | 'OTHER_SIGNERS'

/** A request as the signer reads it: everything to show before asking whether to sign. */
export type SolanaSignRequest = {readonly requestId?: RequestId; readonly origin?: string} & (
  | {
      readonly kind: 'transaction'
      /** The compiled message: the bytes that are signed. */
      readonly message: Uint8Array
      readonly decoded: DecodedSolanaMessage
      /** Lamports the account's own transfers send (fees and rent not included). */
      readonly lamports: bigint
      readonly warnings: readonly SolanaSignWarning[]
    }
  | {
      readonly kind: 'message'
      readonly message: Uint8Array
      /** The message as text, when it is UTF-8 without control characters: what to show. */
      readonly text?: string
    }
)

/** The signer's context: the account it signs as. */
export type SolanaSignContext = {readonly account: SolanaAirgapAccount}

/** The signer's answer: the 64-byte signature (`signTransactionMessage` for a transaction, `signMessage` for a message). */
export type SolanaSignature = {readonly requestId?: RequestId; readonly signature: Uint8Array}

export type SolanaAirgap = AirgapRequester<
  SolanaAirgapRequest,
  SolanaAirgapResponse,
  {readonly request: SolanaAirgapRequest}
> &
  AirgapResponder<SolanaSignRequest, SolanaSignContext, SolanaSignature> & {
    /** A key shared by a signer (from `crypto-multi-accounts`, or a `crypto-hdkey`) as an account to ask for signatures. */
    readonly watchAccount: (key: HDKey, masterFingerprint?: number) => SolanaAirgapAccount
    /** An account's public key as a signer shares it: 32 bytes of Ed25519, with its path and the wallet's fingerprint. */
    readonly pairingKey: (
      account: {readonly publicKey: Uint8Array; readonly path: string},
      fingerprint: number
    ) => HDKey
  }

const BIP44 = 44 + 0x80000000
const SOLANA = 501 + 0x80000000

const mismatch = (message: string) => new AirgapError('REQUEST_MISMATCH', message)

/** A chain's verdict on bytes from outside, as the protocol's error: the cause keeps the chain's own. */
const fromChain = <T>(run: () => T, message: string): T => {
  try {
    return run()
  } catch (error) {
    if (isCryptoError(error)) {
      throw new AirgapError('INVALID_PROTOCOL_DATA', `${message} ${error.message}`, {cause: error})
    }

    throw error
  }
}

const messageBytes = (message: Uint8Array | string) => (typeof message === 'string' ? utf8.encode(message) : message)

/** Text worth showing as text: valid UTF-8 that decodes back to the same bytes, without control characters. */
const readableText = (message: Uint8Array): string | undefined => {
  const text = utf8.decode(message)

  // biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are exactly what this looks for.
  return bytes.equal(utf8.encode(text), message) && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text)
    ? text
    : undefined
}

/**
 * Air-gapped signing for Solana, bound to a chain (`crypto.chains.solana`): Keystone's `sol-sign-request` and
 * `sol-signature`, for legacy transactions the account pays for and for messages. Versioned transactions are refused,
 * as the Solana adapter does not read them. Nothing here signs or verifies by itself: the chain decodes and verifies,
 * the engine signs.
 */
export const solanaAirgap = (chain: SolanaChain<string>): SolanaAirgap => {
  const watchAccount = (key: HDKey, masterFingerprint?: number): SolanaAirgapAccount => {
    const fingerprint = key.origin?.sourceFingerprint ?? masterFingerprint
    const components = key.origin?.components ?? []

    if (key.keyData.length !== 32) {
      throw new AirgapError('INVALID_PROTOCOL_DATA', 'A Solana key is a 32-byte Ed25519 public key.')
    }

    if (fingerprint === undefined || !key.origin) {
      throw new AirgapError('INVALID_PROTOCOL_DATA', 'A key to sign with says which wallet and path it is from.')
    }

    const indexes = components.map(step => ('index' in step && step.hardened ? step.index + 0x80000000 : Number.NaN))

    if (indexes[0] !== BIP44 || indexes[1] !== SOLANA || (key.useInfo && key.useInfo.type !== 501)) {
      throw mismatch("This key is not a Solana key (m/44'/501'/…).")
    }

    if (indexes.length < 3 || indexes.some(Number.isNaN)) {
      throw new AirgapError('INVALID_PROTOCOL_DATA', 'A Solana key`s path is hardened indexes only (SLIP-0010).')
    }

    return Object.freeze({
      address: chain.addressFromPublicKey(key.keyData),
      fingerprint,
      path: formatKeypath(key.origin),
    })
  }

  const compile = (request: Extract<SolanaAirgapRequest, {readonly transaction: unknown}>) => {
    const {instructions, recentBlockhash} = request.transaction
    const message = fromChain(
      () => chain.compileMessage({feePayer: request.account.address, instructions, recentBlockhash}),
      'The transaction is not one to sign.'
    )

    if (chain.decodeMessage(message).signers.length !== 1) {
      throw new AirgapError('INVALID_ARGUMENT', 'An air-gapped transaction is signed by its fee payer alone.')
    }

    return message
  }

  const signRequestOf = (request: SolanaAirgapRequest): SolSignRequest => {
    const base = {
      address: base58.decode(request.account.address),
      derivationPath: parseKeypath(request.account.path, request.account.fingerprint),
      origin: request.origin,
      requestId: request.requestId,
    }

    return 'transaction' in request
      ? {...base, signData: compile(request), signType: 'transaction'}
      : {...base, signData: messageBytes(request.message), signType: 'message'}
  }

  return Object.freeze({
    chain: 'solana',
    decodeSignRequest: (ur: UR, {account}: SolanaSignContext): SolanaSignRequest => {
      const request = fromUR(SOL_SIGN_REQUEST, ur)
      const common = {origin: request.origin, requestId: request.requestId}

      if (formatKeypath(request.derivationPath) !== account.path) {
        throw mismatch('The request is for another key than this account`s.')
      }

      const source = request.derivationPath.sourceFingerprint

      if (source !== undefined && source !== account.fingerprint) {
        throw mismatch('The request is for another wallet than this one.')
      }

      if (request.address && !bytes.equal(request.address, base58.decode(account.address))) {
        throw mismatch('The request names another address than this account`s.')
      }

      let decoded: DecodedSolanaMessage | undefined

      try {
        decoded = chain.decodeMessage(request.signData)
      } catch (error) {
        if (!isCryptoError(error) || request.signType === 'transaction') {
          throw isCryptoError(error)
            ? new AirgapError('INVALID_PROTOCOL_DATA', `The transaction is not one to sign. ${error.message}`, {
                cause: error,
              })
            : error
        }
      }

      if (request.signType === 'message') {
        // A "message" that is a transaction this account would sign is a transaction in disguise.
        if (decoded?.signers.includes(account.address)) {
          throw new AirgapError('INVALID_PROTOCOL_DATA', 'The message is a transaction: it is refused as a message.')
        }

        const text = readableText(request.signData)

        return Object.freeze({
          ...common,
          kind: 'message',
          message: request.signData,
          ...(text === undefined ? {} : {text}),
        })
      }

      if (!decoded?.signers.includes(account.address)) {
        throw mismatch('This account is not among the transaction`s signers.')
      }

      const warnings: SolanaSignWarning[] = []

      if (decoded.instructions.some(instruction => instruction.summary.type === 'unknown')) {
        warnings.push('UNKNOWN_INSTRUCTIONS')
      }

      if (decoded.feePayer !== account.address) {
        warnings.push('NOT_FEE_PAYER')
      }

      if (decoded.signers.length > 1) {
        warnings.push('OTHER_SIGNERS')
      }

      const lamports = decoded.instructions.reduce(
        (total, {summary}) =>
          summary.type === 'transfer' && summary.from === account.address ? total + summary.lamports : total,
        0n
      )

      return Object.freeze({
        ...common,
        decoded,
        kind: 'transaction',
        lamports,
        message: request.signData,
        warnings: Object.freeze(warnings),
      })
    },
    decodeSignResponse: (ur: UR, {request}: {readonly request: SolanaAirgapRequest}): SolanaAirgapResponse => {
      const answer = fromUR(SOL_SIGNATURE, ur)

      if (answer.requestId !== request.requestId) {
        throw mismatch('The signature answers another request than this one.')
      }

      if ('message' in request) {
        const valid = chain.verifyMessage({
          address: request.account.address,
          message: messageBytes(request.message),
          signature: answer.signature,
        })

        if (!valid) {
          throw mismatch('The message signature is not by the account asked.')
        }

        return Object.freeze({kind: 'message', signature: answer.signature})
      }

      const message = compile(request)

      try {
        return Object.freeze({
          kind: 'transaction',
          transaction: chain.assembleTransaction({message, signatures: [answer.signature]}),
        })
      } catch (error) {
        if (isCryptoError(error, 'INVALID_SIGNATURE')) {
          throw new AirgapError(
            'REQUEST_MISMATCH',
            'The signature is not by the account asked, or not of this transaction.',
            {
              cause: error,
            }
          )
        }

        throw error
      }
    },
    encodeSignRequest: (request: SolanaAirgapRequest) => toUR(SOL_SIGN_REQUEST, signRequestOf(request)),
    encodeSignResponse: ({requestId, signature}: SolanaSignature) => toUR(SOL_SIGNATURE, {requestId, signature}),
    pairingKey: ({path, publicKey}, fingerprint) => {
      if (publicKey.length !== 32) {
        throw new AirgapError('INVALID_ARGUMENT', 'A Solana public key is 32 bytes.')
      }

      return {keyData: publicKey.slice(), origin: parseKeypath(path, fingerprint), useInfo: {network: 0, type: 501}}
    },
    requestTypes: Object.freeze(['sol-sign-request']),
    responseTypes: Object.freeze(['sol-signature']),
    watchAccount,
  })
}
