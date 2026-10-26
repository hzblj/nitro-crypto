import {
  type AdapterContext,
  base58,
  CryptoError,
  type Ed25519Key,
  isCryptoError,
  utf8,
} from '@hzblj/nitro-crypto/adapter'

import {addressFromPublicKey, type SolanaAddress, validateAddress} from './address'
import type {SolanaInstruction} from './instructions'
import {decodeMessage} from './message'
import {compileLegacyMessage, type SignedSolanaTransaction, serializeTransaction} from './transaction'

/** Bytes, or text signed as its UTF-8 bytes. */
export type SolanaMessage = string | Uint8Array

/** A 64-byte Ed25519 signature, or its Base58 text as Solana tools print it. */
export type SolanaSignature = Uint8Array | string

export type SolanaCluster = 'mainnet-beta' | 'devnet' | 'testnet'

/**
 * A Solana account whose key the engine holds. `signMessage` signs the message bytes exactly as given, like a
 * wallet's `signMessage`: it is not a transaction signature, and it adds no off-chain message header.
 */
export type SolanaAccount<Id extends string = string> = {
  readonly chain: Id
  readonly cluster: SolanaCluster
  readonly address: SolanaAddress
  /** The Ed25519 public key, 32 bytes. */
  readonly publicKey: Uint8Array
  readonly path: string
  /** The 64-byte Ed25519 signature of the message. */
  readonly signMessage: (request: {readonly message: SolanaMessage}) => Promise<Uint8Array>
  readonly verifyMessage: (request: {
    readonly message: SolanaMessage
    readonly signature: SolanaSignature
  }) => Promise<boolean>
  /**
   * A legacy transaction this account pays for and signs alone: the instructions compiled with the account as fee
   * payer, the message signed, the wire bytes returned. An instruction that needs another signer is refused.
   */
  readonly signTransaction: (request: SolanaTransactionRequest) => Promise<SignedSolanaTransaction>
  /**
   * Signs a compiled legacy message made elsewhere (a watch-only wallet's, received over a QR code, say): the
   * transaction signature, 64 bytes. The message is read first and refused (`INVALID_ARGUMENT`) unless it is a legacy
   * message this account must sign. Show what it does first (`crypto.chains.solana.decodeMessage`).
   */
  readonly signTransactionMessage: (message: Uint8Array) => Promise<Uint8Array>
}

export type SolanaTransactionRequest = {
  /** A blockhash from `getLatestBlockhash`, Base58. */
  readonly recentBlockhash: string
  readonly instructions: readonly SolanaInstruction[]
}

const messageBytes = (message: SolanaMessage) => (typeof message === 'string' ? utf8.encode(message) : message)

const signatureBytes = (signature: SolanaSignature): Uint8Array | undefined => {
  try {
    const bytes = typeof signature === 'string' ? base58.decode(signature) : signature

    return bytes.length === 64 ? bytes : undefined
  } catch (error) {
    if (isCryptoError(error, 'INVALID_ENCODING')) {
      return undefined
    }

    throw error
  }
}

/** Whether `address` signed `message`. A malformed signature is `false`; an address that is not one throws. */
export const verifySigner = (
  context: AdapterContext,
  address: string,
  message: SolanaMessage,
  signature: SolanaSignature
): boolean => {
  const validation = validateAddress(address)

  if (!validation.valid) {
    throw new CryptoError('INVALID_ADDRESS', validation.reason)
  }

  const bytes = signatureBytes(signature)

  if (!bytes) {
    return false
  }

  try {
    return context.ed25519.verify(base58.decode(address), messageBytes(message), bytes)
  } catch (error) {
    // An off-curve address (a program-derived one) has no key to verify with: nothing it "signed" verifies.
    if (isCryptoError(error, 'INVALID_PUBLIC_KEY')) {
      return false
    }

    throw error
  }
}

export const createAccount = <Id extends string>(
  context: AdapterContext,
  chain: Id,
  cluster: SolanaCluster,
  key: Ed25519Key
): SolanaAccount<Id> => {
  const publicKey = key.publicKey()
  const address = addressFromPublicKey(publicKey)

  return Object.freeze({
    address,
    chain,
    cluster,
    path: key.path ?? '',
    publicKey,
    signMessage: async ({message}) => key.sign(messageBytes(message)),
    signTransaction: async ({instructions, recentBlockhash}) => {
      const message = compileLegacyMessage({feePayer: address, instructions, recentBlockhash})
      const others = message.signers.filter(signer => signer !== address)

      if (others.length > 0) {
        throw new CryptoError(
          'INVALID_ARGUMENT',
          `This account signs alone; an instruction also needs ${others.join(', ')}.`
        )
      }

      const signature = key.sign(message.bytes)

      return {serialized: serializeTransaction(message.bytes, [signature]), signature: base58.encode(signature)}
    },
    signTransactionMessage: async (message: Uint8Array) => {
      if (!decodeMessage(message).signers.includes(address)) {
        throw new CryptoError('INVALID_ARGUMENT', 'This account is not among the message`s signers.')
      }

      return key.sign(message)
    },
    verifyMessage: async ({message, signature}) => verifySigner(context, address, message, signature),
  })
}
