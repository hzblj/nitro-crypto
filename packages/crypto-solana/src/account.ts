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
import {decodeMessage, decodeTransaction} from './message'
import {offchainMessageBytes, type SignedSolanaOffchainMessage, type SolanaOffchainMessage} from './offchain'
import {
  compileMessage,
  type PartiallySignedSolanaTransaction,
  type SignedSolanaTransaction,
  type SolanaAddressLookupTables,
  type SolanaMessageVersion,
  serializeTransaction,
} from './transaction'

/** Bytes, or text signed as its UTF-8 bytes. */
export type SolanaMessage = string | Uint8Array

/** A 64-byte Ed25519 signature, or its Base58 text as Solana tools print it. */
export type SolanaSignature = Uint8Array | string

export type SolanaCluster = 'mainnet-beta' | 'devnet' | 'testnet'

/**
 * A Solana account whose key the engine holds. `signMessage` signs the message bytes exactly as given, as a wallet's
 * `signMessage` does for Phantom's API and Sign In With Solana; `signOffchainMessage` signs Solana's off-chain message
 * format instead, whose header no transaction can start with.
 */
export type SolanaAccount<Id extends string = string> = {
  readonly chain: Id
  readonly cluster: SolanaCluster
  readonly address: SolanaAddress
  /** The Ed25519 public key, 32 bytes. */
  readonly publicKey: Uint8Array
  readonly path: string
  /**
   * The 64-byte Ed25519 signature of the message bytes, exactly as given: no prefix and no header, as dApps calling a
   * wallet's `signMessage` (Sign In With Solana among them) expect. Show the text before signing it.
   */
  readonly signMessage: (request: {readonly message: SolanaMessage}) => Promise<Uint8Array>
  readonly verifyMessage: (request: {
    readonly message: SolanaMessage
    readonly signature: SolanaSignature
  }) => Promise<boolean>
  /**
   * Signs an off-chain message (version 0 or 1), given as its fields or as the bytes a dApp sent: the bytes are read
   * first, and refused (`INVALID_ARGUMENT`) unless they are an off-chain message naming this account as a signer.
   * Returns the encoded message and this account's signature of it, as @solana/kit's signers make it.
   */
  readonly signOffchainMessage: (message: SolanaOffchainMessage | Uint8Array) => Promise<SignedSolanaOffchainMessage>
  /**
   * A transaction this account pays for and signs alone: the instructions compiled with the account as fee payer
   * (a legacy message, or v0 with its lookup tables), the message signed, the wire bytes returned. An instruction
   * that needs another signer is refused, and so is a transaction over 1232 bytes.
   */
  readonly signTransaction: (request: SolanaTransactionRequest) => Promise<SignedSolanaTransaction>
  /**
   * Signs a compiled message (legacy or v0) made elsewhere (a watch-only wallet's, received over a QR code, say): the
   * transaction signature, 64 bytes. The message is read first and refused (`INVALID_ARGUMENT`) unless this account
   * must sign it. Show what it does first (`crypto.chains.solana.decodeMessage`).
   */
  readonly signTransactionMessage: (message: Uint8Array) => Promise<Uint8Array>
  /**
   * Signs this account's slot of a wire transaction (legacy or v0) that others build and sign too: what a dApp hands
   * a wallet's `signTransaction`. Every other slot is kept as it is, signed or not. Refused (`INVALID_ARGUMENT`)
   * unless the transaction reads strictly and this account is among its signers. Show what it does first
   * (`crypto.chains.solana.decodeTransaction`).
   */
  readonly partiallySignTransaction: (transaction: Uint8Array) => Promise<PartiallySignedSolanaTransaction>
}

export type SolanaTransactionRequest = {
  /** A blockhash from `getLatestBlockhash`, Base58. */
  readonly recentBlockhash: string
  readonly instructions: readonly SolanaInstruction[]
  /** `'legacy'` unless stated; `0` for a versioned transaction. */
  readonly version?: SolanaMessageVersion
  /** For a v0 transaction: lookup tables to load accounts from (`compileMessage` explains which). */
  readonly addressLookupTables?: SolanaAddressLookupTables
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

const EMPTY_SIGNATURE = new Uint8Array(64)

export const createAccount = <Id extends string>(
  context: AdapterContext,
  chain: Id,
  cluster: SolanaCluster,
  key: Ed25519Key
): SolanaAccount<Id> => {
  const publicKey = key.publicKey()
  const address = addressFromPublicKey(publicKey)
  const notASigner = (what: string) => new CryptoError('INVALID_ARGUMENT', `This account is not among the ${what}.`)

  return Object.freeze({
    address,
    chain,
    cluster,
    partiallySignTransaction: async (transaction: Uint8Array) => {
      const decoded = decodeTransaction(transaction)
      const slot = decoded.signers.indexOf(address)

      if (slot < 0) {
        throw notASigner('transaction`s signers')
      }

      const signature = key.sign(decoded.message)
      const signatures = decoded.signatures.map((existing, index) => (index === slot ? signature : existing))
      const payer = signatures[0]

      return Object.freeze({
        complete: signatures.every(existing => existing !== undefined),
        serialized: serializeTransaction(
          decoded.message,
          signatures.map(existing => existing ?? EMPTY_SIGNATURE)
        ),
        signature: payer && base58.encode(payer),
      })
    },
    path: key.path ?? '',
    publicKey,
    signMessage: async ({message}) => key.sign(messageBytes(message)),
    signOffchainMessage: async (message: SolanaOffchainMessage | Uint8Array) => {
      const {bytes, signers} = offchainMessageBytes(message)

      if (!signers.includes(address)) {
        throw notASigner('off-chain message`s signers')
      }

      return Object.freeze({message: bytes, signature: key.sign(bytes)})
    },
    signTransaction: async ({addressLookupTables, instructions, recentBlockhash, version}) => {
      const message = compileMessage({addressLookupTables, feePayer: address, instructions, recentBlockhash, version})
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
        throw notASigner('message`s signers')
      }

      return key.sign(message)
    },
    verifyMessage: async ({message, signature}) => verifySigner(context, address, message, signature),
  })
}
