import {
  type AdapterContext,
  base58,
  type ChainAdapter,
  CryptoError,
  defineAdapter,
  type KeySource,
} from '@hzblj/nitro-crypto/adapter'

import {
  createAccount,
  type SolanaAccount,
  type SolanaCluster,
  type SolanaMessage,
  type SolanaSignature,
  verifySigner,
} from './account'
import {addressBytes, addressFromPublicKey, type SolanaAddress, validateAddress} from './address'
import {isOnCurveBytes} from './curve'
import {createInstructions, type SolanaInstructions} from './instructions'
import {
  type DecodedSolanaMessage,
  type DecodedSolanaTransaction,
  type DecodeMessageOptions,
  decodeMessage,
  decodeTransaction,
} from './message'
import {
  type DecodedSolanaOffchainMessage,
  decodeOffchainMessage,
  encodeOffchainMessage,
  offchainMessageBytes,
  type SolanaOffchainMessage,
} from './offchain'
import {derivationPath, type SolanaAccountRequest} from './path'
import {type AssociatedTokenRequest, associatedTokenAddress, findProgramAddress, type ProgramAddress} from './pda'
import {
  type CompileMessageRequest,
  compileMessage,
  type SignedSolanaTransaction,
  serializeTransaction,
} from './transaction'
import {VERSION} from './version'

const CLUSTERS: readonly SolanaCluster[] = ['mainnet-beta', 'devnet', 'testnet']

export type SolanaConfig<Id extends string = 'solana'> = {
  readonly id?: Id
  /** Which cluster accounts are presented on. Addresses are the same on every cluster. Defaults to mainnet-beta. */
  readonly cluster?: SolanaCluster
  readonly name?: string
}

/** Solana, bound to an engine: `crypto.chains.solana`. */
export type SolanaChain<Id extends string = 'solana'> = {
  readonly cluster: SolanaCluster
  readonly deriveAccount: (keys: KeySource, request: SolanaAccountRequest) => Promise<SolanaAccount<Id>>
  readonly validateAddress: typeof validateAddress
  readonly addressFromPublicKey: (publicKey: Uint8Array) => SolanaAddress
  /** Whether `address` signed `message` (raw bytes, as `signMessage` signs them). */
  readonly verifyMessage: (request: {
    readonly address: string
    readonly message: SolanaMessage
    readonly signature: SolanaSignature
  }) => boolean
  /** Builders for SOL and SPL token transfers, to pass to `account.signTransaction`. */
  readonly instructions: SolanaInstructions
  /** The associated token account of `owner` for `mint`: where a wallet holds that token. */
  readonly associatedTokenAddress: (request: AssociatedTokenRequest) => SolanaAddress
  /** The canonical program-derived address of `seeds` under `programId`, and its bump. */
  readonly findProgramAddress: (seeds: readonly Uint8Array[], programId: string) => ProgramAddress
  /** Whether an address is a point on the Ed25519 curve: false for program-derived addresses. */
  readonly isOnCurve: (address: string) => boolean
  /**
   * The message of a transaction, legacy unless `version: 0` (with its lookup tables): what each signer signs, and
   * what `getFeeForMessage` prices. Byte for byte what @solana/kit compiles for the same instructions.
   */
  readonly compileMessage: (request: CompileMessageRequest) => Uint8Array
  /**
   * A message read back, legacy or v0: the fee payer, the signers, every account and its role, the blockhash, and each
   * instruction with a summary of what it does. Looked-up accounts are named when their tables' addresses are given.
   * Strict; any other version is refused (`INVALID_ARGUMENT`).
   */
  readonly decodeMessage: (message: Uint8Array, options?: DecodeMessageOptions) => DecodedSolanaMessage
  /**
   * A wire transaction read back (what a dApp asks a wallet to sign, or what is about to be sent): the message as
   * `decodeMessage` reads it, its bytes, and each signer's signature or `undefined` for a slot not signed yet.
   * Signatures are read, not verified.
   */
  readonly decodeTransaction: (transaction: Uint8Array, options?: DecodeMessageOptions) => DecodedSolanaTransaction
  /**
   * The transaction to send, from a message (legacy or v0) and its signatures made elsewhere, one per signer in the
   * message's order. Each signature is verified by the engine against its signer first: one that fails is
   * `INVALID_SIGNATURE`.
   */
  readonly assembleTransaction: (request: {
    readonly message: Uint8Array
    readonly signatures: readonly Uint8Array[]
  }) => SignedSolanaTransaction
  /** The bytes of an off-chain message, version 0 or 1, as @solana/kit encodes them: what each of its signers signs. */
  readonly encodeOffchainMessage: (message: SolanaOffchainMessage) => Uint8Array
  /** An off-chain message read back from its bytes, strictly: what to show before signing it. */
  readonly decodeOffchainMessage: (message: Uint8Array) => DecodedSolanaOffchainMessage
  /**
   * Whether `address` signed an off-chain message: it must be one of the message's signers, and the signature must
   * verify over the message's bytes. Bytes that are not an off-chain message are refused (`INVALID_ARGUMENT`).
   */
  readonly verifyOffchainMessage: (request: {
    readonly address: string
    readonly message: SolanaOffchainMessage | Uint8Array
    readonly signature: SolanaSignature
  }) => boolean
}

const createChain = <Id extends string>(context: AdapterContext, id: Id, cluster: SolanaCluster): SolanaChain<Id> => {
  const sha256 = context.hash.sha256

  return Object.freeze({
    addressFromPublicKey,
    assembleTransaction: ({
      message,
      signatures,
    }: {
      readonly message: Uint8Array
      readonly signatures: readonly Uint8Array[]
    }) => {
      const {signers} = decodeMessage(message)

      if (signatures.length !== signers.length) {
        throw new CryptoError(
          'INVALID_ARGUMENT',
          `The message needs ${signers.length} signatures, not ${signatures.length}.`
        )
      }

      signers.forEach((signer, index) => {
        if (!verifySigner(context, signer, message, signatures[index] ?? new Uint8Array(0))) {
          throw new CryptoError('INVALID_SIGNATURE', `The signature of ${signer} does not verify for this message.`)
        }
      })

      return Object.freeze({
        serialized: serializeTransaction(message, signatures),
        signature: base58.encode(signatures[0] ?? new Uint8Array(0)),
      })
    },
    associatedTokenAddress: (request: AssociatedTokenRequest) => associatedTokenAddress(request, sha256),
    cluster,
    compileMessage: (request: CompileMessageRequest) => compileMessage(request).bytes,
    decodeMessage,
    decodeOffchainMessage,
    decodeTransaction,
    deriveAccount: async (keys: KeySource, request: SolanaAccountRequest) =>
      createAccount(context, id, cluster, keys.deriveKey('slip10', derivationPath(request))),
    encodeOffchainMessage,
    findProgramAddress: (seeds: readonly Uint8Array[], programId: string) =>
      findProgramAddress(seeds, programId, sha256),
    instructions: createInstructions(sha256),
    isOnCurve: (address: string) => isOnCurveBytes(addressBytes(address, 'address')),
    validateAddress,
    verifyMessage: ({address, message, signature}) => verifySigner(context, address, message, signature),
    verifyOffchainMessage: ({address, message, signature}) => {
      const {bytes, signers} = offchainMessageBytes(message)
      // Verified first, so a malformed address throws as it does for `verifyMessage`.
      const verified = verifySigner(context, address, bytes, signature)

      return verified && signers.includes(address)
    },
  })
}

/**
 * Solana: Ed25519 accounts derived with SLIP-0010 at `m/44'/501'/{account}'/0'`, Base58 addresses, signatures of raw
 * message bytes and of off-chain messages, and transactions, legacy and v0 with address lookup tables: SOL and SPL
 * token transfers built, compiled and signed by the account that pays for them, and transactions made elsewhere read
 * and signed, a slot at a time when several sign.
 */
export const solanaAdapter = <const Id extends string = 'solana'>(
  config: SolanaConfig<Id> = {}
): ChainAdapter<NoInfer<Id>, SolanaChain<NoInfer<Id>>> => {
  const cluster = config.cluster ?? 'mainnet-beta'

  if (!CLUSTERS.includes(cluster)) {
    throw new CryptoError('INVALID_CONFIG', 'A Solana cluster is mainnet-beta, devnet or testnet.')
  }

  const name = config.name ?? (cluster === 'mainnet-beta' ? 'Solana' : `Solana ${cluster}`)

  if (name.trim() === '') {
    throw new CryptoError('INVALID_CONFIG', 'A Solana adapter needs a name.')
  }

  const id = (config.id ?? 'solana') as Id

  return defineAdapter({
    create: (context: AdapterContext) => createChain(context, id, cluster),
    curve: 'ed25519',
    features: {
      messageSigning: true,
      offchainMessages: true,
      splTokens: true,
      transactionSigning: true,
      versionedTransactions: true,
    },
    formats: {address: ['base58'], signature: ['ed25519', 'legacy-transaction', 'v0-transaction', 'offchain-message']},
    id,
    name,
    requires: ['ed25519', 'sha256', 'slip10-ed25519'],
    version: VERSION,
  })
}
