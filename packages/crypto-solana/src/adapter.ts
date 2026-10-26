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
import {type DecodedSolanaMessage, decodeMessage} from './message'
import {derivationPath, type SolanaAccountRequest} from './path'
import {type AssociatedTokenRequest, associatedTokenAddress, findProgramAddress, type ProgramAddress} from './pda'
import {
  type CompileMessageRequest,
  compileLegacyMessage,
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
  /** The legacy message of a transaction: what each signer signs, and what `getFeeForMessage` prices. */
  readonly compileMessage: (request: CompileMessageRequest) => Uint8Array
  /**
   * A legacy message read back: the fee payer, the signers, every account and its role, the blockhash, and each
   * instruction with a summary of what it does. Strict; versioned messages are refused (`INVALID_ARGUMENT`).
   */
  readonly decodeMessage: (message: Uint8Array) => DecodedSolanaMessage
  /**
   * The transaction to send, from a message and its signatures made elsewhere, one per signer in the message's
   * order. Each signature is verified by the engine against its signer first: one that fails is `INVALID_SIGNATURE`.
   */
  readonly assembleTransaction: (request: {
    readonly message: Uint8Array
    readonly signatures: readonly Uint8Array[]
  }) => SignedSolanaTransaction
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
    compileMessage: (request: CompileMessageRequest) => compileLegacyMessage(request).bytes,
    decodeMessage,
    deriveAccount: async (keys: KeySource, request: SolanaAccountRequest) =>
      createAccount(context, id, cluster, keys.deriveKey('slip10', derivationPath(request))),
    findProgramAddress: (seeds: readonly Uint8Array[], programId: string) =>
      findProgramAddress(seeds, programId, sha256),
    instructions: createInstructions(sha256),
    isOnCurve: (address: string) => isOnCurveBytes(addressBytes(address, 'address')),
    validateAddress,
    verifyMessage: ({address, message, signature}) => verifySigner(context, address, message, signature),
  })
}

/**
 * Solana: Ed25519 accounts derived with SLIP-0010 at `m/44'/501'/{account}'/0'`, Base58 addresses, signatures of raw
 * message bytes, and legacy transactions: SOL and SPL token transfers built, compiled and signed by the account that
 * pays for them. Versioned (v0) transactions and address lookup tables are not here.
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
      offchainMessages: false,
      splTokens: true,
      transactionSigning: true,
      versionedTransactions: false,
    },
    formats: {address: ['base58'], signature: ['ed25519', 'legacy-transaction']},
    id,
    name,
    requires: ['ed25519', 'sha256', 'slip10-ed25519'],
    version: VERSION,
  })
}
