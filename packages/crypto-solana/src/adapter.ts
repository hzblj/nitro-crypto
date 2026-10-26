import {
  type AdapterContext,
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
import {addressFromPublicKey, type SolanaAddress, validateAddress} from './address'
import {derivationPath, type SolanaAccountRequest} from './path'
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
}

const createChain = <Id extends string>(context: AdapterContext, id: Id, cluster: SolanaCluster): SolanaChain<Id> =>
  Object.freeze({
    addressFromPublicKey,
    cluster,
    deriveAccount: async (keys: KeySource, request: SolanaAccountRequest) =>
      createAccount(context, id, cluster, keys.deriveKey('slip10', derivationPath(request))),
    validateAddress,
    verifyMessage: ({address, message, signature}) => verifySigner(context, address, message, signature),
  })

/**
 * Solana: Ed25519 accounts derived with SLIP-0010 at `m/44'/501'/{account}'/0'`, Base58 addresses, and signatures
 * of raw message bytes. Transaction serialization and signing are a later capability, not covered by
 * `signMessage`.
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
    features: {messageSigning: true, offchainMessages: false, transactionSigning: false},
    formats: {address: ['base58'], signature: ['ed25519']},
    id,
    name,
    requires: ['ed25519', 'slip10-ed25519'],
    version: VERSION,
  })
}
