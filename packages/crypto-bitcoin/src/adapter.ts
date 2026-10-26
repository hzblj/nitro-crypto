import {
  type AdapterContext,
  type ChainAdapter,
  CryptoError,
  defineAdapter,
  type KeySource,
} from '@hzblj/nitro-crypto/adapter'

import {type BitcoinAccount, createAccount} from './account'
import {type BitcoinAddressValidation, p2wpkhAddress, validateAddress} from './address'
import {type BitcoinNetwork, type BitcoinNetworkName, NETWORKS} from './networks'
import {type BitcoinAccountRequest, derivationPath} from './path'
import {VERSION} from './version'

export type BitcoinConfig<Id extends string = 'bitcoin'> = {
  /** The id it registers under: `bitcoin`, or one per network to register several (`bitcoin-testnet`). */
  readonly id?: Id
  /** Mainnet unless stated. Addresses, paths and validation all follow it. */
  readonly network?: BitcoinNetworkName
  /** For people. Defaults to "Bitcoin", or "Bitcoin testnet" and so on. */
  readonly name?: string
}

/** Bitcoin, bound to an engine: `crypto.chains.bitcoin`. */
export type BitcoinChain<Id extends string = 'bitcoin'> = {
  readonly network: BitcoinNetwork
  readonly deriveAccount: (keys: KeySource, request: BitcoinAccountRequest) => Promise<BitcoinAccount<Id>>
  /** Any address this network can pay, with its type and the script that pays it. */
  readonly validateAddress: (address: string) => BitcoinAddressValidation
  /** The P2WPKH address of a compressed public key on this network. */
  readonly addressFromPublicKey: (publicKey: Uint8Array) => string
}

const createChain = <Id extends string>(context: AdapterContext, id: Id, network: BitcoinNetwork): BitcoinChain<Id> =>
  Object.freeze({
    addressFromPublicKey: (publicKey: Uint8Array) =>
      p2wpkhAddress(publicKey, network, context.hash.sha256, context.hash.ripemd160).address,
    deriveAccount: async (keys: KeySource, request: BitcoinAccountRequest) =>
      createAccount(context, id, network, keys.deriveKey('bip32', derivationPath(request, network))),
    network,
    validateAddress: (address: string) => validateAddress(address, network, context.hash.sha256),
  })

/**
 * Bitcoin: native SegWit (P2WPKH) accounts at BIP-84 paths on mainnet, testnet, signet or regtest, and validation of
 * every address type. It signs nothing yet: message signing (BIP-322), PSBT and Taproot (BIP-86, Schnorr) are later
 * capabilities, and `features` says so.
 */
export const bitcoinAdapter = <const Id extends string = 'bitcoin'>(
  config: BitcoinConfig<Id> = {}
): ChainAdapter<NoInfer<Id>, BitcoinChain<NoInfer<Id>>> => {
  const network = NETWORKS[config.network ?? 'mainnet']

  if (!network) {
    throw new CryptoError('INVALID_CONFIG', 'A Bitcoin network is mainnet, testnet, signet or regtest.')
  }

  const name = config.name ?? (network.name === 'mainnet' ? 'Bitcoin' : `Bitcoin ${network.name}`)

  if (name.trim() === '') {
    throw new CryptoError('INVALID_CONFIG', 'A Bitcoin adapter needs a name.')
  }

  const id = (config.id ?? 'bitcoin') as Id

  return defineAdapter({
    create: (context: AdapterContext) => createChain(context, id, network),
    curve: 'secp256k1',
    features: {messageSigning: false, psbt: false, taproot: false, transactionSigning: false},
    formats: {address: ['bech32-p2wpkh'], signature: []},
    id,
    name,
    requires: ['sha256', 'ripemd160', 'bip32-secp256k1'],
    version: VERSION,
  })
}
