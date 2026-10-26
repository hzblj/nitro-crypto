import {
  type AdapterContext,
  type ChainAdapter,
  CryptoError,
  defineAdapter,
  type KeySource,
} from '@hzblj/nitro-crypto/adapter'

import {createAccount, type EthereumAccount, recoverSigner, verifySigner} from './account'
import {type Address, checksumAddress, type EthereumAddressValidation, validateAddress} from './address'
import {type EthereumConfig, type EthereumNetwork, resolveConfig} from './config'
import {hashMessage} from './message'
import {derivationPath, type EthereumAccountRequest} from './path'
import type {Hex, SignableMessage} from './types'
import {VERSION} from './version'

/** Ethereum, bound to an engine: `crypto.chains.ethereum`. */
export type EthereumChain<Id extends string = 'ethereum'> = {
  readonly network: EthereumNetwork
  readonly deriveAccount: (keys: KeySource, request: EthereumAccountRequest) => Promise<EthereumAccount<Id>>
  readonly validateAddress: (address: string) => EthereumAddressValidation
  /** The EIP-55 form of a 20-byte address (hex in any case, or bytes). Throws `INVALID_ADDRESS` for anything else. */
  readonly checksumAddress: (address: string | Uint8Array) => Address
  /** The EIP-191 digest a wallet signs for `message`. */
  readonly hashMessage: (message: SignableMessage) => Uint8Array
  /** The address that signed `message`, or `undefined` when the signature recovers no key. */
  readonly recoverMessageAddress: (request: {
    readonly message: SignableMessage
    readonly signature: Hex
  }) => Address | undefined
  /** Whether `address` signed `message`: recovery, compared with the address. */
  readonly verifyMessage: (request: {
    readonly address: string
    readonly message: SignableMessage
    readonly signature: Hex
  }) => boolean
}

const createChain = <Id extends string>(
  context: AdapterContext,
  id: Id,
  network: EthereumNetwork
): EthereumChain<Id> => {
  const keccak256 = context.hash.keccak256

  return Object.freeze({
    checksumAddress: (address: string | Uint8Array) => {
      const validation = typeof address === 'string' ? validateAddress(address, keccak256) : undefined

      if (validation && !validation.valid) {
        throw new CryptoError('INVALID_ADDRESS', validation.reason)
      }

      return checksumAddress(address, keccak256)
    },
    deriveAccount: async (keys: KeySource, request: EthereumAccountRequest) =>
      createAccount(context, id, network, keys.deriveKey('bip32', derivationPath(request))),
    hashMessage: (message: SignableMessage) => hashMessage(message, keccak256),
    network,
    recoverMessageAddress: ({message, signature}) => recoverSigner(context, message, signature),
    validateAddress: (address: string) => validateAddress(address, keccak256),
    verifyMessage: ({address, message, signature}) => verifySigner(context, address, message, signature),
  })
}

/**
 * Ethereum and every EVM chain: secp256k1 accounts at BIP-44 paths, EIP-55 addresses, EIP-191 message signatures
 * and signer recovery. Register one per network, each with its own id and chain id; the addresses are the same.
 *
 * Not here (yet): EIP-712 typed data and transaction signing.
 */
export const ethereumAdapter = <const Id extends string = 'ethereum'>(
  config: EthereumConfig<Id> = {}
): ChainAdapter<NoInfer<Id>, EthereumChain<NoInfer<Id>>> => {
  const {id, network} = resolveConfig(config)

  return defineAdapter({
    create: (context: AdapterContext) => createChain(context, id, network),
    curve: 'secp256k1',
    features: {messageSigning: true, transactionSigning: false, typedData: false},
    formats: {address: ['eip55'], signature: ['eip191']},
    id,
    name: network.name,
    requires: ['keccak256', 'secp256k1-ecdsa', 'secp256k1-recovery', 'bip32-secp256k1'],
    version: VERSION,
  })
}
