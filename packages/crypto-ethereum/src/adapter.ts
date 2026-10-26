import {
  type AdapterContext,
  type ChainAdapter,
  CryptoError,
  defineAdapter,
  type KeySource,
  type RecoverableSignature,
} from '@hzblj/nitro-crypto/adapter'

import {createAccount, type EthereumAccount, recoverSigner, verifySigner} from './account'
import {type Address, checksumAddress, type EthereumAddressValidation, validateAddress} from './address'
import {type EthereumConfig, type EthereumNetwork, resolveConfig} from './config'
import {createErc20, type Erc20} from './erc20'
import {hashMessage} from './message'
import {derivationPath, type EthereumAccountRequest} from './path'
import {type EthereumTransactionRequest, serializeTransaction} from './transaction'
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
  /**
   * The EIP-2718 envelope of an EIP-1559 transaction on this network: unsigned without a signature (its Keccak-256
   * is what a key signs), ready to broadcast with one. Accounts sign with `signTransaction`.
   */
  readonly serializeTransaction: (request: EthereumTransactionRequest, signature?: RecoverableSignature) => Hex
  /** ERC-20 call data and results: `transfer`, `balanceOf`. */
  readonly erc20: Erc20
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
    erc20: createErc20(keccak256),
    hashMessage: (message: SignableMessage) => hashMessage(message, keccak256),
    network,
    recoverMessageAddress: ({message, signature}) => recoverSigner(context, message, signature),
    serializeTransaction: (request: EthereumTransactionRequest, signature?: RecoverableSignature) =>
      serializeTransaction(request, network, keccak256, signature),
    validateAddress: (address: string) => validateAddress(address, keccak256),
    verifyMessage: ({address, message, signature}) => verifySigner(context, address, message, signature),
  })
}

/**
 * Ethereum and every EVM chain: secp256k1 accounts at BIP-44 paths, EIP-55 addresses, EIP-191 message signatures
 * and signer recovery, EIP-1559 transactions, and ERC-20 call data. Register one per network, each with its own id
 * and chain id; the addresses are the same, and each signs transactions for its own chain id only.
 *
 * Not here (yet): EIP-712 typed data, legacy and EIP-2930 transactions, and contract creation.
 */
export const ethereumAdapter = <const Id extends string = 'ethereum'>(
  config: EthereumConfig<Id> = {}
): ChainAdapter<NoInfer<Id>, EthereumChain<NoInfer<Id>>> => {
  const {id, network} = resolveConfig(config)

  return defineAdapter({
    create: (context: AdapterContext) => createChain(context, id, network),
    curve: 'secp256k1',
    features: {messageSigning: true, transactionSigning: true, typedData: false},
    formats: {address: ['eip55'], signature: ['eip191', 'eip1559']},
    id,
    name: network.name,
    requires: ['keccak256', 'secp256k1-ecdsa', 'secp256k1-recovery', 'bip32-secp256k1'],
    version: VERSION,
  })
}
