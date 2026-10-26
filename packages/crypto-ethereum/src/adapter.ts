import {
  type AdapterContext,
  type ChainAdapter,
  CryptoError,
  defineAdapter,
  type ExtendedPublicKey,
  isCryptoError,
  type KeySource,
  type RecoverableSignature,
} from '@hzblj/nitro-crypto/adapter'

import {createAccount, type EthereumAccount, recoverSigner, verifySigner} from './account'
import {
  type Address,
  addressFromPublicKey,
  checksumAddress,
  type EthereumAddressValidation,
  validateAddress,
} from './address'
import {type EthereumConfig, type EthereumNetwork, resolveConfig} from './config'
import {createErc20, type Erc20} from './erc20'
import {hashMessage} from './message'
import {derivationPath, type EthereumAccountRequest} from './path'
import {parseSignature} from './signature'
import {
  assembleTransaction,
  type EthereumTransactionRequest,
  parseTransaction,
  type SignedEthereumTransaction,
  serializeTransaction,
  transactionDigest,
} from './transaction'
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
  /** The address of a SEC1 public key, compressed or not. Throws `INVALID_PUBLIC_KEY` for a key that is not a point. */
  readonly addressFromPublicKey: (publicKey: Uint8Array) => Address
  /**
   * The request in an unsigned EIP-1559 envelope, as `serializeTransaction` writes it: what a signer that receives a
   * transaction to sign (over a QR code, say) reads and shows first. Strict, and bound to this network's chain id;
   * anything else is `INVALID_ARGUMENT` (malformed RLP is `INVALID_ENCODING`).
   */
  readonly parseTransaction: (
    serialized: Hex | Uint8Array
  ) => EthereumTransactionRequest & {readonly chainId: number; readonly to: Address; readonly data: Hex}
  /** The address that signed `request`, from a signature made elsewhere; `undefined` when it recovers no key. */
  readonly recoverTransactionAddress: (request: {
    readonly transaction: EthereumTransactionRequest
    readonly signature: RecoverableSignature | Hex | Uint8Array
  }) => Address | undefined
  /**
   * The transaction to broadcast, from `request` and a signature made elsewhere. Unchecked: compare
   * `recoverTransactionAddress` with the expected signer first.
   */
  readonly assembleTransaction: (
    request: EthereumTransactionRequest,
    signature: RecoverableSignature | Hex | Uint8Array
  ) => SignedEthereumTransaction
  /**
   * BIP-32 public derivation, the engine's: the extended key `path` below `key`, every step non-hardened (`m/0/5`),
   * for the addresses below an account's extended key a signer shared. `UNSUPPORTED` on an engine without it.
   */
  readonly derivePublic: (key: ExtendedPublicKey, path: string) => ExtendedPublicKey
}

const toRecoverable = (signature: RecoverableSignature | Hex | Uint8Array): RecoverableSignature =>
  typeof signature === 'string' || signature instanceof Uint8Array ? parseSignature(signature) : signature

const createChain = <Id extends string>(
  context: AdapterContext,
  id: Id,
  network: EthereumNetwork
): EthereumChain<Id> => {
  const keccak256 = context.hash.keccak256

  return Object.freeze({
    addressFromPublicKey: (publicKey: Uint8Array) =>
      addressFromPublicKey(context.secp256k1.convertPublicKey(publicKey, 'uncompressed'), keccak256),
    assembleTransaction: (request: EthereumTransactionRequest, signature: RecoverableSignature | Hex | Uint8Array) =>
      assembleTransaction(request, toRecoverable(signature), network, keccak256),
    checksumAddress: (address: string | Uint8Array) => {
      const validation = typeof address === 'string' ? validateAddress(address, keccak256) : undefined

      if (validation && !validation.valid) {
        throw new CryptoError('INVALID_ADDRESS', validation.reason)
      }

      return checksumAddress(address, keccak256)
    },
    deriveAccount: async (keys: KeySource, request: EthereumAccountRequest) =>
      createAccount(context, id, network, keys.deriveKey('bip32', derivationPath(request))),
    derivePublic: (key: ExtendedPublicKey, path: string) => {
      if (!context.engine.has('bip32-public-derivation')) {
        throw new CryptoError('UNSUPPORTED', 'This engine has no BIP-32 public derivation.')
      }

      return context.bip32.derivePublic(key, path)
    },
    erc20: createErc20(keccak256),
    hashMessage: (message: SignableMessage) => hashMessage(message, keccak256),
    network,
    parseTransaction: (serialized: Hex | Uint8Array) => parseTransaction(serialized, network, keccak256),
    recoverMessageAddress: ({message, signature}) => recoverSigner(context, message, signature),
    recoverTransactionAddress: ({signature, transaction}) => {
      try {
        const recovered = context.secp256k1.recover(
          transactionDigest(transaction, network, keccak256),
          toRecoverable(signature),
          'uncompressed'
        )

        return addressFromPublicKey(recovered, keccak256)
      } catch (error) {
        if (isCryptoError(error, 'INVALID_SIGNATURE') || isCryptoError(error, 'VERIFICATION_FAILED')) {
          return undefined
        }

        throw error
      }
    },
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
