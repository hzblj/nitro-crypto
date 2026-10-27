import {
  type AdapterContext,
  type ChainAdapter,
  CryptoError,
  defineAdapter,
  type ExtendedPublicKey,
  type KeySource,
  type RecoverableSignature,
} from '@hzblj/nitro-crypto/adapter'

import {
  createAccount,
  type EthereumAccount,
  recoverAddress,
  recoverSigner,
  verifyRecovered,
  verifySigner,
} from './account'
import {
  type Address,
  addressFromPublicKey,
  checksumAddress,
  type EthereumAddressValidation,
  validateAddress,
} from './address'
import {
  authorizationDigest,
  type EthereumAuthorization,
  type EthereumAuthorizationRequest,
  hashAuthorization,
} from './authorization'
import {type EthereumConfig, type EthereumNetwork, resolveConfig} from './config'
import {createErc20, type Erc20} from './erc20'
import {hashMessage} from './message'
import {derivationPath, type EthereumAccountRequest} from './path'
import {toRecoverable} from './signature'
import {
  assembleTransaction,
  type EthereumTransactionRequest,
  type ParsedEthereumTransaction,
  parseTransaction,
  type SignedEthereumTransaction,
  serializeTransaction,
  transactionDigest,
} from './transaction'
import {
  hashDomain,
  hashStruct,
  hashTypedData,
  type TypedDataDefinition,
  type TypedDataDomain,
  type TypedDataTypes,
} from './typed-data'
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
   * The EIP-712 digest of typed data, what `signTypedData` signs: `keccak256(0x19 0x01 || domainSeparator ||
   * hashStruct(message))`. A domain chain id other than this network's is `CHAIN_MISMATCH`.
   */
  readonly hashTypedData: (typedData: TypedDataDefinition) => Uint8Array
  /**
   * The domain separator, as a contract's `DOMAIN_SEPARATOR()` returns it. `EIP712Domain` comes from `types` when
   * they declare it, or from the fields the domain has. Not bound to this network: it is a part, not a digest.
   */
  readonly hashDomain: (request: {readonly domain: TypedDataDomain; readonly types?: TypedDataTypes}) => Uint8Array
  /** `hashStruct(data)` for a struct of `types`, EIP-712's `keccak256(typeHash || encodeData(data))`. */
  readonly hashStruct: (request: {
    readonly types: TypedDataTypes
    readonly primaryType: string
    readonly data: {readonly [member: string]: unknown}
  }) => Uint8Array
  /**
   * The address that signed the typed data, or `undefined` when the signature recovers no key. Bound to this network
   * as `hashTypedData` is; malformed typed data throws.
   */
  readonly recoverTypedDataAddress: (request: TypedDataDefinition & {readonly signature: Hex}) => Address | undefined
  /** Whether `address` signed the typed data: recovery, compared with the address. */
  readonly verifyTypedData: (
    request: TypedDataDefinition & {readonly address: string; readonly signature: Hex}
  ) => boolean
  /**
   * The EIP-7702 digest of an authorization, what `signAuthorization` signs: `keccak256(0x05 || rlp([chainId,
   * address, nonce]))`. The same checks: this network's chain id, or 0 with `allowAllChains`.
   */
  readonly hashAuthorization: (request: EthereumAuthorizationRequest) => Uint8Array
  /**
   * The account that signed an authorization (from a transaction's list, or sent to a sponsor), or `undefined` when
   * the signature recovers no key. Its chain id is this network's or 0.
   */
  readonly recoverAuthorizationAddress: (authorization: EthereumAuthorization) => Address | undefined
  /**
   * A transaction's raw bytes on this network: unsigned without a signature (its Keccak-256 is what a key signs),
   * ready to broadcast with one. Legacy (EIP-155), EIP-2930, EIP-1559 and EIP-7702. Accounts sign with
   * `signTransaction`.
   */
  readonly serializeTransaction: (request: EthereumTransactionRequest, signature?: RecoverableSignature) => Hex
  /** ERC-20 call data and results: `transfer`, `balanceOf`. */
  readonly erc20: Erc20
  /** The address of a SEC1 public key, compressed or not. Throws `INVALID_PUBLIC_KEY` for a key that is not a point. */
  readonly addressFromPublicKey: (publicKey: Uint8Array) => Address
  /**
   * The request in an unsigned transaction of any type this adapter signs, as `serializeTransaction` writes it: what
   * a signer that receives a transaction to sign (over a QR code, say) reads and shows first. Strict, and bound to
   * this network's chain id (`CHAIN_MISMATCH`). A signed, unprotected legacy or malformed transaction is
   * `INVALID_ARGUMENT` (malformed RLP is `INVALID_ENCODING`); a blob transaction or an unknown type is `UNSUPPORTED`.
   */
  readonly parseTransaction: (serialized: Hex | Uint8Array) => ParsedEthereumTransaction
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
    hashAuthorization: (request: EthereumAuthorizationRequest) => hashAuthorization(request, network, keccak256),
    hashDomain: request => hashDomain(request, keccak256),
    hashMessage: (message: SignableMessage) => hashMessage(message, keccak256),
    hashStruct: request => hashStruct(request, keccak256),
    hashTypedData: (typedData: TypedDataDefinition) => hashTypedData(typedData, keccak256, network),
    network,
    parseTransaction: (serialized: Hex | Uint8Array) => parseTransaction(serialized, network, keccak256),
    recoverAuthorizationAddress: (authorization: EthereumAuthorization) =>
      recoverAddress(context, () => authorizationDigest(authorization, network, keccak256), authorization.signature),
    recoverMessageAddress: ({message, signature}) => recoverSigner(context, message, signature),
    recoverTransactionAddress: ({signature, transaction}) =>
      recoverAddress(context, () => transactionDigest(transaction, network, keccak256), signature),
    recoverTypedDataAddress: ({signature, ...typedData}) =>
      recoverAddress(context, () => hashTypedData(typedData, keccak256, network), signature),
    serializeTransaction: (request: EthereumTransactionRequest, signature?: RecoverableSignature) =>
      serializeTransaction(request, network, keccak256, signature),
    validateAddress: (address: string) => validateAddress(address, keccak256),
    verifyMessage: ({address, message, signature}) => verifySigner(context, address, message, signature),
    verifyTypedData: ({address, signature, ...typedData}) =>
      verifyRecovered(context, address, () =>
        recoverAddress(context, () => hashTypedData(typedData, keccak256, network), signature)
      ),
  })
}

/**
 * Ethereum and every EVM chain: secp256k1 accounts at BIP-44 paths, EIP-55 addresses, EIP-191 messages, EIP-712
 * typed data, transactions of types 0 (EIP-155), 1, 2 and 4 with access lists and contract creation, EIP-7702
 * authorizations, and ERC-20 call data. Register one per network, each with its own id and chain id; the addresses
 * are the same, and each signs for its own chain id only (`CHAIN_MISMATCH` otherwise).
 *
 * Not here: EIP-4844 blob transactions, and signing a bare hash (`eth_sign`).
 */
export const ethereumAdapter = <const Id extends string = 'ethereum'>(
  config: EthereumConfig<Id> = {}
): ChainAdapter<NoInfer<Id>, EthereumChain<NoInfer<Id>>> => {
  const {id, network} = resolveConfig(config)

  return defineAdapter({
    create: (context: AdapterContext) => createChain(context, id, network),
    curve: 'secp256k1',
    features: {
      accessLists: true,
      blobTransactions: false,
      contractCreation: true,
      hashSigning: false,
      legacyTransactions: true,
      messageSigning: true,
      setCodeTransactions: true,
      transactionSigning: true,
      typedData: true,
    },
    formats: {address: ['eip55'], signature: ['eip191', 'eip712', 'eip155', 'eip2930', 'eip1559', 'eip7702']},
    id,
    name: network.name,
    requires: ['keccak256', 'secp256k1-ecdsa', 'secp256k1-recovery', 'bip32-secp256k1'],
    version: VERSION,
  })
}
