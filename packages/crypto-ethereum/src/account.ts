import {
  type AdapterContext,
  CryptoError,
  hex,
  isCryptoError,
  type RecoverableSignature,
  type Secp256k1Key,
} from '@hzblj/nitro-crypto/adapter'

import {type Address, addressFromPublicKey, validateAddress} from './address'
import {type EthereumAuthorizationRequest, type SignedEthereumAuthorization, signAuthorization} from './authorization'
import type {EthereumNetwork} from './config'
import {hashMessage} from './message'
import {serializeSignature, toRecoverable} from './signature'
import {type EthereumTransactionRequest, type SignedEthereumTransaction, signTransaction} from './transaction'
import {hashTypedData, type TypedDataDefinition} from './typed-data'
import type {Hex, SignableMessage} from './types'

/**
 * An Ethereum account whose key the engine holds. It signs EIP-191 messages, EIP-712 typed data, transactions of
 * types 0, 1, 2 and 4, and EIP-7702 authorizations, each bound to its network's chain id. It never signs a bare
 * 32-byte hash (`eth_sign`): a hash shows nothing of what it commits to, which is what makes it a phishing vector.
 */
export type EthereumAccount<Id extends string = string> = {
  readonly chain: Id
  readonly network: EthereumNetwork
  /** EIP-55 checksummed. */
  readonly address: Address
  /** Uncompressed SEC1 (65 bytes, `0x04…`), as Ethereum tooling writes public keys. */
  readonly publicKey: Hex
  readonly path: string
  /** EIP-191 `personal_sign`: 65 bytes of hex, `r || s || v`. */
  readonly signMessage: (request: {readonly message: SignableMessage}) => Promise<Hex>
  /** Whether `signature` is this account's signature of `message`. */
  readonly verifyMessage: (request: {readonly message: SignableMessage; readonly signature: Hex}) => Promise<boolean>
  /**
   * EIP-712 `eth_signTypedData_v4`: 65 bytes of hex, `r || s || v`, byte for byte viem's. A domain chain id other
   * than the network's is `CHAIN_MISMATCH` (as wallets refuse it); a domain without one is signed, and binds no chain.
   * Malformed typed data (an unknown or recursive type, a missing member, a value of the wrong type or out of range)
   * is refused, and no error message repeats a value.
   */
  readonly signTypedData: (typedData: TypedDataDefinition) => Promise<Hex>
  /** Whether `signature` is this account's signature of the typed data. */
  readonly verifyTypedData: (request: TypedDataDefinition & {readonly signature: Hex}) => Promise<boolean>
  /**
   * Signs a transaction for this account's network (legacy with EIP-155, EIP-2930, EIP-1559 by default, or EIP-7702):
   * the result is what `eth_sendRawTransaction` takes, and its hash. Nothing is sent; the nonce, fees and gas and
   * broadcasting are the app's.
   */
  readonly signTransaction: (request: EthereumTransactionRequest) => Promise<SignedEthereumTransaction>
  /**
   * Signs an EIP-7702 authorization: this account delegates its code to the contract at `address`, which can then do
   * anything the account can. For the network's chain id by default; chain id 0 (every chain) only with
   * `allowAllChains: true`. A type 4 transaction carries the result in its `authorizationList`.
   */
  readonly signAuthorization: (request: EthereumAuthorizationRequest) => Promise<SignedEthereumAuthorization>
}

/** The address whose key made `signature` over `digest`, or `undefined` when it recovers no key. */
export const recoverAddress = (
  context: AdapterContext,
  digest: () => Uint8Array,
  signature: RecoverableSignature | Hex | Uint8Array
): Address | undefined => {
  // The digest first, outside the catch: a malformed request throws, only a bad signature is `undefined`.
  const hashed = digest()

  try {
    const recovered = context.secp256k1.recover(hashed, toRecoverable(signature), 'uncompressed')

    return addressFromPublicKey(recovered, context.hash.keccak256)
  } catch (error) {
    if (
      isCryptoError(error, 'INVALID_SIGNATURE') ||
      isCryptoError(error, 'VERIFICATION_FAILED') ||
      isCryptoError(error, 'INVALID_ENCODING')
    ) {
      return undefined
    }
    throw error
  }
}

/** The signer of an EIP-191 message, or `undefined` when the signature recovers no key. */
export const recoverSigner = (
  context: AdapterContext,
  message: SignableMessage,
  signature: Hex | Uint8Array
): Address | undefined => recoverAddress(context, () => hashMessage(message, context.hash.keccak256), signature)

/**
 * Verification is recovery: a signature verifies for an address when the key it recovers to has that address.
 * A malformed or unrecoverable signature is `false`; an address that is not one is the caller's mistake, and throws.
 */
export const verifyRecovered = (
  context: AdapterContext,
  address: string,
  recovered: () => Address | undefined
): boolean => {
  const expected = validateAddress(typeof address === 'string' ? address : '', context.hash.keccak256)

  if (!expected.valid) {
    throw new CryptoError('INVALID_ADDRESS', expected.reason)
  }

  return recovered() === expected.normalized
}

export const verifySigner = (
  context: AdapterContext,
  address: string,
  message: SignableMessage,
  signature: Hex | Uint8Array
): boolean => verifyRecovered(context, address, () => recoverSigner(context, message, signature))

export const createAccount = <Id extends string>(
  context: AdapterContext,
  chain: Id,
  network: EthereumNetwork,
  key: Secp256k1Key
): EthereumAccount<Id> => {
  const keccak256 = context.hash.keccak256
  const uncompressed = key.publicKey('uncompressed')
  const address = addressFromPublicKey(uncompressed, keccak256)

  return Object.freeze({
    address,
    chain,
    network,
    path: key.path ?? '',
    publicKey: hex.encode(uncompressed, {prefix: true}) as Hex,
    signAuthorization: async (request: EthereumAuthorizationRequest) =>
      signAuthorization(request, network, keccak256, digest => key.sign(digest)),
    signMessage: async ({message}) => serializeSignature(key.sign(hashMessage(message, keccak256))),
    signTransaction: async request => signTransaction(request, network, keccak256, key),
    signTypedData: async (typedData: TypedDataDefinition) =>
      serializeSignature(key.sign(hashTypedData(typedData, keccak256, network))),
    verifyMessage: async ({message, signature}) => verifySigner(context, address, message, signature),
    verifyTypedData: async ({signature, ...typedData}) =>
      verifyRecovered(context, address, () =>
        recoverAddress(context, () => hashTypedData(typedData, keccak256, network), signature)
      ),
  })
}
