import {type AdapterContext, CryptoError, hex, isCryptoError, type Secp256k1Key} from '@hzblj/nitro-crypto/adapter'

import {type Address, addressFromPublicKey, validateAddress} from './address'
import type {EthereumNetwork} from './config'
import {hashMessage} from './message'
import {parseSignature, serializeSignature} from './signature'
import type {Hex, SignableMessage} from './types'

/** An Ethereum account whose key the engine holds. */
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
}

/** The signer of an EIP-191 message, or `undefined` when the signature recovers no key. */
export const recoverSigner = (
  context: AdapterContext,
  message: SignableMessage,
  signature: Hex | Uint8Array
): Address | undefined => {
  try {
    const recovered = context.secp256k1.recover(
      hashMessage(message, context.hash.keccak256),
      parseSignature(signature),
      'uncompressed'
    )

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

/**
 * Verification is recovery: a signature verifies for an address when the key it recovers to has that address.
 * A malformed or unrecoverable signature is `false`; an address that is not one is the caller's mistake, and throws.
 */
export const verifySigner = (
  context: AdapterContext,
  address: string,
  message: SignableMessage,
  signature: Hex | Uint8Array
): boolean => {
  const expected = validateAddress(address, context.hash.keccak256)

  if (!expected.valid) {
    throw new CryptoError('INVALID_ADDRESS', expected.reason)
  }

  return recoverSigner(context, message, signature) === expected.normalized
}

export const createAccount = <Id extends string>(
  context: AdapterContext,
  chain: Id,
  network: EthereumNetwork,
  key: Secp256k1Key
): EthereumAccount<Id> => {
  const uncompressed = key.publicKey('uncompressed')
  const address = addressFromPublicKey(uncompressed, context.hash.keccak256)

  return Object.freeze({
    address,
    chain,
    network,
    path: key.path ?? '',
    publicKey: hex.encode(uncompressed, {prefix: true}) as Hex,
    signMessage: async ({message}) => serializeSignature(key.sign(hashMessage(message, context.hash.keccak256))),
    verifyMessage: async ({message, signature}) => verifySigner(context, address, message, signature),
  })
}
