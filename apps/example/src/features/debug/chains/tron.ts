import {
  type AdapterContext,
  type AddressValidation,
  base58check,
  type ChainAdapter,
  defineAdapter,
  isCryptoError,
  type KeySource,
} from '@hzblj/nitro-crypto/adapter'

/**
 * TRON, written in this app and nowhere else: the proof that a chain whose primitives the engine already has
 * (secp256k1, Keccak-256, SHA-256 for Base58Check) is an adapter of a few dozen lines, with no change to
 * @hzblj/nitro-crypto or to any other adapter. docs/adding-an-adapter.md walks through it.
 *
 * A TRON address is Base58Check of 0x41 followed by the last 20 bytes of Keccak-256 over the uncompressed public
 * key: an Ethereum address with another prefix and another encoding.
 */

const ADDRESS_PREFIX = 0x41

export type TronAccount = {
  readonly chain: 'tron'
  readonly address: string
  readonly path: string
}

export type TronChain = {
  readonly deriveAccount: (keys: KeySource, request: {readonly account?: number}) => Promise<TronAccount>
  readonly validateAddress: (address: string) => AddressValidation
}

const addressOf = (context: AdapterContext, uncompressed: Uint8Array) => {
  const payload = new Uint8Array(21)
  payload[0] = ADDRESS_PREFIX
  payload.set(context.hash.keccak256(uncompressed.subarray(1)).subarray(12), 1)
  return base58check.encode(payload, context.hash.sha256)
}

const validate = (context: AdapterContext, address: string): AddressValidation => {
  try {
    const payload = base58check.decode(address, context.hash.sha256)
    return payload.length === 21 && payload[0] === ADDRESS_PREFIX
      ? {normalized: address, valid: true}
      : {reason: 'A TRON address is 0x41 and 20 bytes.', valid: false}
  } catch (error) {
    if (isCryptoError(error, 'INVALID_ENCODING')) {
      return {reason: 'A TRON address is Base58Check.', valid: false}
    }
    throw error
  }
}

export const tronAdapter = (): ChainAdapter<'tron', TronChain> =>
  defineAdapter({
    create: (context: AdapterContext): TronChain => ({
      deriveAccount: async (keys, {account = 0}) => {
        const key = keys.deriveKey('bip32', `m/44'/195'/${account}'/0/0`)
        return {address: addressOf(context, key.publicKey('uncompressed')), chain: 'tron', path: key.path ?? ''}
      },
      validateAddress: address => validate(context, address),
    }),
    curve: 'secp256k1',
    features: {messageSigning: false, transactionSigning: false},
    formats: {address: ['base58check-41'], signature: []},
    id: 'tron',
    name: 'TRON',
    requires: ['keccak256', 'sha256', 'bip32-secp256k1'],
    version: '0.0.0',
  })
