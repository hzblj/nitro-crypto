import type {AdapterContext, Secp256k1Key} from '@hzblj/nitro-crypto/adapter'

import {type BitcoinAddressType, p2wpkhAddress} from './address'
import type {BitcoinNetwork} from './networks'

/**
 * A Bitcoin account whose key the engine holds: one native SegWit (P2WPKH) address. It signs nothing yet, by
 * design: neither message signing (BIP-137, BIP-322) nor transactions (PSBT) is implemented, and an account
 * offering `signMessage` would invite the Ethereum format, which Bitcoin verifiers reject.
 */
export type BitcoinAccount<Id extends string = string> = {
  readonly chain: Id
  readonly network: BitcoinNetwork['name']
  readonly addressType: Extract<BitcoinAddressType, 'p2wpkh'>
  readonly address: string
  /** Compressed SEC1, 33 bytes. */
  readonly publicKey: Uint8Array
  /** The output script that pays this address: `OP_0 <20-byte key hash>`. */
  readonly scriptPubKey: Uint8Array
  readonly path: string
}

export const createAccount = <Id extends string>(
  context: AdapterContext,
  chain: Id,
  network: BitcoinNetwork,
  key: Secp256k1Key
): BitcoinAccount<Id> => {
  const publicKey = key.publicKey('compressed')
  const {address, scriptPubKey} = p2wpkhAddress(publicKey, network, context.hash.sha256, context.hash.ripemd160)

  return Object.freeze({
    address,
    addressType: 'p2wpkh',
    chain,
    network: network.name,
    path: key.path ?? '',
    publicKey,
    scriptPubKey,
  })
}
