import type {AdapterContext, Secp256k1Key} from '@hzblj/nitro-crypto/adapter'

import {type BitcoinAddressType, p2wpkhAddress} from './address'
import type {BitcoinNetwork} from './networks'
import {
  type BitcoinTransactionPlan,
  type BitcoinTransactionRequest,
  planTransaction,
  type SignedBitcoinTransaction,
  signTransaction,
} from './transaction'

/**
 * A Bitcoin account whose key the engine holds: one native SegWit (P2WPKH) address, which spends the coins it
 * receives. It signs transactions (BIP-143) and no messages: neither BIP-137 nor BIP-322 is implemented, and an
 * account offering `signMessage` would invite the Ethereum format, which Bitcoin verifiers reject.
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
  /**
   * A payment from this address: selects coins (largest first), computes the fee, and adds change back to this
   * address (or `changeAddress`) when it is worth an output. Throws `INVALID_ADDRESS` for a recipient of another
   * network, and `INVALID_ARGUMENT` for an amount under the dust limit or more than the coins cover (saying by how
   * much).
   */
  readonly createTransaction: (request: BitcoinTransactionRequest) => BitcoinTransactionPlan
  /**
   * Signs every input of `plan` with this account's key and serializes the transaction for broadcast. Each input must
   * be a coin paying this address: the plan carries no scripts, and a coin of another address gets a signature no
   * node accepts.
   */
  readonly signTransaction: (plan: BitcoinTransactionPlan) => Promise<SignedBitcoinTransaction>
}

export const createAccount = <Id extends string>(
  context: AdapterContext,
  chain: Id,
  network: BitcoinNetwork,
  key: Secp256k1Key
): BitcoinAccount<Id> => {
  const publicKey = key.publicKey('compressed')
  const {address, scriptPubKey} = p2wpkhAddress(publicKey, network, context.hash.sha256, context.hash.ripemd160)
  const transactions = {network, sha256: context.hash.sha256}
  // Copies the caller cannot reach: the account's own fields are plain arrays anyone holding it could overwrite.
  const signer = {key, publicKey: publicKey.slice(), scriptPubKey: scriptPubKey.slice()}

  return Object.freeze({
    address,
    addressType: 'p2wpkh',
    chain,
    createTransaction: (request: BitcoinTransactionRequest) => planTransaction(request, address, transactions),
    network: network.name,
    path: key.path ?? '',
    publicKey,
    scriptPubKey,
    signTransaction: async (plan: BitcoinTransactionPlan) => signTransaction(plan, signer, transactions),
  })
}
