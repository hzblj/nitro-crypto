import type {AdapterContext, Secp256k1Key} from '@hzblj/nitro-crypto/adapter'

import {type BitcoinAddressType, p2wpkhAddress} from './address'
import type {BitcoinNetwork} from './networks'
import {createPsbt, type SignedPsbt, signPsbt} from './psbt'
import {
  type BitcoinTransactionPlan,
  type BitcoinTransactionRequest,
  planTransaction,
  type SignedBitcoinTransaction,
  signTransaction,
} from './transaction'

/** What a PSBT can carry besides the plan: each coin's whole previous transaction, by txid (bytes or hex). */
export type PsbtOptions = {readonly previousTransactions?: Readonly<Record<string, Uint8Array | string>>}

/**
 * A Bitcoin account by its public key alone: its address, and payments from it planned and written as PSBTs for a
 * signer elsewhere (an air-gapped wallet, a hardware wallet) to sign. `crypto.chains.bitcoin.watchAccount` makes one
 * from a public key and its origin; every `BitcoinAccount` is one too.
 */
export type BitcoinWatchAccount<Id extends string = string> = {
  readonly chain: Id
  readonly network: BitcoinNetwork['name']
  readonly addressType: Extract<BitcoinAddressType, 'p2wpkh'>
  readonly address: string
  /** Compressed SEC1, 33 bytes. */
  readonly publicKey: Uint8Array
  /** The output script that pays this address: `OP_0 <20-byte key hash>`. */
  readonly scriptPubKey: Uint8Array
  readonly path: string
  /** The BIP-32 fingerprint of the master key the path starts from: what a PSBT names the signer by. */
  readonly fingerprint: number
  /**
   * A payment from this address: selects coins (largest first), computes the fee, and adds change back to this
   * address (or `changeAddress`) when it is worth an output. Throws `INVALID_ADDRESS` for a recipient of another
   * network, and `INVALID_ARGUMENT` for an amount under the dust limit or more than the coins cover (saying by how
   * much).
   */
  readonly createTransaction: (request: BitcoinTransactionRequest) => BitcoinTransactionPlan
  /**
   * The plan as a PSBT (BIP-174) for a signer: each input's coin and key origin, and the origin on change back to
   * this address. With `previousTransactions`, each input carries its coin's whole previous transaction too, which
   * lets a signer verify the values it signs (hardware wallets ask for them).
   */
  readonly createPsbt: (plan: BitcoinTransactionPlan, options?: PsbtOptions) => Uint8Array
}

/**
 * A Bitcoin account whose key the engine holds: one native SegWit (P2WPKH) address, which spends the coins it
 * receives. It signs transactions (BIP-143) and no messages: neither BIP-137 nor BIP-322 is implemented, and an
 * account offering `signMessage` would invite the Ethereum format, which Bitcoin verifiers reject.
 */
export type BitcoinAccount<Id extends string = string> = BitcoinWatchAccount<Id> & {
  /**
   * Signs every input of `plan` with this account's key and serializes the transaction for broadcast. Each input must
   * be a coin paying this address: the plan carries no scripts, and a coin of another address gets a signature no
   * node accepts.
   */
  readonly signTransaction: (plan: BitcoinTransactionPlan) => Promise<SignedBitcoinTransaction>
  /**
   * Signs every input of a PSBT that spends a coin of this address (SIGHASH_ALL) and returns it with the signatures
   * added. Show what it does first (`crypto.chains.bitcoin.decodePsbt`): signing a PSBT is agreeing to it. Refused
   * (`INVALID_ARGUMENT`): a PSBT with nothing for this account, an input of its own that asks for another sighash
   * type, or a previous transaction that does not match its input.
   */
  readonly signPsbt: (psbt: Uint8Array) => Promise<SignedPsbt>
}

/** The parts of an account that need no key: what a watch-only account and a signing one share. */
export const createWatchAccount = <Id extends string>(
  context: AdapterContext,
  chain: Id,
  network: BitcoinNetwork,
  publicKey: Uint8Array,
  path: string,
  fingerprint: number
): BitcoinWatchAccount<Id> => {
  const {address, scriptPubKey} = p2wpkhAddress(publicKey, network, context.hash.sha256, context.hash.ripemd160)
  const transactions = {network, sha256: context.hash.sha256}
  // Copies the caller cannot reach: the account's own fields are plain arrays anyone holding it could overwrite.
  const signer = {fingerprint, path, publicKey: publicKey.slice(), scriptPubKey: scriptPubKey.slice()}

  return Object.freeze({
    address,
    addressType: 'p2wpkh',
    chain,
    createPsbt: (plan: BitcoinTransactionPlan, options: PsbtOptions = {}) =>
      createPsbt(plan, signer, transactions, options.previousTransactions),
    createTransaction: (request: BitcoinTransactionRequest) => planTransaction(request, address, transactions),
    fingerprint,
    network: network.name,
    path,
    publicKey,
    scriptPubKey,
  })
}

export const createAccount = <Id extends string>(
  context: AdapterContext,
  chain: Id,
  network: BitcoinNetwork,
  key: Secp256k1Key,
  fingerprint: number
): BitcoinAccount<Id> => {
  const publicKey = key.publicKey('compressed')
  const watch = createWatchAccount(context, chain, network, publicKey, key.path ?? '', fingerprint)
  const transactions = {network, sha256: context.hash.sha256}
  // Copies the caller cannot reach: the account's own fields are plain arrays anyone holding it could overwrite.
  const signer = {key, publicKey: publicKey.slice(), scriptPubKey: watch.scriptPubKey.slice()}

  return Object.freeze({
    ...watch,
    signPsbt: async (psbt: Uint8Array) => signPsbt(psbt, signer, transactions),
    signTransaction: async (plan: BitcoinTransactionPlan) => signTransaction(plan, signer, transactions),
  })
}
