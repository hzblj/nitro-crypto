import type {AdapterContext, Secp256k1Key} from '@hzblj/nitro-crypto/adapter'

import {type BitcoinAccountType, p2trAddress, p2wpkhAddress} from './address'
import {
  type BitcoinMessage,
  type BitcoinMessageFormat,
  type MessageContext,
  signMessage,
  verifyMessage,
} from './message'
import type {BitcoinNetwork} from './networks'
import {createPsbt, type SignedPsbt, signPsbt} from './psbt'
import {
  type AccountSigner,
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
  /** `p2wpkh` (native SegWit, BIP-84) or `p2tr` (Taproot, BIP-86: the key path of a key with no script tree). */
  readonly addressType: BitcoinAccountType
  readonly address: string
  /**
   * Compressed SEC1, 33 bytes: the key at `path`. A Taproot account's internal key is its x coordinate
   * (`publicKey.subarray(1)`), which BIP-86 tweaks into the output key and PSBTs name.
   */
  readonly publicKey: Uint8Array
  /** The output script that pays this address: `OP_0 <20-byte key hash>`, or `OP_1 <32-byte output key>` for P2TR. */
  readonly scriptPubKey: Uint8Array
  readonly path: string
  /** The BIP-32 fingerprint of the master key the path starts from: what a PSBT names the signer by. */
  readonly fingerprint: number
  /**
   * A payment from this address: selects coins (largest first), computes the fee for inputs of this account's type,
   * and adds change back to this address (or `changeAddress`) when it is worth an output. Throws `INVALID_ADDRESS`
   * for a recipient of another network, and `INVALID_ARGUMENT` for an amount under the dust limit or more than the
   * coins cover (saying by how much).
   */
  readonly createTransaction: (request: BitcoinTransactionRequest) => BitcoinTransactionPlan
  /**
   * The plan as a PSBT (BIP-174) for a signer: each input's coin and key origin, and the origin on change back to
   * this address. A P2WPKH account's origin is a BIP-32 derivation; a Taproot account's, BIP-371's internal key and
   * Taproot derivation. With `previousTransactions`, each input carries its coin's whole previous transaction too,
   * which lets a signer verify the values it signs (hardware wallets ask for them).
   */
  readonly createPsbt: (plan: BitcoinTransactionPlan, options?: PsbtOptions) => Uint8Array
}

/**
 * A Bitcoin account whose key the engine holds: one address, native SegWit (P2WPKH) or Taproot (P2TR, BIP-86), which
 * spends the coins it receives and signs messages for itself.
 */
export type BitcoinAccount<Id extends string = string> = BitcoinWatchAccount<Id> & {
  /**
   * Signs every input of `plan` with this account's key and serializes the transaction for broadcast: BIP-143 with
   * SIGHASH_ALL for P2WPKH, BIP-341's key path with SIGHASH_DEFAULT for Taproot (the key tweaked inside the engine).
   * Each input must be a coin paying this address: the plan carries no scripts, and a coin of another address gets
   * a signature no node accepts.
   */
  readonly signTransaction: (plan: BitcoinTransactionPlan) => Promise<SignedBitcoinTransaction>
  /**
   * Signs every input of a PSBT that spends a coin of this address and returns it with the signatures added: a
   * partial signature (SIGHASH_ALL) for P2WPKH, a Taproot key path signature (SIGHASH_DEFAULT, or SIGHASH_ALL when
   * the PSBT asks) for P2TR. Inputs of other accounts are left for them, so a PSBT spending coins of both types is
   * signed by each account in turn. Show what it does first (`crypto.chains.bitcoin.decodePsbt`): signing a PSBT is
   * agreeing to it. Refused (`INVALID_ARGUMENT`): a PSBT with nothing for this account, an input of its own that asks
   * for another sighash type, a Taproot input in a PSBT that does not say every coin it spends, or a previous
   * transaction that does not match its input.
   */
  readonly signPsbt: (psbt: Uint8Array) => Promise<SignedPsbt>
  /**
   * Signs a message for this address, as Base64 text. `bip322` (the default) is BIP-322's simple signature, `smp`
   * first; `bip322-unprefixed` leaves `smp` out, for verifiers written before BIP-322 was finalized; `legacy` is the
   * "Bitcoin Signed Message" format (BIP-137) many services still ask for, P2WPKH only (`INVALID_ARGUMENT` for P2TR).
   */
  readonly signMessage: (request: {
    readonly message: BitcoinMessage
    readonly format?: BitcoinMessageFormat
  }) => Promise<string>
  /**
   * Whether `signature` is a signature of `message` by this address: BIP-322 simple (with or without `smp`) or
   * legacy, as `crypto.chains.bitcoin.verifyMessage` reads them.
   */
  readonly verifyMessage: (request: {readonly message: BitcoinMessage; readonly signature: string}) => Promise<boolean>
}

/** The address and script of `publicKey` as an account of `type`: P2WPKH, or BIP-86's Taproot output of the key. */
export const accountOutput = (
  context: AdapterContext,
  network: BitcoinNetwork,
  type: BitcoinAccountType,
  publicKey: Uint8Array
) =>
  type === 'p2tr'
    ? p2trAddress(publicKey, network, context.schnorr.taprootTweak)
    : p2wpkhAddress(publicKey, network, context.hash.sha256, context.hash.ripemd160)

/** The parts of an account that need no key: what a watch-only account and a signing one share. */
export const createWatchAccount = <Id extends string>(
  context: AdapterContext,
  chain: Id,
  network: BitcoinNetwork,
  type: BitcoinAccountType,
  publicKey: Uint8Array,
  path: string,
  fingerprint: number
): BitcoinWatchAccount<Id> => {
  const {address, scriptPubKey} = accountOutput(context, network, type, publicKey)
  const transactions = {network, sha256: context.hash.sha256}
  // Copies the caller cannot reach: the account's own fields are plain arrays anyone holding it could overwrite.
  const signer = {fingerprint, path, publicKey: publicKey.slice(), scriptPubKey: scriptPubKey.slice(), type}

  return Object.freeze({
    address,
    addressType: type,
    chain,
    createPsbt: (plan: BitcoinTransactionPlan, options: PsbtOptions = {}) =>
      createPsbt(plan, signer, transactions, options.previousTransactions),
    createTransaction: (request: BitcoinTransactionRequest) => planTransaction(request, address, transactions, type),
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
  type: BitcoinAccountType,
  key: Secp256k1Key,
  fingerprint: number,
  messages: MessageContext
): BitcoinAccount<Id> => {
  const publicKey = key.publicKey('compressed')
  const watch = createWatchAccount(context, chain, network, type, publicKey, key.path ?? '', fingerprint)
  const transactions = {network, sha256: context.hash.sha256, tweak: context.schnorr.taprootTweak}
  // Copies the caller cannot reach: the account's own fields are plain arrays anyone holding it could overwrite.
  const signer: AccountSigner = {key, publicKey: publicKey.slice(), scriptPubKey: watch.scriptPubKey.slice(), type}

  return Object.freeze({
    ...watch,
    signMessage: async ({format = 'bip322', message}: {message: BitcoinMessage; format?: BitcoinMessageFormat}) =>
      signMessage(message, format, signer, context.hash.sha256),
    signPsbt: async (psbt: Uint8Array) => signPsbt(psbt, signer, transactions),
    signTransaction: async (plan: BitcoinTransactionPlan) => signTransaction(plan, signer, transactions),
    verifyMessage: async ({message, signature}: {message: BitcoinMessage; signature: string}) =>
      verifyMessage(watch.address, message, signature, messages),
  })
}
