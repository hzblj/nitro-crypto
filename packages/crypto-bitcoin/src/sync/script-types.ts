import type {BitcoinWatchAccount} from '../account'
import type {BitcoinChain} from '../adapter'
import {SyncError} from './errors'

/**
 * How an account's keys pay: `p2wpkh` (native SegWit, BIP-84), the one this version follows. `p2tr` (Taproot,
 * BIP-86) is reserved: a sync asked for it is `UNSUPPORTED` until the adapter derives Taproot outputs.
 */
export type ScriptType = 'p2wpkh' | 'p2tr'

/** A key of the account and where it came from: what a PSBT tells its signer. */
export type KeyOrigin = {
  readonly publicKey: Uint8Array
  /** From the master key: `m/84'/1'/0'/1/3`. */
  readonly path: string
  readonly fingerprint: number
}

/**
 * What a sync needs from the adapter for one script type. Everything script-specific goes through here: deriving an
 * address, and a watch-only account of one key, whose `createTransaction` selects coins and sizes the fee for this
 * type's inputs and whose `createPsbt` writes this type's PSBT fields (for P2WPKH: the witness UTXO and the BIP-32
 * derivation). The sync combines those per-key PSBTs into one for every address of the account, without knowing
 * the fields.
 */
export type ScriptSupport = {
  readonly type: ScriptType
  /** The BIP-44 purpose of its standard account path: 84 for P2WPKH, 86 for P2TR. */
  readonly purpose: number
  /** The address a child key pays to, and its output script. */
  readonly output: (
    chain: BitcoinChain<string>,
    publicKey: Uint8Array
  ) => {readonly address: string; readonly scriptPubKey: Uint8Array}
  /** A watch-only account of one key of this type. */
  readonly watch: (chain: BitcoinChain<string>, origin: KeyOrigin) => BitcoinWatchAccount<string>
}

const p2wpkh: ScriptSupport = Object.freeze({
  output: (chain: BitcoinChain<string>, publicKey: Uint8Array) => {
    const address = chain.addressFromPublicKey(publicKey)
    const validation = chain.validateAddress(address)

    if (!validation.valid) {
      throw new SyncError('INVALID_EXTENDED_KEY', validation.reason)
    }

    return {address, scriptPubKey: validation.scriptPubKey}
  },
  purpose: 84,
  type: 'p2wpkh',
  watch: (chain: BitcoinChain<string>, origin: KeyOrigin) => chain.watchAccount(origin),
})

/**
 * Every script type, and how far this version follows it. P2TR plugs in here once the adapter has Taproot: an
 * `output` with the BIP-86 tweaked key's Bech32m address, and a `watch` whose accounts plan with Taproot input
 * sizes and write `PSBT_IN_TAP_BIP32_DERIVATION` and the internal key. Nothing else in the sync changes.
 */
export const SCRIPT_TYPES: Readonly<Record<ScriptType, ScriptSupport | undefined>> = Object.freeze({
  p2tr: undefined,
  p2wpkh,
})

export const scriptSupport = (type: ScriptType): ScriptSupport => {
  const support = Object.hasOwn(SCRIPT_TYPES, type) ? SCRIPT_TYPES[type] : undefined

  if (!support) {
    throw new SyncError(
      'UNSUPPORTED',
      type === 'p2tr'
        ? 'Taproot (P2TR) accounts are not followed in this version.'
        : 'A script type is p2wpkh (or p2tr, in a later version).'
    )
  }

  return support
}
