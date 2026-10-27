import type {BitcoinWatchAccount} from '../account'
import type {BitcoinChain} from '../adapter'
import type {BitcoinAccountType} from '../address'
import {SyncError} from './errors'

/**
 * How an account's keys pay: `p2wpkh` (native SegWit, BIP-84, `m/84'/…`) or `p2tr` (Taproot key path, BIP-86,
 * `m/86'/…`). Taproot has no SLIP-132 prefix: its account is an xpub or tpub with `scriptType: 'p2tr'` (and the
 * `m/86'/…` path, which is the default for it).
 */
export type ScriptType = BitcoinAccountType

/** A key of the account and where it came from: what a PSBT tells its signer. */
export type KeyOrigin = {
  /** Compressed, 33 bytes: for Taproot, the internal key before BIP-86's tweak. */
  readonly publicKey: Uint8Array
  /** From the master key: `m/84'/1'/0'/1/3`. */
  readonly path: string
  readonly fingerprint: number
}

/**
 * What a sync needs from the adapter for one script type. Everything script-specific goes through here: deriving an
 * address, and a watch-only account of one key, whose `createTransaction` selects coins and sizes the fee for this
 * type's inputs and whose `createPsbt` writes this type's PSBT fields (P2WPKH: the witness UTXO and the BIP-32
 * derivation; Taproot: the witness UTXO, the internal key and BIP-371's Taproot derivations). The sync combines those
 * per-key PSBTs into one for every address of the account, without knowing the fields.
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

const support = (type: ScriptType, purpose: number): ScriptSupport =>
  Object.freeze({
    output: (chain: BitcoinChain<string>, publicKey: Uint8Array) => {
      // P2TR: the engine applies BIP-86's tweak to the compressed key (no script tree), as the adapter's accounts do.
      const address = chain.addressFromPublicKey(publicKey, type)
      const validation = chain.validateAddress(address)

      if (!validation.valid) {
        throw new SyncError('INVALID_EXTENDED_KEY', validation.reason)
      }

      return {address, scriptPubKey: validation.scriptPubKey}
    },
    purpose,
    type,
    watch: (chain: BitcoinChain<string>, origin: KeyOrigin) => chain.watchAccount({...origin, addressType: type}),
  })

/**
 * Every script type, and how the sync follows it. Both are the adapter's: P2WPKH (BIP-84) and Taproot key path
 * (BIP-86, the engine's Schnorr and tweak). A later type (P2SH-wrapped, multisig, a script path) plugs in here, once
 * the adapter derives and spends it: nothing else in the sync knows a script's fields.
 */
export const SCRIPT_TYPES: Readonly<Record<ScriptType, ScriptSupport | undefined>> = Object.freeze({
  p2tr: support('p2tr', 86),
  p2wpkh: support('p2wpkh', 84),
})

export const scriptSupport = (type: ScriptType): ScriptSupport => {
  const found = Object.hasOwn(SCRIPT_TYPES, type) ? SCRIPT_TYPES[type] : undefined

  if (!found) {
    throw new SyncError('UNSUPPORTED', 'A script type is p2wpkh or p2tr.')
  }

  return found
}
