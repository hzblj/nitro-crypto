import {bytes} from '@hzblj/nitro-crypto/adapter'

import {parseMaps, serializeMaps} from '../psbt'
import {SyncError} from './errors'

/** `PSBT_IN_NON_WITNESS_UTXO`: the whole previous transaction of an input's coin. */
const IN_NON_WITNESS_UTXO = 0x00

type Combine = {
  /** For each input, a PSBT of the same transaction written by the account of the key that spends it. */
  readonly inputs: readonly Uint8Array[]
  /** For each output, a PSBT written by the account of the key it pays, or `undefined` for an output to others. */
  readonly outputs: readonly (Uint8Array | undefined)[]
  /** For each input, its coin's previous transaction, when the signer should be able to check its value. */
  readonly previous: readonly (Uint8Array | undefined)[]
}

/**
 * One PSBT for a transaction whose coins belong to several keys of one account, from PSBTs of that same transaction
 * each written by one key's watch-only account (BIP-174's combiner, field by field): every input takes its fields
 * (its coin, its key's origin) from its own key's PSBT, every output that pays the account takes its key's origin
 * from that key's, and previous transactions are added as `PSBT_IN_NON_WITNESS_UTXO`. The script type's fields are
 * the adapter's; this only picks which PSBT each map comes from.
 */
export const combinePsbts = ({inputs, outputs, previous}: Combine): Uint8Array => {
  const parsed = new Map<Uint8Array, ReturnType<typeof parseMaps>>()
  const read = (psbt: Uint8Array) => {
    let maps = parsed.get(psbt)

    if (!maps) {
      maps = parseMaps(psbt)
      parsed.set(psbt, maps)
    }

    return maps
  }
  const [first] = inputs

  if (!first) {
    throw new SyncError('INVALID_ARGUMENT', 'A transaction spends at least one coin.')
  }

  const {global} = read(first)
  const unsigned = global.find(entry => entry.key.length === 1 && entry.key[0] === 0)?.value

  for (const psbt of [...inputs, ...outputs]) {
    const other = psbt && read(psbt).global.find(entry => entry.key.length === 1 && entry.key[0] === 0)?.value

    if (psbt && (!unsigned || !other || !bytes.equal(unsigned, other))) {
      throw new SyncError('INVALID_ARGUMENT', 'The PSBTs to combine are not of one transaction.')
    }
  }

  return serializeMaps({
    global,
    inputs: inputs.map((psbt, index) => {
      const entries = (read(psbt).inputs[index] ?? []).filter(
        entry => !(entry.key.length === 1 && entry.key[0] === IN_NON_WITNESS_UTXO)
      )
      const raw = previous[index]

      return raw ? [{key: Uint8Array.of(IN_NON_WITNESS_UTXO), value: raw.slice()}, ...entries] : entries
    }),
    outputs: outputs.map((psbt, index) => (psbt ? (read(psbt).outputs[index] ?? []) : [])),
  })
}
