import {bytes, CryptoError, hex, type Secp256k1Key} from '@hzblj/nitro-crypto/adapter'

import {type Hash, validateAddress} from './address'
import {encodeDerSignature} from './der'
import type {BitcoinNetwork} from './networks'

/** A coin to spend: an output of an earlier transaction, as Esplora and most indexers list them. */
export type BitcoinUtxo = {
  /** The transaction id in display order (the hex block explorers show). */
  readonly txid: string
  readonly vout: number
  /** Satoshis. */
  readonly value: bigint
}

export type BitcoinOutput = {
  /** Normalized: lowercase for SegWit. */
  readonly address: string
  readonly scriptPubKey: Uint8Array
  /** Satoshis. */
  readonly value: bigint
}

export type BitcoinTransactionRequest = {
  /** The coins it may spend, all paying this account's address. Selection takes the largest first. */
  readonly utxos: readonly BitcoinUtxo[]
  /** Any address of the adapter's network. */
  readonly to: string
  /** Satoshis to send, or `max` to spend every coin, less the fee, with no change. */
  readonly amount: bigint | 'max'
  /** Satoshis per virtual byte, more than 0. Fractions are allowed. */
  readonly feeRate: number
  /** Where change goes. The account's own address unless stated. */
  readonly changeAddress?: string
}

/** What a transaction will do, before it is signed: which coins it spends, who it pays, and what it costs. */
export type BitcoinTransactionPlan = {
  readonly inputs: readonly BitcoinUtxo[]
  /** The recipient first, then the change output when there is one. */
  readonly outputs: readonly BitcoinOutput[]
  /** Satoshis the recipient receives. */
  readonly amount: bigint
  /** Satoshis: the inputs less the outputs. */
  readonly fee: bigint
  /** Satoshis back to the change address, or 0 when there is no change output (change below dust joins the fee). */
  readonly change: bigint
  /** The estimated virtual size the fee was computed for. */
  readonly vsize: number
}

export type SignedBitcoinTransaction = {
  /** The serialized transaction with its witnesses: what `sendrawtransaction` and Esplora's `POST /tx` take. */
  readonly hex: string
  /** In display order. */
  readonly txid: string
  /** Virtual bytes of the signed transaction, which can be a byte or two under the plan's estimate. */
  readonly vsize: number
  readonly weight: number
  readonly fee: bigint
}

/** One input of a transaction as it is serialized: the previous output's id in internal byte order. */
export type RawInput = {
  readonly txid: Uint8Array
  readonly vout: number
  readonly sequence: number
  /** The value of the coin it spends, which BIP-143 signs. */
  readonly value: bigint
}

export type RawTransaction = {
  readonly version: number
  readonly locktime: number
  readonly inputs: readonly RawInput[]
  readonly outputs: readonly {readonly scriptPubKey: Uint8Array; readonly value: bigint}[]
}

type TransactionContext = {readonly network: BitcoinNetwork; readonly sha256: Hash}

/** Every satoshi there will ever be: no amount is larger. */
const MAX_MONEY = 2_100_000_000_000_000n

/** Replaceable by fee (BIP-125), and no relative or absolute lock. */
export const SEQUENCE_RBF = 0xfffffffd

const TRANSACTION_VERSION = 2

const SIGHASH_ALL = 1

/** Version, input and output counts, lock time, and the SegWit marker and flag at a quarter weight. */
const OVERHEAD_VBYTES = 10.5

/** Outpoint, empty script and sequence (41 bytes), and a witness of a 72-byte signature and a 33-byte key. */
const P2WPKH_INPUT_VBYTES = 68

const invalid = (message: string) => new CryptoError('INVALID_ARGUMENT', message)

const u32 = (value: number) => {
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, value, true)

  return out
}

const u64 = (value: bigint) => {
  const out = new Uint8Array(8)
  new DataView(out.buffer).setBigUint64(0, value, true)

  return out
}

const varintLength = (value: number) => (value < 0xfd ? 1 : value <= 0xffff ? 3 : 5)

const varint = (value: number) => {
  if (value < 0xfd) {
    return Uint8Array.of(value)
  }

  if (value <= 0xffff) {
    return Uint8Array.of(0xfd, value & 0xff, value >> 8)
  }

  return bytes.concat(Uint8Array.of(0xfe), u32(value))
}

const outputSize = (scriptPubKey: Uint8Array) => 8 + varintLength(scriptPubKey.length) + scriptPubKey.length

/** The virtual size of a transaction spending `inputs` P2WPKH coins to outputs with these scripts, rounded up. */
export const estimateVsize = (inputs: number, scripts: readonly Uint8Array[]): number =>
  Math.ceil(
    OVERHEAD_VBYTES + P2WPKH_INPUT_VBYTES * inputs + scripts.reduce((size, script) => size + outputSize(script), 0)
  )

const isWitnessProgram = (script: Uint8Array) => {
  const version = script[0] ?? -1

  return (
    script.length >= 4 &&
    script.length <= 42 &&
    (version === 0 || (version >= 0x51 && version <= 0x60)) &&
    script[1] === script.length - 2
  )
}

/**
 * The smallest output nodes relay, as Bitcoin Core computes it at its default 3 sat/vB dust fee: 294 satoshis for
 * P2WPKH, 330 for P2WSH and P2TR, 546 for P2PKH.
 */
export const dustThreshold = (scriptPubKey: Uint8Array): bigint => {
  const spendSize = isWitnessProgram(scriptPubKey) ? 67 : 148

  return BigInt(Math.floor(((outputSize(scriptPubKey) + spendSize) * 3000) / 1000))
}

// The tolerance keeps a product like 110 * 1.1 = 121.00000000000001 from costing a satoshi more than it should.
const feeFor = (vsize: number, feeRate: number) => BigInt(Math.ceil(vsize * feeRate - 1e-9))

const TXID = /^[0-9a-fA-F]{64}$/

const checkUtxos = (utxos: readonly BitcoinUtxo[]): BitcoinUtxo[] => {
  if (!Array.isArray(utxos) || utxos.length === 0) {
    throw invalid('There are no coins to spend.')
  }

  const seen = new Set<string>()

  return utxos.map(utxo => {
    if (typeof utxo.txid !== 'string' || !TXID.test(utxo.txid)) {
      throw invalid('A coin`s txid is 64 hex digits.')
    }

    if (!Number.isInteger(utxo.vout) || utxo.vout < 0 || utxo.vout > 0xffffffff) {
      throw invalid('A coin`s vout is an integer from 0 to 2^32 - 1.')
    }

    if (typeof utxo.value !== 'bigint' || utxo.value <= 0n || utxo.value > MAX_MONEY) {
      throw invalid('A coin`s value is a positive number of satoshis, as a bigint.')
    }

    const outpoint = `${utxo.txid.toLowerCase()}:${utxo.vout}`

    if (seen.has(outpoint)) {
      throw invalid(`The coin ${outpoint} is listed twice.`)
    }

    seen.add(outpoint)

    return Object.freeze({txid: utxo.txid.toLowerCase(), value: utxo.value, vout: utxo.vout})
  })
}

const checkFeeRate = (feeRate: number) => {
  if (typeof feeRate !== 'number' || !Number.isFinite(feeRate) || feeRate <= 0) {
    throw invalid('A fee rate is a number of satoshis per virtual byte, more than 0.')
  }
}

/** An address as an output pays it: normalized, with its script. Throws `INVALID_ADDRESS` with the adapter's reason. */
const resolve = (address: string, {network, sha256}: TransactionContext) => {
  const result = validateAddress(address, network, sha256)

  if (!result.valid) {
    throw new CryptoError('INVALID_ADDRESS', result.reason)
  }

  return {address: result.normalized, scriptPubKey: result.scriptPubKey}
}

const sum = (values: readonly bigint[]) => values.reduce((total, value) => total + value, 0n)

const freezePlan = (plan: BitcoinTransactionPlan): BitcoinTransactionPlan =>
  Object.freeze({
    ...plan,
    inputs: Object.freeze([...plan.inputs]),
    outputs: Object.freeze(plan.outputs.map(output => Object.freeze({...output}))),
  })

/**
 * Selects coins and computes the fee for a payment from a P2WPKH account: largest coins first, until they cover the
 * amount and the fee. Change at or above the dust threshold gets an output; below it, it joins the fee.
 */
export const planTransaction = (
  request: BitcoinTransactionRequest,
  ownAddress: string,
  context: TransactionContext
): BitcoinTransactionPlan => {
  const recipient = resolve(request.to, context)
  const change = resolve(request.changeAddress ?? ownAddress, context)
  checkFeeRate(request.feeRate)
  const utxos = checkUtxos(request.utxos).sort((a, b) =>
    a.value === b.value ? a.txid.localeCompare(b.txid) || a.vout - b.vout : a.value > b.value ? -1 : 1
  )
  const recipientDust = dustThreshold(recipient.scriptPubKey)

  if (request.amount === 'max') {
    const total = sum(utxos.map(utxo => utxo.value))
    const vsize = estimateVsize(utxos.length, [recipient.scriptPubKey])
    const fee = feeFor(vsize, request.feeRate)
    const amount = total - fee

    if (amount < recipientDust) {
      throw invalid(
        `Sending everything leaves ${amount} sats after a ${fee}-sat fee, under the ${recipientDust}-sat dust limit.`
      )
    }

    return freezePlan({amount, change: 0n, fee, inputs: utxos, outputs: [{...recipient, value: amount}], vsize})
  }

  const amount = request.amount

  if (typeof amount !== 'bigint' || amount <= 0n || amount > MAX_MONEY) {
    throw invalid('An amount is a positive number of satoshis, as a bigint, or `max`.')
  }

  if (amount < recipientDust) {
    throw invalid(
      `${amount} sats is under the ${recipientDust}-sat dust limit for this address: nodes would not relay it.`
    )
  }

  const changeDust = dustThreshold(change.scriptPubKey)
  const selected: BitcoinUtxo[] = []
  let total = 0n

  for (const utxo of utxos) {
    selected.push(utxo)
    total += utxo.value
    const withChange = estimateVsize(selected.length, [recipient.scriptPubKey, change.scriptPubKey])
    const changeValue = total - amount - feeFor(withChange, request.feeRate)

    if (changeValue >= changeDust) {
      return freezePlan({
        amount,
        change: changeValue,
        fee: total - amount - changeValue,
        inputs: selected,
        outputs: [
          {...recipient, value: amount},
          {...change, value: changeValue},
        ],
        vsize: withChange,
      })
    }

    const withoutChange = estimateVsize(selected.length, [recipient.scriptPubKey])

    if (total >= amount + feeFor(withoutChange, request.feeRate)) {
      return freezePlan({
        amount,
        change: 0n,
        fee: total - amount,
        inputs: selected,
        outputs: [{...recipient, value: amount}],
        vsize: withoutChange,
      })
    }
  }

  const fee = feeFor(estimateVsize(utxos.length, [recipient.scriptPubKey]), request.feeRate)
  const needed = amount + fee

  throw invalid(
    `Not enough funds: ${needed} sats needed (${amount} and a ${fee}-sat fee), ${total} available, ${needed - total} short.`
  )
}

const hash256 = (data: Uint8Array, sha256: Hash) => sha256(sha256(data))

const outpoint = (input: RawInput) => bytes.concat(input.txid, u32(input.vout))

const serializeOutput = (output: RawTransaction['outputs'][number]) =>
  bytes.concat(u64(output.value), varint(output.scriptPubKey.length), output.scriptPubKey)

/** The script code BIP-143 signs for a P2WPKH input, with its length: `OP_DUP OP_HASH160 <key hash> OP_EQUALVERIFY OP_CHECKSIG`. */
export const p2wpkhScriptCode = (keyHash: Uint8Array): Uint8Array =>
  bytes.concat(Uint8Array.of(0x19, 0x76, 0xa9, 0x14), keyHash, Uint8Array.of(0x88, 0xac))

/** BIP-143: the digest a SegWit version 0 input signs with SIGHASH_ALL. `scriptCode` carries its length prefix. */
export const bip143Digest = (tx: RawTransaction, index: number, scriptCode: Uint8Array, sha256: Hash): Uint8Array => {
  const input = tx.inputs[index]

  if (!input) {
    throw invalid('No input at that index.')
  }

  return hash256(
    bytes.concat(
      u32(tx.version),
      hash256(bytes.concat(...tx.inputs.map(outpoint)), sha256),
      hash256(bytes.concat(...tx.inputs.map(item => u32(item.sequence))), sha256),
      outpoint(input),
      scriptCode,
      u64(input.value),
      u32(input.sequence),
      hash256(bytes.concat(...tx.outputs.map(serializeOutput)), sha256),
      u32(tx.locktime),
      u32(SIGHASH_ALL)
    ),
    sha256
  )
}

/** The wire format; with `witnesses`, BIP-144's, marker and flag included. */
export const serializeTransaction = (tx: RawTransaction, witnesses?: readonly (readonly Uint8Array[])[]): Uint8Array =>
  bytes.concat(
    u32(tx.version),
    witnesses ? Uint8Array.of(0x00, 0x01) : new Uint8Array(0),
    varint(tx.inputs.length),
    ...tx.inputs.map(input => bytes.concat(outpoint(input), Uint8Array.of(0), u32(input.sequence))),
    varint(tx.outputs.length),
    ...tx.outputs.map(serializeOutput),
    ...(witnesses ?? []).map(stack =>
      bytes.concat(varint(stack.length), ...stack.flatMap(item => [varint(item.length), item]))
    ),
    u32(tx.locktime)
  )

const checkOutputs = (plan: BitcoinTransactionPlan, context: TransactionContext) => {
  if (!Array.isArray(plan.outputs) || plan.outputs.length === 0) {
    throw invalid('A transaction pays at least one output.')
  }

  return plan.outputs.map(output => {
    if (typeof output.value !== 'bigint' || output.value <= 0n || output.value > MAX_MONEY) {
      throw invalid('An output`s value is a positive number of satoshis, as a bigint.')
    }

    if (!bytes.equal(resolve(output.address, context).scriptPubKey, output.scriptPubKey)) {
      throw invalid(`The output to ${output.address} carries a script that does not pay that address.`)
    }

    return {scriptPubKey: output.scriptPubKey, value: output.value}
  })
}

/** What signs: the account's key, its compressed public key, and the P2WPKH script its coins are locked to. */
export type P2wpkhSigner = {
  readonly key: Secp256k1Key
  readonly publicKey: Uint8Array
  readonly scriptPubKey: Uint8Array
}

/**
 * Signs every input of `plan` as a P2WPKH input of `signer` (BIP-143, SIGHASH_ALL), in a version 2 transaction with
 * lock time 0 and replaceable inputs. The plan is checked first: its outputs must pay their addresses on the
 * network, and its fee must be its inputs less its outputs. An input that does not pay the signer gets a signature no
 * node accepts.
 */
export const signTransaction = (
  plan: BitcoinTransactionPlan,
  signer: P2wpkhSigner,
  context: TransactionContext
): SignedBitcoinTransaction => {
  const inputs = checkUtxos(plan.inputs)
  const outputs = checkOutputs(plan, context)
  const fee = sum(inputs.map(input => input.value)) - sum(outputs.map(output => output.value))

  if (fee < 0n) {
    throw invalid('The outputs spend more than the inputs hold.')
  }

  if (fee !== plan.fee) {
    throw invalid(`The plan says the fee is ${plan.fee} sats, but its inputs less its outputs are ${fee}.`)
  }

  const tx: RawTransaction = {
    inputs: inputs.map(input => ({
      sequence: SEQUENCE_RBF,
      txid: hex.decode(input.txid).reverse(),
      value: input.value,
      vout: input.vout,
    })),
    locktime: 0,
    outputs,
    version: TRANSACTION_VERSION,
  }
  const scriptCode = p2wpkhScriptCode(signer.scriptPubKey.subarray(2))
  const witnesses = tx.inputs.map((_, index) => {
    const {signature} = signer.key.sign(bip143Digest(tx, index, scriptCode, context.sha256))

    return [bytes.concat(encodeDerSignature(signature), Uint8Array.of(SIGHASH_ALL)), signer.publicKey]
  })
  const signed = serializeTransaction(tx, witnesses)
  const stripped = serializeTransaction(tx)
  const weight = stripped.length * 3 + signed.length

  return Object.freeze({
    fee,
    hex: hex.encode(signed),
    txid: hex.encode(hash256(stripped, context.sha256).reverse()),
    vsize: Math.ceil(weight / 4),
    weight,
  })
}
