import {bytes, CryptoError, hex} from '@hzblj/nitro-crypto/adapter'

import {addressFromScript, type Hash, hash160} from './address'
import {decodeDerSignature, encodeDerSignature} from './der'
import type {BitcoinNetwork} from './networks'
import {
  type BitcoinTransactionPlan,
  bip143Digest,
  hash256,
  MAX_MONEY,
  type P2wpkhSigner,
  p2wpkhScriptCode,
  type RawTransaction,
  SIGHASH_ALL,
  type SignedBitcoinTransaction,
  signedTransaction,
  type TransactionContext,
  u32,
  u64,
  unsignedTransaction,
  varint,
} from './transaction'

/**
 * Partially Signed Bitcoin Transactions, version 0 (BIP-174): how a watch-only wallet hands a transaction to a signer
 * it cannot reach (an air-gapped one, a hardware wallet) and gets it back signed. Parsing is strict, because a PSBT
 * arrives from outside: the magic, canonical sizes, no repeated keys, a map per input and output, and an unsigned
 * transaction with empty scripts and no witnesses. Fields this package does not use are kept as they came.
 */

/** Where a key came from: the master key's fingerprint and the path below it. */
export type BitcoinKeyOrigin = {
  /** 33 bytes compressed, as P2WPKH requires (65 uncompressed reads too). */
  readonly publicKey: Uint8Array
  readonly fingerprint: number
  /** `m/84'/1'/0'/0/0`. */
  readonly path: string
}

/** The coin an input spends, as the PSBT states it. */
export type BitcoinSpentOutput = {readonly value: bigint; readonly scriptPubKey: Uint8Array}

export type BitcoinPsbtInput = {
  /** The transaction the coin is from, in display order. */
  readonly txid: string
  readonly vout: number
  readonly sequence: number
  /** The coin it spends, when the PSBT says; from the previous transaction itself when it carries one. */
  readonly spent: BitcoinSpentOutput | undefined
  /** The address of the coin it spends, when it has one. */
  readonly address: string | undefined
  /**
   * Whether the coin's value comes with its whole previous transaction, whose id the input names: a value a signer
   * can check. A SegWit signature commits to the value it is told, so a value that cannot be checked is the one a
   * malicious coordinator would lie about (to make the fee look smaller).
   */
  readonly verifiedValue: boolean
  /** The signature hash type asked for; `undefined` means SIGHASH_ALL. */
  readonly sighashType: number | undefined
  readonly derivations: readonly BitcoinKeyOrigin[]
  /** Signatures made so far: DER with the sighash byte, by key. */
  readonly partialSignatures: readonly {readonly publicKey: Uint8Array; readonly signature: Uint8Array}[]
  /** Whether the input already has its final witness or script. */
  readonly finalized: boolean
}

export type BitcoinPsbtOutput = {
  /** `undefined` for a script with no address (an `OP_RETURN`, a bare script). */
  readonly address: string | undefined
  readonly scriptPubKey: Uint8Array
  /** Satoshis. */
  readonly value: bigint
  /** The keys the output pays, when the PSBT says: how a signer recognizes change to itself. */
  readonly derivations: readonly BitcoinKeyOrigin[]
}

/** What a PSBT asks to be signed, read and checked: every field a wallet shows before it signs. */
export type BitcoinPsbt = {
  /** The id the transaction will have, in display order: SegWit signatures do not change it. */
  readonly txid: string
  readonly version: number
  readonly locktime: number
  readonly inputs: readonly BitcoinPsbtInput[]
  readonly outputs: readonly BitcoinPsbtOutput[]
  /** Satoshis: the inputs less the outputs, when every input states its value. */
  readonly fee: bigint | undefined
}

type KeyValue = {readonly key: Uint8Array; readonly value: Uint8Array}

type PsbtMaps = {readonly global: KeyValue[]; readonly inputs: KeyValue[][]; readonly outputs: KeyValue[][]}

const MAGIC = Uint8Array.of(0x70, 0x73, 0x62, 0x74, 0xff)

const GLOBAL_UNSIGNED_TX = 0x00
const GLOBAL_VERSION = 0xfb
const IN_NON_WITNESS_UTXO = 0x00
const IN_WITNESS_UTXO = 0x01
const IN_PARTIAL_SIG = 0x02
const IN_SIGHASH_TYPE = 0x03
const IN_BIP32_DERIVATION = 0x06
const IN_FINAL_SCRIPTSIG = 0x07
const IN_FINAL_SCRIPTWITNESS = 0x08
const OUT_BIP32_DERIVATION = 0x02

const HARDENED = 0x80000000

/** Far beyond any PSBT a signer would show, and a bound on what a hostile one makes the parser do. */
const MAX_ENTRIES = 1000

const invalid = (message: string) => new CryptoError('INVALID_ARGUMENT', message)

type Reader = {readonly data: Uint8Array; offset: number}

const take = (reader: Reader, length: number): Uint8Array => {
  if (length > reader.data.length - reader.offset) {
    throw invalid('The PSBT ends in the middle of a field.')
  }

  const out = reader.data.subarray(reader.offset, reader.offset + length)
  reader.offset += length

  return out
}

const readU32 = (reader: Reader) => new DataView(take(reader, 4).slice().buffer).getUint32(0, true)

const readU64 = (reader: Reader) => new DataView(take(reader, 8).slice().buffer).getBigUint64(0, true)

/** A CompactSize, canonical as Bitcoin Core requires: the shortest form for its value. */
const readCompactSize = (reader: Reader): number => {
  const first = take(reader, 1)[0] ?? 0

  if (first < 0xfd) {
    return first
  }

  const width = first === 0xfd ? 2 : first === 0xfe ? 4 : 8
  const view = new DataView(take(reader, width).slice().buffer)
  const value =
    width === 2 ? view.getUint16(0, true) : width === 4 ? view.getUint32(0, true) : view.getBigUint64(0, true)
  const minimum = width === 2 ? 0xfd : width === 4 ? 0x10000 : 0x100000000

  if (typeof value === 'bigint' || value < minimum) {
    throw invalid('The PSBT has a size that is not in its shortest form, or is too large.')
  }

  return value
}

const readBytes = (reader: Reader) => take(reader, readCompactSize(reader))

const readMap = (reader: Reader): KeyValue[] => {
  const entries: KeyValue[] = []
  const seen = new Set<string>()

  for (;;) {
    const key = readBytes(reader)

    if (key.length === 0) {
      return entries
    }

    const value = readBytes(reader)
    const id = hex.encode(key)

    if (seen.has(id)) {
      throw invalid('A PSBT map repeats a key.')
    }

    if (entries.length >= MAX_ENTRIES) {
      throw invalid('A PSBT map has more entries than this reads.')
    }

    seen.add(id)
    entries.push({key: key.slice(), value: value.slice()})
  }
}

type ParsedTransaction = RawTransaction & {
  readonly scriptSigs: readonly Uint8Array[]
  readonly hasWitness: boolean
  /** Without witnesses: what the transaction id is the double SHA-256 of. */
  readonly stripped: Uint8Array
}

/** A transaction in the wire format, with or without witnesses (BIP-144). */
const parseTransaction = (data: Uint8Array): ParsedTransaction => {
  const reader: Reader = {data, offset: 0}
  const version = readU32(reader)
  let count = readCompactSize(reader)
  const hasWitness = count === 0

  if (hasWitness) {
    if (take(reader, 1)[0] !== 0x01) {
      throw invalid('A transaction with a SegWit marker has flag 1.')
    }

    count = readCompactSize(reader)
  }

  if (count === 0 || count > MAX_ENTRIES) {
    throw invalid('A transaction has from one input to a thousand.')
  }

  const inputs = Array.from({length: count}, () => {
    const txid = take(reader, 32).slice()
    const vout = readU32(reader)
    const scriptSig = readBytes(reader).slice()

    return {scriptSig, sequence: readU32(reader), txid, value: 0n, vout}
  })
  const outputCount = readCompactSize(reader)

  if (outputCount === 0 || outputCount > MAX_ENTRIES) {
    throw invalid('A transaction has from one output to a thousand.')
  }

  const outputs = Array.from({length: outputCount}, () => {
    const value = readU64(reader)

    if (value > MAX_MONEY) {
      throw invalid('An output pays more bitcoin than there is.')
    }

    return {scriptPubKey: readBytes(reader).slice(), value}
  })

  if (hasWitness) {
    for (let index = 0; index < count; index++) {
      const items = readCompactSize(reader)

      for (let item = 0; item < items; item++) {
        readBytes(reader)
      }
    }
  }

  const locktime = readU32(reader)

  if (reader.offset !== data.length) {
    throw invalid('A transaction has bytes after its lock time.')
  }

  const tx: RawTransaction = {
    inputs: inputs.map(({sequence, txid, value, vout}) => ({sequence, txid, value, vout})),
    locktime,
    outputs,
    version,
  }

  return {
    ...tx,
    hasWitness,
    scriptSigs: inputs.map(input => input.scriptSig),
    // The wire format without witnesses; with the scripts the inputs carry, which the id commits to.
    stripped: bytes.concat(
      u32(version),
      varint(count),
      ...inputs.map(input =>
        bytes.concat(input.txid, u32(input.vout), varint(input.scriptSig.length), input.scriptSig, u32(input.sequence))
      ),
      varint(outputCount),
      ...outputs.map(output =>
        bytes.concat(u64(output.value), varint(output.scriptPubKey.length), output.scriptPubKey)
      ),
      u32(locktime)
    ),
  }
}

export const parseMaps = (data: Uint8Array): PsbtMaps => {
  if (!(data instanceof Uint8Array) || !bytes.equal(data.subarray(0, MAGIC.length), MAGIC)) {
    throw invalid('A PSBT starts with the bytes "psbt" and 0xff.')
  }

  const reader: Reader = {data, offset: MAGIC.length}
  const global = readMap(reader)
  const unsigned = global.find(entry => entry.key[0] === GLOBAL_UNSIGNED_TX)

  if (!unsigned || unsigned.key.length !== 1) {
    throw invalid('A version 0 PSBT carries its unsigned transaction; version 2 PSBTs are not supported.')
  }

  const version = global.find(entry => entry.key[0] === GLOBAL_VERSION && entry.key.length === 1)

  if (version && (version.value.length !== 4 || readU32({data: version.value, offset: 0}) !== 0)) {
    throw invalid('Only version 0 PSBTs are supported.')
  }

  const tx = parseTransaction(unsigned.value)
  const inputs = tx.inputs.map(() => readMap(reader))
  const outputs = tx.outputs.map(() => readMap(reader))

  if (reader.offset !== data.length) {
    throw invalid('The PSBT has bytes after its last output.')
  }

  return {global, inputs, outputs}
}

export const serializeMaps = ({global, inputs, outputs}: PsbtMaps): Uint8Array => {
  const map = (entries: readonly KeyValue[]) =>
    bytes.concat(
      ...entries.flatMap(({key, value}) => [varint(key.length), key, varint(value.length), value]),
      Uint8Array.of(0)
    )

  return bytes.concat(MAGIC, map(global), ...inputs.map(map), ...outputs.map(map))
}

const field = (entries: readonly KeyValue[], type: number) =>
  entries.find(entry => entry.key[0] === type && entry.key.length === 1)

const formatPath = (indexes: readonly number[]) =>
  ['m', ...indexes.map(index => (index >= HARDENED ? `${index - HARDENED}'` : String(index)))].join('/')

const parsePath = (path: string): number[] => {
  const [root, ...steps] = path.split('/')

  if (root !== 'm') {
    throw invalid('A derivation path starts with `m`.')
  }

  return steps.map(step => {
    const hardened = step.endsWith("'") || step.endsWith('h')
    const index = Number(hardened ? step.slice(0, -1) : step)

    if (!/^\d+['h]?$/.test(step) || !Number.isInteger(index) || index >= HARDENED) {
      throw invalid("A derivation path step is an index below 2^31, with `'` when hardened.")
    }

    return hardened ? index + HARDENED : index
  })
}

const isPublicKey = (key: Uint8Array) =>
  (key.length === 33 && (key[0] === 0x02 || key[0] === 0x03)) || (key.length === 65 && key[0] === 0x04)

const derivations = (entries: readonly KeyValue[], type: number): BitcoinKeyOrigin[] =>
  entries
    .filter(entry => entry.key[0] === type && entry.key.length > 1)
    .map(({key, value}) => {
      const publicKey = key.subarray(1)

      if (!isPublicKey(publicKey) || value.length < 4 || value.length % 4 !== 0 || value.length > 4 * 256) {
        throw invalid('A BIP-32 derivation is a public key, a fingerprint and a path.')
      }

      const view = new DataView(value.slice().buffer)
      const path = Array.from({length: value.length / 4 - 1}, (_, index) => view.getUint32(4 + index * 4, true))

      return Object.freeze({
        fingerprint: view.getUint32(0, false),
        path: formatPath(path),
        publicKey: publicKey.slice(),
      })
    })

const derivationEntry = (type: number, origin: BitcoinKeyOrigin): KeyValue => {
  const path = parsePath(origin.path)
  const value = new Uint8Array(4 + path.length * 4)
  const view = new DataView(value.buffer)
  view.setUint32(0, origin.fingerprint >>> 0, false)
  path.forEach((index, position) => view.setUint32(4 + position * 4, index, true))

  return {key: bytes.concat(Uint8Array.of(type), origin.publicKey), value}
}

const readSpentOutput = (value: Uint8Array): BitcoinSpentOutput => {
  const reader: Reader = {data: value, offset: 0}
  const amount = readU64(reader)
  const scriptPubKey = readBytes(reader).slice()

  if (reader.offset !== value.length || amount > MAX_MONEY) {
    throw invalid('A witness UTXO is a value and a script.')
  }

  return {scriptPubKey, value: amount}
}

const writeSpentOutput = ({scriptPubKey, value}: BitcoinSpentOutput) =>
  bytes.concat(u64(value), varint(scriptPubKey.length), scriptPubKey)

/**
 * The coin input `index` spends: from its previous transaction when the PSBT carries one (checked against the id the
 * input names), else from its witness UTXO. Both present must agree.
 */
const spentOutput = (
  entries: readonly KeyValue[],
  input: RawTransaction['inputs'][number],
  sha256: Hash
): {spent: BitcoinSpentOutput | undefined; verified: boolean} => {
  const witness = field(entries, IN_WITNESS_UTXO)
  const nonWitness = field(entries, IN_NON_WITNESS_UTXO)
  const fromWitness = witness && readSpentOutput(witness.value)

  if (!nonWitness) {
    return {spent: fromWitness, verified: false}
  }

  const previous = parseTransaction(nonWitness.value)

  if (!bytes.equal(hash256(previous.stripped, sha256), input.txid)) {
    throw invalid('An input`s previous transaction is not the one it spends from.')
  }

  const output = previous.outputs[input.vout]

  if (!output) {
    throw invalid('An input spends an output its previous transaction does not have.')
  }

  if (
    fromWitness &&
    (fromWitness.value !== output.value || !bytes.equal(fromWitness.scriptPubKey, output.scriptPubKey))
  ) {
    throw invalid('An input`s witness UTXO disagrees with its previous transaction.')
  }

  return {spent: {scriptPubKey: output.scriptPubKey, value: output.value}, verified: true}
}

type Decoded = {readonly maps: PsbtMaps; readonly tx: ParsedTransaction; readonly psbt: BitcoinPsbt}

const decode = (data: Uint8Array, network: BitcoinNetwork, sha256: Hash): Decoded => {
  const maps = parseMaps(data)
  const unsigned = field(maps.global, GLOBAL_UNSIGNED_TX)?.value ?? new Uint8Array(0)
  const tx = parseTransaction(unsigned)

  if (tx.hasWitness || tx.scriptSigs.some(script => script.length > 0)) {
    throw invalid('A PSBT`s unsigned transaction has empty scripts and no witnesses.')
  }

  const inputs = tx.inputs.map((input, index): BitcoinPsbtInput => {
    const entries = maps.inputs[index] ?? []
    const {spent, verified} = spentOutput(entries, input, sha256)
    const sighash = field(entries, IN_SIGHASH_TYPE)

    if (sighash && sighash.value.length !== 4) {
      throw invalid('A sighash type is four bytes.')
    }

    const partialSignatures = entries
      .filter(entry => entry.key[0] === IN_PARTIAL_SIG && entry.key.length > 1)
      .map(({key, value}) => {
        if (!isPublicKey(key.subarray(1))) {
          throw invalid('A partial signature is keyed by a public key.')
        }

        return Object.freeze({publicKey: key.slice(1), signature: value.slice()})
      })

    return Object.freeze({
      address: spent && addressFromScript(spent.scriptPubKey, network, sha256),
      derivations: Object.freeze(derivations(entries, IN_BIP32_DERIVATION)),
      finalized: Boolean(field(entries, IN_FINAL_SCRIPTWITNESS) ?? field(entries, IN_FINAL_SCRIPTSIG)),
      partialSignatures: Object.freeze(partialSignatures),
      sequence: input.sequence,
      sighashType: sighash ? readU32({data: sighash.value, offset: 0}) : undefined,
      spent,
      txid: hex.encode(input.txid.slice().reverse()),
      verifiedValue: verified,
      vout: input.vout,
    })
  })
  const outputs = tx.outputs.map((output, index) =>
    Object.freeze({
      address: addressFromScript(output.scriptPubKey, network, sha256),
      derivations: Object.freeze(derivations(maps.outputs[index] ?? [], OUT_BIP32_DERIVATION)),
      scriptPubKey: output.scriptPubKey,
      value: output.value,
    })
  )
  const values = inputs.map(input => input.spent?.value)
  const total = (items: readonly bigint[]) => items.reduce((sum, value) => sum + value, 0n)
  const fee = values.every(value => value !== undefined)
    ? total(values as bigint[]) - total(outputs.map(output => output.value))
    : undefined

  if (fee !== undefined && fee < 0n) {
    throw invalid('The PSBT spends more than its inputs hold.')
  }

  return {
    maps,
    psbt: Object.freeze({
      fee,
      inputs: Object.freeze(inputs),
      locktime: tx.locktime,
      outputs: Object.freeze(outputs),
      txid: hex.encode(hash256(tx.stripped, sha256).reverse()),
      version: tx.version,
    }),
    tx,
  }
}

/** Reads and checks a PSBT: what it spends, whom it pays, what it costs, and what is signed so far. */
export const decodePsbt = (data: Uint8Array, network: BitcoinNetwork, sha256: Hash): BitcoinPsbt =>
  decode(data, network, sha256).psbt

/** The unsigned transaction as a PSBT carries it: the wire format with empty scripts and no witnesses. */
const serializeUnsigned = (tx: RawTransaction) =>
  bytes.concat(
    u32(tx.version),
    varint(tx.inputs.length),
    ...tx.inputs.map(input => bytes.concat(input.txid, u32(input.vout), Uint8Array.of(0), u32(input.sequence))),
    varint(tx.outputs.length),
    ...tx.outputs.map(output =>
      bytes.concat(u64(output.value), varint(output.scriptPubKey.length), output.scriptPubKey)
    ),
    u32(tx.locktime)
  )

/** What a PSBT for an account says about it: its key and where the key came from. */
export type PsbtSigner = {
  readonly publicKey: Uint8Array
  readonly scriptPubKey: Uint8Array
  readonly fingerprint: number
  readonly path: string
}

/**
 * A PSBT of the payment `plan` describes, for a signer to sign: the unsigned transaction (version 2, lock time 0,
 * replaceable inputs), each input's witness UTXO and the key that spends it with its origin, and the same origin on
 * every output that pays the account back (its change). `previousTransactions`, by txid, adds each coin's whole
 * previous transaction, which lets a signer check the values it signs.
 */
export const createPsbt = (
  plan: BitcoinTransactionPlan,
  signer: PsbtSigner,
  context: TransactionContext,
  previousTransactions: Readonly<Record<string, Uint8Array | string>> = {}
): Uint8Array => {
  const {tx} = unsignedTransaction(plan, context)
  const origin: BitcoinKeyOrigin = {fingerprint: signer.fingerprint, path: signer.path, publicKey: signer.publicKey}
  const inputs = tx.inputs.map(input => {
    const txid = hex.encode(input.txid.slice().reverse())
    const previous = previousTransactions[txid]
    const entries: KeyValue[] = []

    if (previous !== undefined) {
      const raw = typeof previous === 'string' ? hex.decode(previous) : previous
      const parsed = parseTransaction(raw)
      const output = parsed.outputs[input.vout]

      if (
        !bytes.equal(hash256(parsed.stripped, context.sha256), input.txid) ||
        !output ||
        output.value !== input.value ||
        !bytes.equal(output.scriptPubKey, signer.scriptPubKey)
      ) {
        throw invalid(`The previous transaction given for ${txid}:${input.vout} is not the coin the plan spends.`)
      }

      entries.push({key: Uint8Array.of(IN_NON_WITNESS_UTXO), value: raw.slice()})
    }

    entries.push(
      {
        key: Uint8Array.of(IN_WITNESS_UTXO),
        value: writeSpentOutput({scriptPubKey: signer.scriptPubKey, value: input.value}),
      },
      derivationEntry(IN_BIP32_DERIVATION, origin)
    )

    return entries
  })
  const outputs = tx.outputs.map(output =>
    bytes.equal(output.scriptPubKey, signer.scriptPubKey) ? [derivationEntry(OUT_BIP32_DERIVATION, origin)] : []
  )

  return serializeMaps({
    global: [{key: Uint8Array.of(GLOBAL_UNSIGNED_TX), value: serializeUnsigned(tx)}],
    inputs,
    outputs,
  })
}

/** The transaction BIP-143 signs: every input with the value of the coin it spends (0 where it is not known). */
const withValues = (tx: RawTransaction, psbt: BitcoinPsbt): RawTransaction => ({
  ...tx,
  inputs: tx.inputs.map((input, index) => ({...input, value: psbt.inputs[index]?.spent?.value ?? 0n})),
})

export type SignedPsbt = {
  /** The PSBT with this account's partial signatures added. */
  readonly psbt: Uint8Array
  /** The inputs it signed, by index. */
  readonly signedInputs: readonly number[]
}

/**
 * Signs every input of a PSBT that spends a coin of `signer` (a P2WPKH output to its key), with SIGHASH_ALL, and
 * adds the signatures as partial signatures. Inputs of other scripts are left alone. Refused (`INVALID_ARGUMENT`):
 * a PSBT with nothing for this signer, an input of its own that asks for another sighash type, and a previous
 * transaction that does not match its input. Whether to sign at all is the caller's question, asked with what
 * `decodePsbt` shows.
 */
export const signPsbt = (data: Uint8Array, signer: P2wpkhSigner, context: TransactionContext): SignedPsbt => {
  const {maps, psbt, tx} = decode(data, context.network, context.sha256)
  const raw = withValues(tx, psbt)
  const scriptCode = p2wpkhScriptCode(signer.scriptPubKey.subarray(2))
  const signedInputs: number[] = []
  const inputs = maps.inputs.map((entries, index) => {
    const input = psbt.inputs[index]

    if (!input?.spent || input.finalized || !bytes.equal(input.spent.scriptPubKey, signer.scriptPubKey)) {
      return entries
    }

    if (input.sighashType !== undefined && input.sighashType !== SIGHASH_ALL) {
      throw invalid(`Input ${index} asks for sighash type ${input.sighashType}; this account signs only SIGHASH_ALL.`)
    }

    const {signature} = signer.key.sign(bip143Digest(raw, index, scriptCode, context.sha256))
    const key = bytes.concat(Uint8Array.of(IN_PARTIAL_SIG), signer.publicKey)
    signedInputs.push(index)

    return [
      ...entries.filter(entry => !bytes.equal(entry.key, key)),
      {key, value: bytes.concat(encodeDerSignature(signature), Uint8Array.of(SIGHASH_ALL))},
    ]
  })

  if (signedInputs.length === 0) {
    throw invalid('No input of this PSBT spends a coin of this account.')
  }

  return Object.freeze({psbt: serializeMaps({...maps, inputs}), signedInputs: Object.freeze(signedInputs)})
}

export type FinalizeContext = TransactionContext & {
  readonly ripemd160: Hash
  /** Whether a 64-byte `r || s` signature by `publicKey` verifies over `digest`: the engine's secp256k1 `verify`. */
  readonly verify: (publicKey: Uint8Array, digest: Uint8Array, signature: Uint8Array) => boolean
}

/**
 * The broadcastable transaction of a PSBT whose every input is a P2WPKH coin with its signature: each signature is
 * checked (strict DER, SIGHASH_ALL, lower S, made by the key the coin pays, over this transaction) before it becomes
 * a witness. Throws `INVALID_SIGNATURE` for one that fails, and `INVALID_ARGUMENT` for an input it cannot finalize.
 */
export const finalizePsbt = (data: Uint8Array, context: FinalizeContext): SignedBitcoinTransaction => {
  const {psbt, tx} = decode(data, context.network, context.sha256)
  const raw = withValues(tx, psbt)

  if (psbt.fee === undefined) {
    throw invalid('Every input needs its coin`s value to be finalized.')
  }

  const witnesses = psbt.inputs.map((input, index) => {
    const script = input.spent?.scriptPubKey

    if (!script || script.length !== 22 || script[0] !== 0x00 || script[1] !== 20) {
      throw invalid(`Input ${index} is not a P2WPKH coin, the only kind this finalizes.`)
    }

    const program = script.subarray(2)
    const candidates = input.partialSignatures.filter(
      ({publicKey}) =>
        publicKey.length === 33 && bytes.equal(hash160(publicKey, context.sha256, context.ripemd160), program)
    )
    const [entry] = candidates

    if (!entry || candidates.length !== 1) {
      throw invalid(`Input ${index} has no signature by the key its coin pays.`)
    }

    const der = entry.signature.subarray(0, -1)
    const compact = decodeDerSignature(der)
    const digest = bip143Digest(raw, index, p2wpkhScriptCode(program), context.sha256)

    if (
      entry.signature[entry.signature.length - 1] !== SIGHASH_ALL ||
      !compact ||
      !context.verify(entry.publicKey, digest, compact)
    ) {
      throw new CryptoError('INVALID_SIGNATURE', `Input ${index}'s signature does not verify for this transaction.`)
    }

    return [entry.signature.slice(), entry.publicKey.slice()]
  })

  return signedTransaction(tx, witnesses, psbt.fee, context.sha256)
}

/** The unsigned transaction a PSBT carries, as bytes: what two PSBTs of the same transaction share. */
export const psbtUnsignedTransaction = (data: Uint8Array): Uint8Array =>
  (field(parseMaps(data).global, GLOBAL_UNSIGNED_TX)?.value ?? new Uint8Array(0)).slice()
