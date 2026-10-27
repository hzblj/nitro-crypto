import {bytes, CryptoError, hex, isCryptoError} from '@hzblj/nitro-crypto/adapter'

import {addressFromScript, type BitcoinAccountType, type Hash, hash160, type TaprootTweak} from './address'
import {decodeDerSignature, encodeDerSignature} from './der'
import type {BitcoinNetwork} from './networks'
import {
  type AccountSigner,
  type BitcoinTransactionPlan,
  bip143Digest,
  hash256,
  MAX_MONEY,
  p2wpkhScriptCode,
  type RawTransaction,
  SIGHASH_ALL,
  SIGHASH_DEFAULT,
  type SignedBitcoinTransaction,
  signedTransaction,
  TAPROOT_SIGHASH_TYPES,
  type TransactionContext,
  taprootSighash,
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

/** A Taproot key's origin (BIP-371): its x-only key, where it came from, and the script leaves it signs in. */
export type BitcoinTaprootKeyOrigin = {
  /** The x-only public key, 32 bytes. */
  readonly publicKey: Uint8Array
  readonly fingerprint: number
  /** `m/86'/1'/0'/0/0`. */
  readonly path: string
  /** The hashes of the script leaves the key signs in (32 bytes each); none for a key that signs the key path. */
  readonly leafHashes: readonly Uint8Array[]
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
  /** The signature hash type asked for; `undefined` means SIGHASH_ALL (SIGHASH_DEFAULT for a Taproot coin). */
  readonly sighashType: number | undefined
  /** BIP-32 derivations of the keys that sign it (`PSBT_IN_BIP32_DERIVATION`): a P2WPKH coin's. */
  readonly derivations: readonly BitcoinKeyOrigin[]
  /** Signatures made so far: DER with the sighash byte, by key. */
  readonly partialSignatures: readonly {readonly publicKey: Uint8Array; readonly signature: Uint8Array}[]
  /** Taproot derivations (`PSBT_IN_TAP_BIP32_DERIVATION`, BIP-371): x-only keys with their origins. */
  readonly taprootDerivations: readonly BitcoinTaprootKeyOrigin[]
  /** A Taproot coin's x-only internal key (`PSBT_IN_TAP_INTERNAL_KEY`), 32 bytes, when the PSBT says. */
  readonly taprootInternalKey: Uint8Array | undefined
  /** The merkle root of its script tree (`PSBT_IN_TAP_MERKLE_ROOT`), 32 bytes; `undefined` for a BIP-86 key. */
  readonly taprootMerkleRoot: Uint8Array | undefined
  /**
   * The key path signature so far (`PSBT_IN_TAP_KEY_SIG`): 64 bytes for SIGHASH_DEFAULT, 65 with any other type in
   * the last byte.
   */
  readonly taprootKeySignature: Uint8Array | undefined
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
  /** The same for a Taproot output (`PSBT_OUT_TAP_BIP32_DERIVATION`): x-only keys with their origins. */
  readonly taprootDerivations: readonly BitcoinTaprootKeyOrigin[]
  /** A Taproot output's x-only internal key (`PSBT_OUT_TAP_INTERNAL_KEY`), 32 bytes, when the PSBT says. */
  readonly taprootInternalKey: Uint8Array | undefined
}

/** What a PSBT asks to be signed, read and checked: every field a wallet shows before it signs. */
export type BitcoinPsbt = {
  /** The id the transaction will have, in display order: SegWit signatures do not change it. */
  readonly txid: string
  readonly version: number
  readonly locktime: number
  readonly inputs: readonly BitcoinPsbtInput[]
  readonly outputs: readonly BitcoinPsbtOutput[]
  /** Satoshis: the inputs less the outputs, when every input states its value and the outputs do not exceed them. */
  readonly fee: bigint | undefined
  /**
   * Satoshis: the inputs less the outputs, when every input states its value. Negative for a PSBT that is not finished:
   * its outputs ask for more than its inputs hold, as a marketplace offer does (a seller's coin and asking price,
   * signed SIGHASH_SINGLE | ANYONECANPAY, waiting for a buyer's inputs). Such a PSBT reads, and neither signs here nor
   * finalizes.
   */
  readonly balance: bigint | undefined
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
const IN_TAP_KEY_SIG = 0x13
const IN_TAP_BIP32_DERIVATION = 0x16
const IN_TAP_INTERNAL_KEY = 0x17
const IN_TAP_MERKLE_ROOT = 0x18
const OUT_BIP32_DERIVATION = 0x02
const OUT_TAP_INTERNAL_KEY = 0x05
const OUT_TAP_BIP32_DERIVATION = 0x07

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
export const parseTransaction = (data: Uint8Array): ParsedTransaction => {
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
      const message = 'A BIP-32 derivation is a public key, a fingerprint and a path.'

      if (!isPublicKey(publicKey)) {
        throw invalid(message)
      }

      return Object.freeze({...readOrigin(value, message), publicKey: publicKey.slice()})
    })

/** A key origin's value: the fingerprint (big-endian, as BIP-32 prints it), then each step of the path. */
const originValue = (origin: {readonly fingerprint: number; readonly path: string}) => {
  const path = parsePath(origin.path)
  const value = new Uint8Array(4 + path.length * 4)
  const view = new DataView(value.buffer)
  view.setUint32(0, origin.fingerprint >>> 0, false)
  path.forEach((index, position) => view.setUint32(4 + position * 4, index, true))

  return value
}

const readOrigin = (value: Uint8Array, message: string) => {
  if (value.length < 4 || value.length % 4 !== 0 || value.length > 4 * 256) {
    throw invalid(message)
  }

  const view = new DataView(value.slice().buffer)
  const path = Array.from({length: value.length / 4 - 1}, (_, index) => view.getUint32(4 + index * 4, true))

  return {fingerprint: view.getUint32(0, false), path: formatPath(path)}
}

const derivationEntry = (type: number, origin: BitcoinKeyOrigin): KeyValue => ({
  key: bytes.concat(Uint8Array.of(type), origin.publicKey),
  value: originValue(origin),
})

/** BIP-371's derivation of a key that signs the key path: no leaf hashes, then the origin. */
const taprootDerivationEntry = (type: number, origin: BitcoinKeyOrigin): KeyValue => ({
  key: bytes.concat(Uint8Array.of(type), origin.publicKey),
  value: bytes.concat(Uint8Array.of(0), originValue(origin)),
})

/** BIP-371's derivations: keyed by an x-only key, their leaf hashes, then the origin. */
const taprootDerivations = (entries: readonly KeyValue[], type: number): BitcoinTaprootKeyOrigin[] =>
  entries
    .filter(entry => entry.key[0] === type)
    .map(({key, value}) => {
      if (key.length !== 33) {
        throw invalid('A Taproot BIP-32 derivation is keyed by a 32-byte x-only public key.')
      }

      const reader: Reader = {data: value, offset: 0}
      const count = readCompactSize(reader)

      if (count > MAX_ENTRIES) {
        throw invalid('A Taproot BIP-32 derivation names more leaves than this reads.')
      }

      const leafHashes = Array.from({length: count}, () => take(reader, 32).slice())
      const origin = readOrigin(
        value.subarray(reader.offset),
        'A Taproot BIP-32 derivation is its leaf hashes, a fingerprint and a path.'
      )

      return Object.freeze({...origin, leafHashes: Object.freeze(leafHashes), publicKey: key.slice(1)})
    })

/**
 * The one entry of `type` whose key is that byte alone, its value of one of `lengths`; `undefined` when there is
 * none. An entry of the type with key data, or of another length, is malformed.
 */
const fixedField = (entries: readonly KeyValue[], type: number, lengths: readonly number[], name: string) => {
  const matching = entries.filter(entry => entry.key[0] === type)
  const [entry] = matching

  if (!entry) {
    return undefined
  }

  if (matching.length > 1 || entry.key.length !== 1 || !lengths.includes(entry.value.length)) {
    throw invalid(`A PSBT's ${name} is malformed.`)
  }

  return entry.value.slice()
}

/** A Taproot key path signature: 64 bytes, or 65 with a sighash type other than SIGHASH_DEFAULT last. */
const isTaprootSignature = (signature: Uint8Array) =>
  signature.length === 64 ||
  (signature.length === 65 && signature[64] !== SIGHASH_DEFAULT && TAPROOT_SIGHASH_TYPES.includes(signature[64] ?? -1))

const taprootKeySignature = (entries: readonly KeyValue[]) => {
  const signature = fixedField(entries, IN_TAP_KEY_SIG, [64, 65], 'Taproot key path signature')

  if (signature && !isTaprootSignature(signature)) {
    throw invalid('A Taproot signature`s 65th byte is a sighash type other than SIGHASH_DEFAULT.')
  }

  return signature
}

/** `OP_1 <32 bytes>`: a Taproot output. */
const isP2tr = (script: Uint8Array) => script.length === 34 && script[0] === 0x51 && script[1] === 32

/** `OP_0 <20 bytes>`: a P2WPKH output. */
const isP2wpkh = (script: Uint8Array) => script.length === 22 && script[0] === 0x00 && script[1] === 20

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
      taprootDerivations: Object.freeze(taprootDerivations(entries, IN_TAP_BIP32_DERIVATION)),
      taprootInternalKey: fixedField(entries, IN_TAP_INTERNAL_KEY, [32], 'Taproot internal key'),
      taprootKeySignature: taprootKeySignature(entries),
      taprootMerkleRoot: fixedField(entries, IN_TAP_MERKLE_ROOT, [32], 'Taproot merkle root'),
      txid: hex.encode(input.txid.slice().reverse()),
      verifiedValue: verified,
      vout: input.vout,
    })
  })
  const outputs = tx.outputs.map((output, index) => {
    const entries = maps.outputs[index] ?? []

    return Object.freeze({
      address: addressFromScript(output.scriptPubKey, network, sha256),
      derivations: Object.freeze(derivations(entries, OUT_BIP32_DERIVATION)),
      scriptPubKey: output.scriptPubKey,
      taprootDerivations: Object.freeze(taprootDerivations(entries, OUT_TAP_BIP32_DERIVATION)),
      taprootInternalKey: fixedField(entries, OUT_TAP_INTERNAL_KEY, [32], 'Taproot internal key'),
      value: output.value,
    })
  })
  const values = inputs.map(input => input.spent?.value)
  const total = (items: readonly bigint[]) => items.reduce((sum, value) => sum + value, 0n)
  const balance = values.every(value => value !== undefined)
    ? total(values as bigint[]) - total(outputs.map(output => output.value))
    : undefined

  return {
    maps,
    psbt: Object.freeze({
      balance,
      fee: balance !== undefined && balance >= 0n ? balance : undefined,
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

/** What a PSBT for an account says about it: its type, its key and where the key came from. */
export type PsbtSigner = {
  readonly type: BitcoinAccountType
  /** Compressed, 33 bytes; a Taproot account's PSBT names its x-only half. */
  readonly publicKey: Uint8Array
  readonly scriptPubKey: Uint8Array
  readonly fingerprint: number
  readonly path: string
}

/**
 * A PSBT of the payment `plan` describes, for a signer to sign: the unsigned transaction (version 2, lock time 0,
 * replaceable inputs), each input's witness UTXO and the key that spends it with its origin, and the same origin on
 * every output that pays the account back (its change). A P2WPKH account's key is a BIP-32 derivation; a Taproot
 * account's, BIP-371's internal key and Taproot derivation. `previousTransactions`, by txid, adds each coin's whole
 * previous transaction, which lets a signer check the values it signs.
 */
export const createPsbt = (
  plan: BitcoinTransactionPlan,
  signer: PsbtSigner,
  context: TransactionContext,
  previousTransactions: Readonly<Record<string, Uint8Array | string>> = {}
): Uint8Array => {
  const {tx} = unsignedTransaction(plan, context)
  const taproot = signer.type === 'p2tr'
  const internalKey = signer.publicKey.subarray(1)
  const origin: BitcoinKeyOrigin = {
    fingerprint: signer.fingerprint,
    path: signer.path,
    publicKey: taproot ? internalKey : signer.publicKey,
  }
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

    entries.push({
      key: Uint8Array.of(IN_WITNESS_UTXO),
      value: writeSpentOutput({scriptPubKey: signer.scriptPubKey, value: input.value}),
    })

    if (taproot) {
      entries.push(taprootDerivationEntry(IN_TAP_BIP32_DERIVATION, origin), {
        key: Uint8Array.of(IN_TAP_INTERNAL_KEY),
        value: internalKey.slice(),
      })
    } else {
      entries.push(derivationEntry(IN_BIP32_DERIVATION, origin))
    }

    return entries
  })
  const outputs = tx.outputs.map(output => {
    if (!bytes.equal(output.scriptPubKey, signer.scriptPubKey)) {
      return []
    }

    return taproot
      ? [
          {key: Uint8Array.of(OUT_TAP_INTERNAL_KEY), value: internalKey.slice()},
          taprootDerivationEntry(OUT_TAP_BIP32_DERIVATION, origin),
        ]
      : [derivationEntry(OUT_BIP32_DERIVATION, origin)]
  })

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

/**
 * Every input's coin script, which a Taproot signature commits to (with every value): `INVALID_ARGUMENT` when an
 * input does not say which coin it spends.
 */
const spentScripts = (psbt: BitcoinPsbt): Uint8Array[] =>
  psbt.inputs.map((input, index) => {
    if (!input.spent) {
      throw invalid(
        `A Taproot signature commits to every coin the transaction spends, and input ${index} does not say which.`
      )
    }

    return input.spent.scriptPubKey
  })

export type SignedPsbt = {
  /** The PSBT with this account's partial signatures added. */
  readonly psbt: Uint8Array
  /** The inputs it signed, by index. */
  readonly signedInputs: readonly number[]
}

export type SignPsbtContext = TransactionContext & {
  /** The engine's BIP-341 tweak: for a Taproot coin of the account's key under a script tree the PSBT names. */
  readonly tweak: TaprootTweak
}

/** One input's signature entry, or `undefined` when the input is not the signer's. */
type InputSigner = (input: BitcoinPsbtInput, index: number) => KeyValue | undefined

const p2wpkhInputSigner = (raw: RawTransaction, signer: AccountSigner, context: SignPsbtContext): InputSigner => {
  const scriptCode = p2wpkhScriptCode(signer.scriptPubKey.subarray(2))
  const key = bytes.concat(Uint8Array.of(IN_PARTIAL_SIG), signer.publicKey)

  return (input, index) => {
    if (!input.spent || !bytes.equal(input.spent.scriptPubKey, signer.scriptPubKey)) {
      return undefined
    }

    if (input.sighashType !== undefined && input.sighashType !== SIGHASH_ALL) {
      throw invalid(`Input ${index} asks for sighash type ${input.sighashType}; this account signs only SIGHASH_ALL.`)
    }

    const {signature} = signer.key.sign(bip143Digest(raw, index, scriptCode, context.sha256))

    return {key, value: bytes.concat(encodeDerSignature(signature), Uint8Array.of(SIGHASH_ALL))}
  }
}

/**
 * A Taproot account signs the key path of its own BIP-86 coins, and of coins whose internal key is its key under a
 * script tree whose merkle root the PSBT gives (`PSBT_IN_TAP_MERKLE_ROOT`), when the tweaked key is the coin's.
 */
const taprootInputSigner = (
  psbt: BitcoinPsbt,
  raw: RawTransaction,
  signer: AccountSigner,
  context: SignPsbtContext
): InputSigner => {
  const internalKey = signer.publicKey.subarray(1)
  let scripts: Uint8Array[] | undefined

  return (input, index) => {
    const script = input.spent?.scriptPubKey
    const merkleRoot = input.taprootMerkleRoot

    if (!script || !isP2tr(script)) {
      return undefined
    }

    if (merkleRoot === undefined) {
      if (!bytes.equal(script, signer.scriptPubKey)) {
        return undefined
      }
    } else if (
      (input.taprootInternalKey && !bytes.equal(input.taprootInternalKey, internalKey)) ||
      !bytes.equal(context.tweak(internalKey, merkleRoot).publicKey, script.subarray(2))
    ) {
      return undefined
    }

    const hashType = input.sighashType ?? SIGHASH_DEFAULT

    if (hashType !== SIGHASH_DEFAULT && hashType !== SIGHASH_ALL) {
      throw invalid(
        `Input ${index} asks for sighash type ${hashType}; this account signs only SIGHASH_DEFAULT and SIGHASH_ALL.`
      )
    }

    scripts ??= spentScripts(psbt)
    const signature = signer.key.signTaproot(taprootSighash(raw, index, scripts, hashType, context.sha256), merkleRoot)

    return {
      key: Uint8Array.of(IN_TAP_KEY_SIG),
      value: hashType === SIGHASH_DEFAULT ? signature : bytes.concat(signature, Uint8Array.of(hashType)),
    }
  }
}

/**
 * Signs every input of a PSBT that spends a coin of `signer` and adds the signatures: a P2WPKH account's as partial
 * signatures (SIGHASH_ALL), a Taproot account's as key path signatures (BIP-371's `PSBT_IN_TAP_KEY_SIG`, with
 * SIGHASH_DEFAULT or SIGHASH_ALL), so a PSBT that spends coins of several accounts, of either type, is signed by each
 * in turn. Inputs of other scripts are left alone. Refused (`INVALID_ARGUMENT`): a PSBT with nothing for this
 * signer, an input of its own that asks for another sighash type, a Taproot input in a PSBT that does not say every
 * coin it spends, and a previous transaction that does not match its input. Whether to sign at all is the caller's
 * question, asked with what `decodePsbt` shows.
 */
export const signPsbt = (data: Uint8Array, signer: AccountSigner, context: SignPsbtContext): SignedPsbt => {
  const {maps, psbt, tx} = decode(data, context.network, context.sha256)

  // This signs SIGHASH_ALL (or Taproot's DEFAULT), which commits to every input: a PSBT whose outputs exceed its
  // inputs could never be completed with such a signature.
  if (psbt.balance !== undefined && psbt.balance < 0n) {
    throw invalid('The PSBT pays out more than its inputs hold: it is not finished, and this signs only SIGHASH_ALL.')
  }

  const raw = withValues(tx, psbt)
  const sign =
    signer.type === 'p2tr' ? taprootInputSigner(psbt, raw, signer, context) : p2wpkhInputSigner(raw, signer, context)
  const signedInputs: number[] = []
  const inputs = maps.inputs.map((entries, index) => {
    const input = psbt.inputs[index]
    const entry = input && !input.finalized ? sign(input, index) : undefined

    if (!entry) {
      return entries
    }

    signedInputs.push(index)

    return [...entries.filter(other => !bytes.equal(other.key, entry.key)), entry]
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
  /** Whether a BIP-340 signature by a 32-byte x-only key verifies: the engine's `schnorr.verify`, for Taproot coins. */
  readonly verifySchnorr: (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) => boolean
}

/** A final script witness, item by item. */
const readWitness = (value: Uint8Array): Uint8Array[] => {
  const reader: Reader = {data: value, offset: 0}
  const count = readCompactSize(reader)

  if (count > MAX_ENTRIES) {
    throw invalid('A final script witness has more items than this reads.')
  }

  const items = Array.from({length: count}, () => readBytes(reader).slice())

  if (reader.offset !== value.length) {
    throw invalid('A final script witness has bytes after its last item.')
  }

  return items
}

const failed = (index: number) =>
  new CryptoError('INVALID_SIGNATURE', `Input ${index}'s signature does not verify for this transaction.`)

/** A P2WPKH input's witness, `[signature, key]`: from its partial signatures, or the final witness its signer wrote. */
const p2wpkhWitness = (
  input: BitcoinPsbtInput,
  index: number,
  program: Uint8Array,
  final: readonly Uint8Array[] | undefined,
  raw: RawTransaction,
  context: FinalizeContext
): Uint8Array[] => {
  const pays = (publicKey: Uint8Array) =>
    publicKey.length === 33 && bytes.equal(hash160(publicKey, context.sha256, context.ripemd160), program)
  let entry: {readonly publicKey: Uint8Array; readonly signature: Uint8Array} | undefined

  if (final) {
    const [signature, publicKey] = final

    if (final.length !== 2 || !signature || !publicKey) {
      throw invalid(`Input ${index} was finalized with a witness that is not a P2WPKH signature and key.`)
    }

    entry = {publicKey, signature}

    if (!pays(publicKey)) {
      throw failed(index)
    }
  } else {
    const candidates = input.partialSignatures.filter(({publicKey}) => pays(publicKey))
    entry = candidates.length === 1 ? candidates[0] : undefined

    if (!entry) {
      throw invalid(`Input ${index} has no signature by the key its coin pays.`)
    }
  }

  const compact = decodeDerSignature(entry.signature.subarray(0, -1))
  const digest = bip143Digest(raw, index, p2wpkhScriptCode(program), context.sha256)

  if (
    entry.signature[entry.signature.length - 1] !== SIGHASH_ALL ||
    !compact ||
    !context.verify(entry.publicKey, digest, compact)
  ) {
    throw failed(index)
  }

  return [entry.signature.slice(), entry.publicKey.slice()]
}

/**
 * A Taproot input's witness, `[signature]`: its key path signature, or the final witness its signer wrote, verified
 * under the output key the coin pays, with the sighash type the signature says (and the PSBT asks for, if it asks).
 */
const taprootWitness = (
  input: BitcoinPsbtInput,
  index: number,
  outputKey: Uint8Array,
  final: readonly Uint8Array[] | undefined,
  raw: RawTransaction,
  scripts: readonly Uint8Array[],
  context: FinalizeContext
): Uint8Array[] => {
  if (final && final.length !== 1) {
    throw invalid(`Input ${index} was finalized with a witness this cannot check: a script path, or an annex.`)
  }

  const signature = final ? final[0] : input.taprootKeySignature

  if (!signature) {
    throw invalid(`Input ${index} has no Taproot key path signature (script path spends are not finalized here).`)
  }

  const hashType = signature.length === 65 ? (signature[64] ?? -1) : SIGHASH_DEFAULT

  if (!isTaprootSignature(signature) || (input.sighashType !== undefined && input.sighashType !== hashType)) {
    throw failed(index)
  }

  let verified: boolean

  try {
    const sighash = taprootSighash(raw, index, scripts, hashType, context.sha256)
    verified = context.verifySchnorr(outputKey, sighash, signature.subarray(0, 64))
  } catch (error) {
    // SIGHASH_SINGLE with no output to sign, or an output key that is no point: nothing verifies.
    if (isCryptoError(error, 'INVALID_ARGUMENT') || isCryptoError(error, 'INVALID_PUBLIC_KEY')) {
      throw failed(index)
    }

    throw error
  }

  if (!verified) {
    throw failed(index)
  }

  return [signature.slice()]
}

/**
 * The broadcastable transaction of a PSBT whose every input is a P2WPKH or Taproot coin with its signature, or
 * already finalized by its signer. Each signature is checked before it becomes a witness: P2WPKH's strict DER,
 * SIGHASH_ALL, lower S, by the key the coin pays; a Taproot key path's BIP-340 signature under the coin's output key,
 * for the sighash type it carries. Throws `INVALID_SIGNATURE` for one that fails, and `INVALID_ARGUMENT` for an input
 * it cannot finalize (another script, a Taproot script path).
 */
export const finalizePsbt = (data: Uint8Array, context: FinalizeContext): SignedBitcoinTransaction => {
  const {maps, psbt, tx} = decode(data, context.network, context.sha256)
  const raw = withValues(tx, psbt)

  if (psbt.balance !== undefined && psbt.balance < 0n) {
    throw invalid('The PSBT pays out more than its inputs hold: it is not finished, so it does not finalize.')
  }

  if (psbt.fee === undefined) {
    throw invalid('Every input needs its coin`s value to be finalized.')
  }

  const scripts = spentScripts(psbt)
  const witnesses = psbt.inputs.map((input, index) => {
    const script = scripts[index] ?? new Uint8Array(0)
    const entries = maps.inputs[index] ?? []
    const finalScript = field(entries, IN_FINAL_SCRIPTSIG)
    const finalWitness = field(entries, IN_FINAL_SCRIPTWITNESS)

    if (finalScript && finalScript.value.length > 0) {
      throw invalid(`Input ${index} was finalized with a script; native SegWit coins have none.`)
    }

    const final = finalWitness ? readWitness(finalWitness.value) : undefined

    if (isP2wpkh(script)) {
      return p2wpkhWitness(input, index, script.subarray(2), final, raw, context)
    }

    if (isP2tr(script)) {
      return taprootWitness(input, index, script.subarray(2), final, raw, scripts, context)
    }

    throw invalid(`Input ${index} is not a P2WPKH or P2TR coin, the kinds this finalizes.`)
  })

  return signedTransaction(tx, witnesses, psbt.fee, context.sha256)
}

/** The unsigned transaction a PSBT carries, as bytes: what two PSBTs of the same transaction share. */
export const psbtUnsignedTransaction = (data: Uint8Array): Uint8Array =>
  (field(parseMaps(data).global, GLOBAL_UNSIGNED_TX)?.value ?? new Uint8Array(0)).slice()
