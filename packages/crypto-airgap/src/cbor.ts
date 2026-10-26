import {concatBytes, decodeUtf8, encodeUtf8} from './bytes'
import {AirgapError} from './errors'

/**
 * The CBOR (RFC 8949) the UR registry types are written in, and nothing more: integers, byte and text strings,
 * arrays, maps keyed by integers or text, tags, booleans, null and undefined. Floats, indefinite lengths and other
 * simple values are refused, which no registry type uses and every hostile payload might.
 */

/** A map key: what every registry type keys its maps with. */
export type CborKey = number | string

/** A tagged item, such as `#6.304(keypath)`. The only plain object a `CborValue` can be. */
export type CborTagged = {readonly tag: number; readonly value: CborValue}

export type CborMap = ReadonlyMap<CborKey, CborValue>

/** Integers within ±2^53 are numbers; past that, bigints. */
export type CborValue =
  | number
  | bigint
  | string
  | Uint8Array
  | boolean
  | null
  | undefined
  | readonly CborValue[]
  | CborMap
  | CborTagged

export type CborLimits = {
  /** Nesting of arrays, maps and tags. 16 unless stated: the deepest registry type nests six. */
  readonly maxDepth?: number
  /** Items in the whole payload, counted as they are read. 100,000 unless stated. */
  readonly maxItems?: number
}

const DEFAULT_MAX_DEPTH = 16
const DEFAULT_MAX_ITEMS = 100_000

/** Tags past 2^32 exist in the IANA registry, none of them in a UR type. */
const MAX_TAG = 0xffffffff

export const cborTag = (tag: number, value: CborValue): CborTagged => Object.freeze({tag, value})

export const isCborTagged = (value: CborValue): value is CborTagged =>
  typeof value === 'object' &&
  value !== null &&
  !(value instanceof Uint8Array) &&
  !(value instanceof Map) &&
  !Array.isArray(value)

const invalidValue = (message: string) => new AirgapError('INVALID_ARGUMENT', message)

const head = (major: number, value: number | bigint): Uint8Array => {
  const type = major << 5

  if (typeof value === 'number' && value < 24) {
    return Uint8Array.of(type | value)
  }

  if (typeof value === 'number' && value <= 0xff) {
    return Uint8Array.of(type | 24, value)
  }

  if (typeof value === 'number' && value <= 0xffff) {
    return Uint8Array.of(type | 25, value >> 8, value & 0xff)
  }

  if (typeof value === 'number' && value <= 0xffffffff) {
    const out = new Uint8Array(5)
    out[0] = type | 26
    new DataView(out.buffer).setUint32(1, value, false)

    return out
  }

  const out = new Uint8Array(9)
  out[0] = type | 27
  new DataView(out.buffer).setBigUint64(1, BigInt(value), false)

  return out
}

const MAX_UINT64 = 0xffffffffffffffffn

const encodeInteger = (value: number | bigint): Uint8Array => {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) {
    throw invalidValue('A CBOR number is a safe integer: pass a bigint past 2^53, and no fractions.')
  }

  const big = BigInt(value)

  if (big > MAX_UINT64 || big < -MAX_UINT64 - 1n) {
    throw invalidValue('A CBOR integer fits in 64 bits and a sign.')
  }

  if (big >= 0n) {
    return head(0, big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big)
  }

  const magnitude = -1n - big

  return head(1, magnitude <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(magnitude) : magnitude)
}

const compareBytes = (left: Uint8Array, right: Uint8Array) => {
  const length = Math.min(left.length, right.length)

  for (let index = 0; index < length; index++) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0)

    if (difference !== 0) {
      return difference
    }
  }

  return left.length - right.length
}

const encodeItem = (value: CborValue, depth: number): Uint8Array => {
  if (depth > DEFAULT_MAX_DEPTH) {
    throw invalidValue('The value nests deeper than CBOR here allows.')
  }

  switch (typeof value) {
    case 'number':
    case 'bigint':
      return encodeInteger(value)
    case 'string': {
      const text = encodeUtf8(value)

      return concatBytes(head(3, text.length), text)
    }
    case 'boolean':
      return Uint8Array.of(value ? 0xf5 : 0xf4)
    case 'undefined':
      return Uint8Array.of(0xf7)
  }

  if (value === null) {
    return Uint8Array.of(0xf6)
  }

  if (value instanceof Uint8Array) {
    return concatBytes(head(2, value.length), value)
  }

  if (Array.isArray(value)) {
    return concatBytes(head(4, value.length), ...value.map(item => encodeItem(item, depth + 1)))
  }

  if (value instanceof Map) {
    // Core Deterministic Encoding (RFC 8949, 4.2.1): keys in the bytewise order of their own encodings.
    const entries = [...value.entries()].map(([key, item]) => {
      if (typeof key !== 'string' && (typeof key !== 'number' || !Number.isSafeInteger(key))) {
        throw invalidValue('A CBOR map key here is an integer or text.')
      }

      return [encodeItem(key, depth + 1), encodeItem(item, depth + 1)] as const
    })
    entries.sort(([left], [right]) => compareBytes(left, right))

    return concatBytes(head(5, entries.length), ...entries.flat())
  }

  const tagged = value as CborTagged

  if (!Number.isSafeInteger(tagged.tag) || tagged.tag < 0 || tagged.tag > MAX_TAG) {
    throw invalidValue('A CBOR tag is an integer from 0 to 2^32 - 1.')
  }

  return concatBytes(head(6, tagged.tag), encodeItem(tagged.value, depth + 1))
}

/** The deterministic CBOR of `value`: shortest heads, definite lengths, map keys sorted. */
export const encodeCbor = (value: CborValue): Uint8Array => encodeItem(value, 0)

const malformed = (message: string) => new AirgapError('INVALID_CBOR', message)

type Reader = {
  readonly bytes: Uint8Array
  readonly view: DataView
  offset: number
  items: number
  readonly maxDepth: number
  readonly maxItems: number
}

const take = (reader: Reader, length: number): Uint8Array => {
  if (length > reader.bytes.length - reader.offset) {
    throw malformed('The CBOR ends in the middle of an item.')
  }

  const out = reader.bytes.subarray(reader.offset, reader.offset + length)
  reader.offset += length

  return out
}

/** The argument of an item's head: a number when it is a safe integer, a bigint past that. */
const readArgument = (reader: Reader, info: number): number | bigint => {
  if (info < 24) {
    return info
  }

  const width = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : 0

  if (width === 0) {
    // 28 to 30 are reserved; 31 is an indefinite length, refused here.
    throw malformed(info === 31 ? 'Indefinite-length CBOR is not accepted.' : 'The CBOR uses a reserved encoding.')
  }

  const start = reader.offset
  take(reader, width)

  if (width === 1) {
    return reader.view.getUint8(start)
  }

  if (width === 2) {
    return reader.view.getUint16(start, false)
  }

  if (width === 4) {
    return reader.view.getUint32(start, false)
  }

  const big = reader.view.getBigUint64(start, false)

  return big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big
}

/** A length or count: never more than the bytes left, which bounds every allocation by the input's size. */
const readLength = (reader: Reader, info: number, minimumItemSize: number): number => {
  const length = readArgument(reader, info)

  if (typeof length === 'bigint' || length * minimumItemSize > reader.bytes.length - reader.offset) {
    throw malformed('A CBOR length runs past the end of the payload.')
  }

  return length
}

const readItem = (reader: Reader, depth: number): CborValue => {
  if (depth > reader.maxDepth) {
    throw new AirgapError('PAYLOAD_TOO_LARGE', 'The CBOR nests deeper than the configured limit.')
  }

  reader.items++

  if (reader.items > reader.maxItems) {
    throw new AirgapError('PAYLOAD_TOO_LARGE', 'The CBOR holds more items than the configured limit.')
  }

  const initial = take(reader, 1)[0] ?? 0
  const major = initial >> 5
  const info = initial & 0x1f

  switch (major) {
    case 0:
      return readArgument(reader, info)
    case 1: {
      const magnitude = readArgument(reader, info)

      return typeof magnitude === 'number' && magnitude < Number.MAX_SAFE_INTEGER
        ? -1 - magnitude
        : -1n - BigInt(magnitude)
    }
    case 2:
      // A plain copy, whatever the input is: a Node Buffer's `slice` would return a view into it.
      return new Uint8Array(take(reader, readLength(reader, info, 1)))
    case 3: {
      const text = decodeUtf8(take(reader, readLength(reader, info, 1)))

      if (text === undefined) {
        throw malformed('A CBOR text string is not valid UTF-8.')
      }

      return text
    }
    case 4: {
      const length = readLength(reader, info, 1)

      return Object.freeze(Array.from({length}, () => readItem(reader, depth + 1)))
    }
    case 5: {
      const length = readLength(reader, info, 2)
      const map = new Map<CborKey, CborValue>()

      for (let index = 0; index < length; index++) {
        const key = readItem(reader, depth + 1)

        if (typeof key !== 'string' && typeof key !== 'number') {
          throw malformed('A CBOR map key here is an integer or text.')
        }

        if (map.has(key)) {
          throw malformed('A CBOR map repeats a key.')
        }

        map.set(key, readItem(reader, depth + 1))
      }

      return map
    }
    case 6: {
      const tag = readArgument(reader, info)

      if (typeof tag === 'bigint' || tag > MAX_TAG) {
        throw malformed('A CBOR tag past 2^32 is not one a UR type uses.')
      }

      return cborTag(tag, readItem(reader, depth + 1))
    }
  }

  switch (info) {
    case 20:
      return false
    case 21:
      return true
    case 22:
      return null
    case 23:
      return undefined
    case 25:
    case 26:
    case 27:
      throw malformed('Floating-point CBOR is not accepted.')
    default:
      throw malformed(info === 31 ? 'Indefinite-length CBOR is not accepted.' : 'The CBOR uses a simple value.')
  }
}

/**
 * Reads exactly one CBOR item from `bytes`, which must hold nothing after it. Lengths are checked against the bytes
 * left before anything is allocated, and nesting and item counts against `limits`, so hostile input fails fast.
 * Throws `INVALID_CBOR` for malformed or unsupported CBOR, `PAYLOAD_TOO_LARGE` past a limit.
 */
export const decodeCbor = (bytes: Uint8Array, limits: CborLimits = {}): CborValue => {
  const reader: Reader = {
    bytes,
    items: 0,
    maxDepth: limits.maxDepth ?? DEFAULT_MAX_DEPTH,
    maxItems: limits.maxItems ?? DEFAULT_MAX_ITEMS,
    offset: 0,
    view: new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength),
  }
  const value = readItem(reader, 0)

  if (reader.offset !== bytes.length) {
    throw malformed('The CBOR has bytes after its item.')
  }

  return value
}
