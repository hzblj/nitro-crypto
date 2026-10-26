import {bytes, CryptoError} from '@hzblj/nitro-crypto/adapter'

import {integerBytes} from './integer'

/** What RLP encodes: a byte string, or a list of items. */
export type RlpItem = Uint8Array | readonly RlpItem[]

/** The prefix for a payload of `length` bytes: `short + length` up to 55 bytes, else `long + size of length` and it. */
const header = (length: number, short: number, long: number): Uint8Array => {
  if (length <= 55) {
    return Uint8Array.of(short + length)
  }

  const size = integerBytes(BigInt(length))

  return bytes.concat(Uint8Array.of(long + size.length), size)
}

/**
 * Recursive Length Prefix, Ethereum's serialization (Yellow Paper, appendix B). A single byte below 0x80 is itself;
 * any other string and every list carry a length prefix. Integers go in as their minimal big-endian bytes
 * (`rlpInteger`), so zero is the empty string, 0x80.
 */
export const rlpEncode = (item: RlpItem): Uint8Array => {
  if (item instanceof Uint8Array) {
    if (item.length === 1 && (item[0] ?? 0) < 0x80) {
      return item.slice()
    }

    return bytes.concat(header(item.length, 0x80, 0xb7), item)
  }

  const payload = bytes.concat(...item.map(rlpEncode))

  return bytes.concat(header(payload.length, 0xc0, 0xf7), payload)
}

/** An unsigned integer as RLP takes it: big-endian, no leading zeros. */
export const rlpInteger = (value: bigint): Uint8Array => integerBytes(value)

const malformed = (message: string) => new CryptoError('INVALID_ENCODING', message)

type Reader = {readonly data: Uint8Array; offset: number}

/** A long-form length: big-endian, no leading zero, and more than 55 (or the short form was due). */
const longLength = (reader: Reader, size: number): number => {
  const raw = reader.data.subarray(reader.offset, reader.offset + size)

  if (raw.length !== size || raw[0] === 0 || size > 4) {
    throw malformed('An RLP length is cut short, padded with zeros, or too large.')
  }

  reader.offset += size
  const length = raw.reduce((total, byte) => total * 256 + byte, 0)

  if (length <= 55) {
    throw malformed('An RLP item of 55 bytes or fewer uses the short form.')
  }

  return length
}

const readItem = (reader: Reader, depth: number): RlpItem => {
  if (depth > 16) {
    throw malformed('RLP nests deeper than this reads.')
  }

  const first = reader.data[reader.offset]

  if (first === undefined) {
    throw malformed('The RLP ends in the middle of an item.')
  }

  reader.offset++

  if (first < 0x80) {
    return Uint8Array.of(first)
  }

  const isList = first >= 0xc0
  const base = isList ? 0xc0 : 0x80
  const length = first - base <= 55 ? first - base : longLength(reader, first - base - 55)
  const end = reader.offset + length

  if (end > reader.data.length) {
    throw malformed('An RLP item runs past the end of its input.')
  }

  if (!isList) {
    const value = reader.data.slice(reader.offset, end)
    reader.offset = end

    if (value.length === 1 && (value[0] ?? 0) < 0x80) {
      throw malformed('A single byte below 0x80 is its own RLP encoding.')
    }

    return value
  }

  const items: RlpItem[] = []

  while (reader.offset < end) {
    items.push(readItem(reader, depth + 1))
  }

  if (reader.offset !== end) {
    throw malformed('An RLP list`s items run past its length.')
  }

  return items
}

/**
 * RLP decoding, strict: only the canonical encoding of each item is accepted (the one `rlpEncode` writes), and the
 * input must hold exactly one item. Throws `INVALID_ENCODING` for anything else.
 */
export const rlpDecode = (data: Uint8Array): RlpItem => {
  const reader: Reader = {data, offset: 0}
  const item = readItem(reader, 0)

  if (reader.offset !== data.length) {
    throw malformed('The RLP has bytes after its item.')
  }

  return item
}
