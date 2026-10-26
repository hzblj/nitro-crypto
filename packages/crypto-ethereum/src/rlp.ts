import {bytes} from '@hzblj/nitro-crypto/adapter'

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
