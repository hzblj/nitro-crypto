import {AirgapError} from './errors'

export const concatBytes = (...parts: readonly Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((length, part) => length + part.length, 0))
  let offset = 0

  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }

  return out
}

/** Equality without an early exit: the same time for every pair of the same length. */
export const equalBytes = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length !== right.length) {
    return false
  }

  let difference = 0

  for (let index = 0; index < left.length; index++) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0)
  }

  return difference === 0
}

export const u32be = (value: number): Uint8Array => {
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, value >>> 0, false)

  return out
}

const HEX = '0123456789abcdef'

export const toHex = (bytes: Uint8Array): string => {
  let out = ''

  for (const byte of bytes) {
    out += (HEX[byte >> 4] ?? '') + (HEX[byte & 15] ?? '')
  }

  return out
}

export const fromHex = (text: string): Uint8Array => {
  if (text.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(text)) {
    throw new AirgapError('INVALID_ARGUMENT', 'Hex is an even number of hex digits.')
  }

  const out = new Uint8Array(text.length / 2)

  for (let index = 0; index < out.length; index++) {
    out[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16)
  }

  return out
}

/** UTF-8 without `TextEncoder`, which not every React Native runtime has. Lone surrogates are refused. */
export const encodeUtf8 = (text: string): Uint8Array => {
  const out: number[] = []

  for (let index = 0; index < text.length; index++) {
    let point = text.charCodeAt(index)

    if (point >= 0xd800 && point <= 0xdfff) {
      const next = text.charCodeAt(index + 1)

      if (point > 0xdbff || !(next >= 0xdc00 && next <= 0xdfff)) {
        throw new AirgapError('INVALID_ARGUMENT', 'Text contains a lone surrogate, which has no UTF-8 encoding.')
      }

      point = 0x10000 + ((point - 0xd800) << 10) + (next - 0xdc00)
      index++
    }

    if (point < 0x80) {
      out.push(point)
    } else if (point < 0x800) {
      out.push(0xc0 | (point >> 6), 0x80 | (point & 63))
    } else if (point < 0x10000) {
      out.push(0xe0 | (point >> 12), 0x80 | ((point >> 6) & 63), 0x80 | (point & 63))
    } else {
      out.push(0xf0 | (point >> 18), 0x80 | ((point >> 12) & 63), 0x80 | ((point >> 6) & 63), 0x80 | (point & 63))
    }
  }

  return Uint8Array.from(out)
}

/**
 * Strict UTF-8, as CBOR requires of text strings: overlong forms, surrogates, code points past U+10FFFF and truncated
 * sequences are errors, never replacement characters. Returns `undefined` for invalid input.
 */
export const decodeUtf8 = (bytes: Uint8Array): string | undefined => {
  let out = ''
  let index = 0

  while (index < bytes.length) {
    const first = bytes[index] ?? 0
    let needed: number
    let point: number
    let lower = 0x80
    let upper = 0xbf

    if (first <= 0x7f) {
      out += String.fromCharCode(first)
      index++
      continue
    }

    if (first >= 0xc2 && first <= 0xdf) {
      needed = 1
      point = first & 0x1f
    } else if (first >= 0xe0 && first <= 0xef) {
      needed = 2
      point = first & 0xf
      lower = first === 0xe0 ? 0xa0 : 0x80
      upper = first === 0xed ? 0x9f : 0xbf
    } else if (first >= 0xf0 && first <= 0xf4) {
      needed = 3
      point = first & 0x7
      lower = first === 0xf0 ? 0x90 : 0x80
      upper = first === 0xf4 ? 0x8f : 0xbf
    } else {
      return undefined
    }

    for (let offset = 1; offset <= needed; offset++) {
      const byte = bytes[index + offset]

      if (byte === undefined || byte < (offset === 1 ? lower : 0x80) || byte > (offset === 1 ? upper : 0xbf)) {
        return undefined
      }

      point = (point << 6) | (byte & 0x3f)
    }

    out += String.fromCodePoint(point)
    index += needed + 1
  }

  return out
}
