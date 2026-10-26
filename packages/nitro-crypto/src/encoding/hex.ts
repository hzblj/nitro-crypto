import {CryptoError} from '../core/errors'

/** A `0x`-prefixed hex string, as Ethereum writes bytes. */
export type Hex = `0x${string}`

const ALPHABET = '0123456789abcdef'

const nibble = (code: number): number => {
  if (code >= 48 && code <= 57) {
    return code - 48
  }

  const lower = code | 0x20

  if (lower >= 97 && lower <= 102) {
    return lower - 87
  }

  return -1
}

export const hex = {
  /** Even-length hex in either case, with or without `0x`. Anything else is `INVALID_ENCODING`. */
  decode: (text: string): Uint8Array<ArrayBuffer> => {
    const digits = text.startsWith('0x') || text.startsWith('0X') ? text.slice(2) : text

    if (digits.length % 2 !== 0) {
      throw new CryptoError('INVALID_ENCODING', 'Hex needs an even number of digits.')
    }

    const out = new Uint8Array(digits.length / 2)

    for (let index = 0; index < out.length; index++) {
      const high = nibble(digits.charCodeAt(index * 2))
      const low = nibble(digits.charCodeAt(index * 2 + 1))

      if (high < 0 || low < 0) {
        throw new CryptoError('INVALID_ENCODING', 'Hex contains a character that is not a hex digit.')
      }

      out[index] = (high << 4) | low
    }

    return out
  },
  /** Lowercase hex, without a prefix unless asked. */
  encode: (bytes: Uint8Array, options: {prefix?: boolean} = {}): string => {
    let out = options.prefix ? '0x' : ''

    for (const byte of bytes) {
      out += (ALPHABET[byte >> 4] ?? '') + (ALPHABET[byte & 15] ?? '')
    }

    return out
  },

  isHex: (text: string): boolean => /^(0[xX])?([0-9a-fA-F]{2})*$/.test(text),
}
