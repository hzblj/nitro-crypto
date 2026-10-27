import {CryptoError} from '@hzblj/nitro-crypto/adapter'

/**
 * Base64 (RFC 4648, the standard alphabet), as Bitcoin message signatures are written. Not every React Native runtime
 * has `atob`, and `atob` is lenient, so this is the package's own: decoding is strict, and refuses anything that is
 * not the canonical spelling of some bytes.
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

const VALUES = new Map([...ALPHABET].map((char, index) => [char, index]))

const invalid = () => new CryptoError('INVALID_ENCODING', 'Not Base64.')

export const encodeBase64 = (data: Uint8Array): string => {
  let out = ''

  for (let index = 0; index < data.length; index += 3) {
    const [a = 0, b = 0, c = 0] = [data[index], data[index + 1], data[index + 2]]
    const triple = (a << 16) | (b << 8) | c
    const remaining = data.length - index
    out += ALPHABET[(triple >> 18) & 63]
    out += ALPHABET[(triple >> 12) & 63]
    out += remaining > 1 ? ALPHABET[(triple >> 6) & 63] : '='
    out += remaining > 2 ? ALPHABET[triple & 63] : '='
  }

  return out
}

/**
 * The bytes of Base64 text. Padding may be left out, as some wallets do; when it is there it must be right, and the
 * bits after the last byte must be zero. Throws `INVALID_ENCODING`.
 */
export const decodeBase64 = (text: string): Uint8Array => {
  if (typeof text !== 'string') {
    throw invalid()
  }

  const body = text.replace(/={1,2}$/, '')

  if ((body.length !== text.length && text.length % 4 !== 0) || body.length % 4 === 1) {
    throw invalid()
  }

  const out = new Uint8Array(Math.floor((body.length * 3) / 4))
  let buffer = 0
  let bits = 0
  let written = 0

  for (const char of body) {
    const value = VALUES.get(char)

    if (value === undefined) {
      throw invalid()
    }

    buffer = ((buffer << 6) | value) & 0xffffff
    bits += 6

    if (bits >= 8) {
      bits -= 8
      out[written++] = (buffer >> bits) & 0xff
    }
  }

  if ((buffer & ((1 << bits) - 1)) !== 0) {
    throw invalid()
  }

  return out
}
