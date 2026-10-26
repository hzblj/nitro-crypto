import {concatBytes, equalBytes} from '../core/bytes'
import {CryptoError} from '../core/errors'

/** Bitcoin's Base58 alphabet, which Solana, TRON and most chains that use Base58 share. */
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

const DIGITS = new Map([...ALPHABET].map((char, index) => [char, index]))

const leadingZeros = <T>(items: ArrayLike<T>, zero: T): number => {
  let count = 0

  while (count < items.length && items[count] === zero) {
    count++
  }

  return count
}

/** Repeated division by 58 over the big-endian bytes; leading zero bytes become leading `1`s. */
const encode = (bytes: Uint8Array): string => {
  const zeros = leadingZeros(bytes, 0)
  const digits: number[] = []

  for (const byte of bytes.subarray(zeros)) {
    let carry = byte

    for (let index = 0; index < digits.length; index++) {
      carry += (digits[index] ?? 0) << 8
      digits[index] = carry % 58
      carry = Math.floor(carry / 58)
    }

    while (carry > 0) {
      digits.push(carry % 58)
      carry = Math.floor(carry / 58)
    }
  }

  return (
    '1'.repeat(zeros) +
    digits
      .reverse()
      .map(digit => ALPHABET[digit] ?? '')
      .join('')
  )
}

const decode = (text: string): Uint8Array<ArrayBuffer> => {
  const zeros = leadingZeros(text, '1')
  const bytes: number[] = []

  for (const char of text.slice(zeros)) {
    let carry = DIGITS.get(char)

    if (carry === undefined) {
      throw new CryptoError('INVALID_ENCODING', 'Base58 contains a character outside its alphabet.')
    }

    for (let index = 0; index < bytes.length; index++) {
      carry += (bytes[index] ?? 0) * 58
      bytes[index] = carry & 0xff
      carry >>= 8
    }

    while (carry > 0) {
      bytes.push(carry & 0xff)
      carry >>= 8
    }
  }

  return concatBytes(new Uint8Array(zeros), Uint8Array.from(bytes.reverse()))
}

export const base58 = {decode, encode}

/** The SHA-256 Base58Check needs, passed in so this module stays pure (adapters hand it the engine's). */
export type Sha256 = (data: Uint8Array) => Uint8Array

const checksum = (payload: Uint8Array, sha256: Sha256) => sha256(sha256(payload)).subarray(0, 4)

export const base58check = {
  /** Base58 of `payload || SHA-256(SHA-256(payload))[0..4]`. */
  decode: (text: string, sha256: Sha256): Uint8Array<ArrayBuffer> => {
    const raw = decode(text)

    if (raw.length < 4) {
      throw new CryptoError('INVALID_ENCODING', 'Base58Check is shorter than its checksum.')
    }

    const payload = raw.slice(0, -4)

    if (!equalBytes(raw.subarray(-4), checksum(payload, sha256))) {
      throw new CryptoError('INVALID_ENCODING', 'Base58Check checksum does not match.')
    }

    return payload
  },
  encode: (payload: Uint8Array, sha256: Sha256): string => encode(concatBytes(payload, checksum(payload, sha256))),
}
