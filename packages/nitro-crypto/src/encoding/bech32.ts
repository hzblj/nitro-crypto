import {CryptoError} from '../core/errors'

/**
 * Bech32 (BIP-173) and Bech32m (BIP-350): the checksummed base-32 strings of SegWit addresses, and of Cosmos and
 * Lightning. The witness-version rules are Bitcoin's and live in its adapter; this is only the encoding.
 */
export type Bech32Variant = 'bech32' | 'bech32m'

export type Bech32Decoded = {
  /** Lowercase human-readable part, such as `bc` or `tb`. */
  readonly hrp: string
  /** The data part as 5-bit words, without the checksum. */
  readonly words: readonly number[]
  readonly variant: Bech32Variant
}

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
const WORDS = new Map([...CHARSET].map((char, index) => [char, index]))
const CONSTANTS: Record<Bech32Variant, number> = {bech32: 1, bech32m: 0x2bc830a3}
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
/** BIP-173's limit; Lightning invoices, which exceed it, pass their own. */
const DEFAULT_LIMIT = 90

const polymod = (values: readonly number[]): number => {
  let checksum = 1

  for (const value of values) {
    const top = checksum >>> 25
    checksum = ((checksum & 0x1ffffff) << 5) ^ value
    GENERATOR.forEach((generator, bit) => {
      if ((top >>> bit) & 1) {
        checksum ^= generator
      }
    })
  }

  return checksum >>> 0
}

const expandHrp = (hrp: string): number[] => [
  ...[...hrp].map(char => char.charCodeAt(0) >> 5),
  0,
  ...[...hrp].map(char => char.charCodeAt(0) & 31),
]

const createChecksum = (hrp: string, words: readonly number[], variant: Bech32Variant): number[] => {
  const value = polymod([...expandHrp(hrp), ...words, 0, 0, 0, 0, 0, 0]) ^ CONSTANTS[variant]

  return Array.from({length: 6}, (_, index) => (value >>> (5 * (5 - index))) & 31)
}

const invalid = (message: string) => new CryptoError('INVALID_ENCODING', message)

const isValidHrp = (hrp: string) => hrp.length > 0 && [...hrp].every(char => char >= '!' && char <= '~')

const encode = (hrp: string, words: readonly number[], variant: Bech32Variant, limit = DEFAULT_LIMIT): string => {
  const lower = hrp.toLowerCase()

  if (!isValidHrp(lower)) {
    throw invalid('A Bech32 human-readable part is 1 or more printable ASCII characters.')
  }

  if (words.some(word => !Number.isInteger(word) || word < 0 || word > 31)) {
    throw invalid('Bech32 data words are integers from 0 to 31.')
  }

  const text = `${lower}1${[...words, ...createChecksum(lower, words, variant)].map(word => CHARSET[word]).join('')}`

  if (text.length > limit) {
    throw invalid(`Bech32 strings are at most ${limit} characters.`)
  }

  return text
}

const decode = (text: string, limit = DEFAULT_LIMIT): Bech32Decoded => {
  if (text.length > limit) {
    throw invalid(`Bech32 strings are at most ${limit} characters.`)
  }

  if (text !== text.toLowerCase() && text !== text.toUpperCase()) {
    throw invalid('Bech32 strings are all lowercase or all uppercase.')
  }

  const lower = text.toLowerCase()
  const separator = lower.lastIndexOf('1')

  if (separator < 1 || lower.length - separator - 1 < 6) {
    throw invalid('Bech32 needs a human-readable part, a 1, and at least six checksum characters.')
  }

  const hrp = lower.slice(0, separator)

  if (!isValidHrp(hrp)) {
    throw invalid('The Bech32 human-readable part has a character outside printable ASCII.')
  }

  const values = [...lower.slice(separator + 1)].map(char => WORDS.get(char))

  if (values.some(value => value === undefined)) {
    throw invalid('Bech32 data has a character outside its alphabet.')
  }

  const words = values as number[]
  const residue = polymod([...expandHrp(hrp), ...words])
  const variant = (Object.keys(CONSTANTS) as Bech32Variant[]).find(name => CONSTANTS[name] === residue)

  if (!variant) {
    throw invalid('The Bech32 checksum does not match.')
  }

  return {hrp, variant, words: words.slice(0, -6)}
}

/** Regroups bits: 8 to 5 pads the last word with zeros; 5 to 8 refuses padding that is not zeros or too long. */
const convertBits = (data: readonly number[], from: number, to: number, pad: boolean): number[] => {
  let accumulator = 0
  let bits = 0
  const out: number[] = []
  const max = (1 << to) - 1

  for (const value of data) {
    accumulator = (accumulator << from) | value
    bits += from

    while (bits >= to) {
      bits -= to
      out.push((accumulator >> bits) & max)
    }

    accumulator &= (1 << bits) - 1
  }

  if (pad && bits > 0) {
    out.push((accumulator << (to - bits)) & max)
  } else if (!pad && (bits >= from || ((accumulator << (to - bits)) & max) !== 0)) {
    throw invalid('Bech32 data has invalid padding.')
  }

  return out
}

export const bech32 = {
  decode,
  encode,
  /** 5-bit words to bytes. */
  fromWords: (words: readonly number[]): Uint8Array<ArrayBuffer> => Uint8Array.from(convertBits(words, 5, 8, false)),
  /** Bytes to 5-bit words, the last one zero-padded. */
  toWords: (bytes: Uint8Array): number[] => convertBits([...bytes], 8, 5, true),
}
