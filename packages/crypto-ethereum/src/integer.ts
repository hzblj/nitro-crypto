import {CryptoError} from '@hzblj/nitro-crypto/adapter'

export const MAX_UINT64 = (1n << 64n) - 1n

export const MAX_UINT256 = (1n << 256n) - 1n

/** An unsigned integer of at most `max`: a `bigint`, or a safe `number` where the field allows one. */
export const checkUint = (value: unknown, name: string, max: bigint = MAX_UINT256): bigint => {
  const resolved =
    typeof value === 'bigint' ? value : typeof value === 'number' && Number.isSafeInteger(value) ? BigInt(value) : -1n

  if (resolved < 0n || resolved > max) {
    throw new CryptoError(
      'INVALID_ARGUMENT',
      `The ${name} is an unsigned integer of at most ${max.toString(2).length} bits.`
    )
  }

  return resolved
}

/** Big-endian bytes without leading zeros, as RLP writes an integer: zero is no bytes at all. */
export const integerBytes = (value: bigint): Uint8Array => {
  if (value === 0n) {
    return new Uint8Array(0)
  }

  let digits = value.toString(16)

  if (digits.length % 2 === 1) {
    digits = `0${digits}`
  }

  const out = new Uint8Array(digits.length / 2)

  for (let index = 0; index < out.length; index++) {
    out[index] = Number.parseInt(digits.slice(index * 2, index * 2 + 2), 16)
  }

  return out
}

/** A 32-byte ABI word: big-endian, left-padded with zeros. */
export const word = (value: bigint | Uint8Array): Uint8Array => {
  const raw = typeof value === 'bigint' ? integerBytes(value) : value
  const out = new Uint8Array(32)
  out.set(raw, 32 - raw.length)

  return out
}

/** The bytes without their leading zeros: an integer's minimal big-endian form (zero is no bytes at all). */
export const trimLeadingZeros = (raw: Uint8Array): Uint8Array => {
  const start = raw.findIndex(byte => byte !== 0)

  return start === -1 ? new Uint8Array(0) : raw.slice(start)
}

const INTEGER_TEXT = /^(-?)(0x[0-9a-fA-F]+|[0-9]+)$/

/**
 * An integer as a `bigint`, a safe `number`, or text the way JSON-RPC payloads carry one (decimal, or `0x` hex, either
 * with a leading minus). `undefined` for anything else, a fractional or unsafe number included.
 */
export const toInteger = (value: unknown): bigint | undefined => {
  if (typeof value === 'bigint') {
    return value
  }

  if (typeof value === 'number') {
    return Number.isSafeInteger(value) ? BigInt(value) : undefined
  }

  const match = typeof value === 'string' ? INTEGER_TEXT.exec(value) : null

  if (!match) {
    return undefined
  }

  const magnitude = BigInt(match[2] ?? '0')

  return match[1] === '-' ? -magnitude : magnitude
}

/** Big-endian bytes as an unsigned integer. */
export const bytesToUint = (raw: Uint8Array): bigint => {
  let out = 0n

  for (const byte of raw) {
    out = (out << 8n) | BigInt(byte)
  }

  return out
}
