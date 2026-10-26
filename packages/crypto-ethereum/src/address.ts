import {type AddressValidation, hex, utf8} from '@hzblj/nitro-crypto/adapter'

import type {Keccak256} from './types'

/** A `0x`-prefixed, 20-byte address. As returned here, always in its EIP-55 checksum case. */
export type Address = `0x${string}`

export type EthereumAddressValidation =
  | (AddressValidation & {readonly valid: true; readonly normalized: Address; readonly checksum: 'valid' | 'absent'})
  | (AddressValidation & {readonly valid: false})

const SHAPE = /^0x[0-9a-fA-F]{40}$/

/** EIP-55: each letter of the lowercase hex uppercased where the nibble of Keccak-256(lowercase hex) is 8 or more. */
export const checksumAddress = (address: string | Uint8Array, keccak256: Keccak256): Address => {
  const lower = typeof address === 'string' ? address.slice(2).toLowerCase() : hex.encode(address)
  const digest = hex.encode(keccak256(utf8.encode(lower)))
  let out = '0x'

  for (let index = 0; index < lower.length; index++) {
    const char = lower[index] ?? ''
    out += Number.parseInt(digest[index] ?? '0', 16) >= 8 ? char.toUpperCase() : char
  }

  return out as Address
}

/** The address of an uncompressed SEC1 public key: the last 20 bytes of Keccak-256 over its 64 coordinate bytes. */
export const addressFromPublicKey = (uncompressed: Uint8Array, keccak256: Keccak256): Address =>
  checksumAddress(keccak256(uncompressed.subarray(1)).subarray(12), keccak256)

/**
 * Valid when it is 20 bytes of hex and its case is either uniform (no checksum, as many tools write) or exactly
 * EIP-55. Mixed case that is not EIP-55 is a typo the checksum caught.
 */
export const validateAddress = (address: string, keccak256: Keccak256): EthereumAddressValidation => {
  if (!SHAPE.test(address)) {
    return {reason: 'An address is 0x followed by 40 hex digits.', valid: false}
  }

  const normalized = checksumAddress(address, keccak256)
  const body = address.slice(2)

  if (body === body.toLowerCase() || body === body.toUpperCase()) {
    return {checksum: 'absent', normalized, valid: true}
  }

  return address === normalized
    ? {checksum: 'valid', normalized, valid: true}
    : {reason: 'The mixed-case EIP-55 checksum does not match: the address has a typo.', valid: false}
}
