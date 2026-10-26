import {type AddressValidation, base58, CryptoError, isCryptoError} from '@hzblj/nitro-crypto/adapter'

/** A Solana address: the Base58 text of 32 bytes, usually an Ed25519 public key. */
export type SolanaAddress = string

export const PUBLIC_KEY_LENGTH = 32

export const addressFromPublicKey = (publicKey: Uint8Array): SolanaAddress => base58.encode(publicKey)

/**
 * Valid when it is the canonical Base58 of exactly 32 bytes. Whether those bytes are a point on the curve is not
 * checked: program-derived addresses are deliberately off the curve, and they are addresses too.
 */
export const validateAddress = (address: string): AddressValidation => {
  try {
    const decoded = base58.decode(address)

    if (decoded.length !== PUBLIC_KEY_LENGTH) {
      return {reason: 'A Solana address is 32 bytes.', valid: false}
    }

    const canonical = base58.encode(decoded)

    return canonical === address
      ? {normalized: canonical, valid: true}
      : {reason: 'Not the canonical Base58 of its bytes.', valid: false}
  } catch (error) {
    if (isCryptoError(error, 'INVALID_ENCODING')) {
      return {reason: 'A Solana address is Base58.', valid: false}
    }

    throw error
  }
}

/** The 32 bytes of an address, which must be valid: `what` names it in the error (`recipient`, `mint`). */
export const addressBytes = (address: string, what: string): Uint8Array => {
  const validation = validateAddress(address)

  if (!validation.valid) {
    throw new CryptoError('INVALID_ADDRESS', `The ${what} is not a Solana address: ${validation.reason}`)
  }

  return base58.decode(address)
}
