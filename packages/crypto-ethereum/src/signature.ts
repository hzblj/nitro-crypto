import {CryptoError, hex, type RecoverableSignature, type RecoveryId} from '@hzblj/nitro-crypto/adapter'

import type {Hex} from './types'

/** Ethereum writes a signature as 65 bytes of hex, `r || s || v`, with v = 27 + the recovery id. */
export const serializeSignature = ({recovery, signature}: RecoverableSignature): Hex => {
  const out = new Uint8Array(65)
  out.set(signature)
  out[64] = 27 + recovery

  return hex.encode(out, {prefix: true}) as Hex
}

/** Accepts v as 27/28 (legacy) or 0/1 (as EIP-2098 compact producers and some libraries write it). */
export const parseSignature = (text: Hex | Uint8Array): RecoverableSignature => {
  const raw = typeof text === 'string' ? hex.decode(text) : text

  if (raw.length !== 65) {
    throw new CryptoError('INVALID_SIGNATURE', 'An Ethereum signature is 65 bytes: r, s and v.')
  }

  const v = raw[64] ?? 0
  const recovery = v >= 27 ? v - 27 : v

  if (recovery !== 0 && recovery !== 1) {
    throw new CryptoError('INVALID_SIGNATURE', 'An Ethereum signature has v of 27 or 28 (or 0 or 1).')
  }

  return {recovery: recovery as RecoveryId, signature: raw.slice(0, 64)}
}
