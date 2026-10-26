import {bytes, CryptoError} from '@hzblj/nitro-crypto/adapter'

/** An integer as DER writes it: no leading zero bytes, and one zero byte first when the high bit would read as a sign. */
const derInteger = (value: Uint8Array): Uint8Array => {
  let start = 0

  while (start < value.length - 1 && value[start] === 0) {
    start++
  }

  const trimmed = value.subarray(start)

  return (trimmed[0] ?? 0) & 0x80 ? bytes.concat(Uint8Array.of(0), trimmed) : trimmed
}

/**
 * A 64-byte `r || s` signature in strict DER (BIP-66), as a Bitcoin script carries it: `0x30 len 0x02 rlen r 0x02
 * slen s`. The engine signs with a lower-S `s`, which BIP-146's policy requires; this does not change it.
 */
export const encodeDerSignature = (signature: Uint8Array): Uint8Array => {
  if (signature.length !== 64) {
    throw new CryptoError('INVALID_SIGNATURE', 'A secp256k1 signature is 64 bytes, r || s.')
  }

  const r = derInteger(signature.subarray(0, 32))
  const s = derInteger(signature.subarray(32, 64))

  return bytes.concat(Uint8Array.of(0x30, 4 + r.length + s.length, 0x02, r.length), r, Uint8Array.of(0x02, s.length), s)
}

/** One DER integer of a signature, as 32 bytes: positive, minimally encoded, at most 32 bytes of value. */
const readInteger = (der: Uint8Array, offset: number): {value: Uint8Array; next: number} | undefined => {
  const length = der[offset + 1] ?? 0

  if (der[offset] !== 0x02 || length === 0 || length > 33 || offset + 2 + length > der.length) {
    return undefined
  }

  const value = der.subarray(offset + 2, offset + 2 + length)
  const first = value[0] ?? 0

  // Negative, or padded with a zero byte the next byte did not need.
  if (first & 0x80 || (first === 0 && length > 1 && !((value[1] ?? 0) & 0x80))) {
    return undefined
  }

  const trimmed = first === 0 && length > 1 ? value.subarray(1) : value

  if (trimmed.length > 32) {
    return undefined
  }

  const out = new Uint8Array(32)
  out.set(trimmed, 32 - trimmed.length)

  return {next: offset + 2 + length, value: out}
}

/**
 * A strict DER signature (BIP-66) as 64 bytes, `r || s`; `undefined` for anything BIP-66 rejects. Whether `s` is in
 * its lower half is the verifier's question: the engine's `verify` answers no for an upper-S signature.
 */
export const decodeDerSignature = (der: Uint8Array): Uint8Array | undefined => {
  if (der.length < 8 || der.length > 72 || der[0] !== 0x30 || der[1] !== der.length - 2) {
    return undefined
  }

  const r = readInteger(der, 2)
  const s = r && readInteger(der, r.next)

  return r && s && s.next === der.length ? bytes.concat(r.value, s.value) : undefined
}
