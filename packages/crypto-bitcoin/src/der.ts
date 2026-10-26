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
