import {fromArrayBuffer, toArrayBuffer} from '../core/bytes'
import {CryptoError, isCryptoError, native, nativeAsync} from '../core/errors'
import type {HashAlgorithm, NitroCrypto} from '../specs/nitro-crypto.nitro'

export type PublicKeyFormat = 'compressed' | 'uncompressed'

export type RecoveryId = 0 | 1 | 2 | 3

/** An ECDSA signature over secp256k1, `r || s` (64 bytes, lower S), and the id that recovers its public key. */
export type RecoverableSignature = {
  readonly recovery: RecoveryId
  readonly signature: Uint8Array
}

export type Hashes = {
  readonly keccak256: (data: Uint8Array) => Uint8Array
  readonly ripemd160: (data: Uint8Array) => Uint8Array
  readonly sha256: (data: Uint8Array) => Uint8Array
  readonly sha512: (data: Uint8Array) => Uint8Array
  readonly digest: (algorithm: HashAlgorithm, data: Uint8Array) => Uint8Array
  /** `digest` off the JS thread: for payloads large enough to drop frames (about a megabyte and up). */
  readonly digestAsync: (algorithm: HashAlgorithm, data: Uint8Array) => Promise<Uint8Array>
}

export type Hmacs = {
  readonly sha256: (key: Uint8Array, data: Uint8Array) => Uint8Array
  readonly sha512: (key: Uint8Array, data: Uint8Array) => Uint8Array
}

export type Secp256k1Primitives = {
  /** Validates a SEC1 public key and re-encodes it. */
  readonly convertPublicKey: (publicKey: Uint8Array, format: PublicKeyFormat) => Uint8Array
  /** The public key that made `signature` over `digest`. Throws `INVALID_SIGNATURE` when there is none. */
  readonly recover: (digest: Uint8Array, signature: RecoverableSignature, format?: PublicKeyFormat) => Uint8Array
  /**
   * Whether a 64-byte `r || s` signature over a 32-byte digest verifies. A signature in upper-S form is `false`:
   * the engine accepts only the canonical half. Throws only when the key or a length is malformed.
   */
  readonly verify: (publicKey: Uint8Array, digest: Uint8Array, signature: Uint8Array) => boolean
}

export type Ed25519Primitives = {
  /** RFC 8032 verification, strict: non-canonical encodings and small-order keys never verify. */
  readonly verify: (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) => boolean
}

/** The stateless operations: everything that needs no secret held by the engine. */
export type Primitives = {
  readonly ed25519: Ed25519Primitives
  readonly hash: Hashes
  readonly hmac: Hmacs
  /** Bytes from the operating system's CSPRNG; throws `ENTROPY_UNAVAILABLE` rather than return anything weaker. */
  readonly random: (length: number) => Uint8Array
  readonly secp256k1: Secp256k1Primitives
}

/** The 65 bytes the engine takes for a recoverable signature. */
export const joinRecoverable = ({recovery, signature}: RecoverableSignature): Uint8Array<ArrayBuffer> => {
  if (signature.length !== 64) {
    throw new CryptoError('INVALID_LENGTH', 'A secp256k1 signature is 64 bytes, r || s.')
  }

  if (!Number.isInteger(recovery) || recovery < 0 || recovery > 3) {
    throw new CryptoError('INVALID_SIGNATURE', 'A recovery id is 0, 1, 2 or 3.')
  }

  const out = new Uint8Array(65)
  out.set(signature)
  out[64] = recovery

  return out
}

export const splitRecoverable = (bytes: Uint8Array): RecoverableSignature => ({
  recovery: (bytes[64] ?? 0) as RecoveryId,
  signature: bytes.slice(0, 64),
})

/** A malformed or non-canonical signature does not verify; any other failure is the caller's input, and throws. */
const verdict = (verify: () => boolean): boolean => {
  try {
    return native(verify)
  } catch (error) {
    if (isCryptoError(error, 'INVALID_SIGNATURE')) {
      return false
    }

    throw error
  }
}

const checkLength = (length: number) => {
  if (!Number.isSafeInteger(length) || length < 0 || length > 2 ** 31 - 1) {
    throw new CryptoError('INVALID_ARGUMENT', 'A length is a non-negative integer below 2^31.')
  }

  return length
}

export const createPrimitives = (host: NitroCrypto): Primitives => {
  const digest = (algorithm: HashAlgorithm, data: Uint8Array) =>
    fromArrayBuffer(native(() => host.hash(algorithm, toArrayBuffer(data))))

  return Object.freeze({
    ed25519: Object.freeze({
      verify: (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) =>
        verdict(() => host.ed25519Verify(toArrayBuffer(publicKey), toArrayBuffer(message), toArrayBuffer(signature))),
    }),
    hash: Object.freeze({
      digest,
      digestAsync: async (algorithm: HashAlgorithm, data: Uint8Array) =>
        fromArrayBuffer(await nativeAsync(() => host.hashAsync(algorithm, toArrayBuffer(data)))),
      keccak256: (data: Uint8Array) => digest('keccak256', data),
      ripemd160: (data: Uint8Array) => digest('ripemd160', data),
      sha256: (data: Uint8Array) => digest('sha256', data),
      sha512: (data: Uint8Array) => digest('sha512', data),
    }),
    hmac: Object.freeze({
      sha256: (key: Uint8Array, data: Uint8Array) =>
        fromArrayBuffer(native(() => host.hmac('sha256', toArrayBuffer(key), toArrayBuffer(data)))),
      sha512: (key: Uint8Array, data: Uint8Array) =>
        fromArrayBuffer(native(() => host.hmac('sha512', toArrayBuffer(key), toArrayBuffer(data)))),
    }),
    random: (length: number) => fromArrayBuffer(native(() => host.randomBytes(checkLength(length)))),
    secp256k1: Object.freeze({
      convertPublicKey: (publicKey: Uint8Array, format: PublicKeyFormat) =>
        fromArrayBuffer(native(() => host.secp256k1ConvertPublicKey(toArrayBuffer(publicKey), format === 'compressed'))),
      recover: (digest: Uint8Array, signature: RecoverableSignature, format: PublicKeyFormat = 'compressed') => {
        const joined = joinRecoverable(signature)
        const recovered = native(() => host.secp256k1Recover(toArrayBuffer(digest), joined.buffer, format === 'compressed'))

        return fromArrayBuffer(recovered)
      },
      verify: (publicKey: Uint8Array, digest: Uint8Array, signature: Uint8Array) =>
        verdict(() => host.secp256k1Verify(toArrayBuffer(publicKey), toArrayBuffer(digest), toArrayBuffer(signature))),
    }),
  })
}
