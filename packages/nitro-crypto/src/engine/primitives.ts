import {fromArrayBuffer, toArrayBuffer} from '../core/bytes'
import {CryptoError, isCryptoError, native, nativeAsync} from '../core/errors'
import type {HashAlgorithm, NitroCrypto} from '../specs/nitro-crypto.nitro'
import {type Bip32Primitives, createBip32Primitives} from './extended-key'

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

/** BIP-341's output key: what a P2TR output commits to, with the parity a script path's control block carries. */
export type TaprootOutputKey = {
  /** The x-only output key, 32 bytes. */
  readonly publicKey: Uint8Array
  /** The parity of its y coordinate: 0 even, 1 odd. */
  readonly parity: 0 | 1
}

/** BIP-340 Schnorr signatures over secp256k1, and BIP-341's Taproot tweak. Signing is a key's (`signSchnorr`). */
export type SchnorrPrimitives = {
  /**
   * BIP-341's output key for an internal key and the merkle root of its script tree (32 bytes), or for a key with no
   * script tree when `merkleRoot` is left out (BIP-86). `internalKey` is x-only (32 bytes) or SEC1 (33 or 65), whose y
   * parity BIP-341 drops. Public data only.
   */
  readonly taprootTweak: (internalKey: Uint8Array, merkleRoot?: Uint8Array) => TaprootOutputKey
  /**
   * Whether a 64-byte BIP-340 signature of `message` (any length) verifies under a 32-byte x-only public key. A
   * malformed signature is `false`. Throws when the key is the x coordinate of no point, or a length is wrong.
   */
  readonly verify: (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) => boolean
}

export type Ed25519Primitives = {
  /** RFC 8032 verification, strict: non-canonical encodings and small-order keys never verify. */
  readonly verify: (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) => boolean
}

/** The stateless operations: everything that needs no secret held by the engine. */
export type Primitives = {
  /** BIP-32 public derivation, from an extended public key (`wallet.extendedPublicKey`, or one a signer shared). */
  readonly bip32: Bip32Primitives
  readonly ed25519: Ed25519Primitives
  readonly hash: Hashes
  readonly hmac: Hmacs
  /** Bytes from the operating system's CSPRNG; throws `ENTROPY_UNAVAILABLE` rather than return anything weaker. */
  readonly random: (length: number) => Uint8Array
  readonly schnorr: SchnorrPrimitives
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

/** A Taproot merkle root: 32 bytes, or none. The engine reads an empty buffer as none, so an empty one is refused here. */
export const merkleRootBuffer = (merkleRoot: Uint8Array | undefined): ArrayBuffer => {
  if (merkleRoot === undefined) {
    return new ArrayBuffer(0)
  }

  if (merkleRoot.length !== 32) {
    throw new CryptoError('INVALID_LENGTH', 'A Taproot merkle root is 32 bytes.')
  }

  return toArrayBuffer(merkleRoot)
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
    bip32: createBip32Primitives(host),
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
    schnorr: Object.freeze({
      taprootTweak: (internalKey: Uint8Array, merkleRoot?: Uint8Array): TaprootOutputKey => {
        const root = merkleRootBuffer(merkleRoot)
        const output = fromArrayBuffer(native(() => host.secp256k1TaprootTweak(toArrayBuffer(internalKey), root)))

        if (output.length !== 33 || (output[0] !== 2 && output[0] !== 3)) {
          throw new CryptoError('INTERNAL', 'The engine returned an output key of another shape.')
        }

        return Object.freeze({parity: output[0] === 3 ? 1 : 0, publicKey: output.slice(1)})
      },
      verify: (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) =>
        verdict(() =>
          host.secp256k1SchnorrVerify(toArrayBuffer(publicKey), toArrayBuffer(message), toArrayBuffer(signature))
        ),
    }),
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
