import {fromArrayBuffer, toArrayBuffer} from '../core/bytes'
import {CryptoError, native} from '../core/errors'
import type {Curve, DerivationScheme, NitroCrypto, NitroKey} from '../specs/nitro-crypto.nitro'
import {merkleRootBuffer, type PublicKeyFormat, type RecoverableSignature, splitRecoverable} from './primitives'

/** The curve each derivation scheme produces keys on. */
export type SchemeCurve = {bip32: 'secp256k1'; slip10: 'ed25519'}

export const SCHEME_CURVES: SchemeCurve = {bip32: 'secp256k1', slip10: 'ed25519'}

type KeyBase = {
  /** Whether `dispose()` has zeroized the key. Every other member throws `DISPOSED` once it has. */
  readonly disposed: boolean
  /** The derivation path, for a key derived from a wallet. */
  readonly path: string | undefined
  /** Zeroizes the key inside the engine. Idempotent. */
  readonly dispose: () => void
}

/** A secp256k1 private key held by the engine. */
export type Secp256k1Key = KeyBase & {
  readonly curve: 'secp256k1'
  /** SEC1: 33 bytes compressed (the default) or 65 uncompressed. */
  readonly publicKey: (format?: PublicKeyFormat) => Uint8Array
  /** ECDSA over a 32-byte digest, with an RFC 6979 nonce and a lower-S signature. */
  readonly sign: (digest: Uint8Array) => RecoverableSignature
  /** The BIP-340 x-only public key: 32 bytes, the x coordinate of the compressed key. */
  readonly xOnlyPublicKey: () => Uint8Array
  /**
   * A BIP-340 Schnorr signature of `message` (any length), 64 bytes. Its auxiliary randomness is fresh from the
   * operating system, so two signatures of one message differ, and both verify (`crypto.schnorr.verify`).
   */
  readonly signSchnorr: (message: Uint8Array) => Uint8Array
  /**
   * BIP-341's key path: a Schnorr signature of a 32-byte signature hash by this key tweaked inside the engine with
   * the merkle root of its script tree (32 bytes), or with none when `merkleRoot` is left out (BIP-86). It verifies
   * under the output key `crypto.schnorr.taprootTweak(key.xOnlyPublicKey(), merkleRoot)` gives.
   */
  readonly signTaproot: (sighash: Uint8Array, merkleRoot?: Uint8Array) => Uint8Array
}

/** An Ed25519 private key held by the engine. */
export type Ed25519Key = KeyBase & {
  readonly curve: 'ed25519'
  readonly publicKey: () => Uint8Array
  /** The RFC 8032 signature of `message`, 64 bytes. */
  readonly sign: (message: Uint8Array) => Uint8Array
}

export type SigningKey = Secp256k1Key | Ed25519Key

export type KeyOf<C extends Curve> = Extract<SigningKey, {curve: C}>

export type KeyFactory = {
  /** A fresh key from the operating system's CSPRNG. */
  readonly generate: <C extends Curve>(curve: C) => KeyOf<C>
  /**
   * Raw secret material in: a 32-byte secp256k1 private key or Ed25519 seed. For published test vectors and explicit
   * interoperability only. There is no export, and the engine keeps its own copy: wipe yours.
   */
  readonly importRawSecret: <C extends Curve>(curve: C, secret: Uint8Array) => KeyOf<C>
}

type KeyOptions = {
  /** Called once, when the key is disposed: the owning wallet stops tracking it. */
  readonly onDispose?: () => void
  readonly path?: string
}

const disposedError = () => new CryptoError('DISPOSED', 'This key has been disposed.')

/**
 * The facade over a native key: bytes in and out, `DISPOSED` once it is gone, public keys read once. Disposal is
 * tracked here: once JS disposes a Hybrid Object, Nitro detaches it and any read of it throws.
 */
export const wrapKey = (key: NitroKey, options: KeyOptions = {}): SigningKey => {
  const publicKeys = new Map<boolean, Uint8Array>()
  let disposed = false
  const live = () => {
    if (disposed) {
      throw disposedError()
    }

    return key
  }
  const publicKey = (compressed: boolean) => {
    const current = live()
    let cached = publicKeys.get(compressed)

    if (!cached) {
      cached = fromArrayBuffer(native(() => current.getPublicKey(compressed)))
      publicKeys.set(compressed, cached)
    }

    return cached.slice()
  }
  const sign = (data: Uint8Array) => fromArrayBuffer(native(() => live().sign(toArrayBuffer(data))))
  let xOnly: Uint8Array | undefined
  const xOnlyPublicKey = () => {
    const current = live()
    xOnly ??= fromArrayBuffer(native(() => current.getXOnlyPublicKey()))

    return xOnly.slice()
  }
  const dispose = () => {
    if (!disposed) {
      disposed = true
      key.dispose()
      options.onDispose?.()
    }
  }

  if (key.curve === 'secp256k1') {
    const secp256k1: Secp256k1Key = {
      curve: 'secp256k1',
      dispose,
      get disposed() {
        return disposed
      },
      path: options.path,
      publicKey: (format = 'compressed') => publicKey(format === 'compressed'),
      sign: digest => splitRecoverable(sign(digest)),
      signSchnorr: message => fromArrayBuffer(native(() => live().signSchnorr(toArrayBuffer(message)))),
      signTaproot: (sighash, merkleRoot) => {
        const root = merkleRootBuffer(merkleRoot)

        return fromArrayBuffer(native(() => live().signTaproot(toArrayBuffer(sighash), root)))
      },
      xOnlyPublicKey,
    }

    return Object.freeze(secp256k1)
  }

  const ed25519: Ed25519Key = {
    curve: 'ed25519',
    dispose,
    get disposed() {
      return disposed
    },
    path: options.path,
    publicKey: () => publicKey(true),
    sign,
  }

  return Object.freeze(ed25519)
}

const narrow = <C extends Curve>(key: SigningKey, curve: C): KeyOf<C> => {
  if (key.curve !== curve) {
    key.dispose()
    throw new CryptoError('INTERNAL', 'The engine returned a key on another curve.')
  }

  return key as KeyOf<C>
}

export const createKeyFactory = (host: NitroCrypto): KeyFactory =>
  Object.freeze({
    generate: <C extends Curve>(curve: C) => narrow(wrapKey(native(() => host.generateKey(curve))), curve),
    importRawSecret: <C extends Curve>(curve: C, secret: Uint8Array) =>
      narrow(wrapKey(native(() => host.importKey(curve, toArrayBuffer(secret)))), curve),
  })

export const isScheme = (scheme: unknown): scheme is DerivationScheme => scheme === 'bip32' || scheme === 'slip10'
