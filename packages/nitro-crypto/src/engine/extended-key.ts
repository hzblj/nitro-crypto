import {fromArrayBuffer, toArrayBuffer} from '../core/bytes'
import {CryptoError, native} from '../core/errors'
import type {NitroCrypto} from '../specs/nitro-crypto.nitro'

/**
 * A BIP-32 extended public key: a compressed public key and the chain code its non-hardened children derive from,
 * with where it sits. What a signer shares so a watch-only wallet can follow an account (xpub, tpub, zpub: those
 * names are its text with a network's version bytes, a chain's choice), and what that wallet derives addresses from.
 */
export type ExtendedPublicKey = {
  /** Compressed SEC1, 33 bytes. */
  readonly publicKey: Uint8Array
  /** 32 bytes. With a non-hardened child's private key, it gives the parent's away: share it, never a private key. */
  readonly chainCode: Uint8Array
  /** How many derivations below the master key: 3 for an account at `m/84'/0'/0'`. */
  readonly depth: number
  /** The BIP-32 fingerprint of its parent key. */
  readonly parentFingerprint: number
  /** Its index below its parent, plus 2^31 when hardened. */
  readonly childNumber: number
}

/** `NC_EXTENDED_PUBLIC_KEY_LENGTH`: depth, parent fingerprint, child number, chain code, public key. */
const LENGTH = 74

const invalid = (message: string) => new CryptoError('INVALID_ARGUMENT', message)

export const parseExtendedPublicKey = (bytes: Uint8Array): ExtendedPublicKey => {
  if (bytes.length !== LENGTH) {
    throw new CryptoError('INTERNAL', 'The engine returned an extended public key of another length.')
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)

  return Object.freeze({
    chainCode: bytes.slice(9, 41),
    childNumber: view.getUint32(5, false),
    depth: bytes[0] ?? 0,
    parentFingerprint: view.getUint32(1, false),
    publicKey: bytes.slice(41, 74),
  })
}

export const serializeExtendedPublicKey = (key: ExtendedPublicKey): Uint8Array<ArrayBuffer> => {
  const {chainCode, childNumber, depth, parentFingerprint, publicKey} = key
  const uint32 = (value: number) => Number.isInteger(value) && value >= 0 && value <= 0xffffffff

  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 33 || !(chainCode instanceof Uint8Array) || chainCode.length !== 32) {
    throw invalid('An extended public key has a 33-byte compressed key and a 32-byte chain code.')
  }

  if (!Number.isInteger(depth) || depth < 0 || depth > 255 || !uint32(parentFingerprint) || !uint32(childNumber)) {
    throw invalid('An extended public key`s depth is a byte, its parent fingerprint and child number 32-bit integers.')
  }

  const out = new Uint8Array(LENGTH)
  const view = new DataView(out.buffer)
  out[0] = depth
  view.setUint32(1, parentFingerprint, false)
  view.setUint32(5, childNumber, false)
  out.set(chainCode, 9)
  out.set(publicKey, 41)

  return out
}

export type Bip32Primitives = {
  /**
   * BIP-32 public derivation: the extended public key `path` below `key`, every step non-hardened ("m/0/5", its
   * sixth receiving key). A hardened step is `INVALID_PATH`, a key that is not a point `INVALID_PUBLIC_KEY`.
   */
  readonly derivePublic: (key: ExtendedPublicKey, path: string) => ExtendedPublicKey
}

export const createBip32Primitives = (host: NitroCrypto): Bip32Primitives =>
  Object.freeze({
    derivePublic: (key: ExtendedPublicKey, path: string) =>
      parseExtendedPublicKey(
        fromArrayBuffer(native(() => host.bip32DerivePublic(toArrayBuffer(serializeExtendedPublicKey(key)), path)))
      ),
  })
