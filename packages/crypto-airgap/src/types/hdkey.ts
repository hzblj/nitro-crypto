import type {CborValue} from '../cbor'
import {AirgapError} from '../errors'
import {defineURType} from '../registry'
import {
  compact,
  optional,
  readBool,
  readBytes,
  readMap,
  readTagged,
  readText,
  readUint,
  required,
  UINT32_MAX,
  writeMap,
  writeTagged,
} from '../schema'
import {type CoinInfo, CRYPTO_COIN_INFO} from './coin-info'
import {CRYPTO_KEYPATH, type Keypath} from './keypath'

/**
 * A public key, and what derives from it (BCR-2020-007, `crypto-hdkey`, tag 303): what a signer shares so a
 * watch-only wallet can show its addresses and ask it to sign. Only the public form exists here: a master key or a
 * private one is `PRIVATE_KEY_MATERIAL` when read, and cannot be written.
 */
export type HDKey = {
  /**
   * The public key: 33 bytes of compressed secp256k1, or 32 bytes of Ed25519 (the form Keystone shares Solana and
   * other Ed25519 accounts in; the registry itself defines only the 33-byte one).
   */
  readonly keyData: Uint8Array
  /** 32 bytes. Present when keys may be derived from this one (an extended public key); absent for a single key. */
  readonly chainCode?: Uint8Array
  readonly useInfo?: CoinInfo
  /** How the key was derived, from the key `origin.sourceFingerprint` names. */
  readonly origin?: Keypath
  /** The keys meant to be derived from it, such as `0/*` for receiving addresses. */
  readonly children?: Keypath
  readonly parentFingerprint?: number
  readonly name?: string
  /** A note, which some signers use to say which derivation scheme an account follows. */
  readonly note?: string
}

const COMPRESSED = [0x02, 0x03]

/** The key data's length and first byte say what it is; a private key's (33 bytes, `0x00` first) is refused. */
const checkKeyData = (keyData: Uint8Array, onInvalid: (message: string) => AirgapError) => {
  if (keyData.length === 33 && keyData[0] === 0x00) {
    throw new AirgapError('PRIVATE_KEY_MATERIAL', 'The key is a private key, which is refused.')
  }

  if (!(keyData.length === 32 || (keyData.length === 33 && COMPRESSED.includes(keyData[0] ?? -1)))) {
    throw onInvalid('A key is 33 bytes of compressed secp256k1 or 32 bytes of Ed25519.')
  }

  return keyData
}

const toCbor = (key: HDKey): CborValue => {
  const invalid = (message: string) => new AirgapError('INVALID_ARGUMENT', message)
  checkKeyData(key.keyData, invalid)

  if (key.chainCode !== undefined && key.chainCode.length !== 32) {
    throw invalid('A chain code is 32 bytes.')
  }

  if (
    key.parentFingerprint !== undefined &&
    (!Number.isInteger(key.parentFingerprint) || key.parentFingerprint < 1 || key.parentFingerprint > UINT32_MAX)
  ) {
    throw invalid('A fingerprint is a 32-bit integer other than 0.')
  }

  return writeMap([
    [3, key.keyData],
    [4, key.chainCode],
    [5, key.useInfo && writeTagged(305, CRYPTO_COIN_INFO.toCbor(key.useInfo))],
    [6, key.origin && writeTagged(304, CRYPTO_KEYPATH.toCbor(key.origin))],
    [7, key.children && writeTagged(304, CRYPTO_KEYPATH.toCbor(key.children))],
    [8, key.parentFingerprint],
    [9, key.name],
    [10, key.note],
  ])
}

const fromCbor = (item: CborValue): HDKey => {
  const map = readMap(item, 'An HD key')

  // A master key is a private key by definition (BIP-32 has no public master), and is-private says so outright.
  if (optional(map, 1, value => readBool(value, 'An HD key`s master flag')) === true) {
    throw new AirgapError('PRIVATE_KEY_MATERIAL', 'The key is a master key, which is private and refused.')
  }

  if (optional(map, 2, value => readBool(value, 'An HD key`s private flag')) === true) {
    throw new AirgapError('PRIVATE_KEY_MATERIAL', 'The key is a private key, which is refused.')
  }

  const keyData = checkKeyData(
    readBytes(required(map, 3, 'An HD key`s key data'), 'An HD key`s key data'),
    message => new AirgapError('INVALID_PROTOCOL_DATA', message)
  )
  const parentFingerprint = optional(map, 8, value => readUint(value, 'A parent fingerprint', UINT32_MAX))

  return compact({
    chainCode: optional(map, 4, value => readBytes(value, 'A chain code', 32)),
    children: optional(map, 7, value => CRYPTO_KEYPATH.fromCbor(readTagged(value, 304, 'An HD key`s children'))),
    keyData,
    name: optional(map, 9, value => readText(value, 'An HD key`s name')),
    note: optional(map, 10, value => readText(value, 'An HD key`s note')),
    origin: optional(map, 6, value => CRYPTO_KEYPATH.fromCbor(readTagged(value, 304, 'An HD key`s origin'))),
    parentFingerprint: parentFingerprint === 0 ? undefined : parentFingerprint,
    useInfo: optional(map, 5, value => CRYPTO_COIN_INFO.fromCbor(readTagged(value, 305, 'An HD key`s use info'))),
  })
}

/** `crypto-hdkey`: a public key, or an extended one with its chain code, and where it came from. */
export const CRYPTO_HDKEY = defineURType({fromCbor, tag: 303, toCbor, type: 'crypto-hdkey'})
