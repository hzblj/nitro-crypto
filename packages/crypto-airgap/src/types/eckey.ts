import type {CborValue} from '../cbor'
import {AirgapError} from '../errors'
import {defineURType} from '../registry'
import {compact, optional, protocolError, readBool, readBytes, readMap, readUint, required, writeMap} from '../schema'

/** A single public key (BCR-2020-008, `crypto-eckey`, tag 306). The private form is refused when read. */
export type ECKey = {
  /** 33 bytes compressed or 65 uncompressed SEC1. */
  readonly data: Uint8Array
  /** 0 for secp256k1, the only curve the registry names. */
  readonly curve: number
}

const isPublic = (data: Uint8Array) =>
  (data.length === 33 && (data[0] === 0x02 || data[0] === 0x03)) || (data.length === 65 && data[0] === 0x04)

const toCbor = (key: ECKey): CborValue => {
  if (!isPublic(key.data)) {
    throw new AirgapError('INVALID_ARGUMENT', 'A public key is 33 bytes compressed or 65 bytes uncompressed.')
  }

  if (!Number.isInteger(key.curve) || key.curve < 0) {
    throw new AirgapError('INVALID_ARGUMENT', 'A curve is a non-negative integer.')
  }

  return writeMap([
    [1, key.curve === 0 ? undefined : key.curve],
    [3, key.data],
  ])
}

const fromCbor = (item: CborValue): ECKey => {
  const map = readMap(item, 'An EC key')

  if (optional(map, 2, value => readBool(value, 'An EC key`s private flag')) === true) {
    throw new AirgapError('PRIVATE_KEY_MATERIAL', 'The key is a private key, which is refused.')
  }

  const data = readBytes(required(map, 3, 'An EC key`s data'), 'An EC key`s data')

  // A 32-byte key with no flag is a private key written carelessly: still a private key.
  if (data.length === 32) {
    throw new AirgapError('PRIVATE_KEY_MATERIAL', 'The key is a private key, which is refused.')
  }

  if (!isPublic(data)) {
    throw protocolError('An EC key is 33 bytes compressed or 65 bytes uncompressed.')
  }

  return compact({curve: optional(map, 1, value => readUint(value, 'An EC key`s curve')) ?? 0, data})
}

/** `crypto-eckey`: one public key, outside any derivation. */
export const CRYPTO_ECKEY = defineURType({fromCbor, tag: 306, toCbor, type: 'crypto-eckey'})
