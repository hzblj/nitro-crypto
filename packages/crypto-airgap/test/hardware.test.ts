import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {describe, test} from 'node:test'

import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {HDKey as ReferenceHDKey} from '@scure/bip32'

import {
  CRYPTO_HDKEY,
  createMultipartDecoder,
  createURRegistry,
  decodeUR,
  encodeUR,
  formatKeypath,
  fromUR,
  isAirgapError,
  toUR,
} from '../src'
import {fromHex, toHex} from '../src/bytes'

const HARDWARE = JSON.parse(readFileSync(new URL('./vectors/hardware.json', import.meta.url), 'utf8'))
const {sha256} = createTestCryptoEngine().hash

const refusesKey = (run: () => unknown) => assert.throws(run, error => isAirgapError(error, 'PRIVATE_KEY_MATERIAL'))

describe('hardware wallets` crypto-hdkey', () => {
  test('a key Keystone`s firmware codec writes reads here, writes back the same, and is the xpub it reads', () => {
    const cbor = fromHex(HARDWARE.keystoneFirmware.derivedKey)
    const key = fromUR(CRYPTO_HDKEY, {cbor, type: 'crypto-hdkey'})

    assert.equal(toHex(toUR(CRYPTO_HDKEY, key).cbor), HARDWARE.keystoneFirmware.derivedKey)
    assert.equal(encodeUR(toUR(CRYPTO_HDKEY, key)), HARDWARE.keystoneFirmware.derivedKeyUr)
    assert.ok(key.origin)
    assert.equal(formatKeypath(key.origin), "m/44'/1'/1'/0/1")
    assert.deepEqual(key.useInfo, {network: 1, type: 0})

    // Keystone reads it as BIP-32 text with mainnet's version bytes, whatever its network: so does @scure/bip32.
    const reference = new ReferenceHDKey({
      chainCode: key.chainCode,
      depth: key.origin.components.length,
      index: 1,
      parentFingerprint: key.parentFingerprint,
      publicKey: key.keyData,
    })
    assert.equal(reference.publicExtendedKey, HARDWARE.keystoneFirmware.derivedKeyXpub)
  })

  test('master keys are refused: BCR-2020-007`s as Keystone writes it, and OneKey`s, whole or in parts', () => {
    refusesKey(() => fromUR(CRYPTO_HDKEY, {cbor: fromHex(HARDWARE.keystoneFirmware.masterKey), type: 'crypto-hdkey'}))
    refusesKey(() => fromUR(CRYPTO_HDKEY, decodeUR(HARDWARE.onekey.masterKey, {allowedTypes: ['crypto-hdkey']})))

    const registry = createURRegistry([CRYPTO_HDKEY])
    const decoder = createMultipartDecoder({allowedTypes: registry.types, sha256})
    for (const part of HARDWARE.onekey.masterKeyParts) {
      decoder.receivePart(part)
    }
    assert.ok(decoder.isComplete())
    refusesKey(() => registry.decode(decoder.result()))
  })
})
