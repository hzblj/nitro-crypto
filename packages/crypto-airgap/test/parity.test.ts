import assert from 'node:assert/strict'
import {describe, test} from 'node:test'

import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'

import {
  CryptoCoinInfo,
  CryptoHDKey,
  CryptoKeypath,
  CryptoMultiAccounts,
  CryptoECKey as KeystoneECKey,
  PathComponent,
} from '@keystonehq/bc-ur-registry'
import {UR as NgraveUR, URDecoder as NgraveURDecoder, UREncoder as NgraveUREncoder} from '@ngraveio/bc-ur'

import {
  CRYPTO_ECKEY,
  CRYPTO_HDKEY,
  CRYPTO_KEYPATH,
  CRYPTO_MULTI_ACCOUNTS,
  createMultipartDecoder,
  createMultipartEncoder,
  decodeUR,
  encodeUR,
  fromUR,
  type HDKey,
  parseKeypath,
  toUR,
} from '../src'
import {toHex} from '../src/bytes'

/** SHA-256 from the engine (as WebAssembly here): what an app passes, `crypto.hash.sha256`. */
const {sha256} = createTestCryptoEngine().hash

/** mulberry32: the same "random" cases on every run, so a failure can be replayed. */
const seeded = (seed: number) => {
  let state = seed

  return () => {
    state = (state + 0x6d2b79f5) | 0
    let t = Math.imul(state ^ (state >>> 15), 1 | state)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t

    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const randomBytes = (random: () => number, length: number) => Uint8Array.from({length}, () => (random() * 256) | 0)

describe('parity with @ngraveio/bc-ur (an independent UR implementation)', () => {
  const random = seeded(7)
  const cases = Array.from({length: 40}, (_, index) => ({
    cbor: randomBytes(random, 1 + Math.floor(random() * (index % 4 === 0 ? 5000 : 600))),
    firstSeqNum: Math.floor(random() * 50),
    maxFragmentLength: 20 + Math.floor(random() * 300),
  }))

  test('single-part URs, both ways', () => {
    for (const {cbor} of cases) {
      const ours = encodeUR({cbor, type: 'bytes'})
      assert.equal(ours, NgraveUREncoder.encodeSinglePart(new NgraveUR(Buffer.from(cbor), 'bytes')))
      assert.deepEqual(new Uint8Array(NgraveURDecoder.decode(ours).cbor), cbor)
      assert.deepEqual(decodeUR(ours, {allowedTypes: ['bytes']}).cbor, cbor)
    }
  })

  test('multipart parts are the same strings, part for part, fountain parts included', () => {
    for (const {cbor, firstSeqNum, maxFragmentLength} of cases) {
      const ours = createMultipartEncoder({cbor, type: 'bytes'}, {firstSeqNum, maxFragmentLength, sha256})
      const theirs = new NgraveUREncoder(new NgraveUR(Buffer.from(cbor), 'bytes'), maxFragmentLength, firstSeqNum)

      for (let index = 0; index < ours.fragmentCount * 3; index++) {
        assert.equal(ours.nextPart(), theirs.nextPart())
      }
    }
  })

  test('their parts decode here, with three parts in four lost', () => {
    for (const {cbor, maxFragmentLength} of cases) {
      const theirs = new NgraveUREncoder(new NgraveUR(Buffer.from(cbor), 'bytes'), maxFragmentLength)
      const decoder = createMultipartDecoder({allowedTypes: ['bytes'], sha256})
      let sent = 0

      while (!decoder.isComplete()) {
        const part = theirs.nextPart()
        sent++

        if (sent % 4 === 0 || theirs.fragmentsLength === 1) {
          decoder.receivePart(part)
        }

        assert.ok(sent < 50_000, 'the message completes')
      }

      assert.deepEqual(decoder.result().cbor, cbor)
    }
  })

  test('our parts decode there, from the fountain parts alone', () => {
    for (const {cbor, maxFragmentLength} of cases) {
      const ours = createMultipartEncoder({cbor, type: 'bytes'}, {firstSeqNum: 1000, maxFragmentLength, sha256})
      const decoder = new NgraveURDecoder()

      while (!decoder.isComplete()) {
        decoder.receivePart(ours.nextPart())
      }

      assert.ok(decoder.isSuccess())
      assert.deepEqual(new Uint8Array(decoder.resultUR().cbor), cbor)
    }
  })
})

const fingerprint = Buffer.from('73c5da0a', 'hex')

const keystoneKeypath = (path: string, source?: Buffer) =>
  new CryptoKeypath(
    path
      .replace(/^m\//, '')
      .split('/')
      .map(step => new PathComponent({hardened: step.endsWith("'"), index: Number.parseInt(step, 10)})),
    source
  )

describe('parity with @keystonehq/bc-ur-registry', () => {
  const publicKey = Buffer.from('03b8ff1b1c4a1c0b3d6a5b9bd7d2e6fa55a0f1b6b3c5f7e9d1c3b5a7f9e1d3c5b7', 'hex')
  const chainCode = Buffer.from('6456a5df2db0f6d9af72b2a1af4b25f45200ed6fcc29c3440b311d4796b70b5b', 'hex')
  const ed25519 = Buffer.from('e5b3e7ec4ef7d2b6a6b5f3f2e1d0c9b8a7969584736251403f2e1d0c0b0a0908', 'hex')

  test('crypto-keypath, both ways', () => {
    for (const [path, source] of [
      ["m/44'/60'/0'/0/0", fingerprint],
      ["m/84'/1'/0'", fingerprint],
      ["m/44'/501'/0'/0'", undefined],
    ] as const) {
      const theirs = keystoneKeypath(path, source)
      const ours = parseKeypath(path, source?.readUInt32BE(0))
      assert.equal(toHex(toUR(CRYPTO_KEYPATH, ours).cbor), theirs.toCBOR().toString('hex'))
      assert.deepEqual(fromUR(CRYPTO_KEYPATH, {cbor: theirs.toCBOR(), type: 'crypto-keypath'}), ours)
    }
  })

  test('crypto-hdkey: an extended public key with origin, children, use info and names', () => {
    const theirs = new CryptoHDKey({
      chainCode,
      children: keystoneKeypath('m/0/1'),
      isMaster: false,
      key: publicKey,
      name: 'Keystone',
      note: 'account.standard',
      origin: keystoneKeypath("m/44'/60'/0'", fingerprint),
      parentFingerprint: Buffer.from('12345678', 'hex'),
      useInfo: new CryptoCoinInfo(60 as never, 1 as never),
    })
    const ours: HDKey = {
      chainCode,
      children: parseKeypath('m/0/1'),
      keyData: publicKey,
      name: 'Keystone',
      note: 'account.standard',
      origin: parseKeypath("m/44'/60'/0'", 0x73c5da0a),
      parentFingerprint: 0x12345678,
      useInfo: {network: 1, type: 60},
    }

    assert.equal(toHex(toUR(CRYPTO_HDKEY, ours).cbor), theirs.toCBOR().toString('hex'))

    const read = fromUR(CRYPTO_HDKEY, {cbor: theirs.toCBOR(), type: 'crypto-hdkey'})
    assert.deepEqual(read.keyData, new Uint8Array(publicKey))
    assert.deepEqual(read.chainCode, new Uint8Array(chainCode))
    assert.deepEqual(read.origin, parseKeypath("m/44'/60'/0'", 0x73c5da0a))
    assert.deepEqual(read.useInfo, {network: 1, type: 60})
    assert.equal(read.parentFingerprint, 0x12345678)
    assert.equal(read.note, 'account.standard')

    // And back the other way: Keystone reads what this writes.
    const roundTrip = CryptoHDKey.fromCBOR(Buffer.from(toUR(CRYPTO_HDKEY, ours).cbor))
    assert.equal(roundTrip.getBip32Key(), theirs.getBip32Key())
  })

  test('crypto-multi-accounts: secp256k1 and Ed25519 keys, as Keystone pairs them', () => {
    const theirs = new CryptoMultiAccounts(
      fingerprint,
      [
        new CryptoHDKey({isMaster: false, key: ed25519, origin: keystoneKeypath("m/44'/501'/0'/0'", fingerprint)}),
        new CryptoHDKey({
          chainCode,
          isMaster: false,
          key: publicKey,
          note: 'account.standard',
          origin: keystoneKeypath("m/44'/60'/0'", fingerprint),
        }),
      ],
      'Keystone 3 Pro',
      '28475c8d80f6c06bafbe46a7d1750f3fcf2565f7',
      '1.7.0'
    )
    const cbor = theirs.toCBOR()
    const ours = fromUR(CRYPTO_MULTI_ACCOUNTS, {cbor, type: 'crypto-multi-accounts'})

    assert.equal(ours.masterFingerprint, 0x73c5da0a)
    assert.equal(ours.device, 'Keystone 3 Pro')
    assert.equal(ours.keys.length, 2)
    assert.deepEqual(ours.keys[0]?.keyData, new Uint8Array(ed25519))
    assert.equal(ours.keys[1]?.note, 'account.standard')
    assert.equal(toHex(toUR(CRYPTO_MULTI_ACCOUNTS, ours).cbor), cbor.toString('hex'))
  })

  test('crypto-eckey: a public key reads, a private one is refused', () => {
    const theirs = new KeystoneECKey({data: publicKey})
    assert.deepEqual(
      fromUR(CRYPTO_ECKEY, {cbor: theirs.toCBOR(), type: 'crypto-eckey'}).data,
      new Uint8Array(publicKey)
    )

    const secret = new KeystoneECKey({data: Buffer.alloc(32, 7), privateKey: true})
    assert.throws(
      () => fromUR(CRYPTO_ECKEY, {cbor: secret.toCBOR(), type: 'crypto-eckey'}),
      (error: Error & {code?: string}) => error.code === 'PRIVATE_KEY_MATERIAL'
    )
  })

  test('private and master HD keys are refused, however they are flagged', () => {
    const privateKey = Buffer.concat([Buffer.of(0), Buffer.alloc(32, 9)])

    for (const key of [
      new CryptoHDKey({chainCode, isMaster: true, key: privateKey}),
      new CryptoHDKey({chainCode, isMaster: false, isPrivateKey: true, key: privateKey}),
      // Flagged public, but the key data is a private key's.
      new CryptoHDKey({chainCode, isMaster: false, key: privateKey}),
    ]) {
      assert.throws(
        () => fromUR(CRYPTO_HDKEY, {cbor: key.toCBOR(), type: 'crypto-hdkey'}),
        (error: Error & {code?: string}) => error.code === 'PRIVATE_KEY_MATERIAL'
      )
    }
  })
})
