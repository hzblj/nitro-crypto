import assert from 'node:assert/strict'
import {describe, test} from 'node:test'

import {ed25519 as nobleEd25519} from '@noble/curves/ed25519.js'
import {secp256k1 as nobleSecp256k1} from '@noble/curves/secp256k1.js'
import {hmac} from '@noble/hashes/hmac.js'
import {ripemd160} from '@noble/hashes/legacy.js'
import {sha256, sha512} from '@noble/hashes/sha2.js'
import {keccak_256} from '@noble/hashes/sha3.js'

import {isCryptoError} from '../src/core/errors'
import {hex, utf8} from '../src/encoding'
import {crypto, seededBytes} from './support'

const throwsCode = (run: () => unknown, code: string) =>
  assert.throws(run, error => isCryptoError(error) && error.code === code, code)

describe('hashes', () => {
  test('published digests', () => {
    const abc = utf8.encode('abc')
    assert.equal(
      hex.encode(crypto.hash.sha256(abc)),
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    )
    assert.equal(
      hex.encode(crypto.hash.keccak256(new Uint8Array())),
      'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
    )
    assert.equal(hex.encode(crypto.hash.ripemd160(abc)), '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc')
    assert.equal(crypto.hash.sha512(abc).length, 64)
  })

  test('agree with @noble/hashes on random input of every length up to 300 bytes', () => {
    const random = seededBytes(10)
    for (let length = 0; length <= 300; length++) {
      const data = random.bytes(length)
      assert.deepEqual(crypto.hash.sha256(data), sha256(data))
      assert.deepEqual(crypto.hash.sha512(data), sha512(data))
      assert.deepEqual(crypto.hash.keccak256(data), keccak_256(data))
      assert.deepEqual(crypto.hash.ripemd160(data), ripemd160(data))
    }
  })

  test('a 4 MiB payload hashes the same synchronously, asynchronously and in @noble', async () => {
    const data = seededBytes(11).bytes(4 << 20)
    const expected = sha256(data)
    assert.deepEqual(crypto.hash.sha256(data), expected)
    assert.deepEqual(await crypto.hash.digestAsync('sha256', data), expected)
  })

  test('a view into a larger buffer hashes only its own bytes', () => {
    const backing = Uint8Array.from({length: 64}, (_, index) => index)
    const view = backing.subarray(10, 20)
    assert.deepEqual(crypto.hash.sha256(view), sha256(view))
  })

  test('HMAC agrees with @noble/hashes for short, block-sized and long keys', () => {
    const random = seededBytes(12)
    for (const keyLength of [0, 1, 32, 64, 65, 128, 129, 200]) {
      const key = random.bytes(keyLength)
      const data = random.bytes(random.integer(300))
      assert.deepEqual(crypto.hmac.sha256(key, data), hmac(sha256, key, data))
      assert.deepEqual(crypto.hmac.sha512(key, data), hmac(sha512, key, data))
    }
  })
})

test('random returns fresh bytes of the length asked, and refuses nonsense lengths', () => {
  assert.equal(crypto.random(0).length, 0)
  assert.equal(crypto.random(1000).length, 1000)
  assert.notDeepEqual(crypto.random(32), crypto.random(32))
  throwsCode(() => crypto.random(-1), 'INVALID_ARGUMENT')
  throwsCode(() => crypto.random(1.5), 'INVALID_ARGUMENT')
})

describe('secp256k1', () => {
  test('signatures equal @noble/curves (RFC 6979, lower S) and verify and recover both ways', () => {
    const random = seededBytes(20)
    for (let round = 0; round < 64; round++) {
      const secret = nobleSecp256k1.utils.randomSecretKey(random.bytes(48))
      const digest = random.bytes(32)
      const key = crypto.keys.importRawSecret('secp256k1', secret)

      const ours = key.sign(digest)
      // noble's recovered format puts the recovery byte first.
      const theirs = nobleSecp256k1.sign(digest, secret, {format: 'recovered', prehash: false})
      assert.deepEqual(ours.signature, theirs.subarray(1))
      assert.equal(ours.recovery, theirs[0])

      const publicKey = nobleSecp256k1.getPublicKey(secret, true)
      assert.deepEqual(key.publicKey(), publicKey)
      assert.deepEqual(key.publicKey('uncompressed'), nobleSecp256k1.getPublicKey(secret, false))
      assert.equal(crypto.secp256k1.verify(publicKey, digest, ours.signature), true)
      assert.equal(nobleSecp256k1.verify(ours.signature, digest, publicKey, {prehash: false}), true)
      assert.deepEqual(crypto.secp256k1.recover(digest, ours), publicKey)
      assert.deepEqual(crypto.secp256k1.recover(digest, ours, 'uncompressed'), key.publicKey('uncompressed'))
      key.dispose()
    }
  })

  test('verify is false for a changed digest, a changed signature, and the upper-S twin', () => {
    const key = crypto.keys.generate('secp256k1')
    const digest = crypto.random(32)
    const {signature} = key.sign(digest)
    const publicKey = key.publicKey()

    const otherDigest = digest.slice()
    otherDigest[0] = (otherDigest[0] ?? 0) ^ 1
    assert.equal(crypto.secp256k1.verify(publicKey, otherDigest, signature), false)

    const tampered = signature.slice()
    tampered[40] = (tampered[40] ?? 0) ^ 1
    assert.equal(crypto.secp256k1.verify(publicKey, digest, tampered), false)

    const parsed = nobleSecp256k1.Signature.fromBytes(signature, 'compact')
    const upper = new nobleSecp256k1.Signature(parsed.r, nobleSecp256k1.Point.CURVE().n - parsed.s).toBytes('compact')
    assert.equal(nobleSecp256k1.verify(upper, digest, publicKey, {lowS: false, prehash: false}), true)
    assert.equal(crypto.secp256k1.verify(publicKey, digest, upper), false)
    key.dispose()
  })

  test('malformed input throws: lengths, keys, recovery ids', () => {
    const key = crypto.keys.generate('secp256k1')
    const digest = crypto.random(32)
    const signed = key.sign(digest)
    throwsCode(() => crypto.secp256k1.verify(key.publicKey(), digest.subarray(1), signed.signature), 'INVALID_LENGTH')
    throwsCode(() => crypto.secp256k1.verify(new Uint8Array(33), digest, signed.signature), 'INVALID_PUBLIC_KEY')
    throwsCode(() => crypto.secp256k1.recover(digest, {...signed, recovery: 4 as 0}), 'INVALID_SIGNATURE')
    throwsCode(() => key.sign(digest.subarray(1)), 'INVALID_LENGTH')
    throwsCode(() => crypto.keys.importRawSecret('secp256k1', new Uint8Array(32)), 'INVALID_PRIVATE_KEY')
    throwsCode(() => crypto.keys.importRawSecret('secp256k1', new Uint8Array(31).fill(1)), 'INVALID_LENGTH')
    key.dispose()
  })

  test('convertPublicKey re-encodes and validates', () => {
    const key = crypto.keys.generate('secp256k1')
    assert.deepEqual(crypto.secp256k1.convertPublicKey(key.publicKey(), 'uncompressed'), key.publicKey('uncompressed'))
    assert.deepEqual(crypto.secp256k1.convertPublicKey(key.publicKey('uncompressed'), 'compressed'), key.publicKey())
    // x = 5 is on no point of the curve: 5^3 + 7 = 132 is not a square modulo p.
    const offCurve = new Uint8Array(33)
    offCurve[0] = 2
    offCurve[32] = 5
    throwsCode(() => crypto.secp256k1.convertPublicKey(offCurve, 'compressed'), 'INVALID_PUBLIC_KEY')
    key.dispose()
  })
})

describe('ed25519', () => {
  test('signatures and public keys equal @noble/curves, and verify both ways', () => {
    const random = seededBytes(30)
    for (let round = 0; round < 64; round++) {
      const seed = random.bytes(32)
      const message = random.bytes(random.integer(200))
      const key = crypto.keys.importRawSecret('ed25519', seed)
      const signature = key.sign(message)
      assert.deepEqual(key.publicKey(), nobleEd25519.getPublicKey(seed))
      assert.deepEqual(signature, nobleEd25519.sign(message, seed))
      assert.equal(crypto.ed25519.verify(key.publicKey(), message, signature), true)
      key.dispose()
    }
  })

  test('verify is false for a changed message or signature; malformed lengths throw', () => {
    const key = crypto.keys.generate('ed25519')
    const message = utf8.encode('hello')
    const signature = key.sign(message)
    assert.equal(crypto.ed25519.verify(key.publicKey(), utf8.encode('hellO'), signature), false)
    const tampered = signature.slice()
    tampered[0] = (tampered[0] ?? 0) ^ 1
    assert.equal(crypto.ed25519.verify(key.publicKey(), message, tampered), false)
    throwsCode(() => crypto.ed25519.verify(key.publicKey().subarray(1), message, signature), 'INVALID_LENGTH')
    key.dispose()
  })
})

describe('keys', () => {
  test('a disposed key throws DISPOSED and frees its handle', () => {
    const before = crypto.liveHandles()
    const key = crypto.keys.generate('ed25519')
    assert.equal(crypto.liveHandles(), before + 1)
    key.dispose()
    key.dispose()
    assert.equal(key.disposed, true)
    assert.equal(crypto.liveHandles(), before)
    throwsCode(() => key.sign(new Uint8Array()), 'DISPOSED')
    throwsCode(() => key.publicKey(), 'DISPOSED')
  })

  test('returned public keys are copies: mutating one does not change the key', () => {
    const key = crypto.keys.generate('secp256k1')
    const first = key.publicKey()
    first.fill(0)
    assert.notDeepEqual(key.publicKey(), first)
    key.dispose()
  })
})
