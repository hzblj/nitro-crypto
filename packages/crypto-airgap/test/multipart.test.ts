import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {describe, test} from 'node:test'

import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'

import {
  CRYPTO_HDKEY,
  CRYPTO_KEYPATH,
  CRYPTO_MULTI_ACCOUNTS,
  createMultipartDecoder,
  createMultipartEncoder,
  createRequestId,
  createURRegistry,
  decodeUR,
  encodeCbor,
  encodeUR,
  formatKeypath,
  fromUR,
  isAirgapError,
  parseKeypath,
  readRequestId,
  toUR,
  VERSION,
  writeRequestId,
} from '../src'
import {bytewords} from '../src/bytewords'

/** SHA-256 from the engine (as WebAssembly here): what an app passes, `crypto.hash.sha256`. */
const {sha256} = createTestCryptoEngine().hash

const throwsCode = (run: () => unknown, code: Parameters<typeof isAirgapError>[1]) =>
  assert.throws(run, error => isAirgapError(error, code))

const message = (length: number, seed = 1) => Uint8Array.from({length}, (_, index) => (index * 31 + seed * 17) & 0xff)

const bytesUR = (length: number, seed = 1) => ({cbor: encodeCbor(message(length, seed)), type: 'bytes'})

describe('multipart decoder', () => {
  test('parts in any order, with duplicates, complete the message', () => {
    const ur = bytesUR(3000)
    const encoder = createMultipartEncoder(ur, {maxFragmentLength: 100, sha256})
    const parts = Array.from({length: encoder.fragmentCount}, () => encoder.nextPart())
    const decoder = createMultipartDecoder({allowedTypes: ['bytes'], sha256})

    for (const part of [...parts].reverse()) {
      decoder.receivePart(part)
      assert.equal(decoder.receivePart(part), false, 'a duplicate teaches nothing')
    }

    assert.ok(decoder.isComplete())
    assert.deepEqual(decoder.result(), ur)
    assert.equal(decoder.progress.fraction, 1)
  })

  test('fountain parts make up for lost ones', () => {
    for (const keep of [2, 3, 5]) {
      const ur = bytesUR(5000, keep)
      const encoder = createMultipartEncoder(ur, {maxFragmentLength: 150, sha256})
      const decoder = createMultipartDecoder({allowedTypes: ['bytes'], sha256})
      let index = 0

      while (!decoder.isComplete()) {
        const part = encoder.nextPart()

        if (index++ % keep === 0) {
          decoder.receivePart(part)
        }
      }

      assert.deepEqual(decoder.result(), ur)
      assert.ok(decoder.progress.receivedPartCount < encoder.fragmentCount * 3)
    }
  })

  test('progress is reported without any UI', () => {
    const encoder = createMultipartEncoder(bytesUR(1000), {maxFragmentLength: 100, sha256})
    const decoder = createMultipartDecoder({allowedTypes: ['bytes'], sha256})
    assert.deepEqual(decoder.progress, {
      expectedFragmentCount: 0,
      fraction: 0,
      receivedPartCount: 0,
      recoveredFragmentCount: 0,
      type: undefined,
    })

    decoder.receivePart(encoder.nextPart())
    assert.equal(decoder.progress.type, 'bytes')
    assert.equal(decoder.progress.expectedFragmentCount, encoder.fragmentCount)
    assert.equal(decoder.progress.recoveredFragmentCount, 1)
  })

  test('a part of another message is SESSION_MISMATCH, and the decoder keeps what it had', () => {
    const first = createMultipartEncoder(bytesUR(1000, 1), {maxFragmentLength: 100, sha256})
    const second = createMultipartEncoder(bytesUR(1000, 2), {maxFragmentLength: 100, sha256})
    const other = createMultipartEncoder(
      {cbor: encodeCbor(message(1000)), type: 'crypto-psbt'},
      {maxFragmentLength: 100, sha256}
    )
    const decoder = createMultipartDecoder({allowedTypes: ['bytes', 'crypto-psbt'], sha256})

    decoder.receivePart(first.nextPart())
    throwsCode(() => decoder.receivePart(second.nextPart()), 'SESSION_MISMATCH')
    throwsCode(() => decoder.receivePart(other.nextPart()), 'SESSION_MISMATCH')
    throwsCode(() => decoder.receivePart(encodeUR(bytesUR(10))), 'SESSION_MISMATCH')

    while (!decoder.isComplete()) {
      decoder.receivePart(first.nextPart())
    }

    assert.deepEqual(decoder.result(), bytesUR(1000, 1))
  })

  test('reset forgets the message, and a new one can be read', () => {
    const decoder = createMultipartDecoder({allowedTypes: ['bytes'], sha256})
    const first = createMultipartEncoder(bytesUR(800, 1), {maxFragmentLength: 100, sha256})
    decoder.receivePart(first.nextPart())
    decoder.reset()
    assert.equal(decoder.progress.receivedPartCount, 0)
    throwsCode(() => decoder.result(), 'INVALID_ARGUMENT')

    const second = createMultipartEncoder(bytesUR(800, 2), {maxFragmentLength: 100, sha256})

    while (!decoder.isComplete()) {
      decoder.receivePart(second.nextPart())
    }

    const result = decoder.result()
    decoder.reset()
    // The result handed out is the caller's copy: resetting the decoder does not overwrite it.
    assert.deepEqual(result, bytesUR(800, 2))
  })

  test('a single-part UR completes the decoder at once', () => {
    const decoder = createMultipartDecoder({allowedTypes: ['bytes'], sha256})
    assert.ok(decoder.receivePart(encodeUR(bytesUR(20)).toUpperCase()))
    assert.ok(decoder.isComplete())
    assert.equal(decoder.receivePart(encodeUR(bytesUR(20))), false)
    assert.deepEqual(decoder.result(), bytesUR(20))
  })

  test('types not allowed are refused, secret ones whatever the allowlist says', () => {
    const decoder = createMultipartDecoder({allowedTypes: ['crypto-psbt'], sha256})
    throwsCode(() => decoder.receivePart(encodeUR(bytesUR(20))), 'UNSUPPORTED_UR_TYPE')
    throwsCode(
      () => decoder.receivePart(encodeUR({cbor: encodeCbor(message(16)), type: 'crypto-seed'})),
      'PRIVATE_KEY_MATERIAL'
    )
    throwsCode(() => createMultipartDecoder({allowedTypes: ['crypto-seed'], sha256}), 'PRIVATE_KEY_MATERIAL')
    throwsCode(() => createMultipartDecoder({allowedTypes: [], sha256}), 'INVALID_ARGUMENT')
    throwsCode(() => createMultipartDecoder({allowedTypes: ['Not A Type'], sha256}), 'INVALID_ARGUMENT')
  })

  test('limits: message size, fragment count, and the parts a message may take', () => {
    const large = createMultipartEncoder(bytesUR(5000), {maxFragmentLength: 100, sha256})
    throwsCode(
      () =>
        createMultipartDecoder({allowedTypes: ['bytes'], maxMessageBytes: 1000, sha256}).receivePart(large.nextPart()),
      'PAYLOAD_TOO_LARGE'
    )
    throwsCode(
      () => createMultipartDecoder({allowedTypes: ['bytes'], maxFragments: 10, sha256}).receivePart(large.nextPart()),
      'PAYLOAD_TOO_LARGE'
    )

    const decoder = createMultipartDecoder({allowedTypes: ['bytes'], maxParts: 3, sha256})
    const encoder = createMultipartEncoder(bytesUR(5000), {maxFragmentLength: 100, sha256})
    decoder.receivePart(encoder.nextPart())
    decoder.receivePart(encoder.nextPart())
    decoder.receivePart(encoder.nextPart())
    throwsCode(() => decoder.receivePart(encoder.nextPart()), 'PAYLOAD_TOO_LARGE')

    throwsCode(
      () => decodeUR(encodeUR(bytesUR(5000)), {allowedTypes: ['bytes'], maxMessageBytes: 1000}),
      'PAYLOAD_TOO_LARGE'
    )
  })

  test('misreads and forgeries: checksums, sequence numbers, sizes', () => {
    const encoder = createMultipartEncoder(bytesUR(1000), {maxFragmentLength: 100, sha256})
    const part = encoder.nextPart()
    const decoder = createMultipartDecoder({allowedTypes: ['bytes'], sha256})

    // One letter changed: the Bytewords checksum catches it.
    const [prefix, sequence, body = ''] = part.split('/')
    const flipped = `${body.slice(0, 10)}${body[10] === 'a' ? 'b' : 'a'}${body.slice(11)}`
    throwsCode(() => decoder.receivePart(`${prefix}/${sequence}/${flipped}`), 'INVALID_UR')

    // The sequence in the text disagrees with the part's own.
    throwsCode(() => decoder.receivePart(`${prefix}/2-10/${body}`), 'INVALID_UR')

    // A part whose sizes describe no message: a 50-byte fragment of a 10-byte message.
    const bogus = encodeCbor([1, 1, 10, 0, message(50)])
    throwsCode(() => decoder.receivePart(`ur:bytes/1-1/${bytewords.encode(bogus, 'minimal')}`), 'INVALID_UR')

    // Parts that agree on a checksum the fragments do not produce.
    const forged = createMultipartDecoder({allowedTypes: ['bytes'], sha256})
    const fragments = [message(10, 1), message(10, 2)]
    const parts = fragments.map((data, index) => encodeCbor([index + 1, 2, 20, 12345, data]))
    forged.receivePart(`ur:bytes/1-2/${bytewords.encode(parts[0] ?? new Uint8Array(), 'minimal')}`)
    throwsCode(
      () => forged.receivePart(`ur:bytes/2-2/${bytewords.encode(parts[1] ?? new Uint8Array(), 'minimal')}`),
      'INVALID_UR'
    )
    assert.equal(forged.isComplete(), false)

    for (const text of [
      '',
      'ur:',
      'ur:bytes',
      'ur:BYTES/',
      'ur:bytes/0-1/aa',
      'ur:bytes/1-0/aa',
      'ur:by_tes/aeadaolazmjendeoti',
      'ur:bytes/a/b/c',
    ]) {
      throwsCode(() => decoder.receivePart(text), 'INVALID_UR')
    }
  })

  test('hostile strings fail with AirgapErrors only', () => {
    const encoder = createMultipartEncoder(bytesUR(2000), {maxFragmentLength: 100, sha256})
    const parts = Array.from({length: 30}, () => encoder.nextPart())
    let state = 5
    const next = () => {
      state = (Math.imul(state, 1103515245) + 12345) >>> 0

      return state >>> 16
    }

    for (let run = 0; run < 3000; run++) {
      const part = parts[next() % parts.length] ?? ''
      const at = next() % part.length
      const mutated = `${part.slice(0, at)}${String.fromCharCode(97 + (next() % 26))}${part.slice(at + 1)}`

      try {
        createMultipartDecoder({allowedTypes: ['bytes'], sha256}).receivePart(mutated)
      } catch (error) {
        assert.ok(isAirgapError(error), String(error))
      }
    }
  })
})

describe('typed registry', () => {
  test('a registry decodes to a union discriminated by type', () => {
    const registry = createURRegistry([CRYPTO_HDKEY, CRYPTO_MULTI_ACCOUNTS])
    assert.deepEqual(registry.types, ['crypto-hdkey', 'crypto-multi-accounts'])

    const key = {keyData: Uint8Array.of(2, ...new Uint8Array(32).fill(1)), origin: parseKeypath("m/44'/60'/0'", 1)}
    const decoded = registry.decode(toUR(CRYPTO_HDKEY, key))

    if (decoded.type !== 'crypto-hdkey') {
      assert.fail('a crypto-hdkey')
    }

    assert.deepEqual(decoded.value.keyData, key.keyData)
    throwsCode(() => registry.decode(bytesUR(4)), 'UNSUPPORTED_UR_TYPE')
    throwsCode(() => createURRegistry([CRYPTO_HDKEY, CRYPTO_HDKEY]), 'INVALID_ARGUMENT')
  })

  test('fromUR refuses another type, and CBOR that breaks the schema', () => {
    throwsCode(() => fromUR(CRYPTO_HDKEY, bytesUR(4)), 'UNSUPPORTED_UR_TYPE')
    throwsCode(
      () => fromUR(CRYPTO_HDKEY, {cbor: encodeCbor(new Map([[3, 'text']])), type: 'crypto-hdkey'}),
      'INVALID_PROTOCOL_DATA'
    )
    throwsCode(() => fromUR(CRYPTO_HDKEY, {cbor: encodeCbor([1, 2]), type: 'crypto-hdkey'}), 'INVALID_PROTOCOL_DATA')
    throwsCode(
      () => fromUR(CRYPTO_KEYPATH, {cbor: encodeCbor(new Map([[1, [0]]])), type: 'crypto-keypath'}),
      'INVALID_PROTOCOL_DATA'
    )
  })

  test('keypaths: text both ways, wildcards, ranges', () => {
    const path = parseKeypath("m/84'/1'/0'/0/*", 0x73c5da0a)
    assert.equal(formatKeypath(path), "m/84'/1'/0'/0/*")
    assert.deepEqual(fromUR(CRYPTO_KEYPATH, toUR(CRYPTO_KEYPATH, path)), path)
    assert.equal(formatKeypath(parseKeypath('m/44h/60H/0h')), "m/44'/60'/0'")
    assert.equal(
      formatKeypath(
        fromUR(CRYPTO_KEYPATH, {cbor: encodeCbor(new Map([[1, [[0, 1], false]]])), type: 'crypto-keypath'})
      ),
      'm/<0;1>'
    )

    for (const bad of ['', '44/0', "m/2147483648'", 'm/-1', 'm/0/', "m/0''"]) {
      throwsCode(() => parseKeypath(bad), 'INVALID_ARGUMENT')
    }
  })

  test('request ids: version 4 from the caller`s random bytes, and back from CBOR', () => {
    const id = createRequestId(length => new Uint8Array(length).fill(0xff))
    assert.equal(id, 'ffffffff-ffff-4fff-bfff-ffffffffffff')
    assert.equal(readRequestId(writeRequestId(id)), id)
    throwsCode(() => writeRequestId('not-a-uuid'), 'INVALID_ARGUMENT')
  })

  test('multipart needs SHA-256 from the caller: there is no implementation of its own to fall back on', () => {
    throwsCode(() => createMultipartEncoder(bytesUR(1000), {} as never), 'INVALID_ARGUMENT')
    throwsCode(() => createMultipartDecoder({allowedTypes: ['bytes']} as never), 'INVALID_ARGUMENT')
  })

  test('VERSION matches package.json', () => {
    const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
    assert.equal(VERSION, manifest.version)
  })
})
