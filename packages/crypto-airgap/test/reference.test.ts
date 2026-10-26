import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {describe, test} from 'node:test'

import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'

import {
  bytewords,
  createMultipartDecoder,
  createMultipartEncoder,
  decodeCbor,
  decodeUR,
  encodeCbor,
  encodeUR,
  isAirgapError,
} from '../src'
import {fromHex, toHex} from '../src/bytes'
import {crc32} from '../src/crc32'
import {
  chooseDegree,
  chooseFragments,
  createFountainDecoder,
  createFountainEncoder,
  createSampler,
  createXoshiro,
  fragmentLengthFor,
  shuffle,
} from '../src/fountain'

/** SHA-256 from the engine (as WebAssembly here): what an app passes, `crypto.hash.sha256`. */
const {sha256} = createTestCryptoEngine().hash

/** The reference implementation's (bc-ur, C++) own test vectors: see the file's `source`. */
const VECTORS = JSON.parse(readFileSync(new URL('./vectors/bc-ur.json', import.meta.url), 'utf8'))

const text = (value: string) => new TextEncoder().encode(value)

/** The reference's `Xoshiro256(uint32_t)`: the generator seeded with a number's four big-endian bytes. */
const xoshiroOfInt = (value: number) => {
  const bytes = new Uint8Array(4)
  new DataView(bytes.buffer).setUint32(0, value, false)

  return createXoshiro(bytes, sha256)
}

/** The reference's `make_message`: `length` bytes from a generator seeded with "Wolf". */
const makeMessage = (length: number, seed = 'Wolf') => {
  const rng = createXoshiro(text(seed), sha256)

  return Uint8Array.from({length}, () => rng.nextInt(0, 255))
}

/** The reference's `make_message_ur`: the message as a CBOR byte string, in a `bytes` UR. */
const makeMessageUR = (length: number) => ({cbor: encodeCbor(makeMessage(length)), type: 'bytes'})

describe('Blockchain Commons reference vectors', () => {
  test('CRC-32', () => {
    for (const [input, expected] of VECTORS.crc32) {
      assert.equal(crc32(text(input)).toString(16).padStart(8, '0'), expected)
    }
  })

  test('Bytewords: every style, both ways', () => {
    const {badChecksum, ...one} = VECTORS.bytewords1
    const input = Uint8Array.from(one.input)

    for (const style of ['standard', 'uri', 'minimal'] as const) {
      assert.equal(bytewords.encode(input, style), one[style])
      assert.deepEqual(bytewords.decode(one[style], style), input)
      assert.throws(
        () => bytewords.decode(badChecksum[style], style),
        error => isAirgapError(error, 'INVALID_UR')
      )
    }

    assert.throws(
      () => bytewords.decode('wolf', 'standard'),
      error => isAirgapError(error, 'INVALID_UR')
    )
    assert.throws(
      () => bytewords.decode('', 'standard'),
      error => isAirgapError(error, 'INVALID_UR')
    )

    const two = VECTORS.bytewords2
    const bytes = Uint8Array.from(two.input)
    assert.equal(bytewords.encode(bytes, 'standard'), two.standard)
    assert.equal(bytewords.encode(bytes, 'minimal'), two.minimal)
    assert.deepEqual(bytewords.decode(two.standard, 'standard'), bytes)
    assert.deepEqual(bytewords.decode(two.minimal, 'minimal'), bytes)
    assert.deepEqual(bytewords.decode(two.minimal.toUpperCase(), 'minimal'), bytes)
  })

  test('Xoshiro256**', () => {
    const wolf = createXoshiro(text('Wolf'), sha256)
    assert.deepEqual(
      Array.from({length: 100}, () => Number(wolf.next() % 100n)),
      VECTORS.rng1
    )

    const checksum = xoshiroOfInt(crc32(text('Wolf')))
    assert.deepEqual(
      Array.from({length: 100}, () => Number(checksum.next() % 100n)),
      VECTORS.rng2
    )

    const ints = createXoshiro(text('Wolf'), sha256)
    assert.deepEqual(
      Array.from({length: 100}, () => ints.nextInt(1, 10)),
      VECTORS.rng3
    )
  })

  test('nominal fragment length', () => {
    for (const [messageLength, min, max, expected] of VECTORS.fragmentLength) {
      assert.equal(fragmentLengthFor(messageLength, min, max), expected)
    }
  })

  test('alias sampler', () => {
    const sample = createSampler(VECTORS.sampler.weights)
    const rng = createXoshiro(text('Wolf'), sha256)
    assert.deepEqual(
      Array.from({length: 500}, () => sample(rng)),
      VECTORS.sampler.samples
    )
  })

  test('shuffle', () => {
    const rng = createXoshiro(text('Wolf'), sha256)
    const values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    assert.deepEqual(
      Array.from({length: 10}, () => shuffle(values, rng)),
      VECTORS.shuffle
    )
  })

  test('degree', () => {
    const seqLength = Math.ceil(1024 / fragmentLengthFor(1024, 10, 100))
    assert.deepEqual(
      Array.from({length: 200}, (_, index) =>
        chooseDegree(seqLength, createXoshiro(text(`Wolf-${index + 1}`), sha256))
      ),
      VECTORS.degrees
    )
  })

  test('fragment choices', () => {
    const message = makeMessage(1024)
    const fragmentLength = fragmentLengthFor(message.length, 10, 100)
    const seqLength = Math.ceil(message.length / fragmentLength)
    const checksum = crc32(message)

    assert.deepEqual(
      Array.from({length: 30}, (_, index) =>
        chooseFragments(index + 1, seqLength, checksum, sha256).sort((a, b) => a - b)
      ),
      VECTORS.chooseFragments
    )
  })

  test('partition: fragments padded with zeros', () => {
    const message = makeMessage(1024)
    const encoder = createFountainEncoder(message, 100, 10, 0, sha256)

    assert.equal(encoder.seqLength, VECTORS.partition.length)
    assert.deepEqual(
      Array.from({length: encoder.seqLength}, () => toHex(encoder.nextPart().data)),
      VECTORS.partition
    )
  })

  test('XOR of generated data', () => {
    const rng = createXoshiro(text('Wolf'), sha256)
    const first = Uint8Array.from({length: 10}, () => rng.nextInt(0, 255))
    const second = Uint8Array.from({length: 10}, () => rng.nextInt(0, 255))
    assert.equal(toHex(first), VECTORS.xor[0])
    assert.equal(toHex(second), VECTORS.xor[1])
    assert.equal(toHex(first.map((byte, index) => byte ^ (second[index] ?? 0))), VECTORS.xor[2])
  })

  test('fountain encoder: parts, and their CBOR', () => {
    const encoder = createFountainEncoder(makeMessage(256), 30, 10, 0, sha256)

    for (let index = 0; index < 20; index++) {
      const part = encoder.nextPart()
      assert.equal(
        `seqNum:${part.seqNum}, seqLen:${part.seqLength}, messageLen:${part.messageLength}, checksum:${part.checksum}, data:${toHex(part.data)}`,
        VECTORS.fountainParts[index]
      )
      assert.equal(
        toHex(encodeCbor([part.seqNum, part.seqLength, part.messageLength, part.checksum, part.data])),
        VECTORS.fountainPartsCbor[index]
      )
      assert.deepEqual(decodeCbor(fromHex(VECTORS.fountainPartsCbor[index])), [
        part.seqNum,
        part.seqLength,
        part.messageLength,
        part.checksum,
        part.data,
      ])
    }
  })

  test('fountain decoder: a 32767-byte message from part 101 on', () => {
    const message = makeMessage(32767)
    const encoder = createFountainEncoder(message, 1000, 10, 100, sha256)
    const decoder = createFountainDecoder({
      maxFragments: 2048,
      maxMessageBytes: 1_000_000,
      maxPendingParts: 512,
      sha256,
    })

    while (!decoder.result) {
      decoder.receive(encoder.nextPart())
    }

    assert.deepEqual(decoder.result, message)
  })

  test('single-part UR', () => {
    const ur = makeMessageUR(50)
    assert.equal(encodeUR(ur), VECTORS.singlePartUR)
    assert.deepEqual(decodeUR(VECTORS.singlePartUR, {allowedTypes: ['bytes']}), ur)
    assert.deepEqual(decodeUR(VECTORS.singlePartUR.toUpperCase(), {allowedTypes: ['bytes']}), ur)
  })

  test('multipart UR: the first 20 parts', () => {
    const encoder = createMultipartEncoder(makeMessageUR(256), {maxFragmentLength: 30, sha256})
    assert.deepEqual(
      Array.from({length: 20}, () => encoder.nextPart()),
      VECTORS.urParts
    )
  })

  test('multipart UR: a 32767-byte message, decoded from part 101 on', () => {
    const ur = makeMessageUR(32767)
    const encoder = createMultipartEncoder(ur, {firstSeqNum: 100, maxFragmentLength: 1000, sha256})
    const decoder = createMultipartDecoder({allowedTypes: ['bytes'], sha256})

    while (!decoder.isComplete()) {
      decoder.receivePart(encoder.nextPart())
    }

    assert.deepEqual(decoder.result(), ur)
  })
})
