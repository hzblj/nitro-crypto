import assert from 'node:assert/strict'
import {describe, test} from 'node:test'

import {type CborValue, cborTag, decodeCbor, encodeCbor, isAirgapError} from '../src'
import {fromHex, toHex} from '../src/bytes'

const throwsCode = (run: () => unknown, code: Parameters<typeof isAirgapError>[1]) =>
  assert.throws(run, error => isAirgapError(error, code))

describe('CBOR', () => {
  test('RFC 8949 appendix A examples', () => {
    const examples: [CborValue, string][] = [
      [0, '00'],
      [23, '17'],
      [24, '1818'],
      [100, '1864'],
      [1000, '1903e8'],
      [1_000_000, '1a000f4240'],
      [1_000_000_000_000, '1b000000e8d4a51000'],
      [18_446_744_073_709_551_615n, '1bffffffffffffffff'],
      [-1, '20'],
      [-1000, '3903e7'],
      [-18_446_744_073_709_551_616n, '3bffffffffffffffff'],
      [false, 'f4'],
      [true, 'f5'],
      [null, 'f6'],
      [undefined, 'f7'],
      [new Uint8Array(0), '40'],
      [fromHex('01020304'), '4401020304'],
      ['', '60'],
      ['IETF', '6449455446'],
      ['"\\', '62225c'],
      ['ü', '62c3bc'],
      ['水', '63e6b0b4'],
      ['𐅑', '64f0908591'],
      [[], '80'],
      [[1, 2, 3], '83010203'],
      [[1, [2, 3], [4, 5]], '8301820203820405'],
      [
        new Map([
          [1, 2],
          [3, 4],
        ]),
        'a201020304',
      ],
      [
        new Map<string | number, CborValue>([
          ['a', 1],
          ['b', [2, 3]],
        ]),
        'a26161016162820203',
      ],
      [cborTag(1, 1363896240), 'c11a514b67b0'],
      [cborTag(32, 'http://www.example.com'), 'd82076687474703a2f2f7777772e6578616d706c652e636f6d'],
    ]

    for (const [value, hex] of examples) {
      assert.equal(toHex(encodeCbor(value)), hex, hex)
      assert.deepEqual(decodeCbor(fromHex(hex)), value, hex)
    }
  })

  test('map keys in deterministic order, whatever order they were given in', () => {
    assert.equal(
      toHex(
        encodeCbor(
          new Map<string | number, CborValue>([
            ['a', 1],
            [10, 2],
            [-1, 3],
            [1, 4],
            [100, 5],
          ])
        )
      ),
      'a501040a021864052003616101'
    )
  })

  test('refuses what UR types never use and hostile payloads use', () => {
    for (const hex of [
      'f93c00', // half float
      'fa47c35000', // single float
      'fb3ff199999999999a', // double float
      '5f42010243030405ff', // indefinite byte string
      '9f018202039f0405ffff', // indefinite array
      'bf6346756ef563416d7421ff', // indefinite map
      'f0', // simple value 16
      'f818', // simple value 24
      '1c', // reserved additional information
      'a20102010304', // repeated key
      'a1f401', // a boolean key
      '62c328', // invalid UTF-8
      '63eda080', // an encoded surrogate
    ]) {
      throwsCode(() => decodeCbor(fromHex(hex)), 'INVALID_CBOR')
    }
  })

  test('refuses truncation and trailing bytes', () => {
    throwsCode(() => decodeCbor(fromHex('1903')), 'INVALID_CBOR')
    throwsCode(() => decodeCbor(fromHex('4401020304ff')), 'INVALID_CBOR')
    throwsCode(() => decodeCbor(new Uint8Array(0)), 'INVALID_CBOR')
  })

  test('a declared length past the end fails before anything is allocated', () => {
    // A byte string, an array and a map each claiming 2^32 - 1 entries in a handful of bytes.
    for (const hex of ['5affffffff', '9affffffff', 'baffffffff', '5bffffffffffffffff']) {
      throwsCode(() => decodeCbor(fromHex(hex)), 'INVALID_CBOR')
    }
  })

  test('nesting and item limits', () => {
    const deep = fromHex(`${'81'.repeat(40)}00`)
    throwsCode(() => decodeCbor(deep), 'PAYLOAD_TOO_LARGE')
    assert.doesNotThrow(() => decodeCbor(deep, {maxDepth: 64}))
    throwsCode(() => decodeCbor(encodeCbor(Array.from({length: 50}, () => 0)), {maxItems: 10}), 'PAYLOAD_TOO_LARGE')
  })

  test('random bytes either decode or fail with an AirgapError, never anything else', () => {
    let state = 99
    const next = () => {
      state = (Math.imul(state, 1103515245) + 12345) >>> 0

      return state >>> 16
    }

    for (let run = 0; run < 20_000; run++) {
      const bytes = Uint8Array.from({length: 1 + (next() % 40)}, () => next() & 0xff)

      try {
        const value = decodeCbor(bytes)
        // What decodes re-encodes to the same value.
        assert.deepEqual(decodeCbor(encodeCbor(value)), value)
      } catch (error) {
        assert.ok(isAirgapError(error), `${toHex(bytes)}: ${String(error)}`)
      }
    }
  })

  test('encoding refuses what has no CBOR here', () => {
    throwsCode(() => encodeCbor(1.5), 'INVALID_ARGUMENT')
    throwsCode(() => encodeCbor(2 ** 60), 'INVALID_ARGUMENT')
    throwsCode(() => encodeCbor(2n ** 64n), 'INVALID_ARGUMENT')
    throwsCode(() => encodeCbor('\ud800'), 'INVALID_ARGUMENT')
    throwsCode(() => encodeCbor(cborTag(-1, 0)), 'INVALID_ARGUMENT')
  })
})
