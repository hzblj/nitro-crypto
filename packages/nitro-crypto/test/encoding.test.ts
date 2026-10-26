import assert from 'node:assert/strict'
import {describe, test} from 'node:test'

import {base58 as scureBase58, bech32 as scureBech32, bech32m as scureBech32m} from '@scure/base'

import {isCryptoError} from '../src/core/errors'
import {base58, base58check, bech32, hex, utf8} from '../src/encoding'
import {crypto, seededBytes, vectors} from './support'

const rejects = (run: () => unknown, code = 'INVALID_ENCODING') =>
  assert.throws(run, error => isCryptoError(error) && error.code === code)

describe('hex', () => {
  test('round-trips, with and without the prefix, in either case', () => {
    const bytes = Uint8Array.of(0, 1, 0x7f, 0x80, 0xab, 0xff)
    assert.equal(hex.encode(bytes), '00017f80abff')
    assert.equal(hex.encode(bytes, {prefix: true}), '0x00017f80abff')
    assert.deepEqual(hex.decode('0x00017F80ABff'), bytes)
    assert.deepEqual(hex.decode(''), new Uint8Array())
  })

  test('refuses odd lengths and non-hex characters', () => {
    rejects(() => hex.decode('abc'))
    rejects(() => hex.decode('zz'))
    rejects(() => hex.decode('0x0g'))
    assert.equal(hex.isHex('0xab'), true)
    assert.equal(hex.isHex('0xa'), false)
  })
})

describe('utf8', () => {
  test('matches TextEncoder and TextDecoder, valid text and invalid bytes alike', () => {
    const encoder = new TextEncoder()
    const decoder = new TextDecoder()
    for (const text of ['', 'abc', 'é', 'ñandú', '日本語', '😀', 'a\ud800b', '\udc00', 'Ⅻ', '\u0000']) {
      assert.deepEqual(utf8.encode(text), encoder.encode(text), JSON.stringify(text))
      assert.equal(utf8.decode(utf8.encode(text)), decoder.decode(encoder.encode(text)))
    }
    const random = seededBytes(1)
    for (let round = 0; round < 2000; round++) {
      const bytes = random.bytes(random.integer(12))
      assert.equal(utf8.decode(bytes), decoder.decode(bytes), hex.encode(bytes))
    }
  })
})

describe('base58', () => {
  // Bitcoin Core's src/test/data/base58_encode_decode.json.
  const cases: [string, string][] = [
    ['', ''],
    ['61', '2g'],
    ['626262', 'a3gV'],
    ['636363', 'aPEr'],
    ['73696d706c792061206c6f6e6720737472696e67', '2cFupjhnEsSn59qHXstmK2ffpLv2'],
    ['00eb15231dfceb60925886b67d065299925915aeb172c06647', '1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L'],
    ['516b6fcd0f', 'ABnLTmg'],
    ['bf4f89001e670274dd', '3SEo3LWLoPntC'],
    ['572e4794', '3EFU7m'],
    ['ecac89cad93923c02321', 'EJDM8drfXA6uyA'],
    ['10c8511e', 'Rt5zm'],
    ['00000000000000000000', '1111111111'],
  ]

  test("Bitcoin Core's vectors", () => {
    for (const [bytes, text] of cases) {
      assert.equal(base58.encode(hex.decode(bytes)), text)
      assert.deepEqual(base58.decode(text), hex.decode(bytes))
    }
  })

  test('agrees with @scure/base on random input, leading zeros included', () => {
    const random = seededBytes(2)
    for (let round = 0; round < 500; round++) {
      const bytes = random.bytes(random.integer(48))
      bytes.fill(0, 0, random.integer(4))
      assert.equal(base58.encode(bytes), scureBase58.encode(bytes))
      assert.deepEqual(base58.decode(scureBase58.encode(bytes)), bytes)
    }
  })

  test('refuses characters outside the alphabet', () => {
    for (const text of ['0', 'O', 'I', 'l', ' ', '1+']) {
      rejects(() => base58.decode(text))
    }
  })

  test('Base58Check round-trips and refuses a broken checksum', () => {
    const payload = hex.decode('00751e76e8199196d454941c45d1b3a323f1433bd6')
    const text = base58check.encode(payload, crypto.hash.sha256)
    assert.equal(text, '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH')
    assert.deepEqual(base58check.decode(text, crypto.hash.sha256), payload)
    rejects(() => base58check.decode(`${text.slice(0, -1)}J`, crypto.hash.sha256))
    rejects(() => base58check.decode('1', crypto.hash.sha256))
  })
})

type Bech32Vectors = Record<'bech32' | 'bech32m', {valid: string[]; invalid: {string: string; reason: string}[]}>

describe('bech32', () => {
  const sets = vectors<Bech32Vectors>('bech32.json')

  for (const variant of ['bech32', 'bech32m'] as const) {
    test(`BIP-${variant === 'bech32' ? 173 : 350}: valid ${variant} strings decode as ${variant} and re-encode`, () => {
      for (const text of sets[variant].valid) {
        const decoded = bech32.decode(text)
        assert.equal(decoded.variant, variant, text)
        assert.equal(bech32.encode(decoded.hrp, decoded.words, variant), text.toLowerCase())
      }
    })

    test(`BIP-${variant === 'bech32' ? 173 : 350}: invalid ${variant} strings are refused`, () => {
      for (const {reason, string} of sets[variant].invalid) {
        let decoded: ReturnType<typeof bech32.decode> | undefined
        try {
          decoded = bech32.decode(string)
        } catch (error) {
          assert.ok(isCryptoError(error, 'INVALID_ENCODING'), reason)
          continue
        }
        // Valid as the other variant is still invalid as this one.
        assert.notEqual(decoded.variant, variant, `${JSON.stringify(string)}: ${reason}`)
      }
    })
  }

  test('agrees with @scure/base for both variants', () => {
    const random = seededBytes(3)
    for (let round = 0; round < 300; round++) {
      const bytes = random.bytes(random.integer(40))
      const words = bech32.toWords(bytes)
      assert.deepEqual(words, scureBech32.toWords(bytes))
      assert.deepEqual(bech32.fromWords(words), bytes)
      assert.equal(bech32.encode('bc', words, 'bech32'), scureBech32.encode('bc', words))
      assert.equal(bech32.encode('tb', words, 'bech32m'), scureBech32m.encode('tb', words))
    }
  })

  test('refuses non-zero padding and out-of-range words', () => {
    rejects(() => bech32.fromWords([31]))
    rejects(() => bech32.encode('bc', [32], 'bech32'))
    rejects(() => bech32.encode('', [], 'bech32'))
  })
})
