import assert from 'node:assert/strict'
import {test} from 'node:test'

import {CRYPTO_ERROR_CODES, CryptoError, fromNativeError, isCryptoError, native} from '../src/core/errors'
import {createEngine} from '../src/engine/create-engine'
import {SUPPORTED_ABI_VERSION} from '../src/engine/info'
import {testHost} from '../src/testing'

test('native status names map to codes, whatever Nitro prefixes them with', () => {
  const nitro = new Error('`NitroCrypto.hash(...)`: NC_ERR_INVALID_LENGTH')
  assert.equal(fromNativeError(nitro).code, 'INVALID_LENGTH')
  assert.equal(fromNativeError(new Error('NC_ERR_MNEMONIC_CHECKSUM')).code, 'MNEMONIC_CHECKSUM')
  assert.equal(fromNativeError(new Error('NC_ERR_SOMETHING_NEW')).code, 'INTERNAL')
})

test('a native message is never passed through: it could hold an input', () => {
  const mapped = fromNativeError(new Error('Cannot convert "abandon abandon …" to ArrayBuffer'))
  assert.equal(mapped.code, 'INVALID_ARGUMENT')
  assert.doesNotMatch(mapped.message, /abandon/)
  assert.equal(mapped.cause, undefined)
})

test('CryptoError carries a code and a default message for every code', () => {
  for (const code of CRYPTO_ERROR_CODES) {
    const error = new CryptoError(code)
    assert.equal(error.code, code)
    assert.ok(error.message.length > 0)
    assert.ok(isCryptoError(error, code))
  }
  assert.equal(isCryptoError(new Error('x')), false)
})

test('native() rethrows as CryptoError and passes CryptoErrors through', () => {
  assert.throws(
    () =>
      native(() => {
        throw new Error('NC_ERR_INVALID_PATH')
      }),
    error => isCryptoError(error, 'INVALID_PATH')
  )
  const original = new CryptoError('DISPOSED')
  assert.throws(
    () =>
      native(() => {
        throw original
      }),
    error => error === original
  )
})

test('an engine reporting another ABI is refused before anything runs', () => {
  const host = testHost()
  const future = new Proxy(host, {
    get: (target, property) => (property === 'abiVersion' ? SUPPORTED_ABI_VERSION + 1 : Reflect.get(target, property)),
  })
  assert.throws(
    () => createEngine(future),
    error => isCryptoError(error, 'ABI_MISMATCH')
  )
})
