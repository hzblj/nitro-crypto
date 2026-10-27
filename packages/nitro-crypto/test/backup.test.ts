import assert from 'node:assert/strict'
import {describe, test} from 'node:test'

import {xchacha20poly1305} from '@noble/ciphers/chacha.js'
import {hkdf} from '@noble/hashes/hkdf.js'
import {sha256} from '@noble/hashes/sha2.js'

import {hex, utf8} from '../src/encoding'
import {createAbi} from './abi'
import {engineVectorText} from './support'

/**
 * Backups sealed under a 32-byte key (ADR 0010) through the WebAssembly build of the engine. Native callers only:
 * no JavaScript API takes or returns entropy, so these tests reach the C ABI itself.
 */
const abi = createAbi()

const MAX_LENGTH = 103
const KEY_HEADER_LENGTH = 46

type Result<T> = {readonly status: string; readonly value?: T}

const sealWithKey = (entropy: Uint8Array, key: Uint8Array, capacity = MAX_LENGTH): Result<Uint8Array> =>
  abi.frame(frame => {
    const out = frame.allocate(capacity)
    const written = frame.allocate(4)
    const status = abi.engine.nc_backup_seal_with_key(
      ...frame.input(entropy),
      ...frame.input(key),
      out,
      capacity,
      written
    )

    return {status: abi.statusName(status), value: status === 0 ? frame.read(out, frame.u32(written)) : undefined}
  })

const openWithKey = (backup: Uint8Array, key: Uint8Array, capacity = 32): Result<Uint8Array> =>
  abi.frame(frame => {
    const out = frame.allocate(capacity)
    const written = frame.allocate(4)
    const status = abi.engine.nc_backup_open_with_key(
      ...frame.input(backup),
      ...frame.input(key),
      out,
      capacity,
      written
    )

    return {status: abi.statusName(status), value: status === 0 ? frame.read(out, frame.u32(written)) : undefined}
  })

const openWithPassword = (backup: Uint8Array, password: string): string =>
  abi.frame(frame => {
    const out = frame.allocate(32)
    const written = frame.allocate(4)

    return abi.statusName(
      abi.engine.nc_backup_open(...frame.input(backup), ...frame.input(utf8.encode(password)), out, 32, written)
    )
  })

const keyDerivation = (backup: Uint8Array): Result<number> =>
  abi.frame(frame => {
    const kdf = frame.allocate(4)
    const status = abi.engine.nc_backup_kdf(...frame.input(backup), kdf)

    return {status: abi.statusName(status), value: status === 0 ? frame.u32(kdf) : undefined}
  })

/** ADR 0010's format, opened by @noble: HKDF-SHA256 over the key and the salt, XChaCha20-Poly1305, header as data. */
const nobleOpen = (backup: Uint8Array, key: Uint8Array) => {
  const header = backup.subarray(0, KEY_HEADER_LENGTH)
  const sealingKey = hkdf(sha256, key, header.subarray(6, 22), utf8.encode('ncbk xchacha20poly1305 key'), 32)

  return xchacha20poly1305(sealingKey, header.subarray(22, 46), header).decrypt(backup.subarray(KEY_HEADER_LENGTH))
}

const randomKey = () => globalThis.crypto.getRandomValues(new Uint8Array(32))

describe('backups sealed under a key', () => {
  test('open what @noble sealed, and @noble opens what the engine seals, at every entropy length', () => {
    const {vectors} = JSON.parse(engineVectorText('backup_key.json')) as {
      vectors: {backup: string; entropy: string; key: string}[]
    }

    for (const vector of vectors) {
      const opened = openWithKey(hex.decode(vector.backup), hex.decode(vector.key))
      assert.equal(opened.status, 'NC_OK')
      assert.equal(hex.encode(opened.value ?? new Uint8Array()), vector.entropy)
      assert.deepEqual(keyDerivation(hex.decode(vector.backup)), {status: 'NC_OK', value: 2})
    }

    for (const length of [16, 20, 24, 28, 32]) {
      const entropy = globalThis.crypto.getRandomValues(new Uint8Array(length))
      const key = randomKey()
      const sealed = sealWithKey(entropy, key).value ?? new Uint8Array()
      assert.equal(sealed.length, KEY_HEADER_LENGTH + length + 16)
      assert.equal(hex.encode(sealed.subarray(0, 6)), '6e63626b0102')
      assert.deepEqual(nobleOpen(sealed, key), entropy)
      assert.deepEqual(openWithKey(sealed, key).value, entropy)
      // Fresh salt and nonce: the same entropy under the same key seals differently.
      assert.notDeepEqual(sealWithKey(entropy, key).value, sealed)
    }
  })

  test('a wrong key and any changed byte fail; the prefix as unreadable, the rest as unverifiable', () => {
    const key = randomKey()
    const sealed = sealWithKey(new Uint8Array(32).fill(7), key).value ?? new Uint8Array()
    const wrong = key.slice()
    wrong[5] = (wrong[5] ?? 0) ^ 1
    assert.equal(openWithKey(sealed, wrong).status, 'NC_ERR_VERIFICATION_FAILED')

    for (let index = 0; index < sealed.length; index++) {
      const changed = sealed.slice()
      changed[index] = (changed[index] ?? 0) ^ 0x80
      const expected = index < 6 ? 'NC_ERR_INVALID_ARGUMENT' : 'NC_ERR_VERIFICATION_FAILED'
      assert.equal(openWithKey(changed, key).status, expected, `byte ${index}`)
    }
  })

  test('a password cannot open a key-sealed backup, nor a key a password-sealed one, and each says which it is', () => {
    const key = randomKey()
    const sealed = sealWithKey(new Uint8Array(16).fill(1), key).value ?? new Uint8Array()
    assert.equal(openWithPassword(sealed, 'correct horse'), 'NC_ERR_INVALID_ARGUMENT')

    const {vectors} = JSON.parse(engineVectorText('backup.json')) as {vectors: {backup: string}[]}
    const password = hex.decode(vectors[0]?.backup ?? '')
    assert.equal(openWithKey(password, key).status, 'NC_ERR_INVALID_ARGUMENT')
    assert.deepEqual(keyDerivation(password), {status: 'NC_OK', value: 1})

    // Relabelled as the other kind, either fails cleanly.
    const relabelled = password.slice()
    relabelled[5] = 2
    assert.equal(openWithKey(relabelled, key).status, 'NC_ERR_INVALID_LENGTH')
  })

  test('refusals: key and entropy lengths, a key of zeros, short buffers, truncated and foreign backups', () => {
    const key = randomKey()
    const entropy = new Uint8Array(16).fill(3)
    assert.equal(sealWithKey(entropy, key.subarray(1)).status, 'NC_ERR_INVALID_LENGTH')
    assert.equal(sealWithKey(entropy, new Uint8Array(33).fill(1)).status, 'NC_ERR_INVALID_LENGTH')
    assert.equal(sealWithKey(entropy, new Uint8Array(32)).status, 'NC_ERR_INVALID_ARGUMENT')
    assert.equal(sealWithKey(entropy.subarray(1), key).status, 'NC_ERR_INVALID_LENGTH')
    assert.equal(sealWithKey(new Uint8Array(33).fill(3), key).status, 'NC_ERR_INVALID_LENGTH')
    assert.equal(sealWithKey(entropy, key, KEY_HEADER_LENGTH + 31).status, 'NC_ERR_BUFFER_TOO_SMALL')

    const sealed = sealWithKey(entropy, key).value ?? new Uint8Array()
    assert.equal(openWithKey(sealed, key, 31).status, 'NC_ERR_BUFFER_TOO_SMALL')
    assert.equal(openWithKey(sealed, new Uint8Array(32)).status, 'NC_ERR_INVALID_ARGUMENT')
    assert.equal(openWithKey(sealed.subarray(0, -1), key).status, 'NC_ERR_INVALID_LENGTH')
    assert.equal(openWithKey(sealed.subarray(0, 5), key).status, 'NC_ERR_INVALID_LENGTH')
    assert.equal(openWithKey(new Uint8Array(), key).status, 'NC_ERR_INVALID_LENGTH')
    assert.equal(keyDerivation(sealed.subarray(0, -1)).status, 'NC_ERR_INVALID_LENGTH')
    assert.equal(
      keyDerivation(utf8.encode('not a backup at all, but long enough to be one')).status,
      'NC_ERR_INVALID_ARGUMENT'
    )
    const later = sealed.slice()
    later[4] = 2
    assert.equal(keyDerivation(later).status, 'NC_ERR_INVALID_ARGUMENT')
    assert.equal(abi.engine.nc_handle_count(), 0)
  })
})
