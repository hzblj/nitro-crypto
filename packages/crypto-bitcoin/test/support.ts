import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import path from 'node:path'

import {base58check, isCryptoError, type Secp256k1Key} from '@hzblj/nitro-crypto/adapter'

// The engine's own C ABI, in an instance of its own: the WebAssembly build's test hook, which signs Schnorr with the
// auxiliary randomness given. The native libraries lack it; here it makes BIP-340 signatures reproducible.
import {createAbi} from '../../nitro-crypto/test/abi'

export const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

/** A vector file of this package (`test/vectors`). */
export const vectors = <T>(file: string): T =>
  JSON.parse(readFileSync(path.join(import.meta.dirname, 'vectors', file), 'utf8')) as T

/** A published vector file the engine's tests run too (`packages/zig-engine-crypto/test/vectors`). */
export const engineVectors = <T>(file: string): T =>
  JSON.parse(readFileSync(path.join(import.meta.dirname, '../../zig-engine-crypto/test/vectors', file), 'utf8')) as T

/** mulberry32: the same "random" cases on every run, so a failure can be replayed. */
export const seeded = (seed: number) => {
  let state = seed
  const next = () => {
    state = (state + 0x6d2b79f5) | 0
    let t = Math.imul(state ^ (state >>> 15), 1 | state)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t

    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }

  return {
    bytes: (length: number) => Uint8Array.from({length}, () => Math.floor(next() * 256)),
    integer: (below: number) => Math.floor(next() * below),
    next,
  }
}

type Code = Parameters<typeof isCryptoError>[1]

export const throwsWith = (run: () => unknown, code: Code, message?: RegExp) =>
  assert.throws(run, error => isCryptoError(error, code) && (!message || message.test(error.message)))

export const rejectsWith = async (promise: Promise<unknown>, code: Code, message?: RegExp) =>
  assert.rejects(promise, error => isCryptoError(error, code) && (!message || message.test(error.message)))

/** The 32-byte key of a compressed WIF private key (`L…`, `K…`, `c…`). */
export const wifSecret = (wif: string, sha256: (data: Uint8Array) => Uint8Array): Uint8Array => {
  const payload = base58check.decode(wif, sha256)
  assert.equal(payload.length, 34)
  assert.equal(payload[33], 1)

  return payload.slice(1, 33)
}

const abi = createAbi()

/** BIP-340 (or BIP-341's key path, with `taproot`) signed by the engine with the auxiliary randomness given. */
export const signWithAux = (
  secret: Uint8Array,
  message: Uint8Array,
  aux: Uint8Array,
  taproot?: {readonly merkleRoot?: Uint8Array}
): Uint8Array =>
  abi.frame(frame => {
    const handle = frame.allocate(8)
    const [secretPointer, secretLength] = frame.input(secret)
    assert.equal(abi.engine.nc_key_import(1, secretPointer, secretLength, handle), 0)
    const key = frame.u64(handle)

    try {
      const [messagePointer, messageLength] = frame.input(message)
      const [rootPointer, rootLength] = frame.input(taproot?.merkleRoot ?? new Uint8Array())
      const [auxPointer, auxLength] = frame.input(aux)
      const out = frame.allocate(64)
      const written = frame.allocate(4)
      const status = abi.engine.nc_wasm_test_sign_schnorr(
        key,
        messagePointer,
        messageLength,
        taproot ? 1 : 0,
        rootPointer,
        rootLength,
        auxPointer,
        auxLength,
        out,
        64,
        written
      )
      assert.equal(abi.statusName(status), 'NC_OK')

      return frame.read(out, frame.u32(written))
    } finally {
      abi.engine.nc_handle_destroy(key)
    }
  })

/**
 * The engine's key for `secret`, but signing Taproot key paths with `aux` as its auxiliary randomness: what makes a
 * whole Taproot transaction reproducible, to compare with another library's byte for byte.
 */
export const withAux = (key: Secp256k1Key, secret: Uint8Array, aux: Uint8Array): Secp256k1Key =>
  Object.freeze({
    ...key,
    signTaproot: (sighash: Uint8Array, merkleRoot?: Uint8Array) => signWithAux(secret, sighash, aux, {merkleRoot}),
  })
