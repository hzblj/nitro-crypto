import assert from 'node:assert/strict'

import {type CryptoErrorCode, isCryptoError, type KeySource, type Secp256k1Key} from '@hzblj/nitro-crypto/adapter'
import {bytesToHex} from 'viem'

export const HARDHAT = 'test test test test test test test test test test test junk'

/** Hardhat's account 0: `m/44'/60'/0'/0/0` of the mnemonic above. */
export const HARDHAT_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'

export const SEPOLIA = 11155111

export const toHex = (bytes: Uint8Array) => bytesToHex(bytes)

export const throwsCode = (run: () => unknown, code: CryptoErrorCode) =>
  assert.throws(run, error => isCryptoError(error) && error.code === code, code)

export const rejectsCode = (run: () => Promise<unknown>, code: CryptoErrorCode) =>
  assert.rejects(run, error => isCryptoError(error) && error.code === code, code)

/** A key the engine imported, as a wallet's key source: how a test signs with a published private key. */
export const keySourceOf = (key: Secp256k1Key): KeySource => ({
  deriveKey: (() => key) as KeySource['deriveKey'],
  extendedPublicKey: () => {
    throw new Error('An imported key has no extended public key.')
  },
  fingerprint: 0,
})

/** A seeded generator (mulberry32): the same "random" cases on every run. */
export const random = (seed: number) => {
  let state = seed

  const next = () => {
    state = (state + 0x6d2b79f5) | 0
    let t = Math.imul(state ^ (state >>> 15), 1 | state)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t

    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
  const int = (max: number) => Math.floor(next() * max)
  const bytes = (length: number) => Uint8Array.from({length}, () => int(256))
  const pick = <T>(items: readonly T[]): T => items[int(items.length)] as T
  // Integers of every size up to `bits`, zero and the extremes included.
  const uint = (bits: number): bigint => {
    const choice = int(10)

    if (choice === 0) {
      return 0n
    }

    if (choice === 1) {
      return (1n << BigInt(bits)) - 1n
    }

    const size = 1 + int(bits / 8)

    return BigInt(toHex(bytes(size))) >> BigInt(int(8))
  }

  return {bytes, int, pick, uint}
}

export type Random = ReturnType<typeof random>
