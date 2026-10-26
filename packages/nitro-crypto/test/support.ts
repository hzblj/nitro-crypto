import {readFileSync} from 'node:fs'
import path from 'node:path'

import {createTestCryptoEngine} from '../src/testing'

/** One engine for the suite: the WebAssembly build of the same Zig the phones run. */
export const crypto = createTestCryptoEngine()

/** A fixed-seed generator (mulberry32): property tests that fail, fail the same way on the next run. */
export const seededBytes = (seed: number) => {
  let state = seed >>> 0
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0
    let t = state
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
  return {
    bytes: (length: number) => Uint8Array.from({length}, () => Math.floor(next() * 256)),
    integer: (below: number) => Math.floor(next() * below),
  }
}

export const vectors = <T>(file: string): T =>
  JSON.parse(readFileSync(path.join(import.meta.dirname, 'vectors', file), 'utf8')) as T

export const ABANDON = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
