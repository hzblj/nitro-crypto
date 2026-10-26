import type {Ed25519Key, Secp256k1Key} from '@hzblj/nitro-crypto'
import {ed25519} from '@noble/curves/ed25519.js'
import {secp256k1} from '@noble/curves/secp256k1.js'
import {sha256} from '@noble/hashes/sha2.js'
import {keccak_256} from '@noble/hashes/sha3.js'

import type {AppCrypto} from '../crypto'
import {TEST_MNEMONIC} from '../vectors'

/**
 * What both sides of a comparison work on: the same payload, and the same keys, imported into the engine from bytes
 * the JavaScript reference holds too. Raw import is for exactly this kind of test; the app's wallets never do it.
 */
export type Fixture = {
  readonly crypto: AppCrypto
  readonly payload: Uint8Array
  readonly digest: Uint8Array
  readonly secp: {
    readonly key: Secp256k1Key
    readonly secret: Uint8Array
    readonly publicKey: Uint8Array
    readonly signature: Uint8Array
  }
  readonly ed: {
    readonly key: Ed25519Key
    readonly seed: Uint8Array
    readonly publicKey: Uint8Array
    readonly signature: Uint8Array
  }
}

export const createFixture = (crypto: AppCrypto, payloadLength: number): Fixture => {
  let secret = crypto.random(32)
  while (!secp256k1.utils.isValidSecretKey(secret)) {
    secret = crypto.random(32)
  }
  const secpKey = crypto.keys.importRawSecret('secp256k1', secret)
  const edSeed = crypto.random(32)
  const edKey = crypto.keys.importRawSecret('ed25519', edSeed)
  const payload = crypto.random(payloadLength)
  const digest = crypto.hash.sha256(payload)
  return {
    crypto,
    digest,
    ed: {key: edKey, publicKey: edKey.publicKey(), seed: edSeed, signature: edKey.sign(payload)},
    payload,
    secp: {key: secpKey, publicKey: secpKey.publicKey(), secret, signature: secpKey.sign(digest).signature},
  }
}

export const disposeFixture = (fixture: Fixture) => {
  fixture.secp.key.dispose()
  fixture.ed.key.dispose()
}

type Run = () => unknown

export type Operation = {
  readonly id: string
  readonly title: string
  /** What is measured, on both sides, so the comparison is between equal work. */
  readonly measures: string
  /** Whether its cost grows with the payload (and its iterations are capped for large ones). */
  readonly sized: boolean
  readonly native: (fixture: Fixture) => Run
  /** The same operation in @noble's audited JavaScript, when there is an equivalent. */
  readonly javascript?: (fixture: Fixture) => Run
}

export const OPERATIONS: readonly Operation[] = [
  {
    id: 'crossing',
    javascript: () => () => sha256(new Uint8Array()),
    measures: 'SHA-256 of zero bytes: almost all of it is the Nitro call itself.',
    native:
      ({crypto}) =>
      () =>
        crypto.hash.sha256(new Uint8Array()),
    sized: false,
    title: 'Bridge crossing',
  },
  {
    id: 'sha256',
    javascript:
      ({payload}) =>
      () =>
        sha256(payload),
    measures: 'SHA-256 of the payload.',
    native:
      ({crypto, payload}) =>
      () =>
        crypto.hash.sha256(payload),
    sized: true,
    title: 'SHA-256',
  },
  {
    id: 'keccak256',
    javascript:
      ({payload}) =>
      () =>
        keccak_256(payload),
    measures: 'Keccak-256 of the payload.',
    native:
      ({crypto, payload}) =>
      () =>
        crypto.hash.keccak256(payload),
    sized: true,
    title: 'Keccak-256',
  },
  {
    id: 'sha256-async',
    measures: 'SHA-256 on a background thread, awaited: the copy, the hop and the hash. JavaScript has no equivalent.',
    native:
      ({crypto, payload}) =>
      () =>
        crypto.hash.digestAsync('sha256', payload),
    sized: true,
    title: 'SHA-256, async',
  },
  {
    id: 'secp256k1-sign',
    javascript:
      ({digest, secp}) =>
      () =>
        secp256k1.sign(digest, secp.secret, {prehash: false}),
    measures: 'ECDSA over a 32-byte digest, RFC 6979 nonce, lower S: the same signature on both sides.',
    native:
      ({digest, secp}) =>
      () =>
        secp.key.sign(digest),
    sized: false,
    title: 'secp256k1 sign',
  },
  {
    id: 'secp256k1-verify',
    javascript:
      ({digest, secp}) =>
      () =>
        secp256k1.verify(secp.signature, digest, secp.publicKey, {prehash: false}),
    measures: 'ECDSA verification of that signature.',
    native:
      ({crypto, digest, secp}) =>
      () =>
        crypto.secp256k1.verify(secp.publicKey, digest, secp.signature),
    sized: false,
    title: 'secp256k1 verify',
  },
  {
    id: 'ed25519-sign',
    javascript:
      ({ed, payload}) =>
      () =>
        ed25519.sign(payload, ed.seed),
    measures: 'RFC 8032 signature of the payload.',
    native:
      ({ed, payload}) =>
      () =>
        ed.key.sign(payload),
    sized: true,
    title: 'Ed25519 sign',
  },
  {
    id: 'ed25519-verify',
    javascript:
      ({ed, payload}) =>
      () =>
        ed25519.verify(ed.signature, payload, ed.publicKey),
    measures: 'RFC 8032 verification of that signature.',
    native:
      ({crypto, ed, payload}) =>
      () =>
        crypto.ed25519.verify(ed.publicKey, payload, ed.signature),
    sized: true,
    title: 'Ed25519 verify',
  },
  {
    id: 'wallet',
    measures:
      'A wallet from a mnemonic, awaited: BIP-39 (PBKDF2, 2048 rounds) and the BIP-32 fingerprint, off the JS thread.',
    native:
      ({crypto}) =>
      async () =>
        (await crypto.createEphemeralWallet({mnemonic: TEST_MNEMONIC})).dispose(),
    sized: false,
    title: 'Wallet from mnemonic',
  },
]

/** Large payloads get fewer iterations: no run hashes more than this many bytes per side. */
const BYTE_BUDGET = 64 << 20

export const iterationsFor = (operation: Operation, iterations: number, payloadLength: number) =>
  operation.sized ? Math.max(3, Math.min(iterations, Math.floor(BYTE_BUDGET / Math.max(payloadLength, 1)))) : iterations

/** Microseconds per call, after a short warm-up. Promises are awaited one at a time, never in parallel. */
export const measure = async (run: Run, iterations: number): Promise<number> => {
  for (let index = 0; index < 3; index++) {
    await run()
  }
  const started = performance.now()
  for (let index = 0; index < iterations; index++) {
    const result = run()
    if (result instanceof Promise) {
      await result
    }
  }
  return ((performance.now() - started) * 1000) / iterations
}
