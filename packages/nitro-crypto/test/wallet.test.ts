import assert from 'node:assert/strict'
import {describe, test} from 'node:test'

import {ed25519} from '@noble/curves/ed25519.js'
import {hmac} from '@noble/hashes/hmac.js'
import {sha512} from '@noble/hashes/sha2.js'
import {HDKey} from '@scure/bip32'
import {mnemonicToSeedSync, validateMnemonic} from '@scure/bip39'
import {wordlist} from '@scure/bip39/wordlists/english.js'

import {isCryptoError} from '../src/core/errors'
import {utf8} from '../src/encoding'
import {MNEMONIC_LENGTHS} from '../src/engine/mnemonic'
import {ABANDON, crypto} from './support'

const rejectsCode = async (run: () => Promise<unknown>, code: string) =>
  assert.rejects(run, error => isCryptoError(error) && error.code === code, code)

const throwsCode = (run: () => unknown, code: string) =>
  assert.throws(run, error => isCryptoError(error) && error.code === code, code)

/** SLIP-0010 for Ed25519 written out with @noble's HMAC: an independent derivation to compare the engine against. */
const slip10 = (seed: Uint8Array, path: number[]) => {
  let node = hmac(sha512, utf8.encode('ed25519 seed'), seed)
  for (const index of path) {
    const data = new Uint8Array(37)
    data.set(node.subarray(0, 32), 1)
    new DataView(data.buffer).setUint32(33, (index | 0x80000000) >>> 0)
    node = hmac(sha512, node.subarray(32), data)
  }
  return ed25519.getPublicKey(node.subarray(0, 32))
}

const BIP32_PATHS = ["m/44'/60'/0'/0/0", "m/44'/60'/0'/0/7", "m/84'/0'/0'/0/0", "m/84'/1'/3'/1/19", 'm/0/1/2', 'm']

describe('wallets from a known mnemonic', () => {
  test('match @scure/bip39 and @scure/bip32 at every path, with and without a passphrase', async () => {
    for (const passphrase of ['', 'TREZOR', 'ñandú 日本']) {
      const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON, passphrase})
      const reference = HDKey.fromMasterSeed(mnemonicToSeedSync(ABANDON, passphrase))
      assert.equal(wallet.fingerprint, reference.fingerprint)
      assert.equal(wallet.origin, 'mnemonic')
      assert.equal(wallet.words, 12)
      for (const path of BIP32_PATHS) {
        assert.deepEqual(wallet.deriveKey('bip32', path).publicKey(), reference.derive(path).publicKey, path)
      }
      wallet.dispose()
    }
  })

  test('the fingerprint of "abandon … about" is 73c5da0a', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    assert.equal(wallet.fingerprint, 0x73c5da0a)
    wallet.dispose()
  })

  test('Ed25519 keys match an independent SLIP-0010 derivation', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    const seed = mnemonicToSeedSync(ABANDON)
    for (const path of [[44, 501, 0, 0], [44, 501, 7, 0], [44, 501], [0]]) {
      const text = `m/${path.map(index => `${index}'`).join('/')}`
      assert.deepEqual(wallet.deriveKey('slip10', text).publicKey(), slip10(seed, path), text)
    }
    wallet.dispose()
  })

  test('mnemonics are normalized like other wallets: case, spacing, NFKD', async () => {
    const messy = await crypto.createEphemeralWallet({
      mnemonic: `  ${ABANDON.toUpperCase().replaceAll(' ', ' \n\t ')}  `,
    })
    assert.equal(messy.fingerprint, 0x73c5da0a)
    messy.dispose()
    // Precomposed and decomposed é are one passphrase.
    const composed = await crypto.createEphemeralWallet({mnemonic: ABANDON, passphrase: 'é'})
    const decomposed = await crypto.createEphemeralWallet({mnemonic: ABANDON, passphrase: 'é'})
    assert.equal(composed.fingerprint, decomposed.fingerprint)
    assert.equal(composed.fingerprint, HDKey.fromMasterSeed(mnemonicToSeedSync(ABANDON, 'é')).fingerprint)
    composed.dispose()
    decomposed.dispose()
  })

  test('invalid mnemonics are refused with the reason, and leave nothing behind', async () => {
    const before = crypto.liveHandles()
    await rejectsCode(
      () => crypto.createEphemeralWallet({mnemonic: ABANDON.replace('about', 'abandon')}),
      'MNEMONIC_CHECKSUM'
    )
    await rejectsCode(
      () => crypto.createEphemeralWallet({mnemonic: ABANDON.replace('about', 'xyzzy')}),
      'INVALID_MNEMONIC'
    )
    await rejectsCode(() => crypto.createEphemeralWallet({mnemonic: 'abandon abandon'}), 'INVALID_MNEMONIC')
    assert.equal(crypto.liveHandles(), before)
  })
})

describe('generated wallets', () => {
  test('each has its own seed, with the word count asked for', async () => {
    const wallets = await Promise.all(
      [12, 15, 18, 21, 24].map(words => crypto.createEphemeralWallet({words: words as 12}))
    )
    assert.equal(new Set(wallets.map(wallet => wallet.fingerprint)).size, wallets.length)
    assert.deepEqual(
      wallets.map(wallet => wallet.words),
      [12, 15, 18, 21, 24]
    )
    for (const wallet of wallets) {
      assert.equal(wallet.origin, 'generated')
      wallet.dispose()
    }
  })

  test('word counts BIP-39 does not define are refused', async () => {
    await rejectsCode(() => crypto.createEphemeralWallet({words: 13 as 12}), 'INVALID_ARGUMENT')
  })
})

describe('disposal', () => {
  test('disposing a wallet zeroizes its seed and every key derived from it', async () => {
    const before = crypto.liveHandles()
    const wallet = await crypto.createEphemeralWallet()
    const keys = Array.from({length: 20}, (_, index) => wallet.deriveKey('bip32', `m/44'/60'/0'/0/${index}`))
    const solana = wallet.deriveKey('slip10', "m/44'/501'/0'/0'")
    assert.equal(crypto.liveHandles(), before + 22)

    keys[0]?.dispose()
    assert.equal(crypto.liveHandles(), before + 21)

    wallet.dispose()
    wallet.dispose()
    assert.equal(wallet.disposed, true)
    assert.equal(crypto.liveHandles(), before)
    assert.ok(keys.every(key => key.disposed) && solana.disposed)
    throwsCode(() => keys[5]?.sign(new Uint8Array(32)), 'DISPOSED')
    throwsCode(() => wallet.deriveKey('bip32', 'm/0'), 'DISPOSED')
    await rejectsCode(() => wallet.deriveAccount({chain: 'none'} as never), 'DISPOSED')
  })

  test('a bad path or scheme derives nothing', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    const before = crypto.liveHandles()
    throwsCode(() => wallet.deriveKey('bip32', "m/44'/x"), 'INVALID_PATH')
    throwsCode(() => wallet.deriveKey('slip10', "m/44'/501'/0'/0"), 'INVALID_PATH')
    throwsCode(() => wallet.deriveKey('bip44' as 'bip32', 'm/0'), 'INVALID_ARGUMENT')
    assert.equal(crypto.liveHandles(), before)
    wallet.dispose()
  })
})

test('mnemonic.validate reports why, after normalizing', () => {
  assert.deepEqual(crypto.mnemonic.validate(` ${ABANDON.toUpperCase()} `), {valid: true, words: 12})
  assert.deepEqual(crypto.mnemonic.validate(ABANDON.replace('about', 'abandon')), {
    reason: 'MNEMONIC_CHECKSUM',
    valid: false,
    words: 12,
  })
  assert.deepEqual(crypto.mnemonic.validate('hello world'), {reason: 'INVALID_MNEMONIC', valid: false, words: 2})
  assert.deepEqual(crypto.mnemonic.validate(''), {reason: 'INVALID_MNEMONIC', valid: false, words: 0})
})

describe('mnemonic.generate', () => {
  test('every BIP-39 length, valid to the engine and to @scure/bip39, each one different', () => {
    for (const words of MNEMONIC_LENGTHS) {
      const first = crypto.mnemonic.generate(words)
      const second = crypto.mnemonic.generate(words)
      assert.equal(first.split(' ').length, words)
      assert.match(first, /^[a-z]+( [a-z]+)*$/)
      assert.deepEqual(crypto.mnemonic.validate(first), {valid: true, words})
      assert.ok(validateMnemonic(first, wordlist), first)
      assert.notEqual(first, second)
    }
  })

  test('12 words by default, and other counts refused', () => {
    assert.equal(crypto.mnemonic.generate().split(' ').length, 12)
    throwsCode(() => crypto.mnemonic.generate(13 as 12), 'INVALID_ARGUMENT')
    throwsCode(() => crypto.mnemonic.generate(0 as 12), 'INVALID_ARGUMENT')
  })

  test('restores the wallet @scure/bip32 derives from the same words, with and without a passphrase', async () => {
    for (const words of [12, 24] as const) {
      for (const passphrase of ['', 'TREZOR']) {
        const mnemonic = crypto.mnemonic.generate(words)
        const wallet = await crypto.createEphemeralWallet({mnemonic, passphrase})
        const reference = HDKey.fromMasterSeed(mnemonicToSeedSync(mnemonic, passphrase))
        assert.equal(wallet.fingerprint, reference.fingerprint)
        assert.equal(wallet.words, words)
        assert.deepEqual(
          wallet.deriveKey('bip32', "m/44'/60'/0'/0/0").publicKey(),
          reference.derive("m/44'/60'/0'/0/0").publicKey
        )
        wallet.dispose()
      }
    }
  })

  test('stores nothing in the engine', () => {
    const before = crypto.liveHandles()
    for (let index = 0; index < 20; index++) {
      crypto.mnemonic.generate(24)
    }
    assert.equal(crypto.liveHandles(), before)
  })
})
