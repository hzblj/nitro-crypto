import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {readdir, readFile} from 'node:fs/promises'
import path from 'node:path'
import {after, describe, test} from 'node:test'

import {hex} from '@hzblj/nitro-crypto/adapter'
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {HDKey} from '@scure/bip32'
import {mnemonicToSeedSync} from '@scure/bip39'
import {p2wpkh, TEST_NETWORK} from '@scure/btc-signer'

import {bitcoinAdapter} from '../../src'
import {createBitcoinSync, esploraBackend, formatExtendedKey, parseExtendedKey} from '../../src/sync'
import {
  ACCOUNT_PATH,
  chain,
  crypto,
  MNEMONIC,
  openWallet,
  referenceAccount,
  referenceAddress,
  referenceKey,
  throwsSync,
} from './helpers'

const sha256 = crypto.hash.sha256

/** BIP-84's own account key for its test phrase, as its specification prints it. */
const BIP84_ZPUB =
  'zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs'

const VERSIONS = {
  tprv: {private: 0x04358394, public: 0x043587cf},
  upub: {private: 0x044a4e28, public: 0x044a5262},
  vpub: {private: 0x045f18bc, public: 0x045f1cf6},
  xpub: {private: 0x0488ade4, public: 0x0488b21e},
  zpub: {private: 0x04b2430c, public: 0x04b24746},
}

const seed = mnemonicToSeedSync(MNEMONIC)

type Bip84 = {
  readonly accounts: readonly {
    readonly path: string
    readonly request: object
    readonly publicKey: string
    readonly address: string
  }[]
}

const bip84 = JSON.parse(readFileSync(path.join(import.meta.dirname, '../vectors/bip84.json'), 'utf8')) as Bip84
const offline = esploraBackend({
  fetch: () => Promise.reject(new Error('offline')),
  network: 'testnet',
  url: 'https://esplora.test/api',
})

describe('extended keys', async () => {
  const wallet = await openWallet()
  after(() => wallet.dispose())

  test('xpub, tpub, zpub and vpub read as @scure/bip32 writes them, and write back the same', () => {
    for (const [prefix, versions] of Object.entries(VERSIONS).filter(
      ([name]) => name.endsWith('pub') && name !== 'upub'
    )) {
      const key = HDKey.fromMasterSeed(seed, versions).derive(ACCOUNT_PATH)
      const text = key.publicExtendedKey
      const parsed = parseExtendedKey(text, sha256)

      assert.equal(parsed.prefix, prefix)
      assert.equal(parsed.network, prefix === 'xpub' || prefix === 'zpub' ? 'mainnet' : 'test')
      assert.equal(parsed.scriptType, prefix === 'zpub' || prefix === 'vpub' ? 'p2wpkh' : undefined)
      assert.deepEqual(parsed.extendedKey.publicKey, key.publicKey)
      assert.deepEqual(parsed.extendedKey.chainCode, key.chainCode)
      assert.equal(parsed.extendedKey.depth, 3)
      assert.equal(parsed.extendedKey.parentFingerprint, key.parentFingerprint)
      assert.equal(parsed.extendedKey.childNumber, 0x80000000)

      const network = parsed.network === 'mainnet' ? 'mainnet' : 'testnet'
      assert.equal(formatExtendedKey(parsed.extendedKey, {network, scriptType: parsed.scriptType}, sha256), text)
    }
  })

  test('the engine`s extended key is the one @scure/bip32 derives', () => {
    const extendedKey = wallet.extendedPublicKey(ACCOUNT_PATH)
    const text = formatExtendedKey(extendedKey, {network: 'testnet'}, sha256)

    assert.equal(text, HDKey.fromMasterSeed(seed, VERSIONS.tprv).derive(ACCOUNT_PATH).publicExtendedKey)
    assert.deepEqual(parseExtendedKey(text, sha256).extendedKey, extendedKey)
  })

  test('BIP-84`s zpub gives BIP-84`s addresses on mainnet', () => {
    const mainnet = createTestCryptoEngine({adapters: [bitcoinAdapter()]})
    const {extendedKey, scriptType} = parseExtendedKey(BIP84_ZPUB, sha256)
    const sync = createBitcoinSync({
      backend: esploraBackend({fetch: () => Promise.reject(new Error('offline')), network: 'mainnet'}),
      chain: mainnet.chains.bitcoin,
      extendedKey,
      scriptType,
    })

    assert.equal(sync.path, "m/84'/0'/0'")

    for (const vector of bip84.accounts) {
      const {change, index} = vector.request as {change: 0 | 1; index: number}
      const address = sync.addressAt(change, index)

      assert.equal(address.address, vector.address)
      assert.equal(address.path, vector.path)
      assert.equal(hex.encode(address.publicKey ?? new Uint8Array()), vector.publicKey)
    }

    assert.equal(sync.view().receiveAddress.address, bip84.accounts[0]?.address)
  })

  test('every address of the account, both branches, as @scure/bip32 and btc-signer derive them', () => {
    const sync = createBitcoinSync({
      backend: offline,
      chain,
      extendedKey: wallet.extendedPublicKey(ACCOUNT_PATH),
      fingerprint: wallet.fingerprint,
    })

    for (const change of [0, 1] as const) {
      for (let index = 0; index < 40; index++) {
        const address = sync.addressAt(change, index)

        assert.equal(address.address, referenceAddress(change, index))
        assert.deepEqual(address.publicKey, referenceKey(change, index).publicKey)
        assert.equal(address.path, `${ACCOUNT_PATH}/${change}/${index}`)
      }
    }

    assert.equal(sync.fingerprint, HDKey.fromMasterSeed(seed).fingerprint)
    throwsSync(() => sync.addressAt(0, -1), 'INVALID_ARGUMENT')
    throwsSync(() => sync.addressAt(2 as 0, 0), 'INVALID_ARGUMENT')
  })

  test('private keys are refused on sight, wrapped and multisig accounts are not followed, and the text is checked', () => {
    const account = HDKey.fromMasterSeed(seed, VERSIONS.zpub).derive("m/84'/0'/0'")
    throwsSync(() => parseExtendedKey(account.privateExtendedKey, sha256), 'PRIVATE_KEY_MATERIAL')
    throwsSync(
      () => parseExtendedKey(HDKey.fromMasterSeed(seed, VERSIONS.tprv).privateExtendedKey, sha256),
      'PRIVATE_KEY_MATERIAL'
    )
    throwsSync(
      () => parseExtendedKey(HDKey.fromMasterSeed(seed, VERSIONS.upub).derive("m/49'/1'/0'").publicExtendedKey, sha256),
      'UNSUPPORTED',
      /upub/
    )

    const broken = `${BIP84_ZPUB.slice(0, -1)}${BIP84_ZPUB.endsWith('s') ? 't' : 's'}`
    throwsSync(() => parseExtendedKey(broken, sha256), 'INVALID_EXTENDED_KEY')
    throwsSync(() => parseExtendedKey('not a key', sha256), 'INVALID_EXTENDED_KEY')

    // Messages never quote the key.
    try {
      parseExtendedKey(broken, sha256)
    } catch (error) {
      assert.equal(String((error as Error).message).includes(broken.slice(4, 20)), false)
    }
  })

  test('the key, its path and the networks must agree', () => {
    const extendedKey = wallet.extendedPublicKey(ACCOUNT_PATH)

    throwsSync(
      () => createBitcoinSync({backend: offline, chain, extendedKey, path: "m/84'/1'"}),
      'INVALID_EXTENDED_KEY',
      /depth/
    )
    throwsSync(
      () => createBitcoinSync({backend: offline, chain, extendedKey, path: "m/84'/1'/1'"}),
      'INVALID_EXTENDED_KEY',
      /index/
    )
    throwsSync(
      () => createBitcoinSync({backend: offline, chain, extendedKey: wallet.extendedPublicKey("m/84'/1'/0'/0")}),
      'INVALID_ARGUMENT',
      /pass its path/
    )
    throwsSync(
      () =>
        createBitcoinSync({
          backend: esploraBackend({network: 'mainnet'}),
          chain,
          extendedKey,
        }),
      'NETWORK_MISMATCH'
    )
    throwsSync(
      () => createBitcoinSync({backend: offline, chain, extendedKey, scriptType: 'p2tr'}),
      'UNSUPPORTED',
      /Taproot/
    )
    throwsSync(() => createBitcoinSync({backend: offline, chain, extendedKey, gapLimit: 0}), 'INVALID_ARGUMENT')
    throwsSync(() => createBitcoinSync({backend: offline, chain, extendedKey, fingerprint: -1}), 'INVALID_ARGUMENT')
    throwsSync(() => esploraBackend({network: 'regtest'}), 'INVALID_ARGUMENT', /url/)

    // A key from the middle of a path is fine with its path: the account below `m/84'/1'/0'/0` is its receiving branch.
    const below = createBitcoinSync({
      backend: offline,
      chain,
      extendedKey: wallet.extendedPublicKey("m/84'/1'/0'/0"),
      path: "m/84'/1'/0'/0",
    })
    const deeper = referenceAccount.deriveChild(0).deriveChild(0).deriveChild(0).publicKey ?? new Uint8Array()
    assert.equal(below.addressAt(0, 0).address, p2wpkh(deeper, TEST_NETWORK).address)
    assert.equal(below.addressAt(0, 0).path, "m/84'/1'/0'/0/0/0")
  })
})

describe('the package`s entry points', () => {
  test('the main entry has no network code: nothing from sync/, no fetch', async () => {
    const root = path.resolve(import.meta.dirname, '../../src')

    for (const file of (await readdir(root)).filter(name => name.endsWith('.ts'))) {
      const source = await readFile(path.join(root, file), 'utf8')

      assert.equal(/from '\.\/sync/.test(source), false, file)
      assert.equal(/\bfetch\(/.test(source), false, file)
    }
  })

  test('/sync is a subpath of its own, with the source condition like the main entry', async () => {
    const manifest = JSON.parse(await readFile(path.resolve(import.meta.dirname, '../../package.json'), 'utf8'))

    assert.deepEqual(manifest.exports['./sync'], {
      default: './build/sync/index.js',
      source: './src/sync/index.ts',
      types: './build/sync/index.d.ts',
    })
    assert.deepEqual(manifest.publishConfig.exports['./sync'], {
      default: './build/sync/index.js',
      types: './build/sync/index.d.ts',
    })
  })
})
