import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import path from 'node:path'
import {describe, test} from 'node:test'

import {hex, isCryptoError} from '@hzblj/nitro-crypto/adapter'
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {HDKey} from '@scure/bip32'
import {mnemonicToSeedSync} from '@scure/bip39'
import {Address, NETWORK, OutScript, p2wpkh, TEST_NETWORK} from '@scure/btc-signer'

import {bitcoinAdapter, VERSION} from '../src'

type Bip84 = {
  mnemonic: string
  accounts: {
    path: string
    request: {account: number; change: 0 | 1; index: number}
    publicKey: string
    address: string
  }[]
}
type Segwit = {valid: {address: string; scriptPubKey: string}[]; invalid: {address: string; reason: string}[]}

const vectors = <T>(file: string): T =>
  JSON.parse(readFileSync(path.join(import.meta.dirname, 'vectors', file), 'utf8')) as T

const crypto = createTestCryptoEngine({
  adapters: [
    bitcoinAdapter(),
    bitcoinAdapter({id: 'bitcoin-testnet', network: 'testnet'}),
    bitcoinAdapter({id: 'bitcoin-regtest', network: 'regtest'}),
  ],
})
const mainnet = crypto.chains.bitcoin
const testnet = crypto.chains['bitcoin-testnet']
const REGTEST_NETWORK = {...TEST_NETWORK, bech32: 'bcrt'}

describe('accounts', () => {
  test('BIP-84 test vectors: paths, public keys and addresses', async () => {
    const {accounts, mnemonic} = vectors<Bip84>('bip84.json')
    const wallet = await crypto.createEphemeralWallet({mnemonic})
    for (const expected of accounts) {
      const account = await wallet.deriveAccount({chain: 'bitcoin', ...expected.request})
      assert.equal(account.path, expected.path)
      assert.equal(hex.encode(account.publicKey), expected.publicKey)
      assert.equal(account.address, expected.address)
      assert.equal(account.addressType, 'p2wpkh')
      assert.equal(account.network, 'mainnet')
    }
    wallet.dispose()
  })

  test('addresses and scripts equal @scure/btc-signer on every network, at many paths', async () => {
    const mnemonic = vectors<Bip84>('bip84.json').mnemonic
    const wallet = await crypto.createEphemeralWallet({mnemonic, passphrase: 'nitro'})
    const root = HDKey.fromMasterSeed(mnemonicToSeedSync(mnemonic, 'nitro'))
    for (const [chain, network, coin] of [
      ['bitcoin', NETWORK, 0],
      ['bitcoin-testnet', TEST_NETWORK, 1],
      ['bitcoin-regtest', REGTEST_NETWORK, 1],
    ] as const) {
      for (const [account, change, index] of [
        [0, 0, 0],
        [0, 1, 3],
        [4, 0, 17],
      ] as const) {
        const ours = await wallet.deriveAccount({account, chain, change, index})
        const reference = root.derive(`m/84'/${coin}'/${account}'/${change}/${index}`)
        const theirs = p2wpkh(reference.publicKey ?? new Uint8Array(), network)
        assert.equal(ours.address, theirs.address)
        assert.deepEqual(ours.scriptPubKey, theirs.script)
        assert.equal(ours.path, `m/84'/${coin}'/${account}'/${change}/${index}`)
      }
    }
    wallet.dispose()
  })

  test('accounts sign messages (BIP-322, BIP-137) and Taproot, and the adapter says so', async () => {
    const wallet = await crypto.createEphemeralWallet()
    const account = await wallet.deriveAccount({chain: 'bitcoin'})
    assert.equal(typeof account.signMessage, 'function')
    assert.deepEqual(bitcoinAdapter().features, {
      messageSigning: true,
      psbt: true,
      taproot: true,
      transactionSigning: true,
    })
    assert.deepEqual(bitcoinAdapter().formats, {
      address: ['bech32-p2wpkh', 'bech32m-p2tr'],
      signature: ['p2wpkh-bip143', 'p2tr-bip341', 'bip322-simple', 'bip137'],
    })
    // Taproot is not required: an engine without Schnorr signatures still registers the adapter.
    assert.deepEqual(bitcoinAdapter().requires, ['sha256', 'ripemd160', 'bip32-secp256k1'])
    wallet.dispose()
  })

  test('change is 0 or 1, and indexes are in range', async () => {
    const wallet = await crypto.createEphemeralWallet()
    await assert.rejects(
      () => wallet.deriveAccount({chain: 'bitcoin', change: 2 as 1}),
      error => isCryptoError(error, 'INVALID_ARGUMENT')
    )
    await assert.rejects(
      () => wallet.deriveAccount({chain: 'bitcoin', index: 2 ** 31}),
      error => isCryptoError(error, 'INVALID_ARGUMENT')
    )
    wallet.dispose()
  })
})

describe('address validation', () => {
  const segwit = vectors<Segwit>('segwit-addresses.json')

  const chainFor = (address: string) => {
    const prefix = address.toLowerCase().slice(0, address.lastIndexOf('1'))
    return prefix === 'bc' ? mainnet : prefix === 'tb' ? testnet : undefined
  }

  test('BIP-350: every valid address is valid on its network, with the script the BIP gives', () => {
    for (const {address, scriptPubKey} of segwit.valid) {
      const chain = chainFor(address)
      assert.ok(chain, address)
      const result = chain.validateAddress(address)
      assert.ok(result.valid, `${address}: ${result.valid ? '' : result.reason}`)
      assert.equal(hex.encode(result.scriptPubKey), scriptPubKey)
      assert.equal(result.normalized, address.toLowerCase())
    }
  })

  test('BIP-350: every invalid address is invalid on both networks', () => {
    for (const {address, reason} of segwit.invalid) {
      assert.equal(mainnet.validateAddress(address).valid, false, `${address}: ${reason}`)
      assert.equal(testnet.validateAddress(address).valid, false, `${address}: ${reason}`)
    }
  })

  test('types: P2WPKH, P2WSH, P2TR and future witness versions', () => {
    const byType = (address: string) => {
      const result = mainnet.validateAddress(address)
      return result.valid ? result.type : result.reason
    }
    assert.equal(byType('BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4'), 'p2wpkh')
    assert.equal(byType('bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3'), 'p2wsh')
    assert.equal(byType('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0'), 'p2tr')
    assert.equal(byType('bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs'), 'witness')
  })

  test('legacy Base58Check addresses validate on their own network only, and agree with @scure/btc-signer', () => {
    const p2pkh = '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'
    const p2sh = '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy'
    const testnetP2pkh = 'mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn'
    for (const [address, type] of [
      [p2pkh, 'p2pkh'],
      [p2sh, 'p2sh'],
    ] as const) {
      const result = mainnet.validateAddress(address)
      assert.ok(result.valid && result.type === type, address)
      assert.deepEqual(result.scriptPubKey, OutScript.encode(Address(NETWORK).decode(address)))
      assert.equal(testnet.validateAddress(address).valid, false)
    }
    assert.equal(testnet.validateAddress(testnetP2pkh).valid, true)
    assert.equal(mainnet.validateAddress(testnetP2pkh).valid, false)
    assert.equal(mainnet.validateAddress(`${p2pkh.slice(0, -1)}J`).valid, false)
  })

  test('another network`s SegWit address is refused with a reason that names it', () => {
    const result = mainnet.validateAddress('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx')
    assert.equal(result.valid, false)
    assert.match(result.valid ? '' : result.reason, /tb/)
    assert.equal(
      crypto.chains['bitcoin-regtest'].validateAddress('bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080').valid,
      true
    )
  })

  test('garbage is invalid, never an exception', () => {
    for (const text of [
      '',
      ' ',
      'bc1',
      'hello',
      '0x1234',
      'bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
      '1111111111111111111114oLvT3',
    ]) {
      assert.equal(mainnet.validateAddress(text).valid, false, text)
    }
    // The burn address, P2PKH of twenty zero bytes, is a real (unspendable) address.
    assert.equal(mainnet.validateAddress('1111111111111111111114oLvT2').valid, true)
  })
})

describe('adapter', () => {
  test('names and paths follow the network', () => {
    assert.equal(bitcoinAdapter().name, 'Bitcoin')
    assert.equal(bitcoinAdapter({network: 'signet'}).name, 'Bitcoin signet')
    assert.equal(testnet.network.coinType, 1)
    assert.equal(
      mainnet.addressFromPublicKey(hex.decode('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')),
      'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'
    )
  })

  test('an uncompressed key is refused: P2WPKH commits to compressed keys only', () => {
    assert.throws(
      () => mainnet.addressFromPublicKey(new Uint8Array(65)),
      error => isCryptoError(error, 'INVALID_PUBLIC_KEY')
    )
  })

  test('the version is the package`s, and unknown networks are refused', () => {
    const manifest = JSON.parse(readFileSync(path.join(import.meta.dirname, '../package.json'), 'utf8'))
    assert.equal(VERSION, manifest.version)
    assert.equal(bitcoinAdapter().version, manifest.version)
    assert.throws(
      () => bitcoinAdapter({network: 'litecoin' as 'mainnet'}),
      error => isCryptoError(error, 'INVALID_CONFIG')
    )
  })
})
