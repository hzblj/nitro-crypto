import assert from 'node:assert/strict'
import {test} from 'node:test'

import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {secp256k1} from '@noble/curves/secp256k1.js'
import {sha256} from '@noble/hashes/sha2.js'
import {keccak_256} from '@noble/hashes/sha3.js'
import {createBase58check} from '@scure/base'
import {HDKey} from '@scure/bip32'
import {mnemonicToSeedSync} from '@scure/bip39'

import {createAdapters, type TronAccount} from '../src/chains'

const ABANDON = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

/** TRON's address computed from independent libraries only: @scure/bip32, @noble's Keccak, @scure's Base58Check. */
const referenceTronAddress = (mnemonic: string, account: number) => {
  const key = HDKey.fromMasterSeed(mnemonicToSeedSync(mnemonic)).derive(`m/44'/195'/${account}'/0/0`)
  const point = secp256k1.Point.fromBytes(key.publicKey ?? new Uint8Array()).toBytes(false)
  const payload = new Uint8Array([0x41, ...keccak_256(point.subarray(1)).subarray(12)])
  return createBase58check(sha256).encode(payload)
}

test('four chains on one engine: three published adapters and one written in this app', async () => {
  const crypto = createTestCryptoEngine({adapters: createAdapters()})
  assert.deepEqual(
    crypto.adapters.map(adapter => adapter.id),
    ['ethereum', 'bitcoin', 'solana', 'tron']
  )

  const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
  const ethereum = await wallet.deriveAccount({chain: 'ethereum'})
  const bitcoin = await wallet.deriveAccount({chain: 'bitcoin'})
  const solana = await wallet.deriveAccount({chain: 'solana'})
  const tron: TronAccount = await wallet.deriveAccount({chain: 'tron'})

  assert.equal(ethereum.address, '0x9858EfFD232B4033E47d90003D41EC34EcaEda94')
  assert.equal(bitcoin.address, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu')
  assert.equal(solana.address, 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk')
  assert.equal(tron.address, 'TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH')
  assert.equal(tron.address, referenceTronAddress(ABANDON, 0))

  for (const account of [1, 2, 17]) {
    assert.equal((await wallet.deriveAccount({account, chain: 'tron'})).address, referenceTronAddress(ABANDON, account))
  }
  assert.equal(crypto.chains.tron.validateAddress(tron.address).valid, true)
  assert.equal(crypto.chains.tron.validateAddress(bitcoin.address).valid, false)
  wallet.dispose()
})
